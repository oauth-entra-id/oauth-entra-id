import type { webcrypto } from 'node:crypto';
import type { AccountInfo, CryptoProvider } from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import type { z } from 'zod/v4';
import { $err, $ok, OAuthError, type Result } from './error';
import type {
  Azure,
  B2BApp,
  Cookies,
  CryptoType,
  EncryptionKeys,
  GetB2BTokenResult,
  GetTokenOnBehalfOfResult,
  LoginPrompt,
  MsalResponse,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  OboService,
} from './types';
import { $cookieOptions } from './utils/cookie-options';
import { $compressObj, $decompressObj } from './utils/crypto/compress';
import { $decrypt, $decryptObj, $encrypt, $encryptObj, $generateUuid } from './utils/crypto/encrypt';
import { $getAud, $getKid } from './utils/crypto/jwt';
import { $constructorHelper, $filterCoreErrors, $mapAndFilter } from './utils/helpers';
import {
  $prettyErr,
  zAccessTokenStructure,
  zEncrypted,
  zInjectedData,
  zJwt,
  zLooseBase64,
  zMethods,
  zState,
  zUuid,
} from './utils/zod';

/**
 * Core OAuth2/PKCE provider for Microsoft Entra ID (Azure AD).
 *
 * Responsibilities:
 *  - PKCE authorization URL generation
 *  - Authorization‐code and refresh‐token exchanges
 *  - Secure encryption/decryption of state & cookies
 *  - JWT validation via JWKS
 *  - B2B client‐credentials flow
 *  - On‐Behalf-Of (OBO) flow for downstream services
 *
 * Designed to be framework-agnostic (Express, NestJS, etc.)
 */
export class OAuthProvider {
  private readonly azure: Azure;
  private readonly frontendUrls: NonEmptyArray<string>;
  private readonly frontendWhitelist: Set<string>;
  private readonly serverCallbackUrl: string;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly encryptionKeys: EncryptionKeys;
  private readonly b2bMap: Map<string, B2BApp> | undefined;
  private readonly oboMap: Map<string, OboService> | undefined;
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: JwksClient;
  readonly settings: OAuthSettings;

  /**
   * @param configuration The OAuth configuration object:
   * - `azure`: clientId, tenantId, scopes, clientSecret
   * - `frontendUrl`: allowed redirect URIs
   * - `serverCallbackUrl`: your server’s Azure callback endpoint
   * - `secretKey`: 32-byte base encryption secret
   * - `advanced`: optional behaviors (cookies, B2B, OBO, prompts)
   * @throws {OAuthError} if the config fails validation or has duplicate service names
   */
  constructor(configuration: OAuthConfig) {
    const result = $constructorHelper(configuration);
    if (result.error) throw new OAuthError(result.error);

    this.azure = result.azure;
    this.frontendUrls = result.frontendUrls;
    this.frontendWhitelist = result.frontendWhitelist;
    this.serverCallbackUrl = result.serverCallbackUrl;
    this.defaultCookieOptions = result.defaultCookieOptions;
    this.encryptionKeys = result.encryptionKeys;
    this.b2bMap = result.b2bMap;
    this.oboMap = result.oboMap;
    this.msalCryptoProvider = result.msalCryptoProvider;
    this.jwksClient = result.jwksClient;
    this.settings = result.settings;
  }

  /**
   * Generate an OAuth2 authorization URL for user login (PKCE-backed).
   *
   * @param params (optional) - Parameters to customize the auth URL:
   * - `loginPrompt` (optional) - Override the default prompt (`sso`|`email`|`select-account`)
   * - `email` (optional) - Email address to pre-fill the login form
   * - `frontendUrl` (optional) - Frontend URL override to redirect the user after authentication
   * @returns A result containing the authorization URL and a ticket (which is used for bearer flow only)
   */
  async getAuthUrl(params?: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<
    Result<{ authUrl: string; ticket: string }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      return $err('bad_request', { error: 'Invalid params: Email required' });
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    const { uuid: ticketId, error: uuidError } = $generateUuid(this.settings.cryptoType);
    if (uuidError) return $err(uuidError);

    try {
      const [pkce, ticket] = await Promise.all([
        this.msalCryptoProvider.generatePkceCodes(),
        this.$encryptTicket(ticketId),
      ]);
      if (ticket.error) return $err(ticket.error);

      const frontendUrl = parsedParams.frontendUrl ?? this.frontendUrls[0];
      const configuredPrompt = parsedParams.loginPrompt ?? this.settings.loginPrompt;
      const prompt: 'login' | 'select_account' | undefined =
        parsedParams.email || configuredPrompt === 'email'
          ? 'login'
          : configuredPrompt === 'select-account'
            ? 'select_account'
            : undefined;

      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedParams.email, prompt };
      const { encryptedState, error: encryptError } = await this.$encryptState({
        frontendUrl,
        codeVerifier: pkce.verifier,
        ticketId: ticketId,
        ...params,
      } satisfies z.infer<typeof zState>);

      if (encryptError) return $err(encryptError);

      const authUrl = await this.azure.cca.getAuthCodeUrl({
        ...params,
        state: encryptedState,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: pkce.challenge,
      });

      if (new URL(authUrl).hostname !== 'login.microsoftonline.com') {
        return $err('internal', { error: "Invalid redirect URL: must be 'login.microsoftonline.com'", status: 500 });
      }

      return $ok({ authUrl, ticket: ticket.encryptedTicket });
    } catch (err) {
      return $filterCoreErrors(err, 'getAuthUrl');
    }
  }

  /**
   * Exchange an authorization code for encrypted tokens and metadata.
   *
   * @param params - The parameters containing the authorization code and state.
   * - `code` - The authorization code received from the OAuth flow.
   * - `state` -  The state parameter received from Microsoft.
   * @returns A result containing the access token, refresh token (if available), frontend URL, and MSAL response.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<
    Result<{
      accessToken: Cookies['AccessToken'];
      refreshToken: Cookies['RefreshToken'] | null;
      frontendUrl: string;
      ticketId: string;
      msalResponse: MsalResponse;
    }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    const { state, error: decryptError } = await this.$decryptState(parsedParams.state);
    if (decryptError) return $err(decryptError);

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    try {
      const msalResponse = await this.azure.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(msalResponse);
      if (error) return $err(error);

      return $ok({
        accessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken },
        refreshToken: encryptedRefreshToken
          ? { value: encryptedRefreshToken, ...this.defaultCookieOptions.refreshToken }
          : null,
        frontendUrl: state.frontendUrl,
        ticketId: state.ticketId,
        msalResponse,
      });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenByCode');
    }
  }

  /**
   * Build a logout URL and cookie-deletion instructions.
   *
   * @param params (optional) - Parameters to customize the logout URL:
   * - `frontendUrl` (optional) - Frontend URL override to redirect the user after log out
   * @returns A result containing the logout URL and cookie deletion instructions.
   */
  getLogoutUrl(params?: { frontendUrl?: string }): Result<{
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${this.azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', parsedParams.frontendUrl ?? this.frontendUrls[0]);

    return $ok({
      logoutUrl: logoutUrl.toString(),
      deleteAccessToken: {
        name: this.defaultCookieOptions.accessToken.name,
        value: '',
        options: this.defaultCookieOptions.deleteOptions,
      },
      deleteRefreshToken: {
        name: this.defaultCookieOptions.refreshToken.name,
        value: '',
        options: this.defaultCookieOptions.deleteOptions,
      },
    });
  }

  /**
   * Verify the access token (either encrypted or in JWT format) and extract its payload.
   * Make sure that user access tokens are encrypted and app tokens aren't
   *
   * @param accessToken - The access token string either encrypted or in JWT format
   * @returns A result containing the raw access token, its payload, any injected data, and whether it is an app token.
   * @template T - Type of any injected data in the encrypted token
   */
  async verifyAccessToken<T extends object = Record<string, any>>(
    accessToken: string | undefined,
  ): Promise<
    Result<{
      payload: jwt.JwtPayload;
      rawAccessToken: string;
      injectedData: T | undefined;
      hasInjectedData: boolean;
      isApp: boolean;
    }>
  > {
    const {
      rawAccessToken,
      injectedData,
      wasEncrypted,
      error: decryptError,
    } = await this.$decryptAccessToken<T>(accessToken);

    if (decryptError) {
      return $err(decryptError.type, { error: 'Unauthorized', description: decryptError.description, status: 401 });
    }

    const { payload, error: payloadError } = await this.$verifyJwt(rawAccessToken);
    if (payloadError) return $err(payloadError);

    const isApp = payload.sub === payload.oid;

    if (this.settings.acceptB2BRequests === false && isApp === true) {
      return $err('misconfiguration', {
        error: 'B2B requests not allowed',
        description: 'B2B requests are not allowed, please enable them in the configuration',
        status: 403,
      });
    }

    if (isApp === wasEncrypted) {
      return $err('bad_request', {
        error: 'Unauthorized',
        description: 'User tokens must be encrypted, app tokens must not be encrypted',
        status: 401,
      });
    }

    return $ok({ rawAccessToken, payload, injectedData, hasInjectedData: !!injectedData, isApp });
  }

  /**
   * Verifies and uses the refresh token to get new set of access and refresh tokens.
   *
   * @param refreshToken - Encrypted refresh-token value
   * @returns A result containing the new access token, optional new refresh token, the raw access token, its payload, and the MSAL response.
   */
  async getTokenByRefresh(refreshToken: string | undefined): Promise<
    Result<{
      newTokens: {
        accessToken: Cookies['AccessToken'];
        refreshToken: Cookies['RefreshToken'] | null;
      };
      payload: jwt.JwtPayload;
      rawAccessToken: string;
      msalResponse: MsalResponse;
    }>
  > {
    if (!refreshToken) {
      return $err('nullish_value', { error: 'Unauthorized', description: 'Refresh token is required', status: 401 });
    }

    const { rawRefreshToken, error: decryptError } = await this.$decryptRefreshToken(refreshToken);
    if (decryptError) {
      return $err(decryptError.type, { error: 'Unauthorized', description: decryptError.description, status: 401 });
    }

    try {
      const msalResponse = await this.azure.cca.acquireTokenByRefreshToken({
        refreshToken: rawRefreshToken,
        scopes: this.azure.scopes,
        forceCache: true,
      });
      if (!msalResponse) {
        return $err('internal', {
          error: 'Unauthorized',
          description: 'Failed to refresh token, no msal response',
          status: 401,
        });
      }

      const { payload, error: payloadError } = await this.$verifyJwt(msalResponse.accessToken);
      if (payloadError) {
        return $err(payloadError.type, {
          error: 'Unauthorized',
          description: payloadError.description,
          status: 401,
        });
      }

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(msalResponse);
      if (error) {
        return $err(error.type, { error: 'Unauthorized', description: error.description, status: 401 });
      }

      return $ok({
        rawAccessToken: msalResponse.accessToken,
        payload,
        newTokens: {
          accessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken },
          refreshToken: encryptedRefreshToken
            ? { value: encryptedRefreshToken, ...this.defaultCookieOptions.refreshToken }
            : null,
        },
        msalResponse,
      });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenByRefresh');
    }
  }

  /**
   * Embed non-sensitive metadata into the access token.
   *
   * @param params - The parameters containing the access token and data to inject.
   * - `accessToken` - The encrypted access token to inject data into.
   * - `data` - The data to inject into the access token.
   * @returns A result containing the new encrypted access token with injected data and the injected data.
   * @template T - Type of the data to inject into the access token.
   */
  async injectData<T extends object = Record<string, any>>(params: { accessToken: string; data: T }): Promise<
    Result<{ injectedAccessToken: Cookies['AccessToken']; injectedData: T }>
  > {
    const { rawAccessToken, error } = await this.$decryptAccessToken(params.accessToken);
    if (error) return $err(error);

    const { data: dataToInject, error: dataToInjectError } = zInjectedData.safeParse(params.data);
    if (dataToInjectError) {
      return $err('invalid_format', { error: 'Invalid data', description: $prettyErr(dataToInjectError) });
    }

    const { encryptedAccessToken, error: encryptError } = await this.$encryptAccessToken(rawAccessToken, {
      dataToInject,
    });
    if (encryptError) return $err(encryptError);

    return $ok({
      injectedAccessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken },
      injectedData: dataToInject as T,
    });
  }

  /**
   * Decrypts a ticket and returns the ticket ID.
   * Useful for bearer flow.
   *
   * @param ticket - The encrypted ticket string to decrypt (generated by getAuthUrl).
   * @returns A result containing the ticket ID (returned by getTokenByCode).
   */
  async decryptTicket(ticket: string): Promise<Result<{ ticketId: string }>> {
    const { ticketId, error } = await this.$decryptTicket(ticket);
    if (error) return $err(error);

    return $ok({ ticketId });
  }

  /**
   * Acquire client-credential tokens for one or multiple B2B apps.
   *
   * @overload
   * @param params.appName - The name of the B2B app to get the token for.
   * @returns A result containing the B2B app token and metadata.
   *
   * @overload
   * @param params.appsNames - An array of B2B app names to get tokens for.
   * @returns Results containing an array of B2B app tokens and metadata.
   */
  async getB2BToken(params: { appName: string }): Promise<Result<{ result: GetB2BTokenResult }>>;
  async getB2BToken(params: { appsNames: string[] }): Promise<Result<{ results: GetB2BTokenResult[] }>>;
  async getB2BToken(
    params: { appName: string } | { appsNames: string[] },
  ): Promise<Result<{ result: GetB2BTokenResult } | { results: GetB2BTokenResult[] }>> {
    if (!this.b2bMap) return $err('misconfiguration', { error: 'B2B apps not configured', status: 500 });

    const { data: parsedParams, error: paramsError } = zMethods.getB2BToken.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    const apps = parsedParams.appNames.map((appName) => this.b2bMap?.get(appName)).filter((app) => !!app);
    if (!apps || apps.length === 0)
      return $err('bad_request', { error: 'Invalid params', description: 'B2B app not found' });

    try {
      const results = await $mapAndFilter(apps, async (app) => {
        const msalResponse = await this.azure.cca.acquireTokenByClientCredential({
          scopes: [app.scope],
          skipCache: true,
        });
        if (!msalResponse) return null;

        const { result: clientId, error: clientIdError } = $getAud(msalResponse.accessToken);
        if (clientIdError) return null;

        return {
          appName: app.appName,
          clientId: clientId,
          accessToken: msalResponse.accessToken,
          msalResponse: msalResponse,
        } satisfies GetB2BTokenResult;
      });

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get B2B token', status: 500 });
      }

      return $ok('appName' in params ? { result: results[0] as GetB2BTokenResult } : { results });
    } catch (err) {
      return $filterCoreErrors(err, 'getB2BToken');
    }
  }

  /**
   * Acquire On-Behalf-Of tokens for downstream services.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceName - The name of the service to get the token for.
   * @returns A result containing the OBO token and metadata for the specified service.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceNames - An array of service names to get tokens for.
   * @returns Results containing an array of OBO tokens and metadata for the specified services.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; serviceName: string }): Promise<
    Result<{ result: GetTokenOnBehalfOfResult }>
  >;
  async getTokenOnBehalfOf(params: { accessToken: string; serviceNames: string[] }): Promise<
    Result<{ results: GetTokenOnBehalfOfResult[] }>
  >;
  async getTokenOnBehalfOf(
    params: { accessToken: string; serviceName: string } | { accessToken: string; serviceNames: string[] },
  ): Promise<Result<{ result: GetTokenOnBehalfOfResult } | { results: GetTokenOnBehalfOfResult[] }>> {
    if (!this.oboMap) return $err('misconfiguration', { error: 'OBO services not configured', status: 500 });

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    const services = parsedParams.serviceNames
      .map((serviceName) => this.oboMap?.get(serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      return $err('bad_request', { error: 'Invalid params', description: 'OBO service not found' });
    }

    const { rawAccessToken, error } = await this.$decryptAccessToken(parsedParams.accessToken);
    if (error) return $err(error);

    try {
      const results = await $mapAndFilter(services, async (service) => {
        const msalResponse = await this.azure.cca.acquireTokenOnBehalfOf({
          oboAssertion: rawAccessToken,
          scopes: [service.scope],
          skipCache: false,
        });
        if (!msalResponse) return null;

        const { result: clientId, error: clientIdError } = $getAud(msalResponse.accessToken);
        if (clientIdError) return null;

        const { encryptedAccessToken, error } = await this.$encryptAccessToken(msalResponse.accessToken, {
          cryptoType: service.cryptoType,
          otherSecretKey: `access-token-${service.encryptionKey}`,
        });
        if (error) return null;

        await this.$removeFromCache(msalResponse.account);

        const cookieOptions = $cookieOptions({
          clientId,
          secure: service.isSecure,
          sameSite: service.isSamesite,
          timeUnit: this.settings.cookies.timeUnit,
          atMaxAge: service.atMaxAge ?? this.settings.cookies.accessTokenMaxAge,
          rtMaxAge: 0,
        });

        return {
          serviceName: service.serviceName,
          clientId: clientId,
          accessToken: { value: encryptedAccessToken, ...cookieOptions.accessToken },
          msalResponse: msalResponse,
        } satisfies GetTokenOnBehalfOfResult;
      });

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get OBO token', status: 500 });
      }

      return $ok('serviceName' in params ? { result: results[0] as GetTokenOnBehalfOfResult } : { results });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenOnBehalfOf');
    }
  }

  /** Retrieves and caches the public key for a given key ID (kid) from the JWKS endpoint. */
  private $getPublicKey(keyId: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.jwksClient.getSigningKey(keyId, (err, key) => {
        if (err || !key) {
          reject(new Error('Error retrieving signing key'));
          return;
        }
        const publicKey = key.getPublicKey();
        if (!publicKey) {
          reject(new Error('Public key not found'));
          return;
        }
        resolve(publicKey);
      });
    });
  }

  /** Verifies the JWT token and returns its payload. */
  private async $verifyJwt(jwtToken: string): Promise<Result<{ payload: jwt.JwtPayload }>> {
    const kid = $getKid(jwtToken);
    if (kid.error) return $err('jwt_error', { error: 'Unauthorized', description: kid.error.description, status: 401 });

    try {
      const publicKey = await this.$getPublicKey(kid.result);

      const decodedJwt = jwt.verify(jwtToken, publicKey, {
        algorithms: ['RS256'],
        audience: this.azure.clientId,
        issuer: `https://login.microsoftonline.com/${this.azure.tenantId}/v2.0`,
        complete: true,
      });

      if (typeof decodedJwt.payload === 'string') {
        return $err('jwt_error', { error: 'Unauthorized', description: 'Payload is a string', status: 401 });
      }

      return $ok({ payload: decodedJwt.payload });
    } catch {
      return $err('jwt_error', {
        error: 'Unauthorized',
        description:
          "Failed to verify JWT token. Check your Azure Portal, make sure the 'accessTokenAcceptedVersion' is set to '2' in the 'Manifest' area",
        status: 401,
      });
    }
  }

  /** Extracts and encrypts both tokens */
  private async $extractTokens(
    msalResponse: MsalResponse,
  ): Promise<Result<{ encryptedAccessToken: string; encryptedRefreshToken: string | null }>> {
    const [accessTokenRes, refreshTokenRes] = await Promise.all([
      this.$encryptAccessToken(msalResponse.accessToken),
      this.$obtainRefreshToken(msalResponse),
    ]);

    if (accessTokenRes.error) return $err(accessTokenRes.error);
    // ! If the refresh token has any error, we still return the access token

    return $ok({
      encryptedAccessToken: accessTokenRes.encryptedAccessToken,
      encryptedRefreshToken: refreshTokenRes.encryptedRefreshToken ?? null,
    });
  }

  /** Removes the account from the MSAL cache, if it exists. */
  private async $removeFromCache(account: AccountInfo | null) {
    const cache = this.azure.cca.getTokenCache();
    if (account) await cache.removeAccount(account);
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async $obtainRefreshToken(msalResponse: MsalResponse): Promise<Result<{ encryptedRefreshToken: string }>> {
    try {
      const serializedCache = JSON.parse(this.azure.cca.getTokenCache().serialize());
      const refreshTokens = serializedCache.RefreshToken;
      const refreshTokenKey = Object.keys(refreshTokens).find((key) => key.startsWith(msalResponse.uniqueId));
      await this.$removeFromCache(msalResponse.account);
      const refreshToken = refreshTokenKey ? (refreshTokens[refreshTokenKey].secret as string) : null;
      return await this.$encryptRefreshToken(refreshToken);
    } catch {
      return $err('internal', {
        error: 'Failed to obtain refresh token',
        description: 'Failed to obtain refresh token from MSAL cache',
        status: 500,
      });
    }
  }

  /** Updates the secret key for a specific token type if it is a string. */
  private $updateSecretKey(
    type: 'accessToken' | 'refreshToken' | 'state' | 'ticket',
    secretKey: webcrypto.CryptoKey | undefined,
  ): void {
    if (this.settings.cryptoType === 'web-api' && secretKey) {
      switch (type) {
        case 'accessToken':
          if (typeof this.encryptionKeys.accessToken === 'string') {
            this.encryptionKeys.accessToken = secretKey;
          }
          break;
        case 'refreshToken':
          if (typeof this.encryptionKeys.refreshToken === 'string') {
            this.encryptionKeys.refreshToken = secretKey;
          }
          break;
        case 'state':
          if (typeof this.encryptionKeys.state === 'string') {
            this.encryptionKeys.state = secretKey;
          }
          break;
        case 'ticket':
          if (typeof this.encryptionKeys.ticket === 'string') {
            this.encryptionKeys.ticket = secretKey;
          }
          break;
        default:
          throw new OAuthError('misconfiguration', {
            error: 'Invalid secret key type',
            description: `Unknown type: ${type}`,
          });
      }
    }
  }

  private async $encryptAccessToken<T extends object = Record<string, any>>(
    value: string | null,
    params?: {
      dataToInject?: T;
      otherSecretKey?: string;
      cryptoType?: CryptoType;
    },
  ): Promise<Result<{ encryptedAccessToken: string }>> {
    const { data: accessToken, error: jwtError } = zJwt.safeParse(value);
    if (jwtError) {
      return $err('invalid_format', { error: 'Invalid access token format', description: $prettyErr(jwtError) });
    }

    const { data: dataToInject, error: injectError } = zInjectedData.safeParse(params?.dataToInject);
    if (injectError) {
      return $err('invalid_format', { error: 'Invalid injected data format', description: $prettyErr(injectError) });
    }

    const injectedData = dataToInject ? $compressObj(dataToInject, this.settings.disableCompression) : undefined;
    if (injectedData?.error) return $err(injectedData.error);

    const { encrypted, newSecretKey, error } = await $encryptObj(
      params?.cryptoType ?? this.settings.cryptoType,
      { at: accessToken, inj: injectedData?.result } satisfies z.infer<typeof zAccessTokenStructure>,
      params?.otherSecretKey ?? this.encryptionKeys.accessToken,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to encrypt access token', description: error.description });
    }

    if (!params?.otherSecretKey) this.$updateSecretKey('accessToken', newSecretKey);

    if (encrypted.length > 4096) {
      //TODO: check if I should decode and compress the access token to reduce its size
      return $err('invalid_format', {
        error: 'Token too long',
        description: `Encrypted access token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${accessToken.length}, injected data length: ${injectedData?.result.length ?? 0}`,
      });
    }

    return $ok({ encryptedAccessToken: encrypted });
  }

  private async $decryptAccessToken<T extends object = Record<string, any>>(
    value: string | undefined,
  ): Promise<Result<{ rawAccessToken: string; injectedData?: T; wasEncrypted: boolean }>> {
    const { data: jwtToken, success: jwtSuccess } = zJwt.safeParse(value);
    if (jwtSuccess) return $ok({ rawAccessToken: jwtToken, injectedData: undefined, wasEncrypted: false });

    const { data: encryptedAccessToken, error: encryptedAccessTokenError } = zEncrypted.safeParse(value);
    if (encryptedAccessTokenError) {
      return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid access token format' });
    }

    const { result, newSecretKey, error } = await $decryptObj(
      this.settings.cryptoType,
      encryptedAccessToken,
      this.encryptionKeys.accessToken,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to decrypt access token', description: error.description });
    }

    this.$updateSecretKey('accessToken', newSecretKey);

    const { data: accessTokenStruct, error: accessTokenStructError } = zAccessTokenStructure.safeParse(result);
    if (accessTokenStructError) {
      return $err('invalid_format', {
        error: 'Invalid access token format',
        description: $prettyErr(accessTokenStructError),
      });
    }

    const decompressedInjectedData = accessTokenStruct.inj ? $decompressObj(accessTokenStruct.inj) : undefined;
    if (decompressedInjectedData?.error) return $err(decompressedInjectedData.error);

    return $ok({
      rawAccessToken: accessTokenStruct.at,
      injectedData: decompressedInjectedData ? (decompressedInjectedData.result as T) : undefined,
      wasEncrypted: true,
    });
  }

  private async $encryptRefreshToken(value: string | null): Promise<Result<{ encryptedRefreshToken: string }>> {
    const { data, error: parseError } = zLooseBase64.safeParse(value);
    if (parseError) {
      return $err('invalid_format', { error: 'Invalid refresh token format', description: $prettyErr(parseError) });
    }

    const { encrypted, newSecretKey, error } = await $encrypt(
      this.settings.cryptoType,
      data,
      this.encryptionKeys.refreshToken,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to encrypt refresh token', description: error.description });
    }

    this.$updateSecretKey('refreshToken', newSecretKey);

    if (encrypted.length > 4096) {
      return $err('invalid_format', {
        error: 'Token too long',
        description: `Encrypted refresh token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${data.length}`,
      });
    }

    return $ok({ encryptedRefreshToken: encrypted });
  }

  private async $decryptRefreshToken(value: string | undefined): Promise<Result<{ rawRefreshToken: string }>> {
    const { data: encryptedRefreshToken, error: encryptedRefreshTokenError } = zEncrypted.safeParse(value);
    if (encryptedRefreshTokenError) {
      return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid refresh token format' });
    }

    const { result, newSecretKey, error } = await $decrypt(
      this.settings.cryptoType,
      encryptedRefreshToken,
      this.encryptionKeys.refreshToken,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to decrypt refresh token', description: error.description });
    }

    this.$updateSecretKey('refreshToken', newSecretKey);

    return $ok({ rawRefreshToken: result });
  }

  private async $encryptState(value: object | null): Promise<Result<{ encryptedState: string }>> {
    const { data, error: parseError } = zState.safeParse(value);
    if (parseError) {
      return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(parseError) });
    }

    const { encrypted, newSecretKey, error } = await $encryptObj(
      this.settings.cryptoType,
      data,
      this.encryptionKeys.state,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to encrypt state', description: error.description });
    }

    this.$updateSecretKey('state', newSecretKey);

    return $ok({ encryptedState: encrypted });
  }

  private async $decryptState(value: string | undefined): Promise<Result<{ state: z.infer<typeof zState> }>> {
    const { data: encryptedState, error: encryptedStateError } = zEncrypted.safeParse(value);
    if (encryptedStateError) {
      return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(encryptedStateError) });
    }

    const { result, newSecretKey, error } = await $decryptObj(
      this.settings.cryptoType,
      encryptedState,
      this.encryptionKeys.state,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to decrypt state', description: error.description });
    }

    this.$updateSecretKey('state', newSecretKey);

    const { data: state, error: stateError } = zState.safeParse(result);
    if (stateError) {
      return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(stateError) });
    }

    return $ok({ state });
  }

  private async $encryptTicket(ticketId: string): Promise<Result<{ encryptedTicket: string }>> {
    const { data, error: parseError } = zUuid.safeParse(ticketId);
    if (parseError) {
      return $err('invalid_format', { error: 'Invalid ticket format', description: $prettyErr(parseError) });
    }

    const { encrypted, newSecretKey, error } = await $encrypt(
      this.settings.cryptoType,
      data,
      this.encryptionKeys.state,
    );
    if (error) {
      return $err('crypto_error', { error: 'Failed to encrypt ticket', description: error.description });
    }

    this.$updateSecretKey('ticket', newSecretKey);

    return $ok({ encryptedTicket: encrypted });
  }

  private async $decryptTicket(value: string | undefined): Promise<Result<{ ticketId: string }>> {
    const { data, error: encryptedStateError } = zEncrypted.safeParse(value);
    if (encryptedStateError) {
      return $err('invalid_format', { error: 'Invalid ticket format', description: $prettyErr(encryptedStateError) });
    }

    const { result, newSecretKey, error } = await $decrypt(this.settings.cryptoType, data, this.encryptionKeys.state);
    if (error) {
      return $err('crypto_error', { error: 'Failed to decrypt ticket', description: error.description });
    }

    this.$updateSecretKey('ticket', newSecretKey);

    const { data: ticketId, error: stateError } = zUuid.safeParse(result);
    if (stateError) {
      return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(stateError) });
    }

    return $ok({ ticketId });
  }
}
