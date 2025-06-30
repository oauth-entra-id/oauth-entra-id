import type { CryptoProvider } from '@azure/msal-node';
import type jwt from 'jsonwebtoken';
import type { JwksClient } from 'jwks-rsa';
import type { z } from 'zod/v4';
import { $err, $ok, OAuthError, type Result } from './error';
import type {
  Azure,
  B2BApp,
  Cookies,
  CryptoType,
  EncryptionKeys,
  GetTokenOnBehalfOfResult,
  LoginPrompt,
  MsalResponse,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  WebApiCryptoKey,
  tryGetB2BTokenResult,
} from './types';
import { $cookieOptions } from './utils/cookie-options';
import { $generateUuid } from './utils/crypto/encrypt';
import { $getAudAndExp, $verifyJwt } from './utils/crypto/jwt';
import {
  $decryptAccessToken,
  $decryptRefreshToken,
  $decryptState,
  $decryptTicket,
  $encryptAccessToken,
  $encryptRefreshToken,
  $encryptState,
  $encryptTicket,
} from './utils/crypto/tokens';
import { $coreErrors, $mapAndFilter, TIME_SKEW, oauthProviderHelper } from './utils/helpers';
import { $prettyErr, zInjectedData, zMethods, type zState } from './utils/zod';

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
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: JwksClient;
  readonly settings: OAuthSettings;

  /**
   * @param configuration The OAuth configuration object:
   * - `azure`: clientId, tenantId, scopes, clientSecret, B2B apps, and downstream services
   * - `frontendUrl`: allowed redirect URIs
   * - `serverCallbackUrl`: your server’s Azure callback endpoint
   * - `secretKey`: 32 characters base encryption secret
   * - `advanced`: optional behaviors
   * @throws {OAuthError} if the config fails validation or has duplicate service names
   */
  constructor(configuration: OAuthConfig) {
    const result = oauthProviderHelper(configuration);
    if (result.error) throw new OAuthError(result.error);

    this.azure = result.azure;
    this.frontendUrls = result.frontendUrls;
    this.frontendWhitelist = result.frontendWhitelist;
    this.serverCallbackUrl = result.serverCallbackUrl;
    this.defaultCookieOptions = result.defaultCookieOptions;
    this.encryptionKeys = result.encryptionKeys;
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
   * @throws {OAuthError} if something goes wrong.
   */
  async getAuthUrl(params?: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<{
    authUrl: string;
    ticket: string;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) {
      throw new OAuthError('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });
    }

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      throw new OAuthError('bad_request', { error: 'Invalid params: Email required' });
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    const { uuid: ticketId, error: uuidError } = $generateUuid(this.settings.cryptoType);
    if (uuidError) throw new OAuthError(uuidError);

    try {
      const [pkce, { encrypted: encryptedTicket, error: ticketError }] = await Promise.all([
        this.msalCryptoProvider.generatePkceCodes(),
        this.$encryptToken('ticket', ticketId),
      ]);
      if (ticketError) throw new OAuthError(ticketError);

      const configuredPrompt = parsedParams.loginPrompt ?? this.settings.loginPrompt;
      const prompt: 'login' | 'select_account' | undefined =
        parsedParams.email || configuredPrompt === 'email'
          ? 'login'
          : configuredPrompt === 'select-account'
            ? 'select_account'
            : undefined;

      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedParams.email, prompt };
      const { encrypted: encryptedState, error: encryptError } = await this.$encryptToken('state', {
        frontendUrl: parsedParams.frontendUrl ?? this.frontendUrls[0],
        codeVerifier: pkce.verifier,
        ticketId: ticketId,
        ...params,
      } satisfies z.infer<typeof zState>);
      if (encryptError) throw new OAuthError(encryptError);

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
        throw new OAuthError('internal', {
          error: "Invalid redirect URL: must be 'login.microsoftonline.com'",
          status: 500,
        });
      }
      return { authUrl, ticket: encryptedTicket };
    } catch (err) {
      throw new OAuthError($coreErrors(err, 'getAuthUrl'));
    }
  }

  /**
   * Exchange an authorization code for encrypted tokens and metadata.
   *
   * @param params - The parameters containing the authorization code and state.
   * - `code` - The authorization code received from the OAuth flow.
   * - `state` -  The state parameter received from Microsoft.
   * @returns A result containing the access token, refresh token (if available), frontend URL, and MSAL response.
   * @throws {OAuthError} if something goes wrong.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'] | null;
    frontendUrl: string;
    ticketId: string;
    msalResponse: MsalResponse;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) {
      throw new OAuthError('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });
    }

    const { decrypted: state, error: decryptError } = await this.$decryptToken('state', parsedParams.state);
    if (decryptError) throw new OAuthError(decryptError);

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      throw new OAuthError('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    try {
      const msalResponse = await this.azure.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(msalResponse);
      if (error) throw new OAuthError(error);

      return {
        accessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken },
        refreshToken: encryptedRefreshToken
          ? { value: encryptedRefreshToken, ...this.defaultCookieOptions.refreshToken }
          : null,
        frontendUrl: state.frontendUrl,
        ticketId: state.ticketId,
        msalResponse,
      };
    } catch (err) {
      throw new OAuthError($coreErrors(err, 'getTokenByCode'));
    }
  }

  /**
   * Build a logout URL and cookie-deletion instructions.
   *
   * @param params (optional) - Parameters to customize the logout URL:
   * - `frontendUrl` (optional) - Frontend URL override to redirect the user after log out
   * @returns A result containing the logout URL and cookie deletion instructions.
   * @throws {OAuthError} if something goes wrong.
   */
  async getLogoutUrl(params?: { frontendUrl?: string }): Promise<{
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) {
      throw new OAuthError('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });
    }

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${this.azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', parsedParams.frontendUrl ?? this.frontendUrls[0]);

    return {
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
    };
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
      decrypted: rawAccessToken,
      injectedData,
      wasEncrypted,
      error: decryptError,
    } = await this.$decryptToken<T>('accessToken', accessToken);

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
  async tryRefreshTokens(refreshToken: string | undefined): Promise<
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

    const { decrypted: rawRefreshToken, error: decryptError } = await this.$decryptToken('refreshToken', refreshToken);
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
        return $err(payloadError.type, { error: 'Unauthorized', description: payloadError.description, status: 401 });
      }

      const { encryptedAccessToken, encryptedRefreshToken, error } = await this.$extractTokens(msalResponse);
      if (error) return $err(error.type, { error: 'Unauthorized', description: error.description, status: 401 });

      return $ok({
        rawAccessToken: msalResponse.accessToken,
        payload,
        newTokens: {
          accessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken },
          refreshToken: encryptedRefreshToken
            ? { value: encryptedRefreshToken, ...this.defaultCookieOptions.refreshToken }
            : null,
        },
        msalResponse: msalResponse,
      });
    } catch (err) {
      return $coreErrors(err, 'tryRefreshTokens', 401);
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
  async tryInjectData<T extends object = Record<string, any>>(params: { accessToken: string; data: T }): Promise<
    Result<{ injectedAccessToken: Cookies['AccessToken']; injectedData: T }>
  > {
    const { decrypted: rawAccessToken, error } = await this.$decryptToken('accessToken', params.accessToken);
    if (error) return $err(error);

    const { data: dataToInject, error: dataToInjectError } = zInjectedData.safeParse(params.data);
    if (dataToInjectError) {
      return $err('invalid_format', { error: 'Invalid data', description: $prettyErr(dataToInjectError) });
    }

    const { encrypted, error: encryptError } = await this.$encryptToken('accessToken', rawAccessToken, {
      dataToInject,
    });
    if (encryptError) return $err(encryptError);

    return $ok({
      injectedAccessToken: { value: encrypted, ...this.defaultCookieOptions.accessToken },
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
  async tryDecryptTicket(ticket: string): Promise<Result<{ ticketId: string }>> {
    const { decrypted, error } = await this.$decryptToken('ticket', ticket);
    if (error) return $err(error);
    return $ok({ ticketId: decrypted });
  }

  /**
   * Acquire client-credential tokens for one or multiple B2B apps.
   * Caches tokens for better performance.
   *
   * @overload
   * @param params.appName - The name of the B2B app to get the token for.
   * @returns A result containing the B2B app token and metadata.
   * @throws {OAuthError} if something goes wrong.
   *
   * @overload
   * @param params.appsNames - An array of B2B app names to get tokens for.
   * @returns Results containing an array of B2B app tokens and metadata.
   * @throws {OAuthError} if something goes wrong.
   */
  async tryGetB2BToken(params: { app: string }): Promise<Result<{ result: tryGetB2BTokenResult }>>;
  async tryGetB2BToken(params: { apps: string[] }): Promise<Result<{ results: tryGetB2BTokenResult[] }>>;
  async tryGetB2BToken(
    params: { app: string } | { apps: string[] },
  ): Promise<Result<{ result: tryGetB2BTokenResult } | { results: tryGetB2BTokenResult[] }>> {
    if (!this.azure.b2bApps) {
      return $err('misconfiguration', { error: 'B2B apps not configured', status: 500 });
    }

    const { data: parsedParams, error: paramsError } = zMethods.tryGetB2BToken.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

    const apps = parsedParams.apps.map((app) => this.azure.b2bApps?.get(app)).filter((app) => !!app);
    if (!apps || apps.length === 0) {
      return $err('bad_request', { error: 'Invalid params', description: 'B2B app not found' });
    }

    try {
      const results = await $mapAndFilter(apps, async (app) => {
        if (app.token && app.exp > Date.now() / 1000) {
          return {
            appName: app.appName,
            clientId: app.aud,
            token: app.token,
            msalResponse: app.msalResponse,
            isCached: true,
            expiresAt: app.exp,
          } satisfies tryGetB2BTokenResult;
        }

        const msalResponse = await this.azure.cca.acquireTokenByClientCredential({
          scopes: [app.scope],
          skipCache: true,
        });
        if (!msalResponse) return null;

        const { aud, exp, error: audError } = $getAudAndExp(msalResponse.accessToken);
        if (audError) return null;

        this.azure.b2bApps?.set(app.appName, {
          appName: app.appName,
          scope: app.scope,
          token: msalResponse.accessToken,
          exp: exp - TIME_SKEW,
          aud: aud,
          msalResponse: msalResponse,
        } satisfies B2BApp);

        return {
          appName: app.appName,
          clientId: aud,
          token: msalResponse.accessToken,
          msalResponse: msalResponse,
          isCached: false,
          expiresAt: 0,
        } satisfies tryGetB2BTokenResult;
      });

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get B2B token', status: 500 });
      }

      return $ok('app' in params ? { result: results[0] as tryGetB2BTokenResult } : { results });
    } catch (err) {
      return $coreErrors(err, 'tryGetB2BToken');
    }
  }

  /**
   * Acquire On-Behalf-Of tokens for downstream services.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceName - The name of the service to get the token for.
   * @returns A result containing the OBO token and metadata for the specified service.
   * @throws {OAuthError} if something goes wrong.
   *
   * @overload
   * @param params.accessToken - The encrypted access token to use for OBO.
   * @param params.serviceNames - An array of service names to get tokens for.
   * @returns Results containing an array of OBO tokens and metadata for the specified services.
   * @throws {OAuthError} if something goes wrong.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; service: string }): Promise<{
    result: GetTokenOnBehalfOfResult;
  }>;
  async getTokenOnBehalfOf(params: { accessToken: string; services: string[] }): Promise<{
    results: GetTokenOnBehalfOfResult[];
  }>;
  async getTokenOnBehalfOf(
    params: { accessToken: string; service: string } | { accessToken: string; services: string[] },
  ): Promise<{ result: GetTokenOnBehalfOfResult } | { results: GetTokenOnBehalfOfResult[] }> {
    if (!this.azure.oboApps) {
      throw new OAuthError('misconfiguration', { error: 'OBO services not configured', status: 500 });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) {
      throw new OAuthError('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });
    }

    const services = parsedParams.services
      .map((service) => this.azure.oboApps?.get(service))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError('bad_request', { error: 'Invalid params', description: 'OBO service not found' });
    }

    const { decrypted: rawAccessToken, error } = await this.$decryptToken('accessToken', parsedParams.accessToken);
    if (error) throw new OAuthError(error);

    try {
      const results = await $mapAndFilter(services, async (service) => {
        const msalResponse = await this.azure.cca.acquireTokenOnBehalfOf({
          oboAssertion: rawAccessToken,
          scopes: [service.scope],
          skipCache: true,
        });
        if (!msalResponse) return null;

        const { aud, error: audError } = $getAudAndExp(msalResponse.accessToken);
        if (audError) return null;

        const { encrypted, error } = await this.$encryptToken('accessToken', msalResponse.accessToken, {
          cryptoType: service.cryptoType,
          otherSecretKey: `access-token-${service.encryptionKey}`,
        });
        if (error) return null;

        const cookieOptions = $cookieOptions({
          clientId: aud,
          secure: service.isSecure,
          sameSite: service.isSamesite,
          timeUnit: this.settings.cookies.timeUnit,
          atMaxAge: service.atMaxAge ?? this.settings.cookies.accessTokenMaxAge,
        });

        return {
          serviceName: service.serviceName,
          clientId: aud,
          accessToken: { value: encrypted, ...cookieOptions.accessToken },
          msalResponse: msalResponse,
        } satisfies GetTokenOnBehalfOfResult;
      });

      if (!results || results.length === 0) {
        throw new OAuthError('internal', { error: 'Failed to get OBO token', status: 500 });
      }

      return 'service' in params ? { result: results[0] as GetTokenOnBehalfOfResult } : { results };
    } catch (err) {
      throw new OAuthError($coreErrors(err, 'getTokenOnBehalfOf'));
    }
  }

  /** Verifies the JWT token and returns its payload. */
  private async $verifyJwt(jwtToken: string): Promise<Result<{ payload: jwt.JwtPayload }>> {
    return $verifyJwt({ jwtToken: jwtToken, jwksClient: this.jwksClient, azure: this.azure });
  }

  /** Extracts and encrypts both tokens */
  private async $extractTokens(
    msalResponse: MsalResponse,
  ): Promise<Result<{ encryptedAccessToken: string; encryptedRefreshToken: string | null }>> {
    const [accessTokenRes, refreshTokenRes] = await Promise.all([
      this.$encryptToken('accessToken', msalResponse.accessToken),
      this.$obtainRefreshToken(msalResponse),
    ]);

    if (accessTokenRes.error) return $err(accessTokenRes.error);
    // ! If the refresh token has any error, we still return the access token

    return $ok({
      encryptedAccessToken: accessTokenRes.encrypted,
      encryptedRefreshToken: refreshTokenRes.encrypted ?? null,
    });
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async $obtainRefreshToken(msalResponse: MsalResponse): Promise<Result<{ encrypted: string }>> {
    try {
      const cache = this.azure.cca.getTokenCache();
      const serializedCache = JSON.parse(cache.serialize());
      const refreshTokens = serializedCache.RefreshToken;
      const refreshTokenKey = Object.keys(refreshTokens).find((key) => key.startsWith(msalResponse.uniqueId));
      if (msalResponse.account) await cache.removeAccount(msalResponse.account);
      const refreshToken = refreshTokenKey ? (refreshTokens[refreshTokenKey].secret as string) : null;
      return await this.$encryptToken('refreshToken', refreshToken);
    } catch {
      return $err('internal', {
        error: 'Failed to obtain refresh token',
        description: 'Failed to obtain refresh token from MSAL cache',
        status: 500,
      });
    }
  }

  /** Updates the secret key for a specific token type if it is a string. */
  private $updateSecretKey(keyType: keyof typeof this.encryptionKeys, secretKey: WebApiCryptoKey | undefined) {
    if (this.settings.cryptoType !== 'web-api' || !secretKey) return;
    const currentKey = this.encryptionKeys[keyType];
    if (typeof currentKey === 'string') {
      this.encryptionKeys[keyType] = secretKey;
    }
  }

  private async $encryptToken<T extends object = Record<string, any>>(
    keyType: 'accessToken',
    value: string | null,
    params?: { dataToInject?: T; otherSecretKey?: string; cryptoType?: CryptoType },
  ): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken(
    keyType: 'refreshToken' | 'ticket',
    value: string | null,
  ): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken(keyType: 'state', value: object | null): Promise<Result<{ encrypted: string }>>;
  private async $encryptToken<T extends object = Record<string, any>>(
    keyType: keyof typeof this.encryptionKeys,
    value: string | object | null,
    params?: { dataToInject?: T; otherSecretKey?: string; cryptoType?: CryptoType },
  ): Promise<Result<{ encrypted: string }>> {
    const baseParams = {
      key: params?.otherSecretKey ?? this.encryptionKeys[keyType],
      cryptoType: params?.cryptoType ?? this.settings.cryptoType,
      $updateSecretKey: this.$updateSecretKey.bind(this),
    };
    switch (keyType) {
      case 'accessToken':
        return $encryptAccessToken<T>(value as string | null, {
          ...baseParams,
          isOtherKey: !!params?.otherSecretKey,
          dataToInject: params?.dataToInject,
          disableCompression: this.settings.disableCompression,
        });
      case 'refreshToken':
        return $encryptRefreshToken(value as string | null, baseParams);
      case 'state':
        return $encryptState(value as object | null, baseParams);
      case 'ticket':
        return $encryptTicket(value as string | null, baseParams);
      default:
        return $err('misconfiguration', {
          error: 'Invalid encryption key type',
          description: `Key type '${keyType}' is not supported for encryption`,
        });
    }
  }

  private async $decryptToken<T extends object = Record<string, any>>(
    keyType: 'accessToken',
    value: string | undefined,
  ): Promise<Result<{ decrypted: string; injectedData?: T; wasEncrypted: boolean }>>;
  private async $decryptToken(
    keyType: 'refreshToken' | 'ticket',
    value: string | undefined,
  ): Promise<Result<{ decrypted: string }>>;
  private async $decryptToken(
    keyType: 'state',
    value: string | undefined,
  ): Promise<Result<{ decrypted: z.infer<typeof zState> }>>;
  private async $decryptToken<T extends object = Record<string, any>>(
    keyType: keyof typeof this.encryptionKeys,
    value: string | undefined,
  ): Promise<Result<{ decrypted: string | z.infer<typeof zState>; injectedData?: T; wasEncrypted?: boolean }>> {
    const baseParams = {
      key: this.encryptionKeys[keyType],
      cryptoType: this.settings.cryptoType,
      $updateSecretKey: this.$updateSecretKey.bind(this),
    };
    switch (keyType) {
      case 'accessToken':
        return $decryptAccessToken(value, baseParams);
      case 'refreshToken':
        return $decryptRefreshToken(value, baseParams);
      case 'state':
        return $decryptState(value, baseParams);
      case 'ticket':
        return $decryptTicket(value, baseParams);
      default:
        return $err('misconfiguration', {
          error: 'Invalid encryption key type',
          description: `Key type '${keyType}' is not supported for encryption`,
        });
    }
  }
}
