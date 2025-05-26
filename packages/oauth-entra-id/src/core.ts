import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { $err, $ok, OAuthError, type Result } from './error';
import type {
  B2BApp,
  Cookies,
  GetB2BTokenResult,
  GetTokenOnBehalfOfResult,
  InjectedData,
  LoginPrompt,
  MsalResponse,
  OAuthConfig,
  OAuthSettings,
  OboService,
} from './types';
import { $cookieOptions } from './utils/cookie-options';
import {
  $createSecretKeys,
  $decryptObj,
  $decryptToken,
  $encryptObj,
  $encryptToken,
  $getAud,
  $getKid,
} from './utils/crypto';
import { $getB2BInfo, $getOboInfo } from './utils/misc';
import { isJwt } from './utils/regex';
import {
  $prettyError,
  zAccessTokenStructure,
  zConfig,
  zEncrypted,
  zJwt,
  zJwtOrEncrypted,
  zMethods,
  zState,
} from './utils/zod';

/**
 * The core authentication class that handles OAuth 2.0 flows using Microsoft Entra ID (Azure AD).
 *
 * Features:
 * - Generates login and logout URLs
 * - Handles token exchange (authorization code grant)
 * - Issues secure, encrypted cookies
 * - Validates JWTs
 * - Supports refresh token rotation
 * - Implements the On-Behalf-Of (OBO) flow for downstream service access
 *
 * Designed to be framework-agnostic with support for cookie-based workflows and frontend redirects.
 *
 * @class
 */
export class OAuthProvider {
  private readonly azure: OAuthConfig['azure'];
  private readonly frontendUrls: [string, ...string[]];
  private readonly serverCallbackUrl: string;
  private readonly secretKeys: { at: KeyObject; rt: KeyObject; state: KeyObject };
  private readonly frontendWhitelist: Set<string>;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly b2bMap: Map<string, B2BApp> | null;
  private readonly oboMap: Map<string, OboService> | null;
  readonly settings: OAuthSettings;
  private readonly cca: msal.ConfidentialClientApplication;
  private readonly msalCryptoProvider: msal.CryptoProvider;
  private readonly jwksClient: jwks.JwksClient;

  /**
   * Creates a new OAuthProvider instance.
   *
   * @param configuration - The full OAuth configuration including Azure client credentials, frontend redirect URIs, server callback URL, secret keys, and advanced options.
   * @throws {OAuthError} If the configuration is invalid or contains duplicate service definitions.
   */
  constructor(configuration: OAuthConfig) {
    const config = zConfig.safeParse(configuration);
    if (config.error) {
      throw new OAuthError('config', { error: 'Invalid configuration', description: $prettyError(config.error) }, 500);
    }

    const {
      azure,
      frontendUrl,
      serverCallbackUrl,
      secretKey,
      advanced: { loginPrompt, sessionType, acceptB2BRequests, b2bTargetedApps, cookies, downstreamServices },
    } = config.data;

    const secretKeys = $createSecretKeys(secretKey);
    if (secretKeys.error) throw new OAuthError(secretKeys.error);

    const frontHosts = new Set(frontendUrl.map((url) => new URL(url).host));
    const serverHost = new URL(serverCallbackUrl).host;
    const secure = !cookies.disableHttps && [serverHost, ...frontHosts].every((url) => url.startsWith('https'));
    const sameSite = !cookies.disableSameSite && frontHosts.size === 1 ? frontHosts.has(serverHost) : false;

    const b2bInfo = $getB2BInfo(b2bTargetedApps);
    if (b2bInfo.error) throw new OAuthError(b2bInfo.error);

    const oboInfo = $getOboInfo(downstreamServices);
    if (oboInfo.error) throw new OAuthError(oboInfo.error);

    const defaultCookieOptions = $cookieOptions({
      clientId: azure.clientId,
      secure: secure,
      sameSite: sameSite,
      cookiesTimeUnit: cookies.timeUnit,
      accessTokenCookieExpiry: cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: cookies.refreshTokenExpiry,
    });

    const settings = {
      sessionType,
      loginPrompt,
      acceptB2BRequests,
      isHttps: secure,
      isSameSite: sameSite,
      cookiesTimeUnit: cookies.timeUnit,
      accessTokenCookieExpiry: cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: cookies.refreshTokenExpiry,
      b2bApps: b2bInfo.result?.names,
      downstreamServices: oboInfo.result?.names,
    } satisfies OAuthSettings;

    const cca = new msal.ConfidentialClientApplication({
      auth: {
        clientId: azure.clientId,
        authority: `https://login.microsoftonline.com/${azure.tenantId}`,
        clientSecret: azure.clientSecret,
      },
    });

    const jwksClient = jwks({
      jwksUri: `https://login.microsoftonline.com/${azure.tenantId}/discovery/v2.0/keys`,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 60 * 60 * 1000,
      rateLimit: true,
    });

    this.azure = azure;
    this.frontendUrls = frontendUrl as [string, ...string[]];
    this.serverCallbackUrl = serverCallbackUrl;
    this.secretKeys = secretKeys.result;
    this.frontendWhitelist = frontHosts;
    this.defaultCookieOptions = defaultCookieOptions;
    this.b2bMap = b2bInfo.result?.map ?? null;
    this.oboMap = oboInfo.result?.map ?? null;
    this.settings = settings;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;
  }

  /** Removes the account from the MSAL cache, if it exists. */
  private async $removeFromCache(account: msal.AccountInfo | null) {
    const cache = this.cca.getTokenCache();
    if (account) await cache.removeAccount(account);
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async $extractRefreshToken(msalResponse: MsalResponse): Promise<string | null> {
    try {
      const serializedCache = JSON.parse(this.cca.getTokenCache().serialize());
      const refreshTokens = serializedCache.RefreshToken;
      const refreshTokenKey = Object.keys(refreshTokens).find((key) => key.startsWith(msalResponse.uniqueId));
      await this.$removeFromCache(msalResponse.account);
      return refreshTokenKey ? (refreshTokens[refreshTokenKey].secret as string) : null;
    } catch {
      return null;
    }
  }

  /** Encrypts both tokens */
  private async $encryptTokens(
    msalResponse: MsalResponse,
  ): Promise<Result<{ accessTokenValue: string; refreshTokenValue: string | null }>> {
    const accessToken = $encryptToken('accessToken', msalResponse.accessToken, this.secretKeys.at);
    if (accessToken.error) return accessToken;

    const rawRefreshToken = await this.$extractRefreshToken(msalResponse);
    const refreshToken = $encryptToken('refreshToken', rawRefreshToken, this.secretKeys.rt);
    if (refreshToken.error) return refreshToken;

    return $ok({ accessTokenValue: accessToken.result, refreshTokenValue: refreshToken.result });
  }

  /**Decrypts the access token and returns its raw value.*/
  private $decryptAccessToken(accessToken: string): Result<{
    rawAccessToken: string;
    injectedData?: InjectedData;
    wasEncrypted: boolean;
  }> {
    const token = zJwtOrEncrypted.safeParse(accessToken);
    if (token.error) return $err('format', { error: 'Unauthorized', description: 'Invalid access token format' }, 401);

    if (isJwt(token.data)) return $ok({ rawAccessToken: token.data, wasEncrypted: false });

    const decryptedToken = $decryptToken('accessToken', token.data, this.secretKeys.at);
    if (decryptedToken.error) {
      return $err('format', { error: 'Unauthorized', description: decryptedToken.error.description }, 401);
    }

    return $ok({
      rawAccessToken: decryptedToken.result.rawToken,
      injectedData: decryptedToken.result.injectedData,
      wasEncrypted: true,
    });
  }

  /**Decrypts the refresh token and returns its raw value and OBO status. */
  private $decryptRefreshToken(refreshToken: string): Result<{ rawRefreshToken: string }> {
    const token = zEncrypted.safeParse(refreshToken);
    if (token.error) return $err('format', { error: 'Unauthorized', description: 'Invalid refresh token format' }, 401);

    const decryptedToken = $decryptToken('refreshToken', token.data, this.secretKeys.rt);
    if (decryptedToken.error) {
      return $err('format', { error: 'Unauthorized', description: decryptedToken.error.description }, 401);
    }

    return $ok({ rawRefreshToken: decryptedToken.result.rawToken });
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
  private async $verifyJwt(jwtToken: string): Promise<Result<jwt.JwtPayload>> {
    const kid = $getKid(jwtToken);
    if (kid.error) return $err('jwt_error', { error: 'Unauthorized', description: kid.error.description }, 401);

    try {
      const publicKey = await this.$getPublicKey(kid.result);

      const decodedJwt = jwt.verify(jwtToken, publicKey, {
        algorithms: ['RS256'],
        audience: this.azure.clientId,
        issuer: `https://login.microsoftonline.com/${this.azure.tenantId}/v2.0`,
        complete: true,
      });

      if (typeof decodedJwt.payload === 'string') {
        return $err('jwt_error', { error: 'Unauthorized', description: 'Payload is a string' }, 401);
      }

      return $ok(decodedJwt.payload);
    } catch {
      return $err(
        'jwt_error',
        {
          error: 'Unauthorized',
          description:
            "Failed to verify JWT token. Check your Azure Portal, make sure the 'accessTokenAcceptedVersion' is set to '2' in the 'Manifest' area",
        },
        401,
      );
    }
  }

  /**
   * Generates an OAuth2 authorization URL with PKCE, login hints, and encrypted state.
   *
   * @param params - Optional parameters like login prompt, email hint, and custom frontend URL.
   * @returns A signed Microsoft authentication URL.
   * @throws {OAuthError} If validation fails or frontend host is not allowed.
   */
  async getAuthUrl(params?: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<
    Result<{ authUrl: string }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) return $err('input', { error: 'Invalid params', description: $prettyError(paramsError) });

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      return $err('input', { error: 'Invalid params: Email required' });
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('input', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
    }

    try {
      const { verifier, challenge } = await this.msalCryptoProvider.generatePkceCodes();
      const frontendUrl = parsedParams.frontendUrl ?? this.frontendUrls[0];
      const configuredPrompt = parsedParams.loginPrompt ?? this.settings.loginPrompt;
      const prompt =
        parsedParams.email || configuredPrompt === 'email'
          ? 'login'
          : configuredPrompt === 'select-account'
            ? 'select_account'
            : undefined;

      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedParams.email, prompt };
      const state = $encryptObj({ frontendUrl, codeVerifier: verifier, ...params }, this.secretKeys.state);
      if (state.error) return state;

      const authUrl = await this.cca.getAuthCodeUrl({
        ...params,
        state: state.result,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: challenge,
      });

      if (new URL(authUrl).hostname !== 'login.microsoftonline.com') {
        return $err('internal_error', { error: "Invalid redirect URL: must be 'login.microsoftonline.com'" }, 500);
      }

      return $ok({ authUrl });
    } catch (err) {
      //TODO: Handle specific MSAL errors
      if (err instanceof Error) {
        return $err('internal_error', { error: 'An error occurred', description: err.message }, 500);
      }
      if (typeof err === 'string') return $err('internal_error', { error: 'An error occurred', description: err }, 500);
      return $err('internal_error', { error: 'An error occurred', description: String(err) }, 500);
    }
  }

  /**
   * Handles authorization code exchange to return encrypted tokens and redirect metadata.
   *
   * @param params - Includes the OAuth authorization `code` and encrypted `state`.
   * @returns Access token, refresh token (if available), frontend redirect URL, and raw MSAL response.
   * @throws {OAuthError} If the code or state are invalid.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<
    Result<{
      accessToken: Cookies['AccessToken'];
      refreshToken: Cookies['RefreshToken'] | null;
      frontendUrl: string;
      msalResponse: MsalResponse;
    }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) return $err('input', { error: 'Invalid params', description: $prettyError(paramsError) });

    const { data: state, error: stateError } = zState.safeParse($decryptObj(parsedParams.state, this.secretKeys.state));
    if (stateError) return $err('input', { error: 'Invalid state', description: $prettyError(stateError) });

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      return $err('input', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const tokens = await this.$encryptTokens(msalResponse);
      if (tokens.error) return tokens;

      return $ok({
        accessToken: { value: tokens.result.accessTokenValue, ...this.defaultCookieOptions.accessToken },
        refreshToken: tokens.result.refreshTokenValue
          ? { value: tokens.result.refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        frontendUrl: state.frontendUrl,
        msalResponse,
      });
    } catch (err) {
      //TODO: Handle specific MSAL errors
      if (err instanceof Error) {
        return $err('internal_error', { error: 'An error occurred', description: err.message }, 500);
      }
      if (typeof err === 'string') return $err('internal_error', { error: 'An error occurred', description: err }, 500);
      return $err('internal_error', { error: 'An error occurred', description: String(err) }, 500);
    }
  }

  /**
   * Generates a logout URL and the cookie deletion configuration.
   *
   * @param params - Optional `frontendUrl` for post-logout redirection.
   * @returns Logout URL and cookie clear options.
   * @throws {OAuthError} If the URL is not on the whitelist.
   */
  getLogoutUrl(params?: { frontendUrl?: string }): Result<{
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) return $err('input', { error: 'Invalid params', description: $prettyError(paramsError) });

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('input', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
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
   * Returns the cookie names used to store the access and refresh tokens.
   *
   * @returns Object containing `accessTokenName` and `refreshTokenName`.
   */
  getCookieNames() {
    return {
      accessTokenName: this.defaultCookieOptions.accessToken.name,
      refreshTokenName: this.defaultCookieOptions.refreshToken.name,
    } as const;
  }

  /**
   * Verifies an access token, either as a raw JWT or encrypted string.
   *
   * @param accessToken - A JWT or encrypted access token.
   * @returns The original token and decoded payload if valid; `null` otherwise. If the token has injected data, it will be returned as well.
   * @throws {OAuthError} If the token is invalid or verification fails or if the tokens is B2B token and it's encrypted.
   */
  async verifyAccessToken(accessToken: string | undefined): Promise<{
    jwtAccessToken: string;
    payload: jwt.JwtPayload;
    injectedData: InjectedData | undefined;
    isB2B: boolean;
  } | null> {
    if (!accessToken) {
      this.$logger('verifyAccessToken', 'No access token provided');
      return null;
    }

    try {
      const { rawAccessToken: jwtAccessToken, injectedData, wasEncrypted } = this.$decryptAccessToken(accessToken);
      const payload = await this.$verifyJwt(jwtAccessToken);

      const isB2B = payload.sub === payload.oid;

      if (isB2B && (wasEncrypted || !this.settings.acceptB2BRequests)) {
        this.$logger('verifyAccessToken', 'B2B token cannot be encrypted');
        return null;
      }

      return { jwtAccessToken, payload, injectedData, isB2B };
    } catch (err) {
      this.$logger('verifyAccessToken', `Error verifying token: ${err}`);
      return null;
    }
  }

  /**
   * Rotates tokens using a previously stored refresh token.
   *
   * @param refreshToken - Encrypted refresh token.
   * @returns New access and refresh token cookies, raw MSAL response, and payload.
   * @throws {OAuthError} If the refresh token is invalid or decryption fails.
   */
  async getTokenByRefresh(refreshToken: string | undefined): Promise<{
    jwtAccessToken: string;
    payload: jwt.JwtPayload;
    newAccessToken: Cookies['AccessToken'];
    newRefreshToken: Cookies['RefreshToken'] | null;
    isObo: boolean;
    msalResponse: MsalResponse;
  } | null> {
    if (!refreshToken) {
      this.$logger('getTokenByRefresh', 'No refresh token provided');
      return null;
    }

    const { rawRefreshToken, from, target } = this.$decryptRefreshToken(refreshToken);
    if (!rawRefreshToken) {
      this.$logger('getTokenByRefresh', 'Invalid refresh token: no raw refresh token');
      return null;
    }

    if (this.azure.clientId !== from) {
      this.$logger('getTokenByRefresh', 'Invalid refresh token: not from the same client');
      return null;
    }

    const isObo = from !== target;
    const oboScopes = isObo ? this.oboMap?.get(target)?.scope : undefined;

    if (isObo && !oboScopes) {
      this.$logger('getTokenByRefresh', "Couldn't find the OBO scopes");
      return null;
    }

    const scopes = isObo ? [oboScopes as string] : this.azure.scopes;

    try {
      const msalResponse = await this.cca.acquireTokenByRefreshToken({
        refreshToken: rawRefreshToken,
        scopes: scopes,
        forceCache: true,
      });
      if (!msalResponse) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Refresh Token' });

      const payload = await this.$verifyJwt(msalResponse.accessToken);
      const { accessTokenValue, refreshTokenValue } = await this.$encryptTokens(msalResponse);

      return {
        jwtAccessToken: msalResponse.accessToken,
        payload,
        newAccessToken: { value: accessTokenValue, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: refreshTokenValue
          ? { value: refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        isObo,
        msalResponse,
      };
    } catch (err) {
      this.$logger('getTokenByRefresh', `Error refreshing token: ${err}`);
      return null;
    }
  }

  /**
   * Acquires tokens for B2B apps using client credentials.
   *
   * @param params - The parameters containing the B2B app name(s).
   * @returns The B2B access token and MSAL response for the specified app(s).
   * @throws {OAuthError} If the B2B apps are not configured or if the token is invalid.
   */
  async getB2BToken(params: { appName: string }): Promise<GetB2BTokenResult>;
  async getB2BToken(params: { appsNames: string[] }): Promise<GetB2BTokenResult[]>;
  async getB2BToken(
    params: { appName: string } | { appsNames: string[] },
  ): Promise<GetB2BTokenResult | GetB2BTokenResult[]> {
    if (!this.b2bMap) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'B2B apps not configured' });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getB2BToken.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: $prettyError(paramsError) });

    const apps = parsedParams.appNames.map((appName) => this.b2bMap?.get(appName)).filter((app) => !!app);

    if (!apps || apps.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'App not found' });
    }

    try {
      const results = (
        await Promise.all(
          apps.map(async (app) => {
            try {
              const msalResponse = await this.cca.acquireTokenByClientCredential({
                scopes: [app.scope],
                skipCache: true,
              });
              if (!msalResponse) return null;

              const clientId = $getAud(msalResponse.accessToken);
              if (!clientId) return null;

              return {
                appName: app.appName,
                appClientId: clientId,
                accessToken: msalResponse.accessToken,
                msalResponse,
              } satisfies GetB2BTokenResult;
            } catch {
              return null;
            }
          }),
        )
      ).filter((result) => !!result);

      if (!results || results.length === 0) {
        throw new OAuthError(500, { message: 'Internal server error', description: 'Failed to get token' });
      }

      return 'appName' in params ? (results[0] as GetB2BTokenResult) : results;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error getting b2b token', description: err as string });
    }
  }

  /**
   * Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.
   *
   * @param params - The parameters containing the access token and service name(s).
   * @returns The OBO access token and MSAL response for the specified service(s).
   * @throws {OAuthError} If the OBO services are not configured or if the token is invalid.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; clientId: string }): Promise<GetTokenOnBehalfOfResult>;
  async getTokenOnBehalfOf(params: { accessToken: string; clientIds: string[] }): Promise<GetTokenOnBehalfOfResult[]>;
  async getTokenOnBehalfOf(
    params: { accessToken: string; clientId: string } | { accessToken: string; clientIds: string[] },
  ): Promise<GetTokenOnBehalfOfResult | GetTokenOnBehalfOfResult[]> {
    if (!this.oboMap) {
      throw new OAuthError(500, {
        message: 'Invalid params',
        description: 'On-Behalf-Of Services not configured',
      });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: $prettyError(paramsError) });

    const services = parsedParams.clientIds
      .map((clientId) => this.oboMap?.get(clientId))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    }

    this.$logger('getTokenOnBehalfOf', `Services names: ${JSON.stringify(services)}`);

    const { rawAccessToken: jwtAccessToken } = this.$decryptAccessToken(parsedParams.accessToken);

    try {
      const results = (
        await Promise.all(
          services.map(async (service) => {
            try {
              const msalResponse = await this.cca.acquireTokenOnBehalfOf({
                oboAssertion: jwtAccessToken,
                scopes: [service.scope],
                skipCache: false,
              });
              if (!msalResponse) return null;

              const serviceClientId = $getAud(msalResponse.accessToken);
              if (!serviceClientId) return null;

              if (serviceClientId !== service.clientId) {
                this.$logger('getTokenOnBehalfOf', `Client ID mismatch: ${serviceClientId} !== ${service.clientId}`);
                return null;
              }

              const serviceSecretKey = $createSecretKey(service.secretKey);
              const { accessTokenValue, refreshTokenValue } = await this.$encryptTokens(msalResponse, {
                secretKey: serviceSecretKey,
                oboClientId: serviceClientId,
              });

              const cookieOptions = $cookieOptions({
                clientId: serviceClientId,
                secure: service.isHttps as boolean,
                sameSite: service.isHttps as boolean,
                cookiesTimeUnit: this.settings.cookiesTimeUnit,
                accessTokenCookieExpiry: service.accessTokenExpiry ?? this.settings.accessTokenCookieExpiry,
                refreshTokenCookieExpiry: service.refreshTokenExpiry ?? this.settings.refreshTokenCookieExpiry,
              });

              return {
                serviceClientId: serviceClientId,
                accessToken: { value: accessTokenValue, ...cookieOptions.accessToken },
                refreshToken: refreshTokenValue ? { value: refreshTokenValue, ...cookieOptions.refreshToken } : null,
                msalResponse,
              } satisfies GetTokenOnBehalfOfResult;
            } catch {
              return null;
            }
          }),
        )
      ).filter((result) => !!result);

      if (!results || results.length === 0) {
        throw new OAuthError(500, { message: 'Internal server error', description: 'Failed to get token' });
      }

      return 'clientId' in params ? (results[0] as GetTokenOnBehalfOfResult) : results;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error getting token on behalf of', description: err as string });
    }
  }

  /**
   * Injects data into the access token. Useful for embedding non-sensitive metadata into token structure.
   *
   * @param params - The parameters containing the access token value and data to inject.
   * @returns The new access token cookie with injected data, or null if the token is invalid.
   */
  injectData<TValues, TData extends Record<string, TValues>>(params: { accessToken: string; data: TData }):
    | Cookies['AccessToken']
    | null {
    const { rawAccessToken: jwtAccessToken } = this.$decryptAccessToken(params.accessToken);
    const { data: nextAccessToken, error: nextAccessTokenError } = zAccessTokenStructure.safeParse({
      at: jwtAccessToken,
      inj: params.data,
    });

    if (nextAccessTokenError) {
      this.$logger('injectData', 'Invalid access token format');
      return null;
    }

    const encryptedAccessToken = $encryptObj(nextAccessToken, this.secretKey);
    if (encryptedAccessToken.length > 4096) {
      this.$logger('injectData', 'Token length exceeds 4kB');
      return null;
    }

    return { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken };
  }
}
