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
  $createSecretKey,
  $decryptObj,
  $decryptToken,
  $encryptObj,
  $encryptToken,
  $getAud,
  $getKid,
} from './utils/crypto';
import { $filterCoreErrors, $getB2BInfo, $getOboInfo } from './utils/misc';
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
    const { data: config, error: configError } = zConfig.safeParse(configuration);
    if (configError) {
      throw new OAuthError(
        'misconfiguration',
        { error: 'Invalid configuration', description: $prettyError(configError) },
        500,
      );
    }

    const {
      azure,
      frontendUrl,
      serverCallbackUrl,
      secretKey,
      advanced: { loginPrompt, sessionType, acceptB2BRequests, b2bTargetedApps, cookies, downstreamServices },
    } = config;

    const frontHosts = new Set(frontendUrl.map((url) => new URL(url).host));
    const serverHost = new URL(serverCallbackUrl).host;
    const secure = !cookies.disableHttps && [serverHost, ...frontHosts].every((url) => url.startsWith('https'));
    const sameSite = !cookies.disableSameSite && frontHosts.size === 1 ? frontHosts.has(serverHost) : false;

    const { result: atSecretKey, error: atSecretKeyError } = $createSecretKey(`access-token-${secretKey}`);
    if (atSecretKeyError) throw new OAuthError(atSecretKeyError);

    const { result: rtSecretKey, error: rtSecretKeyError } = $createSecretKey(`refresh-token-${secretKey}`);
    if (rtSecretKeyError) throw new OAuthError(rtSecretKeyError);

    const { result: stateSecretKey, error: stateSecretKeyError } = $createSecretKey(`state-${secretKey}`);
    if (stateSecretKeyError) throw new OAuthError(stateSecretKeyError);

    const b2bInfo = $getB2BInfo(b2bTargetedApps);
    if (b2bInfo.error) throw new OAuthError(b2bInfo.error);

    const oboInfo = $getOboInfo(downstreamServices);
    if (oboInfo.error) throw new OAuthError(oboInfo.error);

    const defaultCookieOptions = $cookieOptions({
      clientId: azure.clientId,
      secure: secure,
      sameSite: sameSite,
      timeUnit: cookies.timeUnit,
      atExp: cookies.accessTokenExpiry,
      rtExp: cookies.refreshTokenExpiry,
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
    this.secretKeys = { at: atSecretKey, rt: rtSecretKey, state: stateSecretKey };
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
    if (token.error) {
      return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid access token format' }, 401);
    }

    if (isJwt(token.data)) return $ok({ rawAccessToken: token.data, wasEncrypted: false });

    const decryptedToken = $decryptToken('accessToken', token.data, this.secretKeys.at);
    if (decryptedToken.error) {
      return $err('invalid_format', { error: 'Unauthorized', description: decryptedToken.error.description }, 401);
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
    if (token.error) {
      return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid refresh token format' }, 401);
    }

    const decryptedToken = $decryptToken('refreshToken', token.data, this.secretKeys.rt);
    if (decryptedToken.error) {
      return $err('invalid_format', { error: 'Unauthorized', description: decryptedToken.error.description }, 401);
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

  /** Generates an OAuth2 authorization URL with PKCE, login hints, and encrypted state. */
  async getAuthUrl(params?: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<
    Result<{ authUrl: string }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      return $err('bad_request', { error: 'Invalid params: Email required' });
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
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
        return $err('internal', { error: "Invalid redirect URL: must be 'login.microsoftonline.com'" }, 500);
      }

      return $ok({ authUrl });
    } catch (err) {
      return $filterCoreErrors(err, 'getAuthUrl');
    }
  }

  /**  Handles authorization code exchange to return encrypted tokens and redirect metadata. */
  async getTokenByCode(params: { code: string; state: string }): Promise<
    Result<{
      accessToken: Cookies['AccessToken'];
      refreshToken: Cookies['RefreshToken'] | null;
      frontendUrl: string;
      msalResponse: MsalResponse;
    }>
  > {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    const { data: state, error: stateError } = zState.safeParse($decryptObj(parsedParams.state, this.secretKeys.state));
    if (stateError) return $err('bad_request', { error: 'Invalid state', description: $prettyError(stateError) });

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const { result: tokens, error: tokensError } = await this.$encryptTokens(msalResponse);
      if (tokensError) return $err(tokensError);

      return $ok({
        accessToken: { value: tokens.accessTokenValue, ...this.defaultCookieOptions.accessToken },
        refreshToken: tokens.refreshTokenValue
          ? { value: tokens.refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        frontendUrl: state.frontendUrl,
        msalResponse,
      });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenByCode');
    }
  }

  /** Generates a logout URL and the cookie deletion configuration. */
  getLogoutUrl(params?: { frontendUrl?: string }): Result<{
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL' }, 403);
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

  /** Returns the cookie names used to store the access and refresh tokens.
   * @returns Object containing `accessTokenName` and `refreshTokenName`.
   */
  getCookieNames() {
    return {
      accessTokenName: this.defaultCookieOptions.accessToken.name,
      refreshTokenName: this.defaultCookieOptions.refreshToken.name,
    } as const;
  }

  /** Verifies an access token, either as a raw JWT or encrypted string. */
  async verifyAccessToken(accessToken: string | undefined): Promise<
    Result<{
      rawAccessToken: string;
      payload: jwt.JwtPayload;
      injectedData: InjectedData | undefined;
      isApp: boolean;
    }>
  > {
    if (!accessToken) {
      return $err('nullish_value', { error: 'Unauthorized', description: 'Access token is required' }, 401);
    }

    const { result: at, error: atError } = this.$decryptAccessToken(accessToken);
    if (atError) return $err('invalid_format', { error: 'Unauthorized', description: atError.description }, 401);

    const payload = await this.$verifyJwt(at.rawAccessToken);
    if (payload.error) return payload;

    const isApp = payload.result.sub === payload.result.oid;

    if (this.settings.acceptB2BRequests === false) {
      if (isApp === true && at.wasEncrypted === true) {
        return $err('jwt_error', { error: 'Unauthorized', description: 'App token cannot be encrypted' }, 401);
      }

      if (isApp === false && at.wasEncrypted === false) {
        return $err(
          'jwt_error',
          { error: 'Unauthorized', description: 'Normal user token cannot be unencrypted' },
          401,
        );
      }
    }

    return $ok({ rawAccessToken: at.rawAccessToken, payload: payload.result, injectedData: at.injectedData, isApp });
  }

  /**
   * Rotates tokens using a previously stored refresh token.
   *
   * @param refreshToken - Encrypted refresh token.
   * @returns New access and refresh token cookies, raw MSAL response, and payload.
   * @throws {OAuthError} If the refresh token is invalid or decryption fails.
   */
  async getTokenByRefresh(refreshToken: string | undefined): Promise<
    Result<{
      rawAccessToken: string;
      payload: jwt.JwtPayload;
      newAccessToken: Cookies['AccessToken'];
      newRefreshToken: Cookies['RefreshToken'] | null;
      msalResponse: MsalResponse;
    }>
  > {
    if (!refreshToken) {
      return $err('nullish_value', { error: 'Unauthorized', description: 'Refresh token is required' }, 401);
    }

    const { result: rt, error: rtError } = this.$decryptRefreshToken(refreshToken);
    if (rtError) return $err(rtError);

    try {
      const msalResponse = await this.cca.acquireTokenByRefreshToken({
        refreshToken: rt.rawRefreshToken,
        scopes: this.azure.scopes,
        forceCache: true,
      });
      if (!msalResponse) {
        return $err(
          'internal',
          { error: 'Unauthorized', description: 'Failed to refresh token, no msal response' },
          401,
        );
      }

      const { result: payload, error: payloadError } = await this.$verifyJwt(msalResponse.accessToken);
      if (payloadError) return $err(payloadError);

      const { result: tokens, error: tokensError } = await this.$encryptTokens(msalResponse);
      if (tokensError) return $err(tokensError);

      return $ok({
        rawAccessToken: msalResponse.accessToken,
        payload,
        newAccessToken: { value: tokens.accessTokenValue, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: tokens.refreshTokenValue
          ? { value: tokens.refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        msalResponse,
      });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenByRefresh');
    }
  }

  /** Acquires tokens for B2B apps using client credentials. */
  async getB2BToken(params: { appName: string }): Promise<Result<GetB2BTokenResult>>;
  async getB2BToken(params: { appsNames: string[] }): Promise<Result<GetB2BTokenResult[]>>;
  async getB2BToken(
    params: { appName: string } | { appsNames: string[] },
  ): Promise<Result<GetB2BTokenResult | GetB2BTokenResult[]>> {
    if (!this.b2bMap) return $err('misconfiguration', { error: 'B2B apps not configured' }, 500);

    const { data: parsedParams, error: paramsError } = zMethods.getB2BToken.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    const apps = parsedParams.appNames.map((appName) => this.b2bMap?.get(appName)).filter((app) => !!app);
    if (!apps || apps.length === 0)
      return $err('bad_request', { error: 'Invalid params', description: 'B2B app not found' });

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

              const { result: clientId, error: clientIdError } = $getAud(msalResponse.accessToken);
              if (clientIdError) return null;

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
        return $err('internal', { error: 'Failed to get B2B token' }, 500);
      }

      return $ok('appName' in params ? (results[0] as GetB2BTokenResult) : results);
    } catch (err) {
      return $filterCoreErrors(err, 'getB2BToken');
    }
  }

  /** Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow. */
  async getTokenOnBehalfOf(params: { accessToken: string; serviceName: string }): Promise<
    Result<GetTokenOnBehalfOfResult>
  >;
  async getTokenOnBehalfOf(params: { accessToken: string; serviceNames: string[] }): Promise<
    Result<GetTokenOnBehalfOfResult[]>
  >;
  async getTokenOnBehalfOf(
    params: { accessToken: string; serviceName: string } | { accessToken: string; serviceNames: string[] },
  ): Promise<Result<GetTokenOnBehalfOfResult | GetTokenOnBehalfOfResult[]>> {
    if (!this.oboMap) return $err('misconfiguration', { error: 'OBO services not configured' }, 500);

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    const services = parsedParams.clientIds
      .map((clientId) => this.oboMap?.get(clientId))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      return $err('bad_request', { error: 'Invalid params', description: 'OBO service not found' });
    }

    const { result: at, error: atError } = this.$decryptAccessToken(parsedParams.accessToken);
    if (atError) return $err(atError);

    try {
      const results = (
        await Promise.all(
          services.map(async (service) => {
            try {
              const msalResponse = await this.cca.acquireTokenOnBehalfOf({
                oboAssertion: at.rawAccessToken,
                scopes: [service.scope],
                skipCache: false,
              });
              if (!msalResponse) return null;

              const { result: clientId, error: clientIdError } = $getAud(msalResponse.accessToken);
              if (clientIdError) return null;

              const { result: serviceSecretKey, error: serviceSecretKeyError } = $createSecretKey(
                `access-token-${service.secretKey}`,
              );
              if (serviceSecretKeyError) return null;

              const { result: accessTokenValue, error: accessTokenValueError } = $encryptToken(
                'accessToken',
                msalResponse.accessToken,
                serviceSecretKey,
              );
              if (accessTokenValueError) return null;

              await this.$removeFromCache(msalResponse.account);

              const cookieOptions = $cookieOptions({
                clientId,
                secure: service.secure,
                sameSite: service.sameSite,
                timeUnit: this.settings.cookiesTimeUnit,
                atExp: service.atExp ?? this.settings.accessTokenCookieExpiry,
                rtExp: service.atExp ?? this.settings.refreshTokenCookieExpiry,
              });

              return {
                serviceName: service.serviceName,
                clientId,
                accessToken: { value: accessTokenValue, ...cookieOptions.accessToken },
                msalResponse,
              } satisfies GetTokenOnBehalfOfResult;
            } catch {
              return null;
            }
          }),
        )
      ).filter((result) => !!result);

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get OBO token' }, 500);
      }

      return $ok('serviceName' in params ? (results[0] as GetTokenOnBehalfOfResult) : results);
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenOnBehalfOf');
    }
  }

  /** Injects data into the access token. Useful for embedding non-sensitive metadata into token structure. */
  injectData<TData extends InjectedData<unknown>>(params: { accessToken: string; data: TData }): Result<
    Cookies['AccessToken']
  > {
    const { result: at, error: atError } = this.$decryptAccessToken(params.accessToken);
    if (atError) return $err(atError);

    const { data: nextAtStruct, error: nextAtStructError } = zAccessTokenStructure.safeParse({
      at: at.rawAccessToken,
      inj: params.data,
    });

    if (nextAtStructError) {
      return $err('invalid_format', { error: 'Invalid data', description: $prettyError(nextAtStructError) });
    }

    const { result: accessToken, error: accessTokenError } = $encryptToken(
      'accessToken',
      nextAtStruct.at,
      this.secretKeys.at,
      at.injectedData,
    );
    if (accessTokenError) return $err(accessTokenError);

    return $ok({ value: accessToken, ...this.defaultCookieOptions.accessToken });
  }
}
