import * as msal from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import type { z } from 'zod/v4';
import { $err, $ok, OAuthError, type Result } from './error';
import type {
  B2BApp,
  Cookies,
  GetB2BTokenResult,
  GetTokenOnBehalfOfResult,
  LoginPrompt,
  MsalResponse,
  OAuthConfig,
  OAuthSettings,
  OboService,
} from './types';
import { $cookieOptions } from './utils/cookie-options';
import { $decrypt, $decryptObj, $encrypt, $encryptObj, $getAud, $getKid, type SecretKey } from './utils/crypto';
import { $filterCoreErrors, $getB2BInfo, $getOboInfo } from './utils/misc';
import {
  $prettyError,
  zAccessTokenStructure,
  zConfig,
  zEncrypted,
  zJwt,
  zLooseBase64,
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
  private readonly secretKeys: { at: SecretKey; rt: SecretKey; state: SecretKey };
  private readonly frontendWhitelist: Set<string>;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly b2bMap: Map<string, B2BApp> | undefined;
  private readonly oboMap: Map<string, OboService> | undefined;
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
      throw new OAuthError('misconfiguration', {
        error: 'Invalid configuration',
        description: $prettyError(configError),
        status: 500,
      });
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

    const secretKeys = {
      at: `access-token-${secretKey}`,
      rt: `refresh-token-${secretKey}`,
      state: `state-${secretKey}`,
    };

    const { error: b2bError, b2bMap, b2bNames } = $getB2BInfo(b2bTargetedApps);
    if (b2bError) throw new OAuthError(b2bError);

    const { error: oboError, oboMap, oboNames } = $getOboInfo(downstreamServices);
    if (oboError) throw new OAuthError(oboError);

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
      b2bApps: b2bNames,
      downstreamServices: oboNames,
      cookies: {
        timeUnit: cookies.timeUnit,
        isSecure: secure,
        isSameSite: sameSite,
        accessTokenExpiry: cookies.accessTokenExpiry,
        refreshTokenExpiry: cookies.refreshTokenExpiry,
        accessTokenName: defaultCookieOptions.accessToken.name,
        refreshTokenName: defaultCookieOptions.refreshToken.name,
      },
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
    this.secretKeys = secretKeys;
    this.frontendWhitelist = frontHosts;
    this.defaultCookieOptions = defaultCookieOptions;
    this.b2bMap = b2bMap;
    this.oboMap = oboMap;
    this.settings = settings;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;
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
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
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
      const { encryptedState, error: encryptError } = await this.$encrypt('state', {
        value: { frontendUrl, codeVerifier: verifier, ...params },
      });

      if (encryptError) return $err(encryptError);

      const authUrl = await this.cca.getAuthCodeUrl({
        ...params,
        state: encryptedState,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: challenge,
      });

      if (new URL(authUrl).hostname !== 'login.microsoftonline.com') {
        return $err('internal', { error: "Invalid redirect URL: must be 'login.microsoftonline.com'", status: 500 });
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

    const { state, error: decryptError } = await this.$decrypt('state', parsedParams.state);
    if (decryptError) return $err(decryptError);

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      return $err('bad_request', { error: 'Invalid params: Unlisted host frontend URL', status: 403 });
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
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

  /** Verifies an access token, either as a raw JWT or encrypted string. */
  async verifyAccessToken<T extends object = Record<string, any>>(
    accessToken: string | undefined,
  ): Promise<
    Result<{
      rawAccessToken: string;
      payload: jwt.JwtPayload;
      injectedData: T | undefined;
      isApp: boolean;
    }>
  > {
    const {
      rawAccessToken,
      injectedData,
      wasEncrypted,
      error: decryptError,
    } = await this.$decrypt<T>('accessToken', accessToken);

    if (decryptError) {
      return $err(decryptError.type, {
        error: 'Unauthorized',
        description: decryptError.description,
      });
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

    if (isApp === true && wasEncrypted === true) {
      return $err('jwt_error', {
        error: 'Unauthorized',
        description: 'App token cannot be encrypted',
        status: 401,
      });
    }

    if (isApp === false && wasEncrypted === false) {
      return $err('jwt_error', {
        error: 'Unauthorized',
        description: 'Normal user token cannot be unencrypted',
        status: 401,
      });
    }

    return $ok({ rawAccessToken, payload, injectedData, isApp });
  }

  /** Rotates tokens using a previously stored refresh token.*/
  async getTokenByRefresh(refreshToken: string | undefined): Promise<
    Result<{
      rawAccessToken: string;
      payload: jwt.JwtPayload;
      newTokens: {
        accessToken: Cookies['AccessToken'];
        refreshToken: Cookies['RefreshToken'] | null;
      };
      msalResponse: MsalResponse;
    }>
  > {
    if (!refreshToken) {
      return $err('nullish_value', { error: 'Unauthorized', description: 'Refresh token is required', status: 401 });
    }

    const { rawRefreshToken, error } = await this.$decrypt('refreshToken', refreshToken);
    if (error) {
      return $err(error.type, {
        error: 'Unauthorized',
        description: error.description,
        status: 401,
      });
    }

    try {
      const msalResponse = await this.cca.acquireTokenByRefreshToken({
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

      const {
        encryptedAccessToken,
        encryptedRefreshToken,
        error: tokensError,
      } = await this.$extractTokens(msalResponse);
      if (tokensError) {
        return $err(tokensError.type, {
          error: 'Unauthorized',
          description: tokensError.description,
          status: 401,
        });
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

  /** Acquires tokens for B2B apps using client credentials. */
  async getB2BToken(params: { appName: string }): Promise<Result<{ result: GetB2BTokenResult }>>;
  async getB2BToken(params: { appsNames: string[] }): Promise<Result<{ results: GetB2BTokenResult[] }>>;
  async getB2BToken(
    params: { appName: string } | { appsNames: string[] },
  ): Promise<Result<{ result: GetB2BTokenResult } | { results: GetB2BTokenResult[] }>> {
    if (!this.b2bMap) return $err('misconfiguration', { error: 'B2B apps not configured', status: 500 });

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
        return $err('internal', { error: 'Failed to get B2B token', status: 500 });
      }

      return $ok('appName' in params ? { result: results[0] as GetB2BTokenResult } : { results });
    } catch (err) {
      return $filterCoreErrors(err, 'getB2BToken');
    }
  }

  /** Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow. */
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
    if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyError(paramsError) });

    const services = parsedParams.serviceNames
      .map((serviceName) => this.oboMap?.get(serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      return $err('bad_request', { error: 'Invalid params', description: 'OBO service not found' });
    }

    const { rawAccessToken, error } = await this.$decrypt('accessToken', parsedParams.accessToken);
    if (error) return $err(error);

    try {
      const results = (
        await Promise.all(
          services.map(async (service) => {
            try {
              const msalResponse = await this.cca.acquireTokenOnBehalfOf({
                oboAssertion: rawAccessToken,
                scopes: [service.scope],
                skipCache: false,
              });
              if (!msalResponse) return null;

              const { result: clientId, error: clientIdError } = $getAud(msalResponse.accessToken);
              if (clientIdError) return null;

              const { encryptedAccessToken, error } = await this.$encrypt('accessToken', {
                value: msalResponse.accessToken,
                secretKey: `access-token-${service.secretKey}`,
              });
              if (error) return null;

              await this.$removeFromCache(msalResponse.account);

              const cookieOptions = $cookieOptions({
                clientId,
                secure: service.secure,
                sameSite: service.sameSite,
                timeUnit: this.settings.cookies.timeUnit,
                atExp: service.atExp ?? this.settings.cookies.accessTokenExpiry,
                rtExp: service.atExp ?? this.settings.cookies.refreshTokenExpiry,
              });

              return {
                serviceName: service.serviceName,
                clientId,
                accessToken: { value: encryptedAccessToken, ...cookieOptions.accessToken },
                msalResponse,
              } satisfies GetTokenOnBehalfOfResult;
            } catch {
              return null;
            }
          }),
        )
      ).filter((result) => !!result);

      if (!results || results.length === 0) {
        return $err('internal', { error: 'Failed to get OBO token', status: 500 });
      }

      return $ok('serviceName' in params ? { result: results[0] as GetTokenOnBehalfOfResult } : { results });
    } catch (err) {
      return $filterCoreErrors(err, 'getTokenOnBehalfOf');
    }
  }

  /** Injects data into the access token. Useful for embedding non-sensitive metadata into token structure. */
  async injectData<T extends object = Record<string, any>>(params: { accessToken: string; data: T }): Promise<
    Result<{ injectedAccessToken: Cookies['AccessToken'] }>
  > {
    const { rawAccessToken, error } = await this.$decrypt<T>('accessToken', params.accessToken);
    if (error) return $err(error);

    const { data: accessTokenStruct, error: accessTokenStructError } = zAccessTokenStructure.safeParse({
      at: rawAccessToken,
      inj: params.data,
    });

    if (accessTokenStructError) {
      return $err('invalid_format', { error: 'Invalid data', description: $prettyError(accessTokenStructError) });
    }

    const { encryptedAccessToken, error: encryptError } = await this.$encrypt('accessToken', {
      value: accessTokenStruct.at,
      injectedData: accessTokenStruct.inj,
    });
    if (encryptError) return $err(encryptError);

    return $ok({ injectedAccessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken } });
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

  /** Removes the account from the MSAL cache, if it exists. */
  private async $removeFromCache(account: msal.AccountInfo | null) {
    const cache = this.cca.getTokenCache();
    if (account) await cache.removeAccount(account);
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async $obtainRefreshToken(msalResponse: MsalResponse): Promise<string | null> {
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

  private async $encrypt<T extends object = Record<string, any>>(
    type: 'accessToken',
    params: { value: string | null; secretKey?: string; injectedData?: T },
  ): Promise<Result<{ encryptedAccessToken: string }>>;
  private async $encrypt(
    type: 'refreshToken',
    params: { value: string | null },
  ): Promise<Result<{ encryptedRefreshToken: string }>>;
  private async $encrypt(type: 'state', params: { value: object | null }): Promise<Result<{ encryptedState: string }>>;
  private async $encrypt<T extends object = Record<string, any>>(
    type: 'accessToken' | 'refreshToken' | 'state',
    params: {
      value: object | string | null;
      secretKey?: SecretKey;
      injectedData?: T;
    },
  ): Promise<
    Result<{ encryptedAccessToken: string } | { encryptedRefreshToken: string } | { encryptedState: string }>
  > {
    if (!params.value) {
      return $err('nullish_value', { error: 'Invalid data' });
    }
    switch (type) {
      case 'accessToken': {
        const { data, error: parseError } = zAccessTokenStructure.safeParse({
          at: params.value,
          inj: params.injectedData,
        });
        if (parseError) {
          return $err('invalid_format', {
            error: 'Invalid access token format',
            description: $prettyError(parseError),
          });
        }
        const { encrypted, secretKey, error } = await $encryptObj(data, params.secretKey ?? this.secretKeys.at);
        if (error) {
          return $err('crypto_error', { error: 'Failed to encrypt access token', description: error.description });
        }
        if (encrypted.length > 4096) {
          return $err('invalid_format', {
            error: 'Token too long',
            description: 'Encrypted access token exceeds 4096 characters',
          });
        }

        if (!params.secretKey && typeof this.secretKeys.at === 'string') {
          this.secretKeys.at = secretKey;
        }

        return $ok({ encryptedAccessToken: encrypted });
      }
      case 'refreshToken': {
        const { data, error: parseError } = zLooseBase64.safeParse(params.value);
        if (parseError) {
          return $err('invalid_format', {
            error: 'Invalid refresh token format',
            description: $prettyError(parseError),
          });
        }

        const { encrypted, secretKey, error } = await $encrypt(data, this.secretKeys.rt);
        if (error) {
          return $err('crypto_error', { error: 'Failed to encrypt refresh token', description: error.description });
        }

        if (encrypted.length > 4096) {
          return $err('invalid_format', {
            error: 'Token too long',
            description: 'Encrypted refresh token exceeds 4096 characters',
          });
        }

        if (typeof this.secretKeys.rt === 'string') {
          this.secretKeys.rt = secretKey;
        }

        return $ok({ encryptedRefreshToken: encrypted });
      }
      case 'state': {
        const { data, error: parseError } = zState.safeParse(params.value);
        if (parseError) {
          return $err('invalid_format', {
            error: 'Invalid state format',
            description: $prettyError(parseError),
          });
        }

        const { encrypted, secretKey, error } = await $encryptObj(data, this.secretKeys.state);
        if (error) {
          return $err('crypto_error', { error: 'Failed to encrypt state', description: error.description });
        }

        if (encrypted.length > 4096) {
          return $err('invalid_format', {
            error: 'State too long',
            description: 'Encrypted state exceeds 4096 characters',
          });
        }

        if (typeof this.secretKeys.state === 'string') {
          this.secretKeys.state = secretKey;
        }

        return $ok({ encryptedState: encrypted });
      }
      default: {
        return $err('misconfiguration', { error: 'Invalid encrypt type', description: `Unknown type: ${type}` });
      }
    }
  }

  private async $decrypt<T extends object = Record<string, any>>(
    type: 'accessToken',
    value: string | undefined,
  ): Promise<Result<{ rawAccessToken: string; injectedData?: T; wasEncrypted: boolean }>>;
  private async $decrypt(type: 'refreshToken', value: string | undefined): Promise<Result<{ rawRefreshToken: string }>>;
  private async $decrypt(type: 'state', value: string | undefined): Promise<Result<{ state: z.infer<typeof zState> }>>;
  private async $decrypt<T extends object = Record<string, any>>(
    type: 'accessToken' | 'refreshToken' | 'state',
    value: string | undefined,
  ): Promise<
    Result<
      | { rawAccessToken: string; injectedData?: T; wasEncrypted: boolean }
      | { rawRefreshToken: string }
      | { state: z.infer<typeof zState> }
    >
  > {
    if (!value) return $err('nullish_value', { error: 'Invalid data' });

    switch (type) {
      case 'accessToken': {
        const { data: jwtToken, success: jwtSuccess } = zJwt.safeParse(value);
        if (jwtSuccess) return $ok({ rawAccessToken: jwtToken, injectedData: undefined, wasEncrypted: false });

        const { data: encryptedAccessToken, error: encryptedAccessTokenError } = zEncrypted.safeParse(value);
        if (encryptedAccessTokenError) {
          return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid access token format' });
        }

        const { data, secretKey, error } = await $decryptObj(encryptedAccessToken, this.secretKeys.at);
        if (error) {
          return $err('crypto_error', { error: 'Failed to decrypt access token', description: error.description });
        }

        if (typeof this.secretKeys.at === 'string') {
          this.secretKeys.at = secretKey;
        }

        const { data: accessTokenStruct, error: accessTokenStructError } = zAccessTokenStructure.safeParse(data);
        if (accessTokenStructError) {
          return $err('invalid_format', {
            error: 'Invalid access token format',
            description: $prettyError(accessTokenStructError),
          });
        }

        return $ok({
          rawAccessToken: accessTokenStruct.at,
          injectedData: accessTokenStruct.inj as T,
          wasEncrypted: true,
        });
      }
      case 'refreshToken': {
        const { data: encryptedRefreshToken, error: encryptedRefreshTokenError } = zEncrypted.safeParse(value);
        if (encryptedRefreshTokenError) {
          return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid refresh token format' });
        }

        const { data: rawRefreshToken, secretKey, error } = await $decrypt(encryptedRefreshToken, this.secretKeys.rt);
        if (error) {
          return $err('crypto_error', { error: 'Failed to decrypt refresh token', description: error.description });
        }

        if (typeof this.secretKeys.rt === 'string') {
          this.secretKeys.rt = secretKey;
        }

        return $ok({ rawRefreshToken });
      }
      case 'state': {
        const { data: encryptedState, error: encryptedStateError } = zEncrypted.safeParse(value);
        if (encryptedStateError) {
          return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid state format' });
        }

        const { data, secretKey, error } = await $decryptObj(encryptedState, this.secretKeys.state);
        if (error) {
          return $err('crypto_error', { error: 'Failed to decrypt state', description: error.description });
        }

        if (typeof this.secretKeys.state === 'string') {
          this.secretKeys.state = secretKey;
        }

        const { data: state, error: stateError } = zState.safeParse(data);
        if (stateError) {
          return $err('invalid_format', {
            error: 'Invalid state format',
            description: $prettyError(stateError),
          });
        }

        return $ok({ state });
      }
      default: {
        return $err('misconfiguration', { error: 'Invalid decrypt type', description: `Unknown type: ${type}` });
      }
    }
  }

  /** Extracts and encrypts both tokens */
  private async $extractTokens(
    msalResponse: MsalResponse,
  ): Promise<Result<{ encryptedAccessToken: string; encryptedRefreshToken: string | null }>> {
    const { encryptedAccessToken, error: atError } = await this.$encrypt('accessToken', {
      value: msalResponse.accessToken,
    });
    if (atError) return $err(atError);

    const rawRefreshToken = await this.$obtainRefreshToken(msalResponse);
    const { encryptedRefreshToken, error: rtError } = await this.$encrypt('refreshToken', { value: rawRefreshToken });
    if (rtError) return $err(rtError);

    return $ok({ encryptedAccessToken, encryptedRefreshToken });
  }
}
