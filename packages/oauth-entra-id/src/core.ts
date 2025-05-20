import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { OAuthError } from './error';
import type {
  B2BApp,
  Cookies,
  DownstreamService,
  GetB2BTokenResult,
  GetTokenOnBehalfOfResult,
  InjectedData,
  LoginPrompt,
  MsalResponse,
  OAuthConfig,
  OAuthProviderMethods,
  OAuthSettings,
} from './types';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject, getAudFromJwt } from './utils/crypto';
import { getCookieOptions } from './utils/get-cookie-options';
import { debugLog, getB2BAppsInfo, getDownstreamServicesInfo } from './utils/misc';
import { isJwt } from './utils/regex';
import {
  prettifyError,
  zAccessTokenStructure,
  zConfig,
  zEncrypted,
  zJwt,
  zJwtOrEncrypted,
  zMethods,
  zRefreshTokenStructure,
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
  private readonly secretKey: KeyObject;
  private readonly frontendWhitelist: Set<string>;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly b2bAppsMap: Map<string, B2BApp> | undefined;
  private readonly downstreamServicesMap: Map<string, DownstreamService> | undefined;
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
      throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: prettifyError(configError) });
    }

    const {
      azure,
      frontendUrl,
      serverCallbackUrl,
      secretKey,
      advanced: { loginPrompt, sessionType, acceptB2BRequests, b2bTargetedApps, debug, cookies, downstreamServices },
    } = config;

    const frontHosts = new Set(frontendUrl.map((url) => new URL(url).host));
    const serverHost = new URL(serverCallbackUrl).host;
    const isHttps = !cookies.disableHttps && [serverHost, ...frontHosts].every((url) => url.startsWith('https'));
    const isSameSite = !cookies.disableSameSite && frontHosts.size === 1 ? frontHosts.has(serverHost) : false;

    const { b2bAppsMap, b2bAppsNames } = getB2BAppsInfo(b2bTargetedApps);
    const { downstreamServicesMap, downstreamServicesNames } = getDownstreamServicesInfo(downstreamServices);

    const defaultCookieOptions = getCookieOptions({
      clientId: azure.clientId,
      isHttps,
      isSameSite,
      cookiesTimeUnit: cookies.timeUnit,
      accessTokenCookieExpiry: cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: cookies.refreshTokenExpiry,
    });

    const settings: OAuthSettings = {
      sessionType,
      loginPrompt,
      acceptB2BRequests,
      isHttps,
      isSameSite,
      cookiesTimeUnit: cookies.timeUnit,
      accessTokenCookieExpiry: cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: cookies.refreshTokenExpiry,
      b2bApps: b2bAppsNames,
      downstreamServices: downstreamServicesNames,
      debug,
    };

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
    this.secretKey = createSecretKey(secretKey);
    this.frontendWhitelist = frontHosts;
    this.defaultCookieOptions = defaultCookieOptions;
    this.b2bAppsMap = b2bAppsMap;
    this.downstreamServicesMap = downstreamServicesMap;
    this.settings = settings;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;

    debugLog({
      condition: debug,
      funcName: 'OAuthProvider.constructor',
      message: `OAuthProvider is created with config: ${JSON.stringify(config)}`,
    });
  }

  /** Logs debug messages if the debug mode is enabled. */
  private localDebug(methodName: OAuthProviderMethods, message: string) {
    debugLog({ condition: this.settings.debug, funcName: `OAuthProvider.${methodName}`, message });
  }

  /** Extracts the refresh token from the cache that msal created, and removes the account from the cache. */
  private async extractRefreshTokenFromCache(msalResponse: MsalResponse): Promise<string | null> {
    const tokenCache = this.cca.getTokenCache();
    const refreshTokenMap = JSON.parse(tokenCache.serialize()).RefreshToken;
    const userRefreshTokenKey = Object.keys(refreshTokenMap).find((key) => key.startsWith(msalResponse.uniqueId));
    if (msalResponse.account) await tokenCache.removeAccount(msalResponse.account);
    return userRefreshTokenKey ? (refreshTokenMap[userRefreshTokenKey].secret as string) : null;
  }

  /** Encrypts both tokens, if accessTokenSecretKey is provided, it will assume the refresh token is obo. */
  private async encryptTokens(msalResponse: MsalResponse, accessTokenSecretKey?: KeyObject) {
    const accessTokenValue = encryptObject({ at: msalResponse.accessToken }, accessTokenSecretKey ?? this.secretKey);
    const rawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
    const refreshTokenValue = rawRefreshToken
      ? encryptObject({ rt: rawRefreshToken, isObo: !!accessTokenSecretKey }, this.secretKey)
      : null;

    this.localDebug(
      'getBothTokens',
      `access token length: ${accessTokenValue.length}, refresh token length: ${refreshTokenValue?.length}`,
    );

    if (accessTokenValue.length > 4096 || (refreshTokenValue && refreshTokenValue.length > 4096)) {
      throw new OAuthError(500, 'Token size exceeds maximum allowed length');
    }
    return { accessTokenValue, refreshTokenValue };
  }

  /**Decrypts the access token and returns its raw value.*/
  private decryptAccessToken(accessToken: string): {
    rawAccessToken: string;
    injectedData?: InjectedData;
    wasEncrypted: boolean;
  } {
    const { data: token, error: tokenError } = zJwtOrEncrypted.safeParse(accessToken);
    if (tokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    if (isJwt(token)) {
      return { rawAccessToken: token, wasEncrypted: false };
    }

    const accessTokenObj = decryptObject(token, this.secretKey);
    const { data: parsedAccessToken, error: accessTokenError } = zAccessTokenStructure.safeParse(accessTokenObj);
    if (accessTokenError) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token structure' });
    }

    return { rawAccessToken: parsedAccessToken.at, injectedData: parsedAccessToken.inj, wasEncrypted: true };
  }

  /**Decrypts the refresh token and returns its raw value and OBO status. */
  private decryptRefreshToken(refreshToken: string) {
    const { data: token, error: tokenError } = zEncrypted.safeParse(refreshToken);
    if (tokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });

    const refreshTokenObj = decryptObject(token, this.secretKey);
    const { data: parsedRefreshToken, error: refreshTokenError } = zRefreshTokenStructure.safeParse(refreshTokenObj);
    if (refreshTokenError) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token structure' });
    }

    return { rawRefreshToken: parsedRefreshToken.rt, isObo: parsedRefreshToken.isObo };
  }

  /** Retrieves and caches the public key for a given key ID (kid) from the JWKS endpoint. */
  private getPublicKey(keyId: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.jwksClient.getSigningKey(keyId, (err, key) => {
        if (err || !key) {
          reject(new Error(err?.message || 'Error retrieving signing key'));
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
  private async verifyJwt(jwtToken: string): Promise<jwt.JwtPayload> {
    try {
      const { data: parsedJwtToken, error: jwtTokenError } = zJwt.safeParse(jwtToken);
      if (jwtTokenError) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
      }
      const decodedJwt = jwt.decode(parsedJwtToken, { complete: true });
      if (!decodedJwt || !decodedJwt.header.kid) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Key ID' });
      }
      const publicKey = await this.getPublicKey(decodedJwt.header.kid);

      const fullJwt = jwt.verify(parsedJwtToken, publicKey, {
        algorithms: ['RS256'],
        audience: this.azure.clientId,
        issuer: `https://login.microsoftonline.com/${this.azure.tenantId}/v2.0`,
        complete: true,
      });

      if (typeof fullJwt.payload === 'string') {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Payload' });
      }
      this.localDebug('verifyJwt', `JWT Payload: ${JSON.stringify(fullJwt.payload)}`);

      return fullJwt.payload;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(401, {
        message: 'Unauthorized',
        description: `Check your Entra ID Portal, make sure the 'accessTokenAcceptedVersion' is set to '2' in the 'Manifest' area`,
      });
    }
  }

  /**
   * Generates an OAuth2 authorization URL with PKCE, login hints, and encrypted state.
   *
   * @param params - Optional parameters like login prompt, email hint, and custom frontend URL.
   * @returns A signed Microsoft authentication URL.
   * @throws {OAuthError} If validation fails or frontend host is not allowed.
   */
  async getAuthUrl(params: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<{
    authUrl: string;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getAuthUrl.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      throw new OAuthError(400, 'Invalid params: Email is required');
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
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
      const state = encryptObject({ frontendUrl, codeVerifier: verifier, ...params }, this.secretKey);
      this.localDebug('getAuthUrl', `Params: ${JSON.stringify({ ...params, state, frontendUrl })}`);

      const microsoftUrl = await this.cca.getAuthCodeUrl({
        ...params,
        state: state,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: challenge,
      });

      if (new URL(microsoftUrl).hostname !== 'login.microsoftonline.com') {
        throw new OAuthError(500, 'Illegitimate Microsoft Auth URL');
      }

      return { authUrl: microsoftUrl };
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error generating auth code URL', description: err as string });
    }
  }

  /**
   * Handles authorization code exchange to return encrypted tokens and redirect metadata.
   *
   * @param params - Includes the OAuth authorization `code` and encrypted `state`.
   * @returns Access token, refresh token (if available), frontend redirect URL, and raw MSAL response.
   * @throws {OAuthError} If the code or state are invalid.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'] | null;
    frontendUrl: string;
    msalResponse: MsalResponse;
  }> {
    const { data: parsedParams, error: paramsError } = zMethods.getTokenByCode.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    const { data: state, error: stateError } = zState.safeParse(decryptObject(parsedParams.state, this.secretKey));
    if (stateError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid state', description: prettifyError(stateError) });
    }

    this.localDebug('getTokenByCode', `Decrypted state: ${JSON.stringify(state)}`);

    if (!this.frontendWhitelist.has(new URL(state.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const { accessTokenValue, refreshTokenValue } = await this.encryptTokens(msalResponse);

      return {
        accessToken: { value: accessTokenValue, ...this.defaultCookieOptions.accessToken },
        refreshToken: refreshTokenValue
          ? { value: refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        frontendUrl: state.frontendUrl,
        msalResponse,
      };
    } catch (err) {
      throw new OAuthError(500, { message: 'Error getting token by code', description: err as string });
    }
  }

  /**
   * Generates a logout URL and the cookie deletion configuration.
   *
   * @param params - Optional `frontendUrl` for post-logout redirection.
   * @returns Logout URL and cookie clear options.
   * @throws {OAuthError} If the URL is not on the whitelist.
   */
  getLogoutUrl(params?: { frontendUrl?: string }): {
    logoutUrl: string;
    deleteAccessToken: Cookies['DeleteAccessToken'];
    deleteRefreshToken: Cookies['DeleteRefreshToken'];
  } {
    const { data: parsedParams, error: paramsError } = zMethods.getLogoutUrl.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
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
      this.localDebug('verifyAccessToken', 'No access token provided');
      return null;
    }

    try {
      const { rawAccessToken: jwtAccessToken, injectedData, wasEncrypted } = this.decryptAccessToken(accessToken);
      const payload = await this.verifyJwt(jwtAccessToken);

      const isB2B = payload.sub === payload.oid;

      if (isB2B && (wasEncrypted || !this.settings.acceptB2BRequests)) {
        this.localDebug('verifyAccessToken', 'B2B token cannot be encrypted');
        return null;
      }

      return { jwtAccessToken, payload, injectedData, isB2B };
    } catch (err) {
      this.localDebug('verifyAccessToken', `Error verifying token: ${err}`);
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
    msalResponse: MsalResponse;
  } | null> {
    if (!refreshToken) {
      this.localDebug('getTokenByRefresh', 'No refresh token provided');
      return null;
    }

    const { rawRefreshToken, isObo } = this.decryptRefreshToken(refreshToken);
    if (isObo) return null;

    try {
      const msalResponse = await this.cca.acquireTokenByRefreshToken({
        refreshToken: rawRefreshToken,
        scopes: this.azure.scopes,
        forceCache: true,
      });

      if (!msalResponse) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Refresh Token' });

      const payload = await this.verifyJwt(msalResponse.accessToken);
      const { accessTokenValue, refreshTokenValue } = await this.encryptTokens(msalResponse);

      return {
        jwtAccessToken: msalResponse.accessToken,
        payload,
        newAccessToken: { value: accessTokenValue, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: refreshTokenValue
          ? { value: refreshTokenValue, ...this.defaultCookieOptions.refreshToken }
          : null,
        msalResponse,
      };
    } catch (err) {
      this.localDebug('getTokenByRefresh', `Error refreshing token: ${err}`);
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
    if (!this.b2bAppsMap) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'B2B apps not configured' });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getB2BToken.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    const apps = parsedParams.appsNames.map((appName) => this.b2bAppsMap?.get(appName)).filter((client) => !!client);

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

              const clientId = getAudFromJwt(msalResponse.accessToken);
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
  async getTokenOnBehalfOf(params: { accessToken: string; serviceName: string }): Promise<GetTokenOnBehalfOfResult>;
  async getTokenOnBehalfOf(params: { accessToken: string; servicesNames: string[] }): Promise<
    GetTokenOnBehalfOfResult[]
  >;
  async getTokenOnBehalfOf(
    params: { accessToken: string; serviceName: string } | { accessToken: string; servicesNames: string[] },
  ): Promise<GetTokenOnBehalfOfResult | GetTokenOnBehalfOfResult[]> {
    if (!this.downstreamServicesMap) {
      throw new OAuthError(500, { message: 'Invalid params', description: 'On-Behalf-Of Services not configured' });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    const services = parsedParams.servicesNames
      .map((serviceName) => this.downstreamServicesMap?.get(serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    }

    this.localDebug('getTokenOnBehalfOf', `Services names: ${JSON.stringify(services)}`);

    const { rawAccessToken: jwtAccessToken } = this.decryptAccessToken(parsedParams.accessToken);

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

              const clientId = getAudFromJwt(msalResponse.accessToken);
              if (!clientId) return null;

              const accessTokenSecretKey = createSecretKey(service.secretKey);
              const { accessTokenValue, refreshTokenValue } = await this.encryptTokens(
                msalResponse,
                accessTokenSecretKey,
              );

              const cookieOptions = getCookieOptions({
                clientId,
                isHttps: service.isHttps as boolean,
                isSameSite: service.isHttps as boolean,
                cookiesTimeUnit: this.settings.cookiesTimeUnit,
                accessTokenCookieExpiry: service.accessTokenExpiry ?? this.settings.accessTokenCookieExpiry,
                refreshTokenCookieExpiry: service.refreshTokenExpiry ?? this.settings.refreshTokenCookieExpiry,
              });

              return {
                serviceName: service.serviceName,
                serviceClientId: clientId,
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

      return 'serviceName' in params ? (results[0] as GetTokenOnBehalfOfResult) : results;
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
    const { rawAccessToken: jwtAccessToken } = this.decryptAccessToken(params.accessToken);
    const { data: nextAccessToken, error: nextAccessTokenError } = zAccessTokenStructure.safeParse({
      at: jwtAccessToken,
      inj: params.data,
    });

    if (nextAccessTokenError) {
      this.localDebug('injectData', 'Invalid access token format');
      return null;
    }

    const encryptedAccessToken = encryptObject(nextAccessToken, this.secretKey);
    if (encryptedAccessToken.length > 4096) {
      this.localDebug('injectData', 'Token length exceeds 4kB');
      return null;
    }

    return { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken };
  }
}
