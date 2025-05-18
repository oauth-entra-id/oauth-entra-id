import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { OAuthError } from './error';
import type {
  B2BService,
  Cookies,
  GetB2BTokenResult,
  GetTokenOnBehalfOfResult,
  InjectedData,
  LoginPrompt,
  MsalResponse,
  OAuthConfig,
  OAuthProviderMethods,
  OAuthSettings,
  OnBehalfOfService,
} from './types';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from './utils/crypto';
import { getCookieOptions } from './utils/get-cookie-options';
import { debugLog, getB2BInfo, getOnBehalfOfInfo } from './utils/misc';
import { isJwt } from './utils/regex';
import {
  prettifyError,
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
  private readonly secretKey: KeyObject;
  private readonly frontendWhitelist: Set<string>;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly b2bServicesMap: Map<string, B2BService> | undefined;
  private readonly oboServicesMap: Map<string, OnBehalfOfService> | undefined;
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
      advanced: { cookies, b2b, onBehalfOf, sessionType, debug, loginPrompt },
    } = config;

    const frontHosts = new Set(frontendUrl.map((url) => new URL(url).host));
    const serverHost = new URL(serverCallbackUrl).host;
    const isHttps = !cookies.disableHttps && [serverHost, ...frontHosts].every((url) => url.startsWith('https'));
    const isSameSite = !cookies.disableSameSite && frontHosts.size === 1 ? frontHosts.has(serverHost) : false;

    const { b2bServicesMap, b2bServicesNames } = getB2BInfo(b2b.b2bServices);
    const { oboServicesMap, oboServicesNames } = getOnBehalfOfInfo(onBehalfOf);

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
      isB2BEnabled: b2b.allowB2B,
      isHttps,
      isSameSite,
      cookiesTimeUnit: cookies.timeUnit,
      accessTokenCookieExpiry: cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: cookies.refreshTokenExpiry,
      b2bServices: b2bServicesNames,
      oboServices: oboServicesNames,
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
    this.b2bServicesMap = b2bServicesMap;
    this.oboServicesMap = oboServicesMap;
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

  /**
   * Logs debug messages if the debug mode is enabled.
   *
   * @param methodName - The name of the method where the debug message is logged.
   * @param message - The debug message to log.
   */
  private localDebug(methodName: OAuthProviderMethods, message: string) {
    debugLog({ condition: this.settings.debug, funcName: `OAuthProvider.${methodName}`, message });
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
   * Extracts the refresh token from the cache that msal created, and removes the account from the cache.
   *
   * @param msalResponse - The response from MSAL after acquiring a token.
   * @returns The refresh token if found, otherwise null.
   */
  private async extractRefreshTokenFromCache(msalResponse: MsalResponse): Promise<string | null> {
    const tokenCache = this.cca.getTokenCache();
    const refreshTokenMap = JSON.parse(tokenCache.serialize()).RefreshToken;
    const userRefreshTokenKey = Object.keys(refreshTokenMap).find((key) => key.startsWith(msalResponse.uniqueId));
    if (msalResponse.account) await tokenCache.removeAccount(msalResponse.account);
    return userRefreshTokenKey ? (refreshTokenMap[userRefreshTokenKey].secret as string) : null;
  }

  /**
   * Encrypts and returns both the access and refresh tokens.
   *
   * @param msalResponse - The response from MSAL after acquiring a token.
   * @param secretKey - Override the default secret key for encryption.
   * @returns An object containing the encrypted access and refresh tokens.
   * @throws {OAuthError} If the token size exceeds 4096 bytes.
   */
  private async encryptTokens(msalResponse: MsalResponse, secretKey?: KeyObject) {
    const accessTokenValue = encryptObject({ at: msalResponse.accessToken }, secretKey ?? this.secretKey);
    const rawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
    const refreshTokenValue = rawRefreshToken ? encrypt(rawRefreshToken, secretKey ?? this.secretKey) : null;
    this.localDebug(
      'getBothTokens',
      `access token length: ${accessTokenValue.length}, refresh token length: ${refreshTokenValue?.length}`,
    );
    if (accessTokenValue.length > 4096 || (refreshTokenValue && refreshTokenValue.length > 4096)) {
      throw new OAuthError(500, 'Token size exceeds maximum allowed length');
    }
    return { accessTokenValue, refreshTokenValue };
  }

  /**
   * Decrypts the access token and returns its raw value.
   *
   * @param accessToken - The encrypted or raw access token.
   * @returns An object containing the access token in JWT format, injected data (if any), and whether it was encrypted.
   */
  private decryptAccessToken(accessToken: string): {
    jwtAccessToken: string;
    injectedData?: InjectedData;
    wasEncrypted: boolean;
  } {
    const { data: token, error: tokenError } = zJwtOrEncrypted.safeParse(accessToken);
    if (tokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    if (isJwt(token)) {
      return { jwtAccessToken: token, wasEncrypted: false };
    }

    const accessTokenObj = decryptObject(token, this.secretKey);
    const { data: parsedAccessToken, error: accessTokenError } = zAccessTokenStructure.safeParse(accessTokenObj);
    if (accessTokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    return { jwtAccessToken: parsedAccessToken.at, injectedData: parsedAccessToken.inj, wasEncrypted: true };
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
   * Retrieves and caches the public key for a given key ID (kid) from the JWKS endpoint.
   *
   * @param keyId - The key ID (kid) from the JWT header.
   * @returns The public key in a PEM format.
   */

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

  /**
   * Verifies the JWT token and returns its payload.
   *
   * @param jwtToken - The JWT token to verify.
   * @returns The decoded JWT payload.
   * @throws {OAuthError} If the token is invalid or verification fails.
   */
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
      const { jwtAccessToken, injectedData, wasEncrypted } = this.decryptAccessToken(accessToken);
      const payload = await this.verifyJwt(jwtAccessToken);

      const isB2B = payload.sub === payload.oid;
      if (isB2B && (wasEncrypted || !this.settings.isB2BEnabled)) {
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
   * Injects data into the access token
   * Useful for embedding non-sensitive metadata into token structure.
   *
   * @param params - The parameters containing the access token value and data to inject.
   * @returns The new access token cookie with injected data, or null if the token is invalid.
   */
  injectData<TValues, TData extends Record<string, TValues>>(params: { accessToken: string; data: TData }):
    | Cookies['AccessToken']
    | null {
    const { jwtAccessToken } = this.decryptAccessToken(params.accessToken);
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

    const { data: parsedRefreshToken, error: refreshTokenError } = zEncrypted.safeParse(refreshToken);
    if (refreshTokenError) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Refresh Token' });
    }
    const rawRefreshToken = decrypt(parsedRefreshToken, this.secretKey);
    if (!rawRefreshToken) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Refresh Token' });
    }
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
   * Acquires tokens for B2B services using client credentials.
   * @param params - The parameters containing the B2B service name(s).
   * @returns The B2B access token and MSAL response for the specified service(s).
   * @throws {OAuthError} If the B2B services are not configured or if the token is invalid.
   */
  async getB2BToken(params: { b2bServiceName: string }): Promise<GetB2BTokenResult>;
  async getB2BToken(params: { b2bServiceNames: string[] }): Promise<GetB2BTokenResult[]>;
  async getB2BToken(
    params: { b2bServiceName: string } | { b2bServiceNames: string[] },
  ): Promise<GetB2BTokenResult | GetB2BTokenResult[]> {
    if (!this.b2bServicesMap)
      throw new OAuthError(400, { message: 'Invalid params', description: 'B2B Services not configured' });

    const { data: parsedParams, error: paramsError } = zMethods.getB2BToken.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    const services = parsedParams.b2bServiceNames
      .map((serviceName) => this.b2bServicesMap?.get(serviceName))
      .filter((service) => !!service);

    if (!services) throw new OAuthError(400, { message: 'Invalid params', description: 'Service not found' });

    try {
      const results = (
        await Promise.all(
          services.map(async (service) => {
            try {
              const msalResponse = await this.cca.acquireTokenByClientCredential({
                scopes: [service.b2bScope],
                skipCache: true,
              });
              if (!msalResponse) return null;
              return {
                b2bServiceName: service.b2bServiceName,
                b2bAccessToken: msalResponse.accessToken,
                b2bMsalResponse: msalResponse,
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

      return 'b2bServiceName' in params ? (results[0] as GetB2BTokenResult) : results;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error getting token on behalf of', description: err as string });
    }
  }

  /**
   * Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.
   *
   * @param params - The parameters containing the access token and service name(s).
   * @returns The OBO access token and MSAL response for the specified service(s).
   * @throws {OAuthError} If the OBO services are not configured or if the token is invalid.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; oboServiceName: string }): Promise<GetTokenOnBehalfOfResult>;
  async getTokenOnBehalfOf(params: { accessToken: string; oboServiceNames: string[] }): Promise<
    GetTokenOnBehalfOfResult[]
  >;
  async getTokenOnBehalfOf(
    params: { accessToken: string; oboServiceName: string } | { accessToken: string; oboServiceNames: string[] },
  ): Promise<GetTokenOnBehalfOfResult | GetTokenOnBehalfOfResult[]> {
    if (!this.oboServicesMap) {
      throw new OAuthError(500, { message: 'Invalid params', description: 'On-Behalf-Of Services not configured' });
    }

    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });

    const services = parsedParams.oboServiceNames
      .map((serviceName) => this.oboServicesMap?.get(serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    }
    this.localDebug('getTokenOnBehalfOf', `Services names: ${JSON.stringify(services)}`);

    const rawAccessToken = isJwt(parsedParams.accessToken)
      ? parsedParams.accessToken
      : decrypt(parsedParams.accessToken, this.secretKey);

    if (!rawAccessToken) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });

    try {
      const results = (
        await Promise.all(
          services.map(async (service) => {
            try {
              const msalResponse = await this.cca.acquireTokenOnBehalfOf({
                oboAssertion: rawAccessToken,
                scopes: [service.oboScope],
                skipCache: false,
              });
              if (!msalResponse) return null;

              const decodedAccessToken = jwt.decode(msalResponse.accessToken, { json: true });
              if (!decodedAccessToken) return null;

              const aud = decodedAccessToken.aud;
              if (typeof aud !== 'string') return null;

              this.localDebug('getTokenOnBehalfOf', `Service: ${service.oboServiceName}, Audience: ${aud}`);

              const secretKey = createSecretKey(service.secretKey);
              const { accessTokenValue, refreshTokenValue } = await this.encryptTokens(msalResponse, secretKey);

              const cookieOptions = getCookieOptions({
                clientId: aud,
                isHttps: service.isHttps as boolean,
                isSameSite: service.isSameSite as boolean,
                cookiesTimeUnit: this.settings.cookiesTimeUnit,
                accessTokenCookieExpiry: service.accessTokenExpiry ?? this.settings.accessTokenCookieExpiry,
                refreshTokenCookieExpiry: service.refreshTokenExpiry ?? this.settings.refreshTokenCookieExpiry,
              });

              return {
                oboServiceName: service.oboServiceName,
                oboAccessToken: { value: accessTokenValue, ...cookieOptions.accessToken },
                oboRefreshToken: refreshTokenValue ? { value: refreshTokenValue, ...cookieOptions.refreshToken } : null,
                oboMsalResponse: msalResponse,
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

      return 'oboServiceName' in params ? (results[0] as GetTokenOnBehalfOfResult) : results;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error getting token on behalf of', description: err as string });
    }
  }
}
