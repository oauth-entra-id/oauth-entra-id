import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { OAuthError } from './error';
import type {
  Cookies,
  InjectedData,
  LoginPrompt,
  MsalResponse,
  OAuthConfig,
  OAuthProviderMethods,
  OAuthSettings,
  OnBehalfOfService,
} from './types';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from './utils/crypto';
import { debugLog } from './utils/debugLog';
import { getCookieOptions } from './utils/get-cookie-options';
import { isJwt } from './utils/regex';
import {
  prettifyError,
  zAccessTokenStructure,
  zConfig,
  zEncrypted,
  zJwt,
  zJwtOrEncrypted,
  zMethods,
  zScope,
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
  private readonly loginPrompt: LoginPrompt;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly onBehalfOfServices: Map<string, OnBehalfOfService> | undefined;
  readonly settings: OAuthSettings;
  private readonly cca: msal.ConfidentialClientApplication;
  private readonly msalCryptoProvider: msal.CryptoProvider;
  private readonly jwksClient: jwks.JwksClient;

  /**
   * Creates a new OAuthProvider instance.
   *
   * @param configuration - The full OAuth configuration including Azure client credentials, frontend redirect URIs, server callback URL, secret keys, and advanced options.
   *
   * @throws {OAuthError} If the configuration is invalid or contains duplicate service definitions.
   */
  constructor(configuration: OAuthConfig) {
    const { data: config, error: configError } = zConfig.safeParse(configuration);

    if (configError) {
      throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: prettifyError(configError) });
    }

    const { azure, frontendUrl, serverCallbackUrl, secretKey, advanced } = config;

    const frontHosts = new Set(frontendUrl.map((url) => new URL(url).host));
    const serverHost = new URL(serverCallbackUrl).host;
    const isHttps =
      !advanced.cookies.disableHttps && [serverHost, ...frontHosts].every((url) => url.startsWith('https'));
    const isSameSite = !advanced.cookies.disableSameSite && frontHosts.size === 1 ? frontHosts.has(serverHost) : false;
    const onBehalfOfServices = advanced.onBehalfOf
      ? new Map(
          advanced.onBehalfOf.services.map((service) => [
            service.serviceName,
            {
              ...service,
              isHttps: service.isHttps ?? (advanced.onBehalfOf?.isHttps as boolean),
              isSameSite: service.isSameSite ?? (advanced.onBehalfOf?.isSameSite as boolean),
            },
          ]),
        )
      : undefined;
    const serviceNames = onBehalfOfServices ? Array.from(onBehalfOfServices.keys()) : undefined;

    if (serviceNames && advanced.onBehalfOf && serviceNames.length !== advanced.onBehalfOf.services.length) {
      throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
    }

    const defaultCookieOptions = getCookieOptions({
      clientId: azure.clientId,
      isHttps,
      isSameSite,
      cookiesTimeUnit: advanced.cookies.timeUnit,
      accessTokenCookieExpiry: advanced.cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: advanced.cookies.refreshTokenExpiry,
    });

    const settings = {
      sessionType: advanced.sessionType,
      isB2BEnabled: advanced.allowB2B,
      isHttps,
      isSameSite,
      cookiesTimeUnit: advanced.cookies.timeUnit,
      accessTokenCookieExpiry: advanced.cookies.accessTokenExpiry,
      refreshTokenCookieExpiry: advanced.cookies.refreshTokenExpiry,
      serviceNames,
      debug: advanced.debug,
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
    this.secretKey = createSecretKey(secretKey);
    this.frontendWhitelist = frontHosts;
    this.loginPrompt = advanced.loginPrompt;
    this.defaultCookieOptions = defaultCookieOptions;
    this.onBehalfOfServices = onBehalfOfServices;
    this.settings = settings;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;

    debugLog({
      condition: advanced.debug,
      funcName: 'OAuthProvider.constructor',
      message: `OAuthProvider is created with config: ${JSON.stringify(config)}`,
    });
  }

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
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }
    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      throw new OAuthError(400, 'Invalid params: Email is required');
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.has(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    try {
      const { verifier, challenge } = await this.msalCryptoProvider.generatePkceCodes();
      const frontendUrl = parsedParams.frontendUrl ?? this.frontendUrls[0];
      const configuredPrompt = parsedParams.loginPrompt ?? this.loginPrompt;
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
      throw new OAuthError(500, {
        message: 'Error generating auth code URL',
        description: err as string,
      });
    }
  }

  private async extractRefreshTokenFromCache(msalResponse: MsalResponse) {
    const tokenCache = this.cca.getTokenCache();
    const refreshTokenMap = JSON.parse(tokenCache.serialize()).RefreshToken;
    const userRefreshTokenKey = Object.keys(refreshTokenMap).find((key) => key.startsWith(msalResponse.uniqueId));
    if (msalResponse.account) await tokenCache.removeAccount(msalResponse.account);
    return userRefreshTokenKey ? (refreshTokenMap[userRefreshTokenKey].secret as string) : null;
  }

  private async getTokens(msalResponse: MsalResponse, secretKey?: KeyObject) {
    const accessToken = encryptObject({ at: msalResponse.accessToken }, secretKey ?? this.secretKey);
    const rawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
    const refreshToken = rawRefreshToken ? encrypt(rawRefreshToken, secretKey ?? this.secretKey) : null;
    if (accessToken.length > 4096 || (refreshToken && refreshToken.length > 4096)) {
      throw new OAuthError(500, {
        message: 'Internal server error',
        description: 'Token size exceeds maximum allowed length',
      });
    }
    return { accessToken, refreshToken };
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
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }

    const { data: state, error: stateError } = zState.safeParse(decryptObject(parsedParams.state, this.secretKey));
    if (stateError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid state', description: prettifyError(stateError) });
    }
    this.localDebug('getTokenByCode', `State is decrypted: ${JSON.stringify(state)}`);

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

      const { accessToken, refreshToken } = await this.getTokens(msalResponse);

      return {
        accessToken: { value: accessToken, ...this.defaultCookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...this.defaultCookieOptions.refreshToken } : null,
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
    const { data: parsedParams, error: urlError } = zMethods.getLogoutUrl.safeParse(params);
    if (urlError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid URL', description: prettifyError(urlError) });
    }
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

  private getSigningKey(keyId: string): Promise<string> {
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

  private async verifyJwt(token: string): Promise<jwt.JwtPayload> {
    try {
      const { data: jwtToken, error: jwtTokenError } = zJwt.safeParse(token);
      if (jwtTokenError) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
      }
      const decodedJwt = jwt.decode(jwtToken, { complete: true });
      if (!decodedJwt || !decodedJwt.header.kid) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Key ID' });
      }
      const publicKey = await this.getSigningKey(decodedJwt.header.kid);

      const fullJwt = jwt.verify(jwtToken, publicKey, {
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
        description: `In Entra ID Portal, 'Manifest' area, the 'accessTokenAcceptedVersion' must be set to '2'`,
      });
    }
  }

  private getRawAccessToken(accessToken: string): {
    rawAccessToken: string;
    injectedData?: InjectedData;
    wasEncrypted: boolean;
  } {
    const { data: token, error: tokenError } = zJwtOrEncrypted.safeParse(accessToken);
    if (tokenError) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    if (isJwt(token)) {
      return { rawAccessToken: token, wasEncrypted: false };
    }

    const accessTokenObj = decryptObject(token, this.secretKey);
    const { data: parsedAccessToken, error: accessTokenError } = zAccessTokenStructure.safeParse(accessTokenObj);
    if (accessTokenError) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    return { rawAccessToken: parsedAccessToken.at, injectedData: parsedAccessToken.inj, wasEncrypted: true };
  }

  /**
   * Verifies an access token, either as a raw JWT or encrypted string.
   *
   * @param accessToken - A JWT or encrypted access token.
   * @returns The original token and decoded payload if valid; `null` otherwise. If the token has injected data, it will be returned as well.
   */
  async verifyAccessToken(accessToken: string): Promise<{
    microsoftInfo: {
      rawAccessToken: string;
      accessTokenPayload: jwt.JwtPayload;
    };
    injectedData: InjectedData | undefined;
    isB2B: boolean;
  } | null> {
    try {
      const { rawAccessToken, injectedData, wasEncrypted } = this.getRawAccessToken(accessToken);
      const accessTokenPayload = await this.verifyJwt(rawAccessToken);

      const isB2B = accessTokenPayload.sub === accessTokenPayload.oid;
      if (isB2B && (wasEncrypted || !this.settings.isB2BEnabled)) {
        this.localDebug('verifyAccessToken', 'B2B token cannot be encrypted');
        return null;
      }

      if (!isB2B && !wasEncrypted) {
        this.localDebug('verifyAccessToken', 'Non-B2B token cannot be raw JWT');
        return null;
      }

      return { microsoftInfo: { rawAccessToken, accessTokenPayload }, injectedData, isB2B };
    } catch (err) {
      this.localDebug('verifyAccessToken', `Error verifying token: ${err}`);
      return null;
    }
  }

  injectData<TValues, TData extends Record<string, TValues>>({
    accessToken,
    data,
  }: { accessToken: string; data: TData }): { newAccessToken: Cookies['AccessToken'] } | null {
    const { rawAccessToken, injectedData, wasEncrypted } = this.getRawAccessToken(accessToken);
    const { data: nextAccessToken, error: nextAccessTokenError } = zAccessTokenStructure.safeParse({
      at: rawAccessToken,
      inj: data,
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

    return { newAccessToken: { value: encryptedAccessToken, ...this.defaultCookieOptions.accessToken } };
  }

  /**
   * Rotates tokens using a previously stored refresh token.
   *
   * @param refreshToken - Encrypted refresh token.
   * @returns New access and refresh token cookies, raw MSAL response, and payload.
   * @throws {OAuthError} If the refresh token is invalid or decryption fails.
   */
  async getTokenByRefresh(refreshToken: string): Promise<{
    newAccessToken: Cookies['AccessToken'];
    newRefreshToken: Cookies['RefreshToken'] | null;
    msalResponse: MsalResponse;
    microsoftInfo: { rawAccessToken: string; accessTokenPayload: jwt.JwtPayload };
  } | null> {
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
      if (!msalResponse)
        throw new OAuthError(401, {
          message: 'Unauthorized',
          description: 'Invalid Refresh Token',
        });

      const accessTokenPayload = await this.verifyJwt(msalResponse.accessToken);
      const { accessToken, refreshToken } = await this.getTokens(msalResponse);

      return {
        newAccessToken: { value: accessToken, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: refreshToken ? { value: refreshToken, ...this.defaultCookieOptions.refreshToken } : null,
        msalResponse,
        microsoftInfo: { rawAccessToken: msalResponse.accessToken, accessTokenPayload },
      };
    } catch (err) {
      this.localDebug('getTokenByRefresh', `Error refreshing token: ${err}`);
      return null;
    }
  }

  async getB2BToken(scope: string): Promise<{ b2bAccessToken: string; msalResponse: MsalResponse }> {
    const { data: parsedScope, error: scopeError } = zScope.safeParse(scope);
    if (scopeError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(scopeError) });
    }

    const msalResponse = await this.cca.acquireTokenByClientCredential({ scopes: [parsedScope], skipCache: true });
    if (!msalResponse) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid B2B Token' });
    }

    //TODO: remove or use the cache that MSAL creates
    return { b2bAccessToken: msalResponse.accessToken, msalResponse };
  }

  /**
   * Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.
   *
   * @param params - Includes original access token and array of service names to act on behalf of.
   * @returns Token pairs (access/refresh) and MSAL metadata for each target service.
   * @throws {OAuthError} If configuration or token validation fails.
   */
  async getTokenOnBehalfOf(params: { accessToken: string; serviceNames: string[] }): Promise<
    Array<{
      accessToken: Cookies['AccessToken'];
      refreshToken: Cookies['RefreshToken'] | null;
      msalResponse: MsalResponse;
    }>
  > {
    if (!this.onBehalfOfServices) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'On Behalf Of Services not configured' });
    }
    const { data: parsedParams, error: paramsError } = zMethods.getTokenOnBehalfOf.safeParse(params);
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }

    const services = parsedParams.serviceNames
      .map((serviceName) => this.onBehalfOfServices?.get(serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    }
    this.localDebug('getTokenOnBehalfOf', `Services names: ${JSON.stringify(services)}`);

    const rawAccessToken = isJwt(parsedParams.accessToken)
      ? parsedParams.accessToken
      : decrypt(parsedParams.accessToken, this.secretKey);

    if (!rawAccessToken) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
    }

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

              const decodedAccessToken = jwt.decode(msalResponse.accessToken, { json: true });
              if (!decodedAccessToken) return null;

              const aud = decodedAccessToken.aud;
              if (typeof aud !== 'string') return null;

              this.localDebug('getTokenOnBehalfOf', `Service: ${service.serviceName}, Audience: ${aud}`);

              const secretKey = createSecretKey(service.secretKey);
              const { accessToken, refreshToken } = await this.getTokens(msalResponse, secretKey);

              const cookieOptions = getCookieOptions({
                clientId: aud,
                isHttps: service.isHttps as boolean,
                isSameSite: service.isSameSite as boolean,
                cookiesTimeUnit: this.settings.cookiesTimeUnit,
                accessTokenCookieExpiry: service.accessTokenExpiry ?? this.settings.accessTokenCookieExpiry,
                refreshTokenCookieExpiry: service.refreshTokenExpiry ?? this.settings.refreshTokenCookieExpiry,
              });

              return {
                accessToken: { value: accessToken, ...cookieOptions.accessToken },
                refreshToken: refreshToken ? { value: refreshToken, ...cookieOptions.refreshToken } : null,
                msalResponse,
              };
            } catch {
              return null;
            }
          }),
        )
      ).filter((response) => !!response);

      if (!results || results.length === 0) {
        throw new OAuthError(500, { message: 'Internal server error', description: 'Failed to get token' });
      }

      return results;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, { message: 'Error getting token on behalf of', description: err as string });
    }
  }
}
