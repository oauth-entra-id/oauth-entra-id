import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import type { AuthenticationResult, ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { OAuthError } from './error';
import type { Azure, Cookies, LoginPrompt, MethodKeys, OAuthConfig, OAuthOptions, OnBehalfOfService } from './types';
import { getCookieOptions } from './utils/cookies';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from './utils/crypto';
import { debugLog } from './utils/misc';
import {
  isJwt,
  prettifyError,
  zConfig,
  zEncrypted,
  zGetAuthUrl,
  zGetLogoutUrl,
  zGetTokenByCode,
  zGetTokenOnBehalfOf,
  zJwt,
  zState,
  zToken,
} from './utils/zod';

// TODO: add type safety for Frontend URLs and Service Names
// TODO: add Array.from(new Set()) to remove duplicates from frontendUrl
// TODO: add better try catch to the map of getTokenOnBehalfOf
// TODO: add platforms and checks within the method itself
// TODO: replace cookie-parser with a custom cookie parser to avoid dependency

/**
 * ### The Core of the Package
 * OAuthProvider handles authentication with Microsoft Entra ID using OAuth 2.0.
 * It manages authentication flows, token exchange, and JWT verification.
 *
 * @class
 */
export class OAuthProvider {
  private readonly azure: Azure;
  private readonly frontendUrl: [string, ...string[]];
  private readonly serverCallbackUrl: string;
  private readonly secretKey: KeyObject;
  private readonly frontendWhitelist: string[];
  private readonly loginPrompt: LoginPrompt;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly onBehalfOfServices: OnBehalfOfService[] | undefined;
  readonly options: OAuthOptions;
  private readonly cca: ConfidentialClientApplication;
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: jwks.JwksClient;

  /**
   * Creates an instance of OAuthProvider.
   * @param configuration - The OAuth configuration object.
   * @throws {OAuthError} If the configuration is invalid.
   */
  constructor(configuration: OAuthConfig) {
    const { data: config, error: configError } = zConfig.safeParse(configuration);

    if (configError) {
      throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: prettifyError(configError) });
    }

    const { azure, frontendUrl, serverCallbackUrl, secretKey, advanced } = config;

    const frontHosts = Array.from(new Set(frontendUrl.map((url) => new URL(url).host)));
    const serverHost = new URL(serverCallbackUrl).host;
    const isHttps = !advanced.disableHttps && [serverHost, ...frontHosts].every((host) => host.startsWith('https'));
    const isSameSite = !advanced.disableSameSite && frontHosts.length === 1 ? frontHosts[0] === serverHost : false;
    const serviceNames = advanced.onBehalfOfServices
      ? Array.from(new Set(advanced.onBehalfOfServices.map((service) => service.serviceName)))
      : undefined;

    if (serviceNames && advanced.onBehalfOfServices && serviceNames.length !== advanced.onBehalfOfServices.length) {
      throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
    }

    const defaultCookieOptions = getCookieOptions({
      clientId: azure.clientId,
      isHttps,
      isSameSite,
      cookieTimeFrame: advanced.cookieTimeFrame,
      accessTokenCookieExpiry: advanced.accessTokenCookieExpiry,
      refreshTokenCookieExpiry: advanced.refreshTokenCookieExpiry,
    });

    const options = {
      isHttps,
      isSameSite,
      cookieTimeFrame: advanced.cookieTimeFrame,
      accessTokenCookieExpiry: advanced.accessTokenCookieExpiry,
      refreshTokenCookieExpiry: advanced.refreshTokenCookieExpiry,
      serviceNames,
      debug: advanced.debug,
    } as const;

    const cca = new msal.ConfidentialClientApplication({
      auth: {
        clientId: azure.clientId,
        authority: `https://login.microsoftonline.com/${azure.tenantId}`,
        clientSecret: azure.secret,
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
    this.frontendUrl = frontendUrl as [string, ...string[]];
    this.serverCallbackUrl = serverCallbackUrl;
    this.secretKey = createSecretKey(secretKey);
    this.frontendWhitelist = frontHosts;
    this.loginPrompt = advanced.loginPrompt;
    this.defaultCookieOptions = defaultCookieOptions;
    this.onBehalfOfServices = advanced.onBehalfOfServices;
    this.options = options;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;

    debugLog({
      condition: advanced.debug,
      funcName: 'OAuthProvider.constructor',
      message: `OAuthProvider is created with config: ${JSON.stringify(config)}`,
    });
  }

  private debugLog(methodName: MethodKeys<OAuthProvider> | 'verifyJwt', message: string) {
    debugLog({ condition: this.options.debug, funcName: `OAuthProvider.${methodName}`, message });
  }

  /**
   * Returns the names of the access and refresh token cookies.
   * @returns The cookie names.
   */
  getCookieNames() {
    return {
      accessTokenName: this.defaultCookieOptions.accessToken.name,
      refreshTokenName: this.defaultCookieOptions.refreshToken.name,
    } as const;
  }

  /**
   * Generates an authorization URL for OAuth authentication.
   * @param params - The options for generating the authorization URL.
   * @returns The authorization URL.
   * @throws {OAuthError} If options are invalid.
   */
  async getAuthUrl(params: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string }): Promise<{
    url: string;
  }> {
    const { data: parsedParams, error: paramsError } = zGetAuthUrl.safeParse(params);
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }
    if (parsedParams.loginPrompt === 'email' && !parsedParams.email) {
      throw new OAuthError(400, 'Invalid params: Email is required');
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.includes(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    try {
      const { verifier, challenge } = await this.msalCryptoProvider.generatePkceCodes();
      const frontendUrl = parsedParams.frontendUrl ?? this.frontendUrl[0];
      const configuredPrompt = parsedParams.loginPrompt ?? this.loginPrompt;
      const prompt =
        parsedParams.email || configuredPrompt === 'email'
          ? 'login'
          : configuredPrompt === 'select-account'
            ? 'select_account'
            : undefined;

      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedParams.email, prompt };
      const state = encryptObject({ frontendUrl, codeVerifier: verifier, ...params }, this.secretKey);
      this.debugLog('getAuthUrl', `Params: ${JSON.stringify({ ...params, state, frontendUrl })}`);

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

      return { url: microsoftUrl };
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(500, {
        message: 'Error generating auth code URL',
        description: err as string,
      });
    }
  }

  private async extractRefreshTokenFromCache(msalResponse: msal.AuthenticationResult) {
    const tokenCache = this.cca.getTokenCache();
    const refreshTokenMap = JSON.parse(tokenCache.serialize()).RefreshToken;
    const userRefreshTokenKey = Object.keys(refreshTokenMap).find((key) => key.startsWith(msalResponse.uniqueId));
    if (msalResponse.account) await tokenCache.removeAccount(msalResponse.account);
    return userRefreshTokenKey ? (refreshTokenMap[userRefreshTokenKey].secret as string) : null;
  }

  /**
   * Exchanges an authorization code for an access token and refresh token.
   * @param params - The options (code and state) for exchanging the code.
   * @returns The access token, refresh token, frontend URL to redirect back to, and MSAL response.
   * @throws {OAuthError} If options are invalid.
   */
  async getTokenByCode(params: { code: string; state: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'] | null;
    url: string;
    msalResponse: AuthenticationResult;
  }> {
    const { data: parsedParams, error: paramsError } = zGetTokenByCode.safeParse(params);
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }

    const { data: state, error: stateError } = zState.safeParse(decryptObject(parsedParams.state, this.secretKey));
    if (stateError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid state', description: prettifyError(stateError) });
    }
    this.debugLog('getTokenByCode', `State is decrypted: ${JSON.stringify(state)}`);

    if (!this.frontendWhitelist.includes(new URL(state.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
        code: parsedParams.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const rawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
      const refreshToken = rawRefreshToken ? encrypt(rawRefreshToken, this.secretKey) : null;

      return {
        accessToken: { value: accessToken, ...this.defaultCookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...this.defaultCookieOptions.refreshToken } : null,
        url: state.frontendUrl,
        msalResponse,
      };
    } catch (err) {
      throw new OAuthError(500, { message: 'Error getting token by code', description: err as string });
    }
  }

  /**
   * Generates a logout URL for OAuth authentication.
   * @param params - The options for generating the logout URL.
   * @returns The logout URL and cookie deletion options.
   * @throws {OAuthError} If options are invalid.
   */
  getLogoutUrl(params?: { frontendUrl?: string }): {
    url: string;
    accessToken: Cookies['DeleteAccessToken'];
    refreshToken: Cookies['DeleteRefreshToken'];
  } {
    const { data: parsedParams, error: urlError } = zGetLogoutUrl.safeParse(params);
    if (urlError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid URL', description: prettifyError(urlError) });
    }
    if (parsedParams.frontendUrl && !this.frontendWhitelist.includes(new URL(parsedParams.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${this.azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', parsedParams.frontendUrl ?? this.frontendUrl[0]);

    return {
      url: logoutUrl.toString(),
      accessToken: {
        name: this.defaultCookieOptions.accessToken.name,
        value: '',
        options: this.defaultCookieOptions.deleteOptions,
      },
      refreshToken: {
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
      this.debugLog('verifyJwt', `JWT Payload: ${JSON.stringify(fullJwt.payload)}`);

      return fullJwt.payload;
    } catch (err) {
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(401, {
        message: 'Unauthorized',
        description: `In Entra ID Portal, 'Manifest' area, the 'accessTokenAcceptedVersion' must be set to '2'`,
      });
    }
  }

  /**
   * Verifies an access token and returns the Microsoft token and payload.
   * @param accessToken - An encrypted access token or JWT access token.
   * @returns The Microsoft token and JWT payload.
   * @throws {OAuthError} If the token is invalid.
   */
  async verifyAccessToken(accessToken: string): Promise<{ microsoftToken: string; payload: jwt.JwtPayload } | null> {
    try {
      const { data: token, error: tokenError } = zToken.safeParse(accessToken);
      if (tokenError) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
      }
      const rawAccessToken = isJwt(token) ? token : decrypt(token, this.secretKey);
      if (!rawAccessToken) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
      }
      const payload = await this.verifyJwt(rawAccessToken);
      return { microsoftToken: rawAccessToken, payload };
    } catch (err) {
      this.debugLog('verifyAccessToken', `Error verifying token: ${err}`);
      return null;
    }
  }

  /**
   * Refreshes an access token using a refresh token.
   * @param refreshToken - The encrypted refresh token.
   * @returns The new access token, refresh token, original JWT with its payload, and MSAL response.
   * @throws {OAuthError} If the refresh token is invalid.
   */
  async getTokenByRefresh(refreshToken: string): Promise<{
    newAccessToken: Cookies['AccessToken'];
    newRefreshToken: Cookies['RefreshToken'] | null;
    msalResponse: AuthenticationResult;
    msal: { microsoftToken: string; payload: jwt.JwtPayload };
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

      const newAccessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const newAccessTokenPayload = await this.verifyJwt(msalResponse.accessToken);
      const newRawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
      const newRefreshToken = newRawRefreshToken ? encrypt(newRawRefreshToken, this.secretKey) : null;

      return {
        newAccessToken: { value: newAccessToken, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: newRefreshToken ? { value: newRefreshToken, ...this.defaultCookieOptions.refreshToken } : null,
        msalResponse,
        msal: { microsoftToken: msalResponse.accessToken, payload: newAccessTokenPayload },
      };
    } catch (err) {
      this.debugLog('getTokenByRefresh', `Error refreshing token: ${err}`);
      return null;
    }
  }

  async getTokenOnBehalfOf(params: { accessToken: string; serviceNames: string[] }): Promise<
    {
      accessToken: Cookies['AccessToken'];
      refreshToken: Cookies['RefreshToken'] | null;
      msalResponse: AuthenticationResult;
    }[]
  > {
    if (!this.onBehalfOfServices) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'On Behalf Of Services not configured' });
    }
    const { data: parsedParams, error: paramsError } = zGetTokenOnBehalfOf.safeParse(params);
    if (paramsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(paramsError) });
    }

    const services = parsedParams.serviceNames
      .map((serviceName) => this.onBehalfOfServices?.find((configService) => configService.serviceName === serviceName))
      .filter((service) => !!service);

    if (!services || services.length === 0) {
      throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    }
    this.debugLog('getTokenOnBehalfOf', `Services names: ${JSON.stringify(services)}`);

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

              this.debugLog('getTokenOnBehalfOf', `Service: ${service.serviceName}, Audience: ${aud}`);

              const secretKey = createSecretKey(service.secretKey);

              const accessToken = encrypt(msalResponse.accessToken, secretKey);
              const rawRefreshToken = await this.extractRefreshTokenFromCache(msalResponse);
              const refreshToken = rawRefreshToken ? encrypt(rawRefreshToken, secretKey) : null;

              const cookieOptions = getCookieOptions({
                clientId: aud,
                isHttps: service.isHttps,
                isSameSite: service.isSameSite,
                cookieTimeFrame: this.options.cookieTimeFrame,
                accessTokenCookieExpiry: service.accessTokenExpiry ?? this.options.accessTokenCookieExpiry,
                refreshTokenCookieExpiry: service.refreshTokenExpiry ?? this.options.refreshTokenCookieExpiry,
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
