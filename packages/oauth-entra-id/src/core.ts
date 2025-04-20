import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import type { AuthenticationResult, ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import jwt from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { OAuthError } from './error';
import type { Azure, Cookies, LoginPrompt, MethodKeys, OAuthConfig, OnBehalfOfOptions, Options } from './types';
import { getCookieOptions } from './utils/cookies';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from './utils/crypto';
import { debugLog } from './utils/misc';
import { prettifyError, zConfig, zEncrypted, zGetAuthUrl, zGetTokenByCode, zJwt, zState, zUrl } from './utils/zod';

/**
 * ### The Core of the Package
 * OAuthProvider handles authentication with Microsoft Entra ID using OAuth 2.0.
 * It manages authentication flows, token exchange, and JWT verification.
 *
 * @class
 */
export class OAuthProvider {
  private readonly azure: Azure;
  private readonly frontendUrl: string[];
  private readonly serverCallbackUrl: string;
  private readonly secretKey: KeyObject;
  private readonly frontendHosts: string[];
  private readonly loginPrompt: LoginPrompt;
  private readonly defaultCookieOptions: Cookies['DefaultCookieOptions'];
  private readonly onBehalfOfOptions: OnBehalfOfOptions[] | undefined;
  readonly options: Options;
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
      throw new OAuthError(500, {
        message: 'Invalid OAuthProvider configuration',
        description: prettifyError(configError),
      });
    }

    const {
      azure,
      frontendUrl,
      serverCallbackUrl,
      secretKey,
      advanced: {
        loginPrompt,
        disableHttps,
        disableSameSite,
        cookieTimeFrame,
        accessTokenExpiry,
        refreshTokenExpiry,
        debug,
        onBehalfOfOptions,
      },
    } = config;

    const frontendHosts = Array.from(new Set(frontendUrl.map((frontendUrl) => new URL(frontendUrl).host)));
    const serverHost = new URL(serverCallbackUrl).host;
    const isHttps = !disableHttps && [serverHost, ...frontendHosts].every((host) => host.startsWith('https'));
    const isSameSite = !disableSameSite && frontendHosts.length === 1 ? frontendHosts[0] === serverHost : false;

    const defaultCookieOptions = getCookieOptions({
      clientId: azure.clientId,
      isHttps,
      isSameSite,
      cookieTimeFrame,
      accessTokenExpiry,
      refreshTokenExpiry,
    });

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
    this.frontendUrl = frontendUrl;
    this.serverCallbackUrl = serverCallbackUrl;
    this.secretKey = createSecretKey(secretKey);
    this.frontendHosts = frontendHosts;
    this.loginPrompt = loginPrompt;
    this.defaultCookieOptions = defaultCookieOptions;
    this.onBehalfOfOptions = onBehalfOfOptions;
    this.options = { isHttps, isSameSite, cookieTimeFrame, accessTokenExpiry, refreshTokenExpiry, debug };
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;

    debugLog({
      condition: debug,
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
   * @param options - The options for generating the authorization URL.
   * @returns The authorization URL.
   * @throws {OAuthError} If options are invalid.
   */
  async getAuthUrl(
    options: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string } = {},
  ): Promise<{ url: string }> {
    const { data: parsedOptions, error: optionsError } = zGetAuthUrl.safeParse(options);
    if (optionsError) {
      throw new OAuthError(400, {
        message: 'Invalid params',
        description: prettifyError(optionsError),
      });
    }
    if (parsedOptions.loginPrompt === 'email' && !parsedOptions.email)
      throw new OAuthError(400, 'Invalid params: Email is required');
    if (parsedOptions.frontendUrl && !this.frontendHosts.includes(new URL(parsedOptions.frontendUrl).host))
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');

    try {
      const { verifier, challenge } = await this.msalCryptoProvider.generatePkceCodes();
      const frontendUrl = parsedOptions.frontendUrl ?? (this.frontendUrl[0] as string);
      const configuredPrompt = parsedOptions.loginPrompt ?? this.loginPrompt;
      const prompt =
        parsedOptions.email || configuredPrompt === 'email'
          ? 'login'
          : configuredPrompt === 'select-account'
            ? 'select_account'
            : undefined;

      const params = { nonce: this.msalCryptoProvider.createNewGuid(), loginHint: parsedOptions.email, prompt };
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
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      throw new OAuthError(500, {
        message: 'Error generating auth code URL',
        description: error as string,
      });
    }
  }

  /**
   * Retrieves the refresh token from the cache and clears the account if it exists.
   * @param msalResponse - The MSAL authentication result.
   * @returns The refresh token or null if not found.
   */
  private async getRefreshTokenFromCache(msalResponse: msal.AuthenticationResult) {
    const tokenCache = this.cca.getTokenCache();
    const refreshTokenMap = JSON.parse(tokenCache.serialize()).RefreshToken;
    const userRefreshTokenKey = Object.keys(refreshTokenMap).find((key) => key.startsWith(msalResponse.uniqueId));
    if (msalResponse.account) await tokenCache.removeAccount(msalResponse.account);
    return userRefreshTokenKey ? (refreshTokenMap[userRefreshTokenKey].secret as string) : null;
  }

  /**
   * Exchanges an authorization code for an access token and refresh token.
   * @param options - The options (code and state) for exchanging the code.
   * @returns The access token, refresh token, frontend URL to redirect back to, and MSAL response.
   * @throws {OAuthError} If options are invalid.
   */
  async getTokenByCode(options: { code: string; state: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'] | null;
    url: string;
    msalResponse: AuthenticationResult;
  }> {
    const { data: parsedOptions, error: optionsError } = zGetTokenByCode.safeParse(options);
    if (optionsError) {
      throw new OAuthError(400, { message: 'Invalid params', description: prettifyError(optionsError) });
    }

    const { data: state, error: stateError } = zState.safeParse(decryptObject(parsedOptions.state, this.secretKey));
    if (stateError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid state', description: prettifyError(stateError) });
    }
    this.debugLog('getTokenByCode', `State is decrypted: ${JSON.stringify(state)}`);

    if (!this.frontendHosts.includes(new URL(state.frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    try {
      const msalResponse = await this.cca.acquireTokenByCode({
        code: parsedOptions.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, this.secretKey) : null;

      return {
        accessToken: { value: accessToken, ...this.defaultCookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...this.defaultCookieOptions.refreshToken } : null,
        url: state.frontendUrl,
        msalResponse,
      };
    } catch (error) {
      throw new OAuthError(500, { message: 'Error exchanging code for token', description: error as string });
    }
  }

  /**
   * Generates a logout URL for OAuth authentication.
   * @param options - The options for generating the logout URL.
   * @returns The logout URL and cookie deletion options.
   * @throws {OAuthError} If options are invalid.
   */
  getLogoutUrl(options: { frontendUrl?: string } = {}): {
    url: string;
    accessToken: Cookies['DeleteAccessToken'];
    refreshToken: Cookies['DeleteRefreshToken'];
  } {
    const { data: frontendUrl, error: urlError } = zUrl.optional().safeParse(options.frontendUrl);
    if (urlError) {
      throw new OAuthError(400, { message: 'Invalid params: Invalid URL', description: prettifyError(urlError) });
    }
    if (frontendUrl && !this.frontendHosts.includes(new URL(frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${this.azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', frontendUrl ?? (this.frontendUrl[0] as string));

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

  /**
   * Retrieves the public key for verifying JWT tokens.
   * @param keyId - The key ID from the JWT header.
   * @returns The public key.
   * @throws {Error} If the key is not found.
   */
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

  /**
   * Verifies a JWT token and returns the payload.
   * @param jwtToken - The JWT token to verify.
   * @returns The JWT payload.
   * @throws {OAuthError} If the token is invalid.
   */
  private async verifyJwt(jwtToken: string): Promise<jwt.JwtPayload> {
    try {
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
        description: `In Entra ID Portal, 'Manifest' area, the 'requestedAccessTokenVersion' must be set to '2'`,
      });
    }
  }

  /**
   * Verifies an access token and returns the Microsoft token and payload.
   * @param accessToken - An encrypted access token or JWT access token.
   * @returns The Microsoft token and JWT payload.
   * @throws {OAuthError} If the token is invalid.
   */
  async verifyAccessToken(
    accessToken: string | undefined,
  ): Promise<{ microsoftToken: string; payload: jwt.JwtPayload } | null> {
    if (!accessToken) return null;
    try {
      const { data: jwtToken, success: jwtTokenSuccess } = zJwt.safeParse(
        zEncrypted.safeParse(accessToken).success ? decrypt(accessToken, this.secretKey) : accessToken,
      );
      if (!jwtTokenSuccess) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
      const payload = await this.verifyJwt(jwtToken);
      return { microsoftToken: jwtToken, payload };
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
    const { data: encryptedToken, success: encryptedTokenSuccess } = zEncrypted.safeParse(refreshToken);
    if (!encryptedTokenSuccess)
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Refresh Token' });
    try {
      const token = decrypt(encryptedToken, this.secretKey);
      const msalResponse = await this.cca.acquireTokenByRefreshToken({
        refreshToken: token,
        scopes: this.azure.scopes,
        forceCache: true,
      });
      if (!msalResponse)
        throw new OAuthError(401, {
          message: 'Unauthorized',
          description: 'Invalid Refresh Token',
        });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const accessTokenPayload = await this.verifyJwt(msalResponse.accessToken);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, this.secretKey) : null;

      return {
        newAccessToken: { value: accessToken, ...this.defaultCookieOptions.accessToken },
        newRefreshToken: refreshToken ? { value: refreshToken, ...this.defaultCookieOptions.refreshToken } : null,
        msalResponse,
        msal: { microsoftToken: msalResponse.accessToken, payload: accessTokenPayload },
      };
    } catch (error) {
      this.debugLog('getTokenByRefresh', `Error refreshing token: ${error}`);
      return null;
    }
  }

  async getTokenOnBehalfOf(options: { accessToken: string; serviceName: string }): Promise<{
    accessToken: Cookies['AccessToken'];
    refreshToken: Cookies['RefreshToken'] | null;
    msalResponse: AuthenticationResult;
  }> {
    const behalfOfOptions = this.onBehalfOfOptions?.find((option) => option.serviceName === options.serviceName);
    if (!behalfOfOptions) throw new OAuthError(400, { message: 'Invalid params', description: 'Service not Found' });
    try {
      const { data: token, error: tokenError } = zJwt.safeParse(
        zEncrypted.safeParse(options.accessToken).success
          ? decrypt(options.accessToken, this.secretKey)
          : options.accessToken,
      );
      if (tokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });

      const msalResponse = await this.cca.acquireTokenOnBehalfOf({
        oboAssertion: token,
        scopes: behalfOfOptions.scopes,
        skipCache: false,
      });

      if (!msalResponse) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Access Token' });

      const decodedAccessToken = jwt.decode(msalResponse.accessToken, { json: true });
      if (!decodedAccessToken) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Access Token' });
      }

      const secretKey = createSecretKey(behalfOfOptions.secretKey);

      const accessToken = encrypt(msalResponse.accessToken, secretKey);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, secretKey) : null;

      const cookieOptions = getCookieOptions({
        clientId: decodedAccessToken.aud as string,
        isHttps: behalfOfOptions.isHttps,
        isSameSite: behalfOfOptions.isSameSite,
        cookieTimeFrame: this.options.cookieTimeFrame,
        accessTokenExpiry: behalfOfOptions.accessTokenExpiry ?? this.options.accessTokenExpiry,
        refreshTokenExpiry: behalfOfOptions.refreshTokenExpiry ?? this.options.refreshTokenExpiry,
      });

      return {
        accessToken: { value: accessToken, ...cookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...cookieOptions.refreshToken } : null,
        msalResponse,
      };
    } catch (error) {
      if (error instanceof OAuthError) throw error;
      throw new OAuthError(500, {
        message: 'Error exchanging code for token',
        description: error as string,
      });
    }
  }
}
