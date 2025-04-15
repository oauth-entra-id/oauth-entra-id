import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import type { AuthenticationResult, ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import jwks, { type JwksClient } from 'jwks-rsa';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from '~/core/crypto';
import { zConfig, zEncrypted, zGetAuthUrl, zGetTokenByCode, zJwt, zState, zUrl } from '~/core/zod';
import { OAuthError } from './OAuthError';

const ACCESS_TOKEN_NAME = 'AccessToken' as const;
const REFRESH_TOKEN_NAME = 'RefreshToken' as const;

type LoginPrompt = 'email' | 'select-account' | 'sso';

export interface OAuthConfig {
  azure: { clientId: string; tenantId: string; scopes: string[]; secret: string };
  frontendUrl: string | string[];
  serverCallbackUrl: string;
  secretKey: string;
  advanced?: {
    loginPrompt?: LoginPrompt;
    cookieTimeFrame?: 'ms' | 'sec';
    refreshTokenExpiry?: number; // in seconds
    debug?: boolean;
  };
}

/**
 * ### The Core of the Package
 * OAuthProvider handles authentication with Microsoft Entra ID using OAuth 2.0.
 * It manages authentication flows, token exchange, and JWT verification.
 *
 * @class
 */
export class OAuthProvider {
  private readonly azure: OAuthConfig['azure'];
  private readonly frontendUrl: string[];
  private readonly serverCallbackUrl: string;
  private readonly secretKey: KeyObject;
  private readonly frontendHosts: string[];
  private readonly isHttps: boolean;
  private readonly isCrossOrigin: boolean;
  private readonly loginPrompt: LoginPrompt;
  private readonly cookieTimeFrame: 'ms' | 'sec';
  private readonly refreshTokenExpiry: number;
  readonly debug: boolean;
  private readonly cca: ConfidentialClientApplication;
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: JwksClient;

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
        description: configError.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', '),
      });
    }

    const frontendHosts = config.frontendUrl.map((url) => new URL(url).host);
    const serverHost = new URL(config.serverCallbackUrl).host;
    const isHttps =
      config.serverCallbackUrl.startsWith('https') && config.frontendUrl.every((url) => url.startsWith('https'));
    const isCrossOrigin = config.frontendUrl.length === 1 ? frontendHosts[0] !== serverHost : true;

    const cca = new msal.ConfidentialClientApplication({
      auth: {
        clientId: config.azure.clientId,
        authority: `https://login.microsoftonline.com/${config.azure.tenantId}`,
        clientSecret: config.azure.secret,
      },
    });

    const jwksClient = jwks({
      jwksUri: `https://login.microsoftonline.com/${config.azure.tenantId}/discovery/v2.0/keys`,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 60 * 60 * 1000,
      rateLimit: true,
    });

    this.azure = config.azure;
    this.frontendUrl = config.frontendUrl;
    this.serverCallbackUrl = config.serverCallbackUrl;
    this.secretKey = createSecretKey(config.secretKey);
    this.frontendHosts = frontendHosts;
    this.isHttps = isHttps;
    this.isCrossOrigin = isCrossOrigin;
    this.loginPrompt = config.advanced.loginPrompt;
    this.cookieTimeFrame = config.advanced.cookieTimeFrame;
    this.refreshTokenExpiry = config.advanced.refreshTokenExpiry;
    this.debug = config.advanced.debug;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;

    if (config.advanced.debug) console.log('[oauth-entra-id] OAuthProvider is created.');
  }

  private debugLog({ message, methodName }: { message: string; methodName: string }) {
    if (this.debug) console.log(`[oauth-entra-id] OAuthProvider.${methodName}: ${message}`);
  }

  /**
   * Returns the names of the access and refresh token cookies.
   * @returns The cookie names.
   */
  getCookieNames() {
    return {
      accessTokenName: `${`${this.isHttps ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${this.azure.clientId}`}`,
      refreshTokenName: `${`${this.isHttps ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${this.azure.clientId}`}`,
    } as const;
  }

  private getCookieOptions(clientId?: string) {
    const cookieBaseOptions = {
      httpOnly: true,
      secure: this.isHttps,
      sameSite: this.isCrossOrigin ? (this.isHttps ? 'none' : undefined) : 'strict',
      path: '/',
    } as const;

    return {
      accessToken: {
        name: `${`${this.isHttps ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${clientId ? clientId : this.azure.clientId}`}`,
        options: {
          ...cookieBaseOptions,
          maxAge: 3600 * (this.cookieTimeFrame === 'sec' ? 1 : 1000),
        },
      },
      refreshToken: {
        name: `${`${this.isHttps ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${clientId ? clientId : this.azure.clientId}`}`,
        options: {
          ...cookieBaseOptions,
          maxAge: this.refreshTokenExpiry * (this.cookieTimeFrame === 'sec' ? 1 : 1000),
        },
      },
      deleteOptions: {
        ...cookieBaseOptions,
        sameSite: this.isHttps ? 'none' : undefined,
        maxAge: 0,
      },
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
  ): Promise<{ authUrl: string }> {
    this.debugLog({
      message: `Options: ${JSON.stringify(options)}`,
      methodName: 'generateAuthUrl',
    });

    const { data: validOptions, error: optionsError } = zGetAuthUrl.safeParse(options);
    if (optionsError) {
      throw new OAuthError(400, {
        message: 'Invalid params',
        description: optionsError.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', '),
      });
    }
    if (validOptions.loginPrompt === 'email' && !validOptions.email)
      throw new OAuthError(400, 'Invalid params: Email is required');
    if (validOptions.frontendUrl && !this.frontendHosts.includes(new URL(validOptions.frontendUrl).host))
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');

    try {
      const { verifier, challenge } = await this.msalCryptoProvider.generatePkceCodes();
      const nonce = this.msalCryptoProvider.createNewGuid();
      const prompt = validOptions.loginPrompt ?? this.loginPrompt;
      const params = {
        nonce: nonce,
        loginHint: validOptions.email,
        prompt:
          validOptions.email || prompt === 'email'
            ? 'login'
            : prompt === 'select-account'
              ? 'select_account'
              : undefined,
      };
      const state = encryptObject(
        {
          frontendUrl: validOptions.frontendUrl ?? (this.frontendUrl[0] as string),
          codeVerifier: verifier,
          ...params,
        },
        this.secretKey,
      );
      this.debugLog({
        message: `Params: ${JSON.stringify({ ...params, state })}`,
        methodName: 'generateAuthUrl',
      });

      const microsoftUrl = await this.cca.getAuthCodeUrl({
        ...params,
        state: state,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        responseMode: 'form_post',
        codeChallengeMethod: 'S256',
        codeChallenge: challenge,
      });

      if (new URL(microsoftUrl).hostname !== 'login.microsoftonline.com')
        throw new OAuthError(500, 'Illegitimate Microsoft Auth URL');

      return { authUrl: microsoftUrl };
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
   * @returns The access token, refresh token, frontend URL, and MSAL response.
   * @throws {OAuthError} If options are invalid.
   */
  async getTokenByCode(options: { code: string; state: string }): Promise<{
    accessToken: SetToken;
    refreshToken: SetToken | null;
    frontendUrl: string;
    msalResponse: AuthenticationResult;
  }> {
    this.debugLog({
      message: `Options: ${JSON.stringify({ code: !!options.code, state: !!options.state })}`,
      methodName: 'exchangeCodeForToken',
    });

    const { data: validOptions, error: optionsError } = zGetTokenByCode.safeParse(options);
    if (optionsError) {
      throw new OAuthError(400, {
        message: 'Invalid params',
        description: optionsError.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', '),
      });
    }

    try {
      const { data: state, error: stateError } = zState.safeParse(decryptObject(validOptions.state, this.secretKey));
      if (stateError)
        throw new OAuthError(400, {
          message: 'Invalid params: Invalid state',
          description: stateError.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', '),
        });

      this.debugLog({
        message: `State is decrypted: ${JSON.stringify(state)}`,
        methodName: 'exchangeCodeForToken',
      });

      if (!this.frontendHosts.includes(new URL(state.frontendUrl).host))
        throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');

      const msalResponse = await this.cca.acquireTokenByCode({
        code: validOptions.code,
        scopes: this.azure.scopes,
        redirectUri: this.serverCallbackUrl,
        ...state,
      });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, this.secretKey) : null;
      const cookieOptions = this.getCookieOptions();

      return {
        accessToken: { value: accessToken, ...cookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...cookieOptions.refreshToken } : null,
        frontendUrl: state.frontendUrl,
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

  /**
   * Generates a logout URL for OAuth authentication.
   * @param options - The options for generating the logout URL.
   * @returns The logout URL and cookie deletion options.
   * @throws {OAuthError} If options are invalid.
   */
  getLogoutUrl(options: { frontendUrl?: string } = {}): {
    logoutUrl: string;
    accessToken: DeleteToken;
    refreshToken: DeleteToken;
  } {
    this.debugLog({ message: `Options: ${JSON.stringify(options)}`, methodName: 'getLogoutUrl' });
    const { data: frontendUrl, error: frontendUrlError } = zUrl.optional().safeParse(options.frontendUrl);
    if (frontendUrlError)
      throw new OAuthError(400, {
        message: 'Invalid params: Invalid frontend URL',
        description: frontendUrlError.issues.join(', '),
      });
    if (frontendUrl && !this.frontendHosts.includes(new URL(frontendUrl).host)) {
      throw new OAuthError(403, 'Invalid params: Unlisted host frontend URL');
    }

    const logoutUrl = new URL(`https://login.microsoftonline.com/${this.azure.tenantId}/oauth2/v2.0/logout`);
    logoutUrl.searchParams.set('post_logout_redirect_uri', frontendUrl ?? (this.frontendUrl[0] as string));

    const cookieOptions = this.getCookieOptions();

    return {
      logoutUrl: logoutUrl.toString(),
      accessToken: {
        name: cookieOptions.accessToken.name,
        value: '',
        options: cookieOptions.deleteOptions,
      },
      refreshToken: {
        name: cookieOptions.refreshToken.name,
        value: '',
        options: cookieOptions.deleteOptions,
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
  private async verifyJwt(jwtToken: string): Promise<JwtPayload> {
    try {
      const decodedJwt = jwt.decode(jwtToken, { complete: true });
      if (!decodedJwt || !decodedJwt.header.kid)
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Key ID' });
      const publicKey = await this.getSigningKey(decodedJwt.header.kid);

      const fullJwt = jwt.verify(jwtToken, publicKey, {
        algorithms: ['RS256'],
        audience: this.azure.clientId,
        issuer: `https://login.microsoftonline.com/${this.azure.tenantId}/v2.0`,
        complete: true,
      });
      if (typeof fullJwt.payload === 'string')
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Payload' });
      this.debugLog({
        message: `JWT Payload: ${JSON.stringify(fullJwt.payload)}`,
        methodName: 'verifyJwt',
      });

      return fullJwt.payload;
    } catch (err) {
      this.debugLog({
        message: 'Error verifying JWT',
        methodName: 'verifyJwt',
      });
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
  ): Promise<{ microsoftToken: string; payload: JwtPayload } | null> {
    if (!accessToken) return null;
    try {
      const { data: jwtToken, success: jwtTokenSuccess } = zJwt.safeParse(
        zEncrypted.safeParse(accessToken).success ? decrypt(accessToken, this.secretKey) : accessToken,
      );
      if (!jwtTokenSuccess) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });
      const payload = await this.verifyJwt(jwtToken);
      return { microsoftToken: jwtToken, payload };
    } catch (err) {
      this.debugLog({ message: `Error verifying token: ${err}`, methodName: 'verifyToken' });
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
    newAccessToken: SetToken;
    newRefreshToken: SetToken | null;
    msalResponse: AuthenticationResult;
    msal: { microsoftToken: string; payload: JwtPayload };
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
      const cookieOptions = this.getCookieOptions();

      return {
        newAccessToken: { value: accessToken, ...cookieOptions.accessToken },
        newRefreshToken: refreshToken ? { value: refreshToken, ...cookieOptions.refreshToken } : null,
        msalResponse,
        msal: { microsoftToken: msalResponse.accessToken, payload: accessTokenPayload },
      };
    } catch (error) {
      this.debugLog({ message: `Error refreshing token: ${error}`, methodName: 'refreshToken' });
      return null;
    }
  }

  async getTokenOnBehalfOf(options: { accessToken: string; scopeOfRemoteServer: string }): Promise<{
    accessToken: SetToken;
    refreshToken: SetToken | null;
    msalResponse: AuthenticationResult;
  }> {
    try {
      const { data: token, error: tokenError } = zJwt.safeParse(
        zEncrypted.safeParse(options.accessToken).success
          ? decrypt(options.accessToken, this.secretKey)
          : options.accessToken,
      );
      if (tokenError) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid JWT Token' });

      const msalResponse = await this.cca.acquireTokenOnBehalfOf({
        oboAssertion: token,
        scopes: [options.scopeOfRemoteServer],
        skipCache: false,
      });

      if (!msalResponse) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Access Token' });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, this.secretKey) : null;

      const decodedAccessToken = jwt.decode(msalResponse.accessToken, { json: true });
      if (!decodedAccessToken) {
        throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid Access Token' });
      }
      const cookieOptions = this.getCookieOptions(decodedAccessToken.aud as string);

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

export interface SetToken {
  readonly name:
    | `${typeof ACCESS_TOKEN_NAME}-${string}`
    | `__Host-${typeof ACCESS_TOKEN_NAME}-${string}`
    | `${typeof REFRESH_TOKEN_NAME}-${string}`
    | `__Host-${typeof REFRESH_TOKEN_NAME}-${string}`;
  readonly value: string;
  readonly options: {
    readonly maxAge: number;
    readonly httpOnly: true;
    readonly secure: boolean;
    readonly path: '/';
    readonly sameSite: 'strict' | 'none' | undefined;
  };
}
export interface DeleteToken {
  readonly name:
    | `${typeof ACCESS_TOKEN_NAME}-${string}`
    | `__Host-${typeof ACCESS_TOKEN_NAME}-${string}`
    | `${typeof REFRESH_TOKEN_NAME}-${string}`
    | `__Host-${typeof REFRESH_TOKEN_NAME}-${string}`;
  readonly value: '';
  readonly options: {
    readonly httpOnly: true;
    readonly secure: boolean;
    readonly path: '/';
    readonly sameSite: 'none' | undefined;
    readonly maxAge: 0;
  };
}
