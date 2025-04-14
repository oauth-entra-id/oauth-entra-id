import type { KeyObject } from 'node:crypto';
import * as msal from '@azure/msal-node';
import type { AuthenticationResult, ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import jwks, { type JwksClient } from 'jwks-rsa';
import { createSecretKey, decrypt, decryptObject, encrypt, encryptObject } from '~/core/crypto';
import {
  zConfig,
  zEncrypted,
  zExchangeCodeForTokenOptions,
  zGenerateAuthUrlOptions,
  zJwt,
  zState,
  zUrl,
} from '~/core/zod';
import { OAuthError } from './OAuthError';

const SECURE_COOKIE_PREFIX = '__Host';
const ACCESS_TOKEN_NAME = 'AccessToken';
const REFRESH_TOKEN_NAME = 'RefreshToken';

type LoginPrompt = 'email' | 'select-account' | 'sso';

export interface OAuthConfig {
  azure: { clientId: string; tenantId: string; clientScopes: string[]; clientSecret: string };
  frontendUrl: string | string[];
  serverFullCallbackUrl: string;
  secretKey: string;
  cookieTimeFrame?: 'ms' | 'sec';
  loginPrompt?: LoginPrompt;
  debug?: boolean;
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
  private readonly frontendHosts: string[];
  private readonly serverFullCallbackUrl: string;
  private readonly secretKey: KeyObject;
  private readonly loginPrompt: LoginPrompt;
  private readonly cca: ConfidentialClientApplication;
  private readonly msalCryptoProvider: CryptoProvider;
  private readonly jwksClient: JwksClient;
  private readonly cookieOptions: CookieOptions;
  private readonly isHttps: boolean;
  readonly debug: boolean;

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

    const cca = new msal.ConfidentialClientApplication({
      auth: {
        clientId: config.azure.clientId,
        authority: `https://login.microsoftonline.com/${config.azure.tenantId}`,
        clientSecret: config.azure.clientSecret,
      },
    });

    const jwksClient = jwks({
      jwksUri: `https://login.microsoftonline.com/${config.azure.tenantId}/discovery/v2.0/keys`,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 60 * 60 * 1000,
      rateLimit: true,
    });

    const cookieBaseOptions = { httpOnly: true, secure: config.isHttps, path: '/' } as const;

    const cookieOptions = {
      accessToken: {
        name: config.isHttps
          ? `${SECURE_COOKIE_PREFIX}-${ACCESS_TOKEN_NAME}-${config.azure.clientId}`
          : `${ACCESS_TOKEN_NAME}-${config.azure.clientId}`,
        options: {
          ...cookieBaseOptions,
          sameSite: config.isCrossOrigin ? (config.isHttps ? 'none' : undefined) : 'strict',
          maxAge: config.cookieTimeFrame === 'sec' ? 3600 : 3600000,
        },
      },
      refreshToken: {
        name: config.isHttps
          ? `${SECURE_COOKIE_PREFIX}-${REFRESH_TOKEN_NAME}-${config.azure.clientId}`
          : `${REFRESH_TOKEN_NAME}-${config.azure.clientId}`,
        options: {
          ...cookieBaseOptions,
          sameSite: config.isCrossOrigin ? (config.isHttps ? 'none' : undefined) : 'strict',
          maxAge: config.cookieTimeFrame === 'sec' ? 2592000 : 2592000000,
        },
      },
      deleteOptions: {
        ...cookieBaseOptions,
        sameSite: config.isHttps ? 'none' : undefined,
        maxAge: 0,
      },
    } as const;

    this.azure = config.azure;
    this.frontendUrl = config.frontendUrl;
    this.serverFullCallbackUrl = config.serverFullCallbackUrl;
    this.secretKey = createSecretKey(config.secretKey);
    this.frontendHosts = config.frontendHosts;
    this.loginPrompt = config.loginPrompt;
    this.cca = cca;
    this.msalCryptoProvider = new msal.CryptoProvider();
    this.jwksClient = jwksClient;
    this.cookieOptions = cookieOptions;
    this.isHttps = config.isHttps;
    this.debug = config.debug;

    if (config.debug) console.log('[oauth-entra-id] OAuthProvider is created.');
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
      accessTokenName: this.cookieOptions.accessToken.name,
      refreshTokenName: this.cookieOptions.refreshToken.name,
    } as const;
  }

  /**
   * Generates an authorization URL for OAuth authentication.
   * @param options - The options for generating the authorization URL.
   * @returns The authorization URL.
   * @throws {OAuthError} If options are invalid.
   */
  async generateAuthUrl(
    options: { loginPrompt?: LoginPrompt; email?: string; frontendUrl?: string } = {},
  ): Promise<{ authUrl: string }> {
    this.debugLog({
      message: `Options: ${JSON.stringify(options)}`,
      methodName: 'generateAuthUrl',
    });

    const { data: validOptions, error: optionsError } = zGenerateAuthUrlOptions.safeParse(options);
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
        scopes: this.azure.clientScopes,
        redirectUri: this.serverFullCallbackUrl,
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
  async exchangeCodeForToken(options: { code: string; state: string }): Promise<{
    accessToken: AccessToken;
    refreshToken: RefreshToken | null;
    frontendUrl: string;
    msalResponse: AuthenticationResult;
  }> {
    this.debugLog({
      message: `Options: ${JSON.stringify({ code: !!options.code, state: !!options.state })}`,
      methodName: 'exchangeCodeForToken',
    });

    const { data: validOptions, error: optionsError } = zExchangeCodeForTokenOptions.safeParse(options);
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
        scopes: this.azure.clientScopes,
        redirectUri: this.serverFullCallbackUrl,
        ...state,
      });

      const accessToken = encrypt(msalResponse.accessToken, this.secretKey);
      const cachedRefreshToken = await this.getRefreshTokenFromCache(msalResponse);
      const refreshToken = cachedRefreshToken ? encrypt(cachedRefreshToken, this.secretKey) : null;

      return {
        accessToken: { value: accessToken, ...this.cookieOptions.accessToken },
        refreshToken: refreshToken ? { value: refreshToken, ...this.cookieOptions.refreshToken } : null,
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
    accessToken: DeleteAccessToken;
    refreshToken: DeleteRefreshToken;
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

    return {
      logoutUrl: logoutUrl.toString(),
      accessToken: {
        name: this.cookieOptions.accessToken.name,
        value: '',
        options: this.cookieOptions.deleteOptions,
      },
      refreshToken: {
        name: this.cookieOptions.refreshToken.name,
        value: '',
        options: this.cookieOptions.deleteOptions,
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
  async refreshAccessToken(refreshToken: string): Promise<{
    newAccessToken: AccessToken;
    newRefreshToken: RefreshToken | null;
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
        scopes: this.azure.clientScopes,
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
        newAccessToken: { value: accessToken, ...this.cookieOptions.accessToken },
        newRefreshToken: refreshToken ? { value: refreshToken, ...this.cookieOptions.refreshToken } : null,
        msalResponse,
        msal: { microsoftToken: msalResponse.accessToken, payload: accessTokenPayload },
      };
    } catch (error) {
      this.debugLog({ message: `Error refreshing token: ${error}`, methodName: 'refreshToken' });
      return null;
    }
  }

  async getTokenRemotely(options: { accessToken: string; scopeOfRemoteServer: string }) {
    const newToken = await this.cca.acquireTokenOnBehalfOf({
      oboAssertion: options.accessToken,
      scopes: [options.scopeOfRemoteServer],
      skipCache: false,
    });
    return newToken;
  }
}

interface AccessToken {
  readonly name: CookieOptions['accessToken']['name'];
  readonly value: string;
  readonly options: CookieOptions['accessToken']['options'];
}

interface RefreshToken {
  readonly name: CookieOptions['refreshToken']['name'];
  readonly value: string;
  readonly options: CookieOptions['refreshToken']['options'];
}

interface DeleteAccessToken {
  readonly name: CookieOptions['accessToken']['name'];
  readonly value: '';
  readonly options: CookieOptions['deleteOptions'];
}

interface DeleteRefreshToken {
  readonly name: CookieOptions['refreshToken']['name'];
  readonly value: '';
  readonly options: CookieOptions['deleteOptions'];
}

interface CookieOptions {
  readonly accessToken: {
    readonly name: string;
    readonly options: {
      readonly httpOnly: true;
      readonly secure: boolean;
      readonly path: '/';
      readonly sameSite: 'strict' | 'none' | undefined;
      readonly maxAge: 3600 | 3600000; // 1 hour
    };
  };
  readonly refreshToken: {
    readonly name: string;
    readonly options: {
      readonly httpOnly: true;
      readonly secure: boolean;
      readonly path: '/';
      readonly sameSite: 'strict' | 'none' | undefined;
      readonly maxAge: 2592000 | 2592000000; // 30 days
    };
  };
  readonly deleteOptions: {
    readonly httpOnly: true;
    readonly secure: boolean;
    readonly path: '/';
    readonly sameSite: 'none' | undefined;
    readonly maxAge: 0;
  };
}
