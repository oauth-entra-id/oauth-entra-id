import type { AuthenticationResult } from '@azure/msal-node';
import type { OAuthProvider } from './core';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/get-cookie-options';

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
export type SessionType = 'cookie-session' | 'bearer-token';

/**
 * Optional custom data to embed in access tokens.
 * Should not contain sensitive information.
 */
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
export type InjectedData = Record<string, any>;

/**
 * Configuration for acquiring client credentials for a B2B service.
 */
export interface B2BService {
  /** Unique identifier of the external service. */
  b2bServiceName: string;

  /** OAuth 2.0 scope to request for the service.
   * Usually end with `/.default` to request all permissions.
   */
  b2bScope: string;
}

/**
 * Configuration for acquiring On-Behalf-Of (OBO) tokens for downstream services.
 */
export interface OnBehalfOfService {
  /** Unique identifier of the downstream service. */
  oboServiceName: string;

  /** OAuth 2.0 scope to request for the downstream service.
   * Usually end with `/.default` to request all permissions.
   */
  oboScope: string;

  /** Encryption key used to encrypt tokens for this service. */
  secretKey: string;

  /** Whether HTTPS is required when setting cookies for this service. */
  isHttps?: boolean;

  /** Whether `SameSite` cookies should be enforced for this service. */
  isSameSite?: boolean;

  /** Expiration for access token cookies (default from global if not set). */
  accessTokenExpiry?: number;

  /** Expiration for refresh token cookies (default from global if not set). */
  refreshTokenExpiry?: number;
}

/**
 * Configuration object for initializing the OAuthProvider.
 */
export interface OAuthConfig {
  /** Microsoft Entra ID configuration. */
  azure: {
    /** Microsoft Entra ID client ID. */
    clientId: string;
    /** Azure tenant ID or `'common'` for multi-tenant support. */
    tenantId: 'common' | string;
    /** OAuth 2.0 scopes to request during authentication. */
    scopes: string[];
    /** Client secret associated with the Azure app registration. */
    clientSecret: string;
  };
  /** Allowed frontend redirect URL(s). */
  frontendUrl: string | string[];
  /** The server-side callback URL (must match the one registered in Azure). */
  serverCallbackUrl: string;
  /** 32-byte encryption key used to encrypt/decrypt tokens. */
  secretKey: string;
  /** Optional advanced configuration for cookies, logging, B2B, and OBO. */
  advanced?: {
    /** Controls login UI behavior. Defaults to `'sso'`. */
    loginPrompt?: LoginPrompt;
    /** Session persistence method. Defaults to `'cookie-session'`. */
    sessionType?: SessionType;
    /** External B2B system integration configuration. */
    b2b?: {
      /** Whether to accept tokens issued by other systems. */
      allowB2B?: boolean;
      /** Create B2B access tokens for external services. */
      b2bServices?: B2BService[];
    };
    /** Enables verbose debug logging. */
    debug?: boolean;
    /** Cookie behavior and expiration settings. */
    cookies?: {
      /** Unit used for cookie expiration times. */
      timeUnit?: TimeUnit;
      /** If true, disables HTTPS enforcement on cookies. */
      disableHttps?: boolean;
      /** If true, disables SameSite enforcement on cookies. */
      disableSameSite?: boolean;
      /** Max-age for access token cookies. */
      accessTokenExpiry?: number;
      /** Max-age for refresh token cookies. */
      refreshTokenExpiry?: number;
    };
    /** Configuration for acquiring downstream tokens via the OBO flow. */
    onBehalfOf?: {
      /** Whether HTTPS is enforced. */
      isHttps: boolean;
      /** Whether to enforce SameSite on OBO cookies. */
      isSameSite: boolean;
      /** List of trusted services requiring On-Behalf-Of delegation. */
      oboServices: OnBehalfOfService[];
    };
  };
}

/**
 * Parsed and resolved configuration used internally by the OAuthProvider.
 */
export interface OAuthSettings {
  readonly sessionType: SessionType;
  readonly loginPrompt: LoginPrompt;
  readonly isB2BEnabled: boolean;
  readonly isHttps: boolean;
  readonly isSameSite: boolean;
  readonly cookiesTimeUnit: TimeUnit;
  readonly b2bServices?: string[];
  readonly oboServices?: string[];
  readonly accessTokenCookieExpiry: number;
  readonly refreshTokenCookieExpiry: number;
  readonly debug: boolean;
}

export type MsalResponse = AuthenticationResult;

type AccessTokenName = `${typeof ACCESS_TOKEN_NAME}-${string}` | `__Host-${typeof ACCESS_TOKEN_NAME}-${string}`;
type RefreshTokenName = `${typeof REFRESH_TOKEN_NAME}-${string}` | `__Host-${typeof REFRESH_TOKEN_NAME}-${string}`;

interface CookieOptions {
  readonly maxAge: number;
  readonly httpOnly: true;
  readonly secure: boolean;
  readonly path: '/';
  readonly sameSite: 'strict' | 'none' | undefined;
}

export interface Cookies {
  DefaultCookieOptions: {
    readonly accessToken: {
      readonly name: AccessTokenName;
      readonly options: CookieOptions;
    };
    readonly refreshToken: {
      readonly name: RefreshTokenName;
      readonly options: CookieOptions;
    };
    readonly deleteOptions: CookieOptions;
  };
  AccessToken: {
    readonly name: AccessTokenName;
    readonly value: string;
    readonly options: CookieOptions;
  };
  RefreshToken: {
    readonly name: RefreshTokenName;
    readonly value: string;
    readonly options: CookieOptions;
  };
  DeleteAccessToken: {
    readonly name: AccessTokenName;
    readonly value: string;
    readonly options: CookieOptions;
  };
  DeleteRefreshToken: {
    readonly name: RefreshTokenName;
    readonly value: string;
    readonly options: CookieOptions;
  };
}

type PrivateMethods = 'verifyJwt' | 'getBothTokens';

export type OAuthProviderMethods =
  | {
      // biome-ignore lint/suspicious/noExplicitAny: The only way to get the method names of the class
      [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
    }[keyof OAuthProvider]
  | PrivateMethods;

export interface GetB2BTokenResult {
  b2bServiceName: string;
  b2bAccessToken: string;
  b2bMsalResponse: MsalResponse;
}

export interface GetTokenOnBehalfOfResult {
  oboServiceName: string;
  oboAccessToken: Cookies['AccessToken'];
  oboRefreshToken: Cookies['RefreshToken'] | null;
  oboMsalResponse: MsalResponse;
}
