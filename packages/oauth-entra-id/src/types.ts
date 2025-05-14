import type { AuthenticationResult } from '@azure/msal-node';
import type { OAuthProvider } from './core';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/get-cookie-options';

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
export type SessionType = 'cookie-session' | 'bearer-token';

// biome-ignore lint/suspicious/noExplicitAny: More choices
export type InjectedData = Record<string, any>;

/**
 * Configuration for On-Behalf-Of authentication with an external service.
 */
export interface OnBehalfOfService {
  /** Unique identifier for the service. */
  serviceName: string;
  /** OAuth2 scope required to access the service. */
  scope: string;
  /** Secret key used for decrypting/encrypting tokens. */
  secretKey: string;
  /** Whether HTTPS is enforced. */
  isHttps?: boolean;
  /** Whether `SameSite` cookies are enforced. */
  isSameSite?: boolean;
  /** Optional expiration time for access tokens (in seconds or ms, based on time frame). */
  accessTokenExpiry?: number;
  /** Optional expiration time for refresh tokens (in seconds or ms, based on time frame). */
  refreshTokenExpiry?: number;
}

/**
 * Configuration object for initializing the OAuth provider.
 */
export interface OAuthConfig {
  azure: {
    /** Azure client ID. */
    clientId: string;
    /** Azure tenant ID or `'common'`. */
    tenantId: 'common' | string;
    /** Scopes requested for authentication. */
    scopes: string[];
    /** Azure client secret. */
    clientSecret: string;
  };
  /** Allowed frontend redirect URL(s). */
  frontendUrl: string | string[];
  /** Backend callback URL configured in Azure. */
  serverCallbackUrl: string;
  /** 32-byte encryption key used to encrypt/decrypt tokens. */
  secretKey: string;
  /** Optional advanced settings. */
  advanced?: {
    /** Login prompt behavior during user authentication. */
    loginPrompt?: LoginPrompt;
    /** Session type for verifying user identity. */
    sessionType?: SessionType;
    /** Allow tokens issued by other trusted systems. */
    enableB2b?: boolean;
    /** Enable debug logging for internal flow. */
    debug?: boolean;
    /** Cookie behavior and expiration settings. */
    cookies?: {
      /** Unit of time used for cookie max-age (e.g. `"ms"` or `"sec"`). */
      timeUnit?: TimeUnit;
      /** Disable Secure cookie enforcement. */
      disableHttps?: boolean;
      /** Disable SameSite enforcement (e.g., for cross-domain). */
      disableSameSite?: boolean;
      /** Max-age for access token cookies. */
      accessTokenExpiry?: number;
      /** Max-age for refresh token cookies. */
      refreshTokenExpiry?: number;
    };
    /** Additional trusted services for On-Behalf-Of token exchange. */
    onBehalfOf?: {
      /** Whether HTTPS is enforced. */
      isHttps: boolean;
      /** Whether `SameSite` cookies are enforced. */
      isSameSite: boolean;
      /** List of services for On-Behalf-Of authentication. */
      services: OnBehalfOfService[];
    };
  };
}

/**
 * Settings after parsing `OAuthConfig`.
 */
export interface OAuthSettings {
  readonly sessionType: SessionType;
  readonly isB2BEnabled: boolean;
  readonly isHttps: boolean;
  readonly isSameSite: boolean;
  readonly cookiesTimeUnit: TimeUnit;
  readonly serviceNames?: string[];
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

type PrivateMethods = 'verifyJwt';

export type OAuthProviderMethods =
  | {
      // biome-ignore lint/suspicious/noExplicitAny: The only way to get the method names of the class
      [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
    }[keyof OAuthProvider]
  | PrivateMethods;
