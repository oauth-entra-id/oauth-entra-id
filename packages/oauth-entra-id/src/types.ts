import type { AuthenticationResult } from '@azure/msal-node';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookie-options';

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
export type SessionType = 'cookie-session' | 'bearer-token';

/**
 * Configuration for acquiring client credentials for a B2B service.
 */
export interface B2BApp {
  /** Unique identifier of the external client service. */
  appName: string;

  /** OAuth 2.0 scope to request for the service.
   * Usually end with `/.default` to request all permissions.
   */
  scope: string;
}

/**
 * Configuration for acquiring On-Behalf-Of (OBO) tokens for downstream services.
 */
export interface DownstreamService {
  /** Unique identifier of the downstream service. */
  serviceName: string;

  /** OAuth 2.0 scope to request for the downstream service.
   * Usually end with `/.default` to request all permissions.
   */
  scope: string;

  /** Encryption key used to encrypt tokens for this service. */
  secretKey: string;

  /** Whether HTTPS is required when setting cookies for this service. */
  isHttps?: boolean;

  /** Whether `SameSite` cookies should be enforced for this service. */
  isSameOrigin?: boolean;

  /** Expiration for access token cookies (default from global if not set). */
  accessTokenExpiry?: number;

  /** Expiration for refresh token cookies (default from global if not set). */
  refreshTokenExpiry?: number;
}

export interface OboService {
  serviceName: string;
  secure: boolean;
  sameSite: boolean;
  scope: string;
  secretKey: string;
  atExp?: number;
  rtExp?: number;
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
    tenantId: 'common' | (string & {});
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
    /** Whether to accept tokens issued by other systems. */
    acceptB2BRequests?: boolean;
    /** List of external B2B services to acquire tokens for. */
    b2bTargetedApps?: B2BApp[];
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
    /** Configuration for acquiring downstream tokens via the on-behalf-of flow. */
    downstreamServices?: {
      /** Whether HTTPS is enforced. */
      areHttps: boolean;
      /** Whether to enforce SameSite on OBO cookies. */
      areSameOrigin: boolean;
      /** List of trusted services requiring On-Behalf-Of delegation. */
      services: DownstreamService[];
    };
  };
}

/**
 * Parsed and resolved configuration used internally by the OAuthProvider.
 */
export interface OAuthSettings {
  readonly sessionType: SessionType;
  readonly loginPrompt: LoginPrompt;
  readonly acceptB2BRequests: boolean;
  readonly b2bApps?: string[];
  readonly downstreamServices?: string[];
  readonly cookies: {
    readonly timeUnit: TimeUnit;
    readonly isSecure: boolean;
    readonly isSameSite: boolean;
    readonly accessTokenExpiry: number;
    readonly refreshTokenExpiry: number;
    readonly accessTokenName: AccessTokenName;
    readonly refreshTokenName: RefreshTokenName;
  };
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

export interface GetB2BTokenResult {
  appName: string;
  clientId: string;
  accessToken: string;
  msalResponse: MsalResponse;
}

export interface GetTokenOnBehalfOfResult {
  serviceName: string;
  clientId: string;
  accessToken: Cookies['AccessToken'];
  msalResponse: MsalResponse;
}
