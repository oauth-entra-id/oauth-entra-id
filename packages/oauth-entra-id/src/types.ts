import type { AuthenticationResult } from '@azure/msal-node';
import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from './core';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/get-cookie-options';

export type ServerType = 'express' | 'nestjs';
export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
type Primitive = string | number | boolean;
export type InjectedData = Record<string, Primitive | Primitive[] | Record<string, Primitive | Primitive[]>>;

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
  isHttps: boolean;
  /** Whether `SameSite` cookies are enforced. */
  isSameSite: boolean;
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
    /** Allow tokens issued by other trusted systems. */
    allowOtherSystems?: boolean;
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
    onBehalfOfServices?: OnBehalfOfService[];
  };
}

/**
 * Computed options after parsing `OAuthConfig`.
 */
export interface OAuthOptions {
  readonly areOtherSystemsAllowed: boolean;
  readonly isHttps: boolean;
  readonly isSameSite: boolean;
  readonly cookiesTimeUnit: TimeUnit;
  readonly serviceNames?: string[];
  readonly accessTokenCookieExpiry: number;
  readonly refreshTokenCookieExpiry: number;
  readonly debug: boolean;
}

export interface Endpoints {
  Authenticate: {
    loginPrompt?: 'email' | 'select-account' | 'sso';
    email?: string;
    frontendUrl: string;
  };
  Callback: {
    code: string;
    state: string;
  };
  Logout: {
    frontendUrl?: string;
  };
  OnBehalfOf: {
    serviceNames: string[];
  };
}

export type MsalResponse = AuthenticationResult;

declare global {
  namespace Express {
    export interface Request {
      /** OAuthProvider instance bound to the request. */
      oauthProvider: OAuthProvider;
      /** The backend framework type. */
      serverType: ServerType;

      /**
       * Stores the raw Microsoft access token and its decoded payload.
       */
      msal?: {
        microsoftToken: string;
        payload: JwtPayload;
      };

      /**
       * Stores user authentication details.
       *
       * - If `isOtherApp` is `false`, the user is authenticated locally.
       * - If `isOtherApp` is `true`, the token was issued by another service.
       */
      userInfo?:
        | {
            isOtherApp: false;
            uniqueId: string;
            roles: string[];
            name: string;
            email: string;
            injectedData?: InjectedData;
          }
        | { isOtherApp: true; uniqueId: string; roles: string[]; appId: string };
    }
  }
}

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

export interface CookieParserOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
  domain?: string;
}
