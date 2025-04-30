import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from './core';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookies';

export type ServerType = 'express' | 'nestjs';
export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeFrame = 'ms' | 'sec';
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
    /** Client secret. */
    secret: string;
  };
  /** Frontend redirect URL(s) allowed post-authentication. */
  frontendUrl: string | string[];
  /** Server callback URL. */
  serverCallbackUrl: string;
  /** Encryption secret key. */
  secretKey: string;
  /** Optional advanced settings. */
  advanced?: {
    /** Optional login prompt strategy. */
    loginPrompt?: LoginPrompt;
    /** Allow cross-app token validation. */
    allowOtherSystems?: boolean;
    /** Disable HTTPS enforcement. */
    disableHttps?: boolean;
    /** Disable SameSite cookie enforcement. */
    disableSameSite?: boolean;
    /** Cookie time unit. */
    cookieTimeFrame?: TimeFrame;
    /** Cookie max-age for access tokens. */
    accessTokenCookieExpiry?: number;
    /** Cookie max-age for refresh tokens. */
    refreshTokenCookieExpiry?: number;
    /** Enable verbose logging. */
    debug?: boolean;
    /** Configure on-behalf-of services. */
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
  readonly cookieTimeFrame: TimeFrame;
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
        | { isOtherApp: false; uniqueId: string; roles: string[]; name: string; email: string }
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

export type MethodKeys<T> = {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  [K in keyof T]: T[K] extends (...args: any[]) => any ? K : never;
}[keyof T];
