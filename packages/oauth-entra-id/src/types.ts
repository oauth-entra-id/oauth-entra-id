import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from './core';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookies';

export type ServerType = 'express' | 'nestjs';
export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeFrame = 'ms' | 'sec';

export interface Azure {
  clientId: string;
  tenantId: 'common' | string;
  scopes: string[];
  secret: string;
}

export interface OnBehalfOfService {
  serviceName: string;
  scope: string;
  secretKey: string;
  isHttps: boolean;
  isSameSite: boolean;
  accessTokenExpiry?: number;
  refreshTokenExpiry?: number;
}

export interface OAuthConfig {
  azure: Azure;
  frontendUrl: string | string[];
  serverCallbackUrl: string;
  secretKey: string;
  advanced?: {
    loginPrompt?: LoginPrompt;
    disableHttps?: boolean;
    disableSameSite?: boolean;
    cookieTimeFrame?: TimeFrame;
    accessTokenExpiry?: number; // in seconds
    refreshTokenExpiry?: number; // in seconds
    debug?: boolean;
    onBehalfOfServices?: OnBehalfOfService[];
  };
}

export interface OAuthOptions {
  readonly isHttps: boolean;
  readonly isSameSite: boolean;
  readonly cookieTimeFrame: TimeFrame;
  readonly serviceNames?: string[];
  readonly accessTokenExpiry: number; // in seconds
  readonly refreshTokenExpiry: number; // in seconds
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
      oauthProvider: OAuthProvider;
      serverType: ServerType;
      allowOtherSystems: boolean;
      /**
       * Stores the raw Microsoft access token and its payload.
       */
      msal?: {
        microsoftToken: string;
        payload: JwtPayload;
      };
      /**
       * Stores user authentication details.
       *
       * - If `isFromAnotherApp` is `false`, the user is authenticated locally.
       * - If `isFromAnotherApp` is `true`, authentication comes from an external system.
       */
      userInfo?:
        | { isFromAnotherApp: false; uniqueId: string; roles: string[]; name: string; email: string }
        | { isFromAnotherApp: true; uniqueId: string; roles: string[]; appId: string };
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
