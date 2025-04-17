import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from './OAuthProvider';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookies';

export type ServerType = 'express' | 'nestjs';

declare global {
  namespace Express {
    export interface Request {
      oauthProvider?: OAuthProvider;
      serverType: ServerType;
      areOtherSystemsAllowed: boolean;
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
       * - If `isAnotherSystem` is `false`, the user is authenticated locally.
       * - If `isAnotherSystem` is `true`, authentication comes from an external system.
       */
      userInfo?:
        | { isAnotherSystem: false; uniqueId: string; roles: string[]; name: string; email: string }
        | { isAnotherSystem: true; uniqueId: string; roles: string[]; appId: string };
    }
  }
}

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeFrame = 'ms' | 'sec';

export interface OAuthConfig {
  azure: { clientId: string; tenantId: string; scopes: string[]; secret: string };
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
  };
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

export interface DefaultCookieOptions {
  readonly accessToken: {
    readonly name: AccessTokenName;
    readonly options: CookieOptions;
  };
  readonly refreshToken: {
    readonly name: RefreshTokenName;
    readonly options: CookieOptions;
  };
  readonly deleteOptions: CookieOptions;
}

interface SetToken {
  readonly value: string;
  readonly options: CookieOptions;
}

export interface SetAccessToken extends SetToken {
  readonly name: AccessTokenName;
}

export interface SetRefreshToken extends SetToken {
  readonly name: RefreshTokenName;
}

interface DeleteToken {
  readonly value: '';
  readonly options: CookieOptions;
}

export interface DeleteAccessToken extends DeleteToken {
  readonly name: AccessTokenName;
}

export interface DeleteRefreshToken extends DeleteToken {
  readonly name: RefreshTokenName;
}
