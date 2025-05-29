import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core';
import type { Result } from '~/error';

export type ServerType = 'express' | 'nestjs';

export type UserInfo<T extends object = Record<string, any>> =
  | {
      readonly isApp: false;
      readonly name: string;
      readonly email: string;
      readonly injectedData?: T;
      readonly uniqueId: string;
      readonly roles: string[];
    }
  | {
      readonly isApp: true;
      readonly appId: string;
      readonly name?: undefined;
      readonly email?: undefined;
      readonly injectedData?: undefined;
      readonly uniqueId: string;
      readonly roles: string[];
    };

export type InjectDataFunction<T extends object = Record<string, any>> = (data: T) => Promise<Result<void>>;

export type CallbackFunction = (params: {
  userInfo: UserInfo;
  injectData: InjectDataFunction;
}) => Promise<void> | void;

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

export interface CookieParserOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
  domain?: string;
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
      accessTokenInfo?: {
        readonly jwt: string;
        readonly payload: JwtPayload;
      };

      /**
       * Stores user authentication details.
       *
       * - If `isApp` is `false`, the user is authenticated locally.
       * - If `isApp` is `true`, the token was issued by another service.
       */
      userInfo?: UserInfo;
    }
  }
}
