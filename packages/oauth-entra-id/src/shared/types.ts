import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core';
import type { InjectedData } from '~/types';

export type ServerType = 'express' | 'nestjs';

export interface User {
  isApp: false;
  uniqueId: string;
  roles: string[];
  name: string;
  email: string;
  injectedData?: InjectedData;
}

export interface AppUser {
  isApp: true;
  uniqueId: string;
  roles: string[];
  appId: string;
}

export type UserInfo = User | AppUser;

export type InjectDataFunction<T = any> = (data: InjectedData<T>) => void;

export type CallbackFunction = (params: {
  userInfo: UserInfo;
  injectData: InjectDataFunction;
}) => void | Promise<void>;

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
        jwt: string;
        payload: JwtPayload;
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
