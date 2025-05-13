import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core';
import type { InjectedData } from '~/types';

export type ServerType = 'express' | 'nestjs';

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
