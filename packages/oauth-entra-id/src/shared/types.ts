import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core';
import type { Result } from '~/error';

/** Supported server frameworks for binding the OAuthProvider */
export type ServerType = 'express' | 'nestjs';

/**
 * Represents either an end-user or a service principal.
 *
 * @template T  Type of any injected metadata for a user.
 */
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

/**
 * Adds metadata into an existing access token.
 *
 * @template T  Shape of the object to inject.
 * @param data  Arbitrary JSON to embed.
 * @returns A `Result<{ injectedData: T }>` containing the injected data.
 */
export type InjectDataFunction<T extends object = Record<string, any>> = (
  data: T,
) => Promise<Result<{ injectedData: T }>>;

/**
 * Optional callback invoked once a request is authenticated.
 *
 * @param params.userInfo - Information about the authenticated user or service principal.
 * @param params.tryInjectData - Function to inject additional data into the access token.
 */
export type CallbackFunction =
  | (() => Promise<void> | void)
  | ((params: { userInfo: UserInfo; tryInjectData: InjectDataFunction }) => Promise<void> | void);

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
    services: string[];
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
      /** Bound OAuthProvider instance. */
      oauthProvider: OAuthProvider;

      /** Which server adapter is in use. */
      serverType: ServerType;

      /** Raw JWT and decoded payload, if present. */
      accessTokenInfo?: {
        readonly jwt: string;
        readonly payload: JwtPayload;
      };

      /** Information about the authenticated user or service principal. */
      userInfo?: UserInfo;
    }
  }
}
