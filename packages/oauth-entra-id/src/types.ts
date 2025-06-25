import type { webcrypto } from 'node:crypto';
import type nodeCrypto from 'node:crypto';
import type { AuthenticationResult, ConfidentialClientApplication } from '@azure/msal-node';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookie-options';

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
export type CryptoType = 'node' | 'web-api';
export type WebApiCryptoKey = webcrypto.CryptoKey;
export type NodeCryptoKey = nodeCrypto.KeyObject;
export type EncryptionKey = NodeCryptoKey | WebApiCryptoKey | string;
export type LooseString<T extends string> = T | (string & {});
export type NonEmptyArray<T> = [T, ...T[]];
export type OneOrMore<T> = T | [T, ...T[]];

/**
 * Configuration object for initializing the OAuthProvider.
 */
export interface OAuthConfig {
  azure: {
    clientId: string;
    tenantId: LooseString<'common'>;
    scopes: NonEmptyArray<string>;
    clientSecret: string;
    downstreamServices?: NonEmptyArray<{
      serviceName: string;
      scope: string;
      serviceUrl: OneOrMore<string>;
      encryptionKey: string;
      cryptoType?: CryptoType;
      accessTokenMaxAge?: number;
    }>;
    b2bApps?: NonEmptyArray<{ appName: string; scope: string }>;
  };
  frontendUrl: OneOrMore<string>;
  serverCallbackUrl: string;
  encryptionKey: string;
  advanced?: {
    loginPrompt?: LoginPrompt;
    acceptB2BRequests?: boolean;
    cryptoType?: CryptoType;
    disableCompression?: boolean;
    cookies?: {
      timeUnit?: TimeUnit;
      disableSecure?: boolean;
      disableSameSite?: boolean;
      accessTokenMaxAge?: number;
      refreshTokenMaxAge?: number;
    };
  };
}
export interface Azure {
  clientId: string;
  tenantId: LooseString<'common'>;
  scopes: NonEmptyArray<string>;
  cca: ConfidentialClientApplication;
}

export type EncryptionKeys = {
  accessToken: EncryptionKey;
  refreshToken: EncryptionKey;
  state: EncryptionKey;
  ticket: EncryptionKey;
};

export type B2BApp =
  | {
      appName: string;
      scope: string;
      token: string;
      exp: number;
      aud: string;
      msalResponse: MsalResponse;
    }
  | {
      appName: string;
      scope: string;
      token: null;
      exp: null;
      aud: null;
      msalResponse: null;
    };

export interface OboService {
  serviceName: string;
  scope: string;
  encryptionKey: string;
  cryptoType: CryptoType;
  isSecure: boolean;
  isSamesite: boolean;
  atMaxAge: number;
}

/**
 * Parsed and resolved configuration used internally by the OAuthProvider.
 */
export interface OAuthSettings {
  readonly loginPrompt: LoginPrompt;
  readonly acceptB2BRequests: boolean;
  readonly b2bApps?: string[];
  readonly downstreamServices?: string[];
  readonly disableCompression: boolean;
  readonly cryptoType: CryptoType;
  readonly cookies: {
    readonly timeUnit: TimeUnit;
    readonly isSecure: boolean;
    readonly isSameSite: boolean;
    readonly accessTokenMaxAge: number;
    readonly refreshTokenMaxAge: number;
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
  token: string;
  isCached: boolean;
  msalResponse: MsalResponse;
  expiresAt: number;
}

export interface GetTokenOnBehalfOfResult {
  serviceName: string;
  clientId: string;
  accessToken: Cookies['AccessToken'];
  msalResponse: MsalResponse;
}
