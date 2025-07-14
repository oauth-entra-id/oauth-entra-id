import type nodeCrypto from 'node:crypto';
import type { webcrypto } from 'node:crypto';
import type { AuthenticationResult, ConfidentialClientApplication } from '@azure/msal-node';
import type jwt from 'jsonwebtoken';
import type { ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME } from './utils/cookie-options';

export type LoginPrompt = 'email' | 'select-account' | 'sso';
export type TimeUnit = 'ms' | 'sec';
export type CryptoType = 'node' | 'web-api';
export type JwtPayload = jwt.JwtPayload;
export type WebApiCryptoKey = webcrypto.CryptoKey;
export type NodeCryptoKey = nodeCrypto.KeyObject;
export type EncryptionKey = NodeCryptoKey | WebApiCryptoKey | string;
export type LooseString<T extends string> = T | (string & {});
export type NonEmptyArray<T> = [T, ...T[]];
export type OneOrMore<T> = T | [T, ...T[]];
export type BaseWithExtended<TBase extends object, TExtended extends object> =
  | { [KBase in keyof TBase]: TBase[KBase] }
  | ({ [KBase in keyof TBase]: TBase[KBase] } & { [KExtended in keyof TExtended]: TExtended[KExtended] });

/**
 * Configuration object for initializing the OAuthProvider.
 */
export interface OAuthConfig {
  azure: OneOrMore<{
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
      accessTokenExpiry?: number;
    }>;
    b2bApps?: NonEmptyArray<{ appName: string; scope: string }>;
  }>;
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
      accessTokenExpiry?: number;
      refreshTokenExpiry?: number;
    };
  };
}
export interface Azure {
  clientId: string;
  tenantId: string;
  scopes: NonEmptyArray<string>;
  cca: ConfidentialClientApplication;
  cookiesNames: BaseCookieNames;
  b2b: Map<string, B2BApp> | undefined;
  b2bNames: NonEmptyArray<string> | undefined;
  obo: Map<string, OboService> | undefined;
  oboNames: NonEmptyArray<string> | undefined;
}

export type LiteConfig = BaseWithExtended<
  { clientId: string; tenantId: LooseString<'common'> },
  { clientSecret: string; b2bApps: NonEmptyArray<{ appName: string; scope: string }> }
>;

export interface MinimalAzure {
  clientId: string;
  tenantId: LooseString<'common'>;
  cca: ConfidentialClientApplication | undefined;
  b2bApps: Map<string, B2BApp> | undefined;
}

export type EncryptionKeys = {
  accessToken: EncryptionKey;
  refreshToken: EncryptionKey;
  state: EncryptionKey;
  ticket: EncryptionKey;
};

export type B2BApp = { appName: string; scope: string } & (
  | { token: string; exp: number; aud: string; msalResponse: MsalResponse }
  | { token: null; exp: null; aud: null; msalResponse: null }
);

export interface OboService {
  serviceName: string;
  scope: string;
  encryptionKey: string;
  cryptoType: CryptoType;
  isSecure: boolean;
  isSamesite: boolean;
  atExp: number;
}

/** Parsed and resolved configuration used internally by the OAuthProvider */
export interface OAuthSettings {
  readonly loginPrompt: LoginPrompt;
  readonly acceptB2BRequests: boolean;
  readonly b2bApps: NonEmptyArray<{ azureId: string; names: NonEmptyArray<string> }> | undefined;
  readonly downstreamServices: NonEmptyArray<{ azureId: string; names: NonEmptyArray<string> }> | undefined;
  readonly disableCompression: boolean;
  readonly cryptoType: CryptoType;
  readonly azures: NonEmptyArray<{ azureId: string; tenantId: string }>;
  readonly cookies: {
    readonly timeUnit: TimeUnit;
    readonly isSecure: boolean;
    readonly isSameSite: boolean;
    readonly accessTokenExpiry: number;
    readonly accessTokenName: AccessTokenName;
    readonly refreshTokenExpiry: number;
    readonly refreshTokenName: RefreshTokenName;
    readonly cookieNames: NonEmptyArray<{
      azureId: string;
      accessTokenName: AccessTokenName;
      refreshTokenName: RefreshTokenName;
    }>;
    readonly deleteOptions: CookieOptions;
  };
}

export type MsalResponse = AuthenticationResult;

export type AccessTokenName = `${typeof ACCESS_TOKEN_NAME}-${string}` | `__Host-${typeof ACCESS_TOKEN_NAME}-${string}`;
export type RefreshTokenName =
  | `${typeof REFRESH_TOKEN_NAME}-${string}`
  | `__Host-${typeof REFRESH_TOKEN_NAME}-${string}`;

interface CookieOptions {
  readonly maxAge: number;
  readonly httpOnly: true;
  readonly secure: boolean;
  readonly path: '/';
  readonly sameSite: 'strict' | 'none' | undefined;
}

export interface BaseCookieOptions {
  readonly accessTokenOptions: CookieOptions;
  readonly refreshTokenOptions: CookieOptions;
  readonly deleteTokenOptions: CookieOptions;
}

export interface BaseCookieNames {
  readonly accessTokenName: AccessTokenName;
  readonly refreshTokenName: RefreshTokenName;
}

export interface Cookies {
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

export interface B2BResult {
  appName: string;
  appId: string;
  clientId: string;
  token: string;
  isCached: boolean;
  msalResponse: MsalResponse;
  expiresAt: number;
}

export interface OboResult {
  serviceName: string;
  serviceId: string;
  clientId: string;
  accessToken: Cookies['AccessToken'];
  msalResponse: MsalResponse;
}

export type Metadata = {
  audience: string | undefined;
  issuer: string | undefined;
  subject: string | undefined;
  issuedAt: number | undefined;
  expiration: number | undefined;
  uniqueId: string | undefined;
  azureId: string | undefined;
  tenantId: string | undefined;
  roles: string[] | undefined;
  uniqueTokenId: string | undefined;
} & (
  | {
      isApp: true;
      appId: string | undefined;
      name?: undefined;
      email?: undefined;
    }
  | {
      isApp: false;
      appId?: undefined;
      name: string | undefined;
      email: string | undefined;
    }
);
