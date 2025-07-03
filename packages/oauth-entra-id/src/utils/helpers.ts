import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { JwksClient } from 'jwks-rsa';
import type { z } from 'zod/v4';
import type { OAuthProvider } from '~/core';
import { $err, $ok, type HttpErrorCodes, OAuthError, type Result } from '~/error';
import type {
  Azure,
  B2BApp,
  B2BResult,
  Cookies,
  EncryptionKeys,
  LiteConfig,
  LoginPrompt,
  MinimalAzure,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  OboService,
} from '~/types';
import { $cookieOptions } from './cookie-options';
import { $createSecretKeys } from './crypto/encrypt';
import { $getAudienceAndExpiry } from './crypto/jwt';
import { $prettyErr, zConfig, zJwtClientConfig, zMethods } from './zod';

/** Time skew in seconds to account for clock drift between client and server */
export const TIME_SKEW = 5 * 60;

function $createJwksClient(tenantId: string): Result<{ jwksClient: JwksClient }> {
  try {
    return $ok({
      jwksClient: new JwksClient({
        cache: true,
        cacheMaxEntries: 5,
        cacheMaxAge: 10 * 60 * 1000,
        jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
      }),
    });
  } catch (error) {
    return $err('misconfiguration', {
      error: 'Failed to create JWKS client',
      description: `Error creating JWKS client for tenant ${tenantId}: ${error instanceof Error ? error.message : String(error)}`,
      status: 500,
    });
  }
}

function $createConfidentialClientApplication(params: {
  clientId: string;
  tenantId: string;
  clientSecret: string;
}): Result<{ cca: ConfidentialClientApplication }> {
  try {
    return $ok({
      cca: new ConfidentialClientApplication({
        auth: {
          clientId: params.clientId,
          authority: `https://login.microsoftonline.com/${params.tenantId}`,
          clientSecret: params.clientSecret,
        },
      }),
    });
  } catch (error) {
    return $err('misconfiguration', {
      error: 'Failed to create Confidential Client Application',
      description: `Error creating Confidential Client Application for clientId ${params.clientId} and tenantId ${params.tenantId}: ${
        error instanceof Error ? error.message : String(error)
      }`,
      status: 500,
    });
  }
}

export function oauthProviderHelper(config: OAuthConfig): Result<{
  azure: Azure;
  frontendUrls: NonEmptyArray<string>;
  frontendWhitelist: Set<string>;
  serverCallbackUrl: string;
  defaultCookieOptions: Cookies['DefaultCookieOptions'];
  encryptionKeys: EncryptionKeys;
  b2bMap: Map<string, B2BApp> | undefined;
  oboMap: Map<string, OboService> | undefined;
  msalCryptoProvider: CryptoProvider;
  jwksClient: JwksClient;
  settings: OAuthSettings;
}> {
  const { data: parsedConfig, error: configError } = zConfig.safeParse(config);
  if (configError) {
    return $err('misconfiguration', { error: 'Invalid config', description: $prettyErr(configError), status: 500 });
  }

  const frontendUrls: NonEmptyArray<string> = parsedConfig.frontendUrl as NonEmptyArray<string>;
  const frontendHosts = new Set(frontendUrls.map((url) => new URL(url).host));
  const serverHost = new URL(parsedConfig.serverCallbackUrl).host;
  const defaultCookieOptions = $cookieOptions({
    clientId: parsedConfig.azure.clientId,
    timeUnit: parsedConfig.advanced.cookies.timeUnit,
    atMaxAge: parsedConfig.advanced.cookies.accessTokenMaxAge,
    rtMaxAge: parsedConfig.advanced.cookies.refreshTokenMaxAge,
    secure:
      !parsedConfig.advanced.cookies.disableSecure &&
      [serverHost, ...frontendHosts].every((url) => url.startsWith('https')),
    sameSite:
      !parsedConfig.advanced.cookies.disableSameSite && frontendHosts.size === 1
        ? frontendHosts.has(serverHost)
        : false,
  });

  const { secretKeys: encryptionKeys, error: secretKeysError } = $createSecretKeys(parsedConfig.advanced.cryptoType, {
    accessToken: `access-token-${parsedConfig.encryptionKey}`,
    refreshToken: `refresh-token-${parsedConfig.encryptionKey}`,
    state: `state-${parsedConfig.encryptionKey}`,
    ticket: `ticket-${parsedConfig.encryptionKey}`,
  });
  if (secretKeysError) return $err(secretKeysError);

  const { b2bMap, b2bNames, error: b2bMapError } = $getB2BInfo(parsedConfig.azure.b2bApps);
  if (b2bMapError) return $err(b2bMapError);

  const {
    oboMap,
    oboNames,
    error: oboMapError,
  } = $getOboInfo(parsedConfig.azure.downstreamServices, defaultCookieOptions.accessToken.options, serverHost);
  if (oboMapError) return $err(oboMapError);

  const { cca, error: ccaError } = $createConfidentialClientApplication({
    clientId: parsedConfig.azure.clientId,
    tenantId: parsedConfig.azure.tenantId,
    clientSecret: parsedConfig.azure.clientSecret,
  });
  if (ccaError) return $err(ccaError);

  const azure: Azure = {
    clientId: parsedConfig.azure.clientId,
    tenantId: parsedConfig.azure.tenantId,
    scopes: parsedConfig.azure.scopes as NonEmptyArray<string>,
    cca: cca,
    b2bApps: b2bMap,
    oboApps: oboMap,
  };

  const msalCryptoProvider = new CryptoProvider();

  const { jwksClient, error: jwksError } = $createJwksClient(parsedConfig.azure.tenantId);
  if (jwksError) return $err(jwksError);

  const settings: OAuthSettings = {
    loginPrompt: parsedConfig.advanced.loginPrompt,
    acceptB2BRequests: parsedConfig.advanced.acceptB2BRequests,
    cryptoType: parsedConfig.advanced.cryptoType,
    disableCompression: parsedConfig.advanced.disableCompression,
    b2bApps: b2bNames,
    downstreamServices: oboNames,
    cookies: {
      timeUnit: parsedConfig.advanced.cookies.timeUnit,
      isSecure: defaultCookieOptions.accessToken.options.secure,
      isSameSite: defaultCookieOptions.accessToken.options.sameSite === 'strict',
      accessTokenName: defaultCookieOptions.accessToken.name,
      refreshTokenName: defaultCookieOptions.refreshToken.name,
      accessTokenMaxAge: defaultCookieOptions.accessToken.options.maxAge,
      refreshTokenMaxAge: defaultCookieOptions.refreshToken.options.maxAge,
    },
  };

  return $ok({
    azure: azure,
    frontendUrls: frontendUrls,
    frontendWhitelist: frontendHosts,
    serverCallbackUrl: parsedConfig.serverCallbackUrl,
    defaultCookieOptions: defaultCookieOptions,
    encryptionKeys: encryptionKeys,
    b2bMap: b2bMap,
    oboMap: oboMap,
    msalCryptoProvider: msalCryptoProvider,
    jwksClient: jwksClient,
    settings: settings,
  });
}

export function $jwtClientHelper(config: LiteConfig): Result<{
  azure: MinimalAzure;
  jwksClient: JwksClient;
}> {
  const { data: parsedConfig, error: configError } = zJwtClientConfig.safeParse(config);
  if (configError) {
    return $err('misconfiguration', { error: 'Invalid config', description: $prettyErr(configError), status: 500 });
  }

  const { jwksClient, error: jwksError } = $createJwksClient(parsedConfig.azure.tenantId);
  if (jwksError) return $err(jwksError);

  if (!('clientSecret' in parsedConfig.azure)) {
    return $ok({
      azure: {
        clientId: parsedConfig.azure.clientId,
        tenantId: parsedConfig.azure.tenantId,
        cca: undefined,
        b2bApps: undefined,
      },
      jwksClient: jwksClient,
    });
  }

  const { b2bMap, error: b2bMapError } = $getB2BInfo(parsedConfig.azure.b2bApps);
  if (b2bMapError) return $err(b2bMapError);

  const { cca, error: ccaError } = $createConfidentialClientApplication({
    clientId: parsedConfig.azure.clientId,
    tenantId: parsedConfig.azure.tenantId,
    clientSecret: parsedConfig.azure.clientSecret,
  });
  if (ccaError) return $err(ccaError);

  return $ok({
    azure: {
      clientId: parsedConfig.azure.clientId,
      tenantId: parsedConfig.azure.tenantId,
      cca: cca,
      b2bApps: b2bMap,
    },
    jwksClient: jwksClient,
  });
}

function $getB2BInfo(
  b2bApps: z.infer<typeof zConfig>['azure']['b2bApps'],
): Result<{ b2bMap: Map<string, B2BApp> | undefined; b2bNames: string[] | undefined }> {
  if (!b2bApps) return $ok({ b2bMap: undefined, b2bNames: undefined });

  const b2bMap = new Map(
    b2bApps.map((app) => [
      app.appName,
      {
        appName: app.appName,
        scope: app.scope,
        token: null,
        exp: null,
        aud: null,
        msalResponse: null,
      } satisfies B2BApp,
    ]),
  );
  const b2bNames = Array.from(b2bMap.keys());

  if (b2bNames.length !== b2bApps.length) {
    return $err('misconfiguration', { error: 'Invalid config', description: 'B2B has duplicates', status: 500 });
  }

  return $ok({ b2bMap, b2bNames });
}

function $getOboInfo(
  oboServices: z.infer<typeof zConfig>['azure']['downstreamServices'],
  accessTokenOptions: Cookies['DefaultCookieOptions']['accessToken']['options'],
  serverHost: string,
): Result<{ oboMap: Map<string, OboService> | undefined; oboNames: string[] | undefined }> {
  if (!oboServices) return $ok({ oboMap: undefined, oboNames: undefined });

  const oboMap = new Map(
    oboServices.map((service) => {
      const serviceUrlHosts = new Set(service.serviceUrl.map((url) => new URL(url).host));
      return [
        service.serviceName,
        {
          serviceName: service.serviceName,
          scope: service.scope,
          encryptionKey: service.encryptionKey,
          cryptoType: service.cryptoType,
          isSecure: accessTokenOptions.secure && service.serviceUrl.every((url) => url.startsWith('https')),
          isSamesite:
            accessTokenOptions.sameSite === 'strict' && serviceUrlHosts.size === 1 && serviceUrlHosts.has(serverHost),
          atMaxAge: service.accessTokenMaxAge ?? accessTokenOptions.maxAge,
        } satisfies OboService,
      ];
    }),
  );

  const oboNames = Array.from(oboMap.keys());

  if (oboNames.length !== oboServices.length) {
    return $err('misconfiguration', { error: 'Invalid config', description: 'OBO has duplicates', status: 500 });
  }

  return $ok({ oboMap, oboNames });
}

export async function $mapAndFilter<T, R>(items: T[], callback: (item: T) => Promise<R | null>): Promise<R[]> {
  return (
    await Promise.all(
      items.map(async (item) => {
        try {
          return await callback(item);
        } catch {
          return null;
        }
      }),
    )
  ).filter((result): result is Awaited<R> => !!result);
}

export function $coreErrors(
  err: unknown,
  method: {
    [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
  }[keyof OAuthProvider],
  defaultStatusCode: HttpErrorCodes = 500,
) {
  if (err instanceof OAuthError) {
    return $err(err.type, { error: err.message, description: err.description, status: err.statusCode });
  }

  if (err instanceof Error) {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err.message}, stack : ${err.stack}`,
      status: defaultStatusCode,
    });
  }

  if (typeof err === 'string') {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err}`,
      status: defaultStatusCode,
    });
  }

  return $err('internal', {
    error: 'Unknown error',
    description: `method: ${method}, error: ${JSON.stringify(err)}`,
    status: defaultStatusCode,
  });
}

export function $transformToMsalPrompt(
  prompt: LoginPrompt,
  email: string | undefined,
): 'login' | 'select_account' | undefined {
  if (email || prompt === 'email') return 'login';
  if (prompt === 'select-account') return 'select_account';
  return undefined;
}

export async function $tryGetB2BToken(
  params: { app: string } | { apps: string[] },
  b2bApps: Map<string, B2BApp> | undefined,
  cca: ConfidentialClientApplication | undefined,
): Promise<Result<{ result: B2BResult } | { results: B2BResult[] }>> {
  if (!b2bApps || !cca) {
    return $err('misconfiguration', { error: 'B2B apps not configured', status: 500 });
  }

  const { data: parsedParams, error: paramsError } = zMethods.tryGetB2BToken.safeParse(params);
  if (paramsError) return $err('bad_request', { error: 'Invalid params', description: $prettyErr(paramsError) });

  const apps = parsedParams.apps.map((app) => b2bApps.get(app)).filter((app) => !!app);
  if (!apps || apps.length === 0) {
    return $err('bad_request', { error: 'Invalid params', description: 'B2B app not found' });
  }

  try {
    const results = await $mapAndFilter(apps, async (app) => {
      if (app.token && app.exp > Date.now() / 1000) {
        return {
          appName: app.appName,
          clientId: app.aud,
          token: app.token,
          msalResponse: app.msalResponse,
          isCached: true,
          expiresAt: app.exp,
        } satisfies B2BResult;
      }

      const msalResponse = await cca.acquireTokenByClientCredential({ scopes: [app.scope], skipCache: true });
      if (!msalResponse) return null;

      const { aud, exp, error: audError } = $getAudienceAndExpiry(msalResponse.accessToken);
      if (audError) return null;

      b2bApps.set(app.appName, {
        appName: app.appName,
        scope: app.scope,
        token: msalResponse.accessToken,
        exp: exp - TIME_SKEW,
        aud: aud,
        msalResponse: msalResponse,
      } satisfies B2BApp);

      return {
        appName: app.appName,
        clientId: aud,
        token: msalResponse.accessToken,
        msalResponse: msalResponse,
        isCached: false,
        expiresAt: 0,
      } satisfies B2BResult;
    });

    if (!results || results.length === 0) {
      return $err('internal', { error: 'Failed to get B2B token', status: 500 });
    }

    return $ok('app' in params ? { result: results[0] as B2BResult } : { results });
  } catch (err) {
    return $coreErrors(err, 'tryGetB2BToken');
  }
}
