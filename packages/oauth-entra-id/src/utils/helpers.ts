import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { JwksClient } from 'jwks-rsa';
import type { z } from 'zod/v4';
import type { OAuthProvider } from '~/core';
import { $err, $ok, type HttpErrorCodes, OAuthError, type Result } from '~/error';
import type {
  Azure,
  B2BApp,
  Cookies,
  EncryptionKeys,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  OboService,
} from '~/types';
import { $cookieOptions } from './cookie-options';
import { $createSecretKeys } from './crypto/encrypt';
import { $prettyErr, zConfig } from './zod';

export function $constructorHelper(config: OAuthConfig): Result<{
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

  const azure: Azure = {
    clientId: parsedConfig.azure.clientId,
    tenantId: parsedConfig.azure.tenantId,
    scopes: parsedConfig.azure.scopes as NonEmptyArray<string>,
    cca: new ConfidentialClientApplication({
      auth: {
        clientId: parsedConfig.azure.clientId,
        authority: `https://login.microsoftonline.com/${parsedConfig.azure.tenantId}`,
        clientSecret: parsedConfig.azure.clientSecret,
      },
    }),
  };

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

  const msalCryptoProvider = new CryptoProvider();

  const jwksClient = new JwksClient({
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 10 * 60 * 1000, // 10 minutes
    jwksUri: `https://login.microsoftonline.com/${parsedConfig.azure.tenantId}/discovery/v2.0/keys`,
  });

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

function $getB2BInfo(
  b2bApps: z.infer<typeof zConfig>['azure']['b2bApps'],
): Result<{ b2bMap: Map<string, B2BApp> | undefined; b2bNames: string[] | undefined }> {
  if (!b2bApps) return $ok({ b2bMap: undefined, b2bNames: undefined });

  const b2bMap = new Map(b2bApps.map((app) => [app.appName, app]));
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
