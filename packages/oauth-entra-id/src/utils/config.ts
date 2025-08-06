import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { JwksClient } from 'jwks-rsa';
import type { z } from 'zod/v4';
import { $err, $ok, OAuthError, type Result } from '~/error';
import type {
  AccessTokenName,
  Azure,
  B2BApp,
  BaseCookieOptions,
  EncryptionKeys,
  LiteConfig,
  MinimalAzure,
  NonEmptyArray,
  OAuthConfig,
  OAuthSettings,
  OboService,
  RefreshTokenName,
} from '~/types';
import { $getCookieNames, $getCookieOptions } from './cookie-options';
import { $newSecretKeys } from './encrypt';
import { $prettyErr, type zAzure, zConfig, zJwtClientConfig } from './zod';

export function $oauthConfig(configuration: OAuthConfig): Result<{
  azures: NonEmptyArray<Azure>;
  frontendUrls: NonEmptyArray<string>;
  frontendWhitelist: Set<string>;
  serverCallbackUrl: string;
  baseCookieOptions: BaseCookieOptions;
  encryptionKeys: EncryptionKeys;
  msalCryptoProvider: CryptoProvider;
  jwksClient: JwksClient;
  settings: OAuthSettings;
}> {
  const { data: config, error: configError } = zConfig.safeParse(configuration);
  if (configError) {
    return $err({ msg: 'Invalid config', desc: `Failed zConfig schema: ${$prettyErr(configError)}`, status: 500 });
  }

  const frontendUrls = config.frontendUrl as NonEmptyArray<string>;
  const frontendWhitelist = new Set(frontendUrls.map((url) => new URL(url).host));
  const serverHost = new URL(config.serverCallbackUrl).host;

  const { cookies } = config.advanced;
  const baseCookieOptions = $getCookieOptions({
    timeUnit: cookies.timeUnit,
    atExp: cookies.accessTokenExpiry,
    rtExp: cookies.refreshTokenExpiry,
    secure: !cookies.disableSecure && [serverHost, ...frontendWhitelist].every((url) => url.startsWith('https')),
    sameSite: !cookies.disableSameSite && frontendWhitelist.size === 1 ? frontendWhitelist.has(serverHost) : false,
  });

  try {
    const azures = config.azure
      .map((azure) => {
        const cca = $createCca({
          clientId: azure.clientId,
          tenantId: azure.tenantId,
          clientSecret: azure.clientSecret,
        });

        const b2b = $getB2B(azure.b2bApps);
        const obo = $getObo({
          oboServices: azure.downstreamServices,
          secure: baseCookieOptions.accessTokenOptions.secure,
          sameSite: baseCookieOptions.accessTokenOptions.sameSite,
          atExp: config.advanced.cookies.accessTokenExpiry,
          serverHost: serverHost,
        });

        const cookieNames = $getCookieNames(azure.clientId, baseCookieOptions.accessTokenOptions.secure);

        return {
          clientId: azure.clientId,
          tenantId: azure.tenantId,
          scopes: azure.scopes as NonEmptyArray<string>,
          cookiesNames: cookieNames,
          cca: cca,
          b2b: b2b.map,
          b2bNames: b2b.names,
          obo: obo.map,
          oboNames: obo.names,
        } satisfies Azure;
      })
      .filter((azure) => !!azure) as NonEmptyArray<Azure>;

    if (azures.length === 0) {
      throw new OAuthError({
        msg: 'No valid Azure configurations found',
        desc: 'Ensure at least one Azure configuration is provided in the config file.',
        status: 500,
      });
    }

    const { secretKeys: encryptionKeys, error: secretKeysError } = $newSecretKeys(config.advanced.cryptoType, {
      accessToken: `access-token-${config.encryptionKey}`,
      refreshToken: `refresh-token-${config.encryptionKey}`,
      state: `state-${config.encryptionKey}`,
      ticket: `ticket-${config.encryptionKey}`,
    });
    if (secretKeysError) return $err(secretKeysError);

    const msalCryptoProvider = new CryptoProvider();

    const { jwksClient, error: jwksError } = $createJwks(azures.length === 1 ? azures[0].tenantId : 'common');
    if (jwksError) return $err(jwksError);

    const settings: OAuthSettings = {
      loginPrompt: config.advanced.loginPrompt,
      acceptB2BRequests: config.advanced.acceptB2BRequests,
      cryptoType: config.advanced.cryptoType,
      disableCompression: config.advanced.disableCompression,
      b2bApps: azures.some((azure) => azure.b2bNames)
        ? (azures
            .map((azure) => ({ azureId: azure.clientId, names: azure.b2bNames }))
            .filter((azure) => !!azure) as NonEmptyArray<{ azureId: string; names: NonEmptyArray<string> }>)
        : undefined,
      downstreamServices: azures.some((azure) => azure.oboNames)
        ? (azures
            .map((azure) => ({ azureId: azure.clientId, names: azure.oboNames }))
            .filter((azure) => !!azure) as NonEmptyArray<{ azureId: string; names: NonEmptyArray<string> }>)
        : undefined,
      azures: azures.map((azure) => ({ azureId: azure.clientId, tenantId: azure.tenantId })) as NonEmptyArray<{
        azureId: string;
        tenantId: string;
      }>,
      cookies: {
        timeUnit: config.advanced.cookies.timeUnit,
        isSecure: baseCookieOptions.accessTokenOptions.secure,
        isSameSite: baseCookieOptions.accessTokenOptions.sameSite === 'strict',
        accessTokenName: azures[0].cookiesNames.accessTokenName,
        accessTokenExpiry: config.advanced.cookies.accessTokenExpiry,
        refreshTokenName: azures[0].cookiesNames.refreshTokenName,
        refreshTokenExpiry: config.advanced.cookies.refreshTokenExpiry,
        cookieNames: azures.map((azure) => ({
          azureId: azure.clientId,
          accessTokenName: azure.cookiesNames.accessTokenName,
          refreshTokenName: azure.cookiesNames.refreshTokenName,
        })) as NonEmptyArray<{ azureId: string; accessTokenName: AccessTokenName; refreshTokenName: RefreshTokenName }>,
        deleteOptions: baseCookieOptions.deleteTokenOptions,
      },
    };

    return $ok({
      azures: azures,
      frontendUrls: frontendUrls,
      frontendWhitelist: frontendWhitelist,
      serverCallbackUrl: config.serverCallbackUrl,
      baseCookieOptions: baseCookieOptions,
      encryptionKeys: encryptionKeys,
      msalCryptoProvider: msalCryptoProvider,
      jwksClient: jwksClient,
      settings: settings,
    });
  } catch (error) {
    if (error instanceof OAuthError) return $err(error);
    return $err({
      msg: 'Failed to create Azure configurations',
      desc: `Error creating Azure configurations: ${error instanceof Error ? error.message : typeof error === 'string' ? error : String(error)}`,
      status: 500,
    });
  }
}

export function $jwtClientConfig(config: LiteConfig): Result<{
  azure: MinimalAzure;
  jwksClient: JwksClient;
}> {
  const { data: parsedConfig, error: configError } = zJwtClientConfig.safeParse(config);
  if (configError) {
    return $err({
      msg: 'Invalid config',
      desc: `Failed zJwtClientConfig schema: ${$prettyErr(configError)}`,
      status: 500,
    });
  }

  const { jwksClient, error: jwksError } = $createJwks(parsedConfig.azure.tenantId);
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
  try {
    const b2b = $getB2B(parsedConfig.azure.b2bApps);
    const cca = $createCca({
      clientId: parsedConfig.azure.clientId,
      tenantId: parsedConfig.azure.tenantId,
      clientSecret: parsedConfig.azure.clientSecret,
    });

    return $ok({
      azure: {
        clientId: parsedConfig.azure.clientId,
        tenantId: parsedConfig.azure.tenantId,
        cca: cca,
        b2bApps: b2b.map,
      },
      jwksClient: jwksClient,
    });
  } catch (error) {
    if (error instanceof OAuthError) return $err(error);
    return $err({
      msg: 'Failed to create Azure configuration',
      desc: `Error creating Azure configuration for clientId ${parsedConfig.azure.clientId} and tenantId ${parsedConfig.azure.tenantId}: ${error instanceof Error ? error.message : typeof error === 'string' ? error : String(error)}`,
      status: 500,
    });
  }
}

function $createJwks(tenantId: string): Result<{ jwksClient: JwksClient }> {
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
    return $err({
      msg: 'Failed to create JWKS client',
      desc: `Error creating JWKS client for tenant ${tenantId}: ${error instanceof Error ? error.message : typeof error === 'string' ? error : String(error)}`,
      status: 500,
    });
  }
}

function $createCca(params: {
  clientId: string;
  tenantId: string;
  clientSecret: string;
}): ConfidentialClientApplication {
  try {
    return new ConfidentialClientApplication({
      auth: {
        clientId: params.clientId,
        authority: `https://login.microsoftonline.com/${params.tenantId}`,
        clientSecret: params.clientSecret,
      },
    });
  } catch (error) {
    throw new OAuthError({
      msg: 'Failed to create Confidential Client Application',
      desc: `Error creating Confidential Client Application for clientId ${params.clientId} and tenantId ${params.tenantId}: ${error instanceof Error ? error.message : typeof error === 'string' ? error : String(error)}`,
      status: 500,
    });
  }
}

function $getB2B(b2bApps: z.infer<typeof zAzure>['b2bApps']): {
  map: Map<string, B2BApp> | undefined;
  names: NonEmptyArray<string> | undefined;
} {
  if (!b2bApps) return { map: undefined, names: undefined };

  const map = new Map<string, B2BApp>(
    b2bApps.map((app) => [
      app.appName,
      { appName: app.appName, scope: app.scope, token: null, exp: null, aud: null, msalResponse: null },
    ]),
  );
  const names = Array.from(map.keys());

  if (names.length !== b2bApps.length) {
    throw new OAuthError({ msg: 'Invalid config', desc: 'B2B has duplicates', status: 500 });
  }

  return { map, names: names as NonEmptyArray<string> };
}

function $getObo({
  oboServices,
  secure,
  sameSite,
  atExp,
  serverHost,
}: {
  oboServices: z.infer<typeof zAzure>['downstreamServices'];
  secure: boolean;
  sameSite: 'strict' | 'none' | undefined;
  atExp: number;
  serverHost: string;
}): { map: Map<string, OboService> | undefined; names: NonEmptyArray<string> | undefined } {
  if (!oboServices) return { map: undefined, names: undefined };

  const map = new Map<string, OboService>(
    oboServices.map((service) => {
      const serviceUrlHosts = new Set(service.serviceUrl.map((url) => new URL(url).host));
      return [
        service.serviceName,
        {
          serviceName: service.serviceName,
          scope: service.scope,
          encryptionKey: service.encryptionKey,
          cryptoType: service.cryptoType,
          isSecure: secure && service.serviceUrl.every((url) => url.startsWith('https')),
          isSamesite: sameSite === 'strict' && serviceUrlHosts.size === 1 && serviceUrlHosts.has(serverHost),
          atExp: service.accessTokenExpiry ?? atExp,
        },
      ];
    }),
  );

  const names = Array.from(map.keys());

  if (names.length !== oboServices.length) {
    throw new OAuthError({ msg: 'Invalid config', desc: 'OBO has duplicates', status: 500 });
  }

  return { map, names: names as NonEmptyArray<string> };
}
