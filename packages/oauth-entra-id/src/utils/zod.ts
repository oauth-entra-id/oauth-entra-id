import { ENCRYPTED_REGEX } from 'cipher-kit';
import { z } from 'zod';

export function $isStr(value: unknown): value is string {
  return value !== null && value !== undefined && typeof value === 'string' && value.trim().length > 0;
}

export function $isObj(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    value !== undefined &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

export const base64urlWithDotRegex = /^[A-Za-z0-9._-]+$/;

export const zStr = z.string().trim();
export const zUuid = z.uuid();
export const zUrl = z.url();
export const zEmail = z.email({ pattern: z.regexes.html5Email });
export const zBase64 = z.base64url();
export const zLooseBase64 = zStr.regex(base64urlWithDotRegex);

export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);
export const zTimeUnit = z.enum(['ms', 'sec']);
export const zCryptoType = z.enum(['web-api', 'node']);
export const zAccessTokenExpiry = z.number().positive();
export const zRefreshTokenExpiry = z.number().min(3600);
const zOneOrMoreUrls = z.union([zUrl.max(2048).transform((url) => [url]), z.array(zUrl.max(2048)).min(1)]);

export const zEncrypted = zStr.max(4096).regex(ENCRYPTED_REGEX.general);
export const zJwt = z.jwt().max(4096);

export const zTenantId = z.union([z.literal('common'), zUuid]);
export const zScope = zStr.min(3).max(128);
export const zEncryptionKey = zStr.min(32).max(64);
export const zServiceName = zStr.min(1).max(64);

export const zAzure = z.object({
  clientId: zUuid,
  tenantId: zTenantId,
  scopes: z.array(zScope).min(1),
  clientSecret: zStr.min(32).max(128),
  downstreamServices: z
    .array(
      z.object({
        serviceName: zServiceName,
        scope: zScope,
        serviceUrl: zOneOrMoreUrls,
        encryptionKey: zEncryptionKey,
        cryptoType: zCryptoType.default('node'),
        accessTokenExpiry: zAccessTokenExpiry.default(3600),
      }),
    )
    .min(1)
    .optional(),
  b2bApps: z
    .array(z.object({ appName: zServiceName, scope: zScope }))
    .min(1)
    .optional(),
});

export const zConfig = z.object({
  azure: z.union([zAzure.transform((azure) => [azure]), z.array(zAzure).min(1)]),
  frontendUrl: zOneOrMoreUrls,
  serverCallbackUrl: zUrl.max(2048),
  encryptionKey: zEncryptionKey,
  advanced: z
    .object({
      loginPrompt: zLoginPrompt.default('sso'),
      acceptB2BRequests: z.boolean().default(false),
      cryptoType: zCryptoType.default('node'),
      disableCompression: z.boolean().default(false),
      cookies: z
        .object({
          timeUnit: zTimeUnit.default('sec'),
          disableSecure: z.boolean().default(false),
          disableSameSite: z.boolean().default(false),
          accessTokenExpiry: zAccessTokenExpiry.default(3600),
          refreshTokenExpiry: zRefreshTokenExpiry.default(2592000),
        })
        .prefault({}),
    })
    .prefault({}),
});

const zJwtClientConfigBase = z.object({ clientId: zUuid, tenantId: zTenantId });

export const zJwtClientConfig = z.object({
  azure: z.union([
    zJwtClientConfigBase,
    zJwtClientConfigBase.extend({
      clientSecret: zStr.min(32).max(128),
      b2bApps: z
        .array(z.object({ appName: zServiceName, scope: zScope }))
        .min(1)
        .optional(),
    }),
  ]),
});

export const zState = z.object({
  azureId: zUuid,
  frontendUrl: zUrl.max(2048),
  codeVerifier: zStr.max(256),
  nonce: zUuid,
  email: zEmail.max(320).optional(),
  prompt: z.enum(['login', 'select_account']).optional(),
  ticketId: zUuid,
});

export const zInjectedData = z.record(zStr, z.any()).optional();

export const zAtStruct = z.object({
  at: zJwt,
  inj: zStr.max(4096).optional(),
  exp: z.number().int().positive(),
  aid: zUuid,
});

export const zRtStruct = z.object({
  rt: zLooseBase64,
  exp: z.number().int().positive(),
  aid: zUuid,
});

export const zMethods = {
  getAuthUrl: z
    .object({
      loginPrompt: zLoginPrompt.optional(),
      email: zEmail.max(320).optional(),
      frontendUrl: zUrl.max(2048).optional(),
      azureId: zUuid.optional(),
    })
    .default({}),
  getTokenByCode: z.object({
    code: zStr.max(2048).regex(base64urlWithDotRegex),
    state: zEncrypted,
  }),
  getLogoutUrl: z
    .object({
      frontendUrl: zUrl.max(2048).optional(),
      azureId: zUuid.optional(),
    })
    .default({}),
  tryGetB2BToken: z.union([
    z
      .object({
        azureId: zUuid.optional(),
        app: zServiceName,
      })
      .transform((data) => ({
        azureId: data.azureId,
        apps: [data.app],
      })),
    z.object({
      azureId: zUuid.optional(),
      apps: z.array(zServiceName).min(1),
    }),
  ]),
  getTokenOnBehalfOf: z.union([
    z
      .object({
        accessToken: z.union([zJwt, zEncrypted]),
        service: zServiceName,
        azureId: zUuid.optional(),
      })
      .transform((data) => ({
        accessToken: data.accessToken,
        services: [data.service],
        azureId: data.azureId,
      })),
    z.object({
      accessToken: z.union([zJwt, zEncrypted]),
      services: z.array(zServiceName).min(1),
      azureId: zUuid.optional(),
    }),
  ]),
};
