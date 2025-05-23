import { type ZodError, z } from 'zod';
import { base64urlWithDotRegex, encryptedRegex, jwtOrEncryptedRegex, jwtRegex } from './regex';

export const prettifyError = (error: ZodError) =>
  error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', ');

export const zStr = z.string().trim();
export const zUuid = zStr.uuid();
export const zUrl = zStr.url().max(2048);
export const zEmail = zStr.max(320).email();
export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);
export const zSessionType = z.enum(['cookie-session', 'bearer-token']);
export const zEncrypted = zStr.max(4096).regex(encryptedRegex);
export const zJwt = zStr.max(4096).regex(jwtRegex);
export const zJwtOrEncrypted = zStr.max(4096).regex(jwtOrEncryptedRegex);
export const zScope = zStr.min(3).max(128);
export const zSecretKey = zStr.min(16).max(64);
export const zServiceName = zStr.min(1).max(64);

const zAzure = z.object({
  clientId: zUuid,
  tenantId: z.union([z.literal('common'), zUuid]),
  scopes: z.array(zScope).min(1),
  clientSecret: zStr.min(32),
});

const zB2BApp = z.object({
  appName: zServiceName,
  scope: zScope,
});

const zCookiesConfig = z.object({
  timeUnit: z.enum(['ms', 'sec']).default('sec'),
  disableHttps: z.boolean().default(false),
  disableSameSite: z.boolean().default(false),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

const zDownstreamService = z.object({
  serviceName: zServiceName,
  scope: zScope,
  secretKey: zSecretKey,
  isHttps: z.boolean().optional(),
  isSameOrigin: z.boolean().optional(),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

const zDownstreamConfig = z.object({
  areHttps: z.boolean(),
  areSameOrigin: z.boolean(),
  services: z.array(zDownstreamService).min(1),
});

const zAdvanced = z.object({
  loginPrompt: zLoginPrompt.default('sso'),
  sessionType: zSessionType.default('cookie-session'),
  acceptB2BRequests: z.boolean().default(false),
  b2bTargetedApps: z.array(zB2BApp).min(1).optional(),
  debug: z.boolean().default(false),
  cookies: zCookiesConfig.default({}),
  downstreamServices: zDownstreamConfig.optional(),
});

export const zConfig = z.object({
  azure: zAzure,
  frontendUrl: z.union([zUrl.transform((url) => [url]), z.array(zUrl).min(1)]),
  serverCallbackUrl: zUrl,
  secretKey: zSecretKey,
  advanced: zAdvanced.default({}),
});

export const zState = z.object({
  frontendUrl: zUrl,
  codeVerifier: zStr.max(256),
  nonce: zUuid,
  email: zEmail.optional(),
  prompt: z.enum(['login', 'select_account']).optional(),
});

export const zAuthParams = z.object({
  state: zStr.max(512),
  nonce: zUuid,
  loginHint: zStr.max(320).optional(),
  prompt: zStr.max(10).optional(),
  codeVerifier: zStr.max(128),
});

export const zAccessTokenStructure = z.object({
  at: zJwt,
  inj: z.record(zStr, z.any()).optional(),
});

export const zMethods = {
  getAuthUrl: z
    .object({
      loginPrompt: zLoginPrompt.optional(),
      email: zEmail.optional(),
      frontendUrl: zUrl.optional(),
    })
    .default({}),
  getTokenByCode: z.object({
    code: zStr.max(2048).regex(base64urlWithDotRegex),
    state: zEncrypted,
  }),
  getLogoutUrl: z
    .object({
      frontendUrl: zUrl.optional(),
    })
    .default({}),
  getB2BToken: z.union([
    z
      .object({
        appName: zServiceName,
      })
      .transform((data) => ({
        appsNames: [data.appName],
      })),
    z.object({
      appsNames: z.array(zServiceName).min(1),
    }),
  ]),
  getTokenOnBehalfOf: z.union([
    z
      .object({
        accessToken: zJwtOrEncrypted,
        serviceName: zServiceName,
      })
      .transform((data) => ({
        accessToken: data.accessToken,
        servicesNames: [data.serviceName],
      })),
    z.object({
      accessToken: zJwtOrEncrypted,
      servicesNames: z.array(zServiceName).min(1),
    }),
  ]),
};
