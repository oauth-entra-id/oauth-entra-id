import { type ZodError, z } from 'zod';
import { base64urlWithDotRegex, encryptedRegex, jwtOrEncryptedRegex, jwtRegex } from './regex';

export const prettifyError = (error: ZodError) =>
  error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', ');

export const zStr = z.string().trim();
export const zUuid = zStr.uuid();
export const zUrl = zStr.url().max(2048);
export const zEmail = zStr.max(320).email();
export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);
export const zEncrypted = zStr.max(4096).regex(encryptedRegex);
export const zJwt = zStr.max(4096).regex(jwtRegex);
export const zJwtOrEncrypted = zStr.max(4096).regex(jwtOrEncryptedRegex);

const zAzure = z.object({
  clientId: zUuid,
  tenantId: z.union([z.literal('common'), zUuid]),
  scopes: z.array(zStr.min(3).max(128)).min(1),
  clientSecret: zStr.min(32),
});

const zCookieConfig = z.object({
  timeUnit: z.enum(['ms', 'sec']).default('sec'),
  disableHttps: z.boolean().default(false),
  disableSameSite: z.boolean().default(false),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

const zOnBehalfOfService = z.object({
  serviceName: zStr.min(1).max(64),
  scope: zStr.min(3).max(128),
  secretKey: zStr.min(16).max(64),
  isHttps: z.boolean(),
  isSameSite: z.boolean(),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

const zAdvanced = z.object({
  loginPrompt: zLoginPrompt.default('sso'),
  allowOtherSystems: z.boolean().default(false),
  debug: z.boolean().default(false),
  cookies: zCookieConfig.default({}),
  onBehalfOfServices: z.array(zOnBehalfOfService).min(1).optional(),
});

export const zConfig = z.object({
  azure: zAzure,
  frontendUrl: z.union([zUrl.transform((url) => [url]), z.array(zUrl).min(1)]),
  serverCallbackUrl: zUrl,
  secretKey: zStr.min(16).max(64),
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
  getTokenOnBehalfOf: z.object({
    accessToken: zJwtOrEncrypted,
    serviceNames: z.array(zStr.min(1).max(64)).min(1),
  }),
};
