import { type ZodError, z } from 'zod';
import { base64urlWithDotRegex, encryptedRegex, jwtRegex, tokenRegex } from './regex';

export function prettifyError(error: ZodError) {
  return error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', ');
}

export const zStr = z.string().trim();
export const zUuid = zStr.uuid();
export const zUrl = zStr.url().max(2048);
export const zEmail = zStr.max(320).email();
export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);
export const zEncrypted = zStr.max(4096).regex(encryptedRegex);
export const zJwt = zStr.max(4096).regex(jwtRegex);
export const zToken = zStr.max(4096).regex(tokenRegex);
const zSecretKey = zStr.min(16).max(64);
const zScope = zStr.min(3).max(128);
const zScopes = z.array(zScope).min(1);
const zServiceName = zStr.min(1).max(64);

const zOnBehalfOfService = z.object({
  serviceName: zServiceName,
  scope: zScope,
  secretKey: zSecretKey,
  isHttps: z.boolean(),
  isSameSite: z.boolean(),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

export const zConfig = z.object({
  azure: z.object({
    clientId: zUuid,
    tenantId: z.union([z.literal('common'), zUuid]),
    scopes: zScopes,
    clientSecret: zStr.min(32),
  }),
  frontendUrl: z.union([zUrl.transform((url) => [url]), z.array(zUrl).min(1)]),
  serverCallbackUrl: zUrl,
  secretKey: zSecretKey,
  advanced: z
    .object({
      loginPrompt: zLoginPrompt.default('sso'),
      allowOtherSystems: z.boolean().default(false),
      debug: z.boolean().default(false),
      cookies: z
        .object({
          timeUnit: z.enum(['ms', 'sec']).default('ms'),
          disableHttps: z.boolean().default(false),
          disableSameSite: z.boolean().default(false),
          accessTokenExpiry: z.number().positive().default(3600),
          refreshTokenExpiry: z.number().min(3600).default(2592000),
        })
        .default({}),
      onBehalfOfServices: z.array(zOnBehalfOfService).min(1).optional(),
    })
    .default({}),
});

export const zGetAuthUrl = z
  .object({
    loginPrompt: zLoginPrompt.optional(),
    email: zEmail.optional(),
    frontendUrl: zUrl.optional(),
  })
  .default({});

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

export const zGetTokenByCode = z.object({
  code: zStr.max(2048).regex(base64urlWithDotRegex),
  state: zEncrypted,
});

export const zGetLogoutUrl = z
  .object({
    frontendUrl: zUrl.optional(),
  })
  .default({});

export const zGetTokenOnBehalfOf = z.object({
  accessToken: zToken,
  serviceNames: z.array(zServiceName).min(1),
});
