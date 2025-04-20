import { type ZodError, z } from 'zod';
import { base64urlWithDotRegex, encryptedRegex, jwtRegex } from './regexes';

export function prettifyError(error: ZodError) {
  return error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join(', ');
}

export const zStr = z.string().trim();

export const zUuid = zStr.uuid();

export const zUrl = zStr.url().max(2048);

export const zEmail = zStr.max(320).email();

export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);

const zAdvanced = z
  .object({
    loginPrompt: zLoginPrompt.default('sso'),
    disableHttps: z.boolean().default(false),
    disableSameSite: z.boolean().default(false),
    cookieTimeFrame: z.enum(['ms', 'sec']).default('ms'),
    accessTokenExpiry: z.number().positive().default(3600),
    refreshTokenExpiry: z.number().min(3600).default(2592000),
    debug: z.boolean().default(false),
  })
  .default({
    loginPrompt: 'sso',
    disableHttps: false,
    disableSameSite: false,
    cookieTimeFrame: 'ms',
    accessTokenExpiry: 3600,
    refreshTokenExpiry: 2592000,
    debug: false,
  });

export const zConfig = z.object({
  azure: z.object({
    clientId: zUuid,
    tenantId: zUuid,
    scopes: z.array(zStr.min(3)).min(1),
    secret: zStr.min(32),
  }),
  frontendUrl: z.union([zUrl.transform((url) => [url]), z.array(zUrl).min(1)]),
  serverCallbackUrl: zUrl,
  secretKey: zStr.min(16).max(64),
  advanced: zAdvanced,
});

export const zEncrypted = zStr.max(4096).regex(encryptedRegex);

export const zJwt = zStr.max(4096).regex(jwtRegex);

export const zGetAuthUrl = z.object({
  loginPrompt: zLoginPrompt.optional(),
  email: zEmail.optional(),
  frontendUrl: zUrl.optional(),
});

export const zGetTokenByCode = z.object({
  code: zStr.max(2048).regex(base64urlWithDotRegex),
  state: zEncrypted,
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
