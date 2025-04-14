import { z } from 'zod';

export const zStr = z.string().trim();

export const zUuid = zStr.uuid();

export const zUrl = zStr.url().max(2048);

export const zEmail = zStr.max(320).email({ message: 'Invalid email format' });

export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);

export const zConfig = z
  .object({
    azure: z.object({
      clientId: zUuid,
      tenantId: zUuid,
      clientScopes: z.array(zStr.min(3)).min(1),
      clientSecret: zStr.min(32),
    }),
    frontendUrl: z.union([zUrl.transform((url) => [url]), z.array(zUrl).min(1)]),
    serverFullCallbackUrl: zUrl,
    secretKey: zStr.min(16).max(64),
    cookieTimeFrame: z.enum(['ms', 'sec']).default('ms'),
    loginPrompt: zLoginPrompt.default('sso'),
    debug: z.boolean().default(false),
  })
  .transform((config) => {
    const { frontendUrl, serverFullCallbackUrl } = config;
    const frontendHosts = frontendUrl.map((url) => new URL(url).host);
    const serverHost = new URL(serverFullCallbackUrl).host;
    return {
      ...config,
      isCrossOrigin: frontendHosts.length === 1 ? frontendHosts[0] !== serverHost : true,
      isHttps: serverFullCallbackUrl.startsWith('https') && frontendUrl.every((url) => url.startsWith('https')),
      frontendHosts: frontendHosts,
    };
  });

export const zEncrypted = zStr.max(4096).regex(/^OA2\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?$/);

export const zJwt = zStr.max(4096).regex(/^[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?$/);

export const zGenerateAuthUrlOptions = z.object({
  loginPrompt: zLoginPrompt.optional(),
  email: zEmail.optional(),
  frontendUrl: zUrl.optional(),
});

export const zExchangeCodeForTokenOptions = z.object({
  code: zStr.max(2048).regex(/^[A-Za-z0-9._-]+$/),
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
