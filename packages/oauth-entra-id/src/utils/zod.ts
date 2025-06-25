import { type ZodError, z } from 'zod/v4';

export function $isString(value: unknown): value is string {
  return (value !== null || value !== undefined) && typeof value === 'string' && value.trim().length > 0;
}

export function $isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

export const base64urlWithDotRegex = /^[A-Za-z0-9._-]+$/;
export const encryptedWebApiRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/;
export const encryptedNodeRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/;
export const encryptedRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\.$/;
export const compressedRegex = /^[A-Za-z0-9_-]+\.\.$/;

export const $prettyErr = (error: ZodError): string => {
  return error.issues
    .map((issue) => {
      const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
      return `${path}: ${issue.message}`;
    })
    .join('. ');
};

export const zStr = z.string().trim();
export const zUuid = z.uuid();
export const zUrl = z.url();
export const zEmail = z.email({ pattern: z.regexes.html5Email });
export const zBase64 = z.base64url();
export const zLooseBase64 = zStr.regex(base64urlWithDotRegex);
export const zCompressed = zStr.regex(compressedRegex);

export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);
export const zTimeUnit = z.enum(['ms', 'sec']);
export const zCryptoType = z.enum(['web-api', 'node']);
export const zAccessTokenMaxAge = z.number().positive();
export const zRefreshTokenMaxAge = z.number().min(3600);
const zOneOrMoreUrls = z.union([zUrl.max(2048).transform((url) => [url]), z.array(zUrl.max(2048)).min(1)]);

export const zEncrypted = zStr.max(4096).regex(encryptedRegex);
export const zJwt = z.jwt().max(4096);

export const zScope = zStr.min(3).max(128);
export const zEncryptionKey = zStr.min(32).max(64);
export const zServiceName = zStr.min(1).max(64);

export const zConfig = z.object({
  azure: z.object({
    clientId: zUuid,
    tenantId: z.union([z.literal('common'), zUuid]),
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
          accessTokenMaxAge: zAccessTokenMaxAge.default(3600),
        }),
      )
      .min(1)
      .optional(),
    b2bApps: z
      .array(z.object({ appName: zServiceName, scope: zScope }))
      .min(1)
      .optional(),
  }),
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
          accessTokenMaxAge: zAccessTokenMaxAge.default(3600),
          refreshTokenMaxAge: zRefreshTokenMaxAge.default(2592000),
        })
        .prefault({}),
    })
    .prefault({}),
});

export const zState = z.object({
  frontendUrl: zUrl.max(2048),
  codeVerifier: zStr.max(256),
  nonce: zUuid,
  email: zEmail.max(320).optional(),
  prompt: z.enum(['login', 'select_account']).optional(),
  ticketId: zUuid,
});

export const zAuthParams = z.object({
  state: zStr.max(512),
  nonce: zUuid,
  loginHint: zStr.max(320).optional(),
  prompt: zStr.max(10).optional(),
  codeVerifier: zStr.max(128),
});

export const zInjectedData = z.record(zStr, z.any()).optional();

export const zAccessTokenStructure = z.object({
  at: zJwt,
  inj: zStr.max(4096).optional(),
});

export const zMethods = {
  getAuthUrl: z
    .object({
      loginPrompt: zLoginPrompt.optional(),
      email: zEmail.max(320).optional(),
      frontendUrl: zUrl.max(4096).optional(),
    })
    .default({}),
  getTokenByCode: z.object({ code: zStr.max(2048).regex(base64urlWithDotRegex), state: zEncrypted }),
  getLogoutUrl: z.object({ frontendUrl: zUrl.max(4096).optional() }).default({}),
  getB2BToken: z.union([
    z.object({ app: zServiceName }).transform((data) => ({ apps: [data.app] })),
    z.object({ apps: z.array(zServiceName).min(1) }),
  ]),
  getTokenOnBehalfOf: z.union([
    z
      .object({ accessToken: z.union([zJwt, zEncrypted]), service: zServiceName })
      .transform((data) => ({ accessToken: data.accessToken, services: [data.service] })),
    z.object({ accessToken: z.union([zJwt, zEncrypted]), services: z.array(zServiceName).min(1) }),
  ]),
};
