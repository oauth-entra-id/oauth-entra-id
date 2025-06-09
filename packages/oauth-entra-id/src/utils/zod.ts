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
  // return error.issues
  //   .map((issue) => {
  //     const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
  //     return `${path}: ${issue.message}`;
  //   })
  //   .join('. ');
  return z.prettifyError(error);
};

export const zStr = z.string().trim();
export const zUuid = z.uuid();
export const zUrl = z.url();
export const zEmail = z.email({ pattern: z.regexes.html5Email });
export const zBase64 = z.base64url();
export const zLooseBase64 = zStr.regex(base64urlWithDotRegex);
export const zCompressed = zStr.regex(compressedRegex);

export const zLoginPrompt = z.enum(['email', 'select-account', 'sso']);

export const zEncrypted = zStr.max(4096).regex(encryptedRegex);
export const zJwt = z.jwt().max(4096);

export const zScope = zStr.min(3).max(128);
export const zSecretKey = zStr.min(32).max(64);
export const zServiceName = zStr.min(1).max(64);

const zAzure = z.object({
  clientId: zUuid,
  tenantId: z.union([z.literal('common'), zUuid]),
  scopes: z.array(zScope).min(1),
  clientSecret: zStr.min(32).max(128),
});

const zB2BApp = z.object({
  appName: zServiceName,
  scope: zScope,
});

const zDownstreamService = z.object({
  serviceName: zServiceName,
  scope: zScope,
  secretKey: zSecretKey,
  cryptoType: z.enum(['web-api', 'node']).optional(),
  isHttps: z.boolean().optional(),
  isSameOrigin: z.boolean().optional(),
  accessTokenExpiry: z.number().positive().default(3600),
  refreshTokenExpiry: z.number().min(3600).default(2592000),
});

const zAdvanced = z.object({
  loginPrompt: zLoginPrompt.default('sso'),
  acceptB2BRequests: z.boolean().default(false),
  b2bTargetedApps: z.array(zB2BApp).min(1).optional(),
  disableCompression: z.boolean().default(false),
  cryptoType: z.enum(['web-api', 'node']).default('node'),
  cookies: z
    .object({
      timeUnit: z.enum(['ms', 'sec']).default('sec'),
      disableHttps: z.boolean().default(false),
      disableSameSite: z.boolean().default(false),
      accessTokenExpiry: z.number().positive().default(3600),
      refreshTokenExpiry: z.number().min(3600).default(2592000),
    })
    .prefault({}),
  downstreamServices: z
    .object({
      areHttps: z.boolean(),
      areSameOrigin: z.boolean(),
      services: z.array(zDownstreamService).min(1),
    })
    .optional(),
});

export const zConfig = z.object({
  azure: zAzure,
  frontendUrl: z.union([zUrl.max(2048).transform((url) => [url]), z.array(zUrl.max(2048)).min(1)]),
  serverCallbackUrl: zUrl.max(2048),
  secretKey: zSecretKey,
  advanced: zAdvanced.prefault({}),
});

export const zState = z.object({
  frontendUrl: zUrl.max(2048),
  codeVerifier: zStr.max(256),
  nonce: zUuid,
  email: zEmail.max(320).optional(),
  prompt: z.enum(['login', 'select_account']).optional(),
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
    z.object({ appName: zServiceName }).transform((data) => ({ appNames: [data.appName] })),
    z.object({ appNames: z.array(zServiceName).min(1) }),
  ]),
  getTokenOnBehalfOf: z.union([
    z
      .object({ accessToken: z.union([zJwt, zEncrypted]), serviceName: zServiceName })
      .transform((data) => ({ accessToken: data.accessToken, serviceNames: [data.serviceName] })),
    z.object({ accessToken: z.union([zJwt, zEncrypted]), serviceNames: z.array(zServiceName).min(1) }),
  ]),
};
