/** biome-ignore-all lint/style/noProcessEnv: env.ts file */
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env', quiet: true });
if (!process.env.NODE_ENV) dotenv.config({ quiet: true });

const zStr = z.string().trim().min(1);

export const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  EXPRESS_URL: z.url().default('http://localhost:3001'),
  EXPRESS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3001),
  NESTJS_URL: z.url().default('http://localhost:3002'),
  NESTJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3002),
  FASTIFY_URL: z.url().default('http://localhost:3003'),
  FASTIFY_PORT: zStr.regex(/^\d+$/).transform(Number).default(3003),
  HONOJS_URL: z.url().default('http://localhost:3004'),
  HONOJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3004),
  REACT_FRONTEND_URL: z.url().default('http://localhost:5000'),
  MOBILE_RETURN_PATH: zStr.startsWith('/').default('/mobile-return'),
  MOBILE_TICKET_TTL_SEC: zStr.regex(/^\d+$/).transform(Number).default(120),
  YELLOW_SECRET_KEY: zStr,
  RED_SECRET_KEY: zStr,
  BLUE_SECRET_KEY: zStr,
});

// One registration is the same five settings for each app: <COLOR><1|2>_AZURE_<CLIENT_ID|TENANT_ID|CUSTOM_SCOPE|CLIENT_SECRET|EXPOSED_SCOPE>.
// The first one is required. The second one is optional but all or nothing, it is only for trying a second tenant.
const zAzureSettings = {
  CLIENT_ID: z.uuid(),
  TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  CUSTOM_SCOPE: zStr,
  CLIENT_SECRET: zStr,
  EXPOSED_SCOPE: zStr,
};

type AzureSetting = keyof typeof zAzureSettings;
type AppColor = 'yellow' | 'red' | 'blue';
const appColors: AppColor[] = ['yellow', 'red', 'blue'];

export interface AzureApp {
  clientId: string;
  tenantId: string;
  customScope: string;
  clientSecret: string;
  exposedScope: string;
}
export type Registration = Record<AppColor, AzureApp>;

const azureVar = (color: AppColor, number: '1' | '2', setting: AzureSetting) =>
  `${color.toUpperCase()}${number}_AZURE_${setting}`;

function readRegistration(number: '1' | '2'): Registration {
  const shape: Record<string, z.ZodType<string>> = {};
  for (const color of appColors) {
    for (const [setting, schema] of Object.entries(zAzureSettings)) {
      shape[azureVar(color, number, setting as AzureSetting)] = schema;
    }
  }

  const { data, error } = z.object(shape).safeParse(process.env);
  if (error) {
    console.error(`❌ Azure registration ${number} environment variables are invalid. Errors:`, z.prettifyError(error));
    process.exit(1);
  }

  const readApp = (color: AppColor): AzureApp => {
    const read = (setting: AzureSetting) => data[azureVar(color, number, setting)] ?? '';
    return {
      clientId: read('CLIENT_ID'),
      tenantId: read('TENANT_ID'),
      customScope: read('CUSTOM_SCOPE'),
      clientSecret: read('CLIENT_SECRET'),
      exposedScope: read('EXPOSED_SCOPE'),
    };
  };
  return { yellow: readApp('yellow'), red: readApp('red'), blue: readApp('blue') };
}

const hasSecondRegistration = appColors.some((color) =>
  Object.keys(zAzureSettings).some((setting) => process.env[azureVar(color, '2', setting as AzureSetting)]?.trim()),
);

export const registrations = {
  first: readRegistration('1'),
  second: hasSecondRegistration ? readRegistration('2') : undefined,
};

/** The client IDs the demo site shows: '2' is only there when a second registration is configured. */
export function getRegistrationIds() {
  const idsOf = (color: AppColor) => ({
    '1': registrations.first[color].clientId,
    ...(registrations.second ? { '2': registrations.second[color].clientId } : {}),
  });
  return { blue: idsOf('blue'), red: idsOf('red'), yellow: idsOf('yellow') };
}

const { data: parsedEnv, error: envError } = zEnv.safeParse(process.env);

if (envError) {
  console.error('❌ Fastify App environment variables are invalid. Errors:', z.prettifyError(envError));
  process.exit(1);
}

export const env = {
  ...parsedEnv,
  SERVER_URL: parsedEnv.FASTIFY_URL,
  SERVER_PORT: parsedEnv.FASTIFY_PORT,
  MOBILE_RETURN_URL: `${new URL(parsedEnv.REACT_FRONTEND_URL).origin}${parsedEnv.MOBILE_RETURN_PATH}`,
};

export const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
  honojs: env.HONOJS_URL,
};
