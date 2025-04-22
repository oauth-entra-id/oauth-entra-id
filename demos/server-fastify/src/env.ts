import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  FASTIFY_URL: zStr.url().default('https://localhost:3003'),
  FASTIFY_PORT: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(3003),
  REACT_FRONTEND_URL: zStr.url().default('http://localhost:5000'),
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  SECRET_KEY1: zStr,
  AZURE1_CLIENT_ID: zStr.uuid(),
  AZURE1_TENANT_ID: zStr.uuid(),
  AZURE1_CLIENT_SCOPES: zStr,
  AZURE1_CLIENT_SECRET: zStr,
  SECRET_KEY2: zStr,
  AZURE2_CLIENT_ID: zStr.uuid(),
  AZURE2_TENANT_ID: zStr.uuid(),
  AZURE2_CLIENT_SCOPES: zStr,
  AZURE2_CLIENT_SECRET: zStr,
  SECRET_KEY3: zStr,
  AZURE3_CLIENT_ID: zStr.uuid(),
  AZURE3_TENANT_ID: zStr.uuid(),
  AZURE3_CLIENT_SCOPES: zStr,
  AZURE3_CLIENT_SECRET: zStr,
});

const parsedEnv = zEnv.safeParse(process.env);

if (parsedEnv.error) {
  console.error('❌ Fastify App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  SECRET_KEY_BLUE: parsedEnv.data.SECRET_KEY1,
  AZURE_BLUE: {
    clientId: parsedEnv.data.AZURE1_CLIENT_ID,
    tenantId: parsedEnv.data.AZURE1_TENANT_ID,
    scopes: [parsedEnv.data.AZURE1_CLIENT_SCOPES],
    secret: parsedEnv.data.AZURE1_CLIENT_SECRET,
  },
  SECRET_KEY_RED: parsedEnv.data.SECRET_KEY2,
  AZURE_RED: {
    clientId: parsedEnv.data.AZURE2_CLIENT_ID,
    tenantId: parsedEnv.data.AZURE2_TENANT_ID,
    scopes: [parsedEnv.data.AZURE2_CLIENT_SCOPES],
    secret: parsedEnv.data.AZURE2_CLIENT_SECRET,
  },
  SECRET_KEY_YELLOW: parsedEnv.data.SECRET_KEY3,
  AZURE_YELLOW: {
    clientId: parsedEnv.data.AZURE3_CLIENT_ID,
    tenantId: parsedEnv.data.AZURE3_TENANT_ID,
    scopes: [parsedEnv.data.AZURE3_CLIENT_SCOPES],
    secret: parsedEnv.data.AZURE3_CLIENT_SECRET,
  },
  NODE_ENV: parsedEnv.data.NODE_ENV,
  SERVER_URL: parsedEnv.data.FASTIFY_URL,
  SERVER_PORT: parsedEnv.data.FASTIFY_PORT,
  REACT_FRONTEND_URL: parsedEnv.data.REACT_FRONTEND_URL,
  PROXIES: parsedEnv.data.PROXIES,
};
