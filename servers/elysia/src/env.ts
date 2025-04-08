import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  ELYSIA_URL: zStr.url().default('http://localhost:3005'),
  ELYSIA_PORT: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(3005),
  REACT_FRONTEND_URL: zStr.url().default('http://localhost:5000'),
  SECRET_KEY: zStr,
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  AZURE_CLIENT_ID: zStr.uuid(),
  AZURE_TENANT_ID: zStr.uuid(),
  AZURE_CLIENT_SCOPES: zStr,
  AZURE_CLIENT_SECRET: zStr,
});

const parsedEnv = zEnv.safeParse(process.env);

if (parsedEnv.error) {
  console.error('❌ Elysia App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  AZURE: {
    clientId: parsedEnv.data.AZURE_CLIENT_ID,
    tenantId: parsedEnv.data.AZURE_TENANT_ID,
    clientScopes: parsedEnv.data.AZURE_CLIENT_SCOPES,
    clientSecret: parsedEnv.data.AZURE_CLIENT_SECRET,
  },
  NODE_ENV: parsedEnv.data.NODE_ENV,
  SERVER_URL: parsedEnv.data.ELYSIA_URL,
  SERVER_PORT: parsedEnv.data.ELYSIA_PORT,
  REACT_FRONTEND_URL: parsedEnv.data.REACT_FRONTEND_URL,
  SECRET_KEY: parsedEnv.data.SECRET_KEY,
  PROXIES: parsedEnv.data.PROXIES,
};
