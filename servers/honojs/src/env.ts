import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  HONOJS_URL: zStr.url().default('http://localhost:3003'),
  HONOJS_PORT: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(3003),
  REACT_FRONTEND_URL: zStr.url().default('http://localhost:5173'),
  SECRET_KEY: zStr,
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  AZURE_CLIENT_ID: zStr.uuid(),
  AZURE_TENANT_ID: zStr.uuid(),
  AZURE_CLIENT_SCOPES: zStr,
  AZURE_CLIENT_SECRET: zStr,
});

const { data: env, error } = zEnv.safeParse(process.env);

if (error) {
  console.error('❌ HonoJS App environment variables are invalid. Errors:', error.format());
  process.exit(1);
}

export const AZURE = {
  clientId: env.AZURE_CLIENT_ID,
  tenantId: env.AZURE_TENANT_ID,
  clientScopes: env.AZURE_CLIENT_SCOPES,
  clientSecret: env.AZURE_CLIENT_SECRET,
};

export const { NODE_ENV, HONOJS_URL, HONOJS_PORT, REACT_FRONTEND_URL, SECRET_KEY, PROXIES } = env;
