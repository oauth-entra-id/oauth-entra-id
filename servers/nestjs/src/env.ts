import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

export const zStr = z.string().trim().min(1);

export const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  NESTJS_URL: zStr.url().default('https://localhost:3002'),
  NESTJS_PORT: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(3002),
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
  console.error('❌ NestJS App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  AZURE: {
    clientId: parsedEnv.data.AZURE_CLIENT_ID,
    tenantId: parsedEnv.data.AZURE_TENANT_ID,
    clientScopes: [parsedEnv.data.AZURE_CLIENT_SCOPES],
    clientSecret: parsedEnv.data.AZURE_CLIENT_SECRET,
  },
  NODE_ENV: parsedEnv.data.NODE_ENV,
  SERVER_URL: parsedEnv.data.NESTJS_URL,
  SERVER_PORT: parsedEnv.data.NESTJS_PORT,
  REACT_FRONTEND_URL: parsedEnv.data.REACT_FRONTEND_URL,
  SECRET_KEY: parsedEnv.data.SECRET_KEY,
  PROXIES: parsedEnv.data.PROXIES,
};
