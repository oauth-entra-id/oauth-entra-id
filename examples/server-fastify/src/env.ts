import dotenv from 'dotenv';
import { z } from 'zod/v4';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  EXPRESS_URL: z.url().default('https://localhost:3001'),
  EXPRESS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3001),
  NESTJS_URL: z.url().default('https://localhost:3002'),
  NESTJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3002),
  FASTIFY_URL: z.url().default('https://localhost:3003'),
  FASTIFY_PORT: zStr.regex(/^\d+$/).transform(Number).default(3003),
  HONOJS_URL: z.url().default('http://localhost:3004'),
  HONOJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3004),
  REACT_FRONTEND_URL: z.url().default('http://localhost:5000'),
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  BLUE_SECRET_KEY: zStr,
  AZURE_BLUE_CLIENT_ID: z.uuid(),
  AZURE_BLUE_TENANT_ID: z.uuid(),
  AZURE_BLUE_CUSTOM_SCOPE: zStr,
  AZURE_BLUE_CLIENT_SECRET: zStr,
  AZURE_BLUE_EXPOSED_SCOPE: zStr,
  RED_SECRET_KEY: zStr,
  AZURE_RED_CLIENT_ID: z.uuid(),
  AZURE_RED_TENANT_ID: z.uuid(),
  AZURE_RED_CUSTOM_SCOPE: zStr,
  AZURE_RED_CLIENT_SECRET: zStr,
  AZURE_RED_EXPOSED_SCOPE: zStr,
  YELLOW_SECRET_KEY: zStr,
  AZURE_YELLOW_CLIENT_ID: z.uuid(),
  AZURE_YELLOW_TENANT_ID: z.uuid(),
  AZURE_YELLOW_CUSTOM_SCOPE: zStr,
  AZURE_YELLOW_CLIENT_SECRET: zStr,
  AZURE_YELLOW_EXPOSED_SCOPE: zStr,
});

const parsedEnv = zEnv.safeParse(process.env);

if (parsedEnv.error) {
  console.error('❌ Fastify App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  ...parsedEnv.data,
  SERVER_URL: parsedEnv.data.FASTIFY_URL,
  SERVER_PORT: parsedEnv.data.FASTIFY_PORT,
};
