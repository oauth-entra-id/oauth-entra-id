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
  AZURE_BLUE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_BLUE_CUSTOM_SCOPE: zStr,
  AZURE_BLUE_CLIENT_SECRET: zStr,
  AZURE_BLUE_EXPOSED_SCOPE: zStr,
  RED_SECRET_KEY: zStr,
  AZURE_RED_CLIENT_ID: z.uuid(),
  AZURE_RED_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_RED_CUSTOM_SCOPE: zStr,
  AZURE_RED_CLIENT_SECRET: zStr,
  AZURE_RED_EXPOSED_SCOPE: zStr,
  YELLOW_SECRET_KEY: zStr,
  AZURE_YELLOW_CLIENT_ID: z.uuid(),
  AZURE_YELLOW_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_YELLOW_CUSTOM_SCOPE: zStr,
  AZURE_YELLOW_CLIENT_SECRET: zStr,
  AZURE_YELLOW_EXPOSED_SCOPE: zStr,
  GREEN_SECRET_KEY: zStr,
  AZURE_GREEN_CLIENT_ID: z.uuid(),
  AZURE_GREEN_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_GREEN_CUSTOM_SCOPE: zStr,
  AZURE_GREEN_CLIENT_SECRET: zStr,
  AZURE_GREEN_EXPOSED_SCOPE: zStr,
  ORANGE_SECRET_KEY: zStr,
  AZURE_ORANGE_CLIENT_ID: z.uuid(),
  AZURE_ORANGE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_ORANGE_CUSTOM_SCOPE: zStr,
  AZURE_ORANGE_CLIENT_SECRET: zStr,
  AZURE_ORANGE_EXPOSED_SCOPE: zStr,
  PURPLE_SECRET_KEY: zStr,
  AZURE_PURPLE_CLIENT_ID: z.uuid(),
  AZURE_PURPLE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  AZURE_PURPLE_CUSTOM_SCOPE: zStr,
  AZURE_PURPLE_CLIENT_SECRET: zStr,
  AZURE_PURPLE_EXPOSED_SCOPE: zStr,
});

const parsedEnv = zEnv.safeParse(process.env);

if (parsedEnv.error) {
  console.error('❌ Express App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  ...parsedEnv.data,
  SERVER_URL: parsedEnv.data.EXPRESS_URL,
  SERVER_PORT: parsedEnv.data.EXPRESS_PORT,
};

export const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
  honojs: env.HONOJS_URL,
};
