/** biome-ignore-all lint/style/noProcessEnv: env.ts file */
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env', quiet: true });
if (!process.env.NODE_ENV) dotenv.config({ quiet: true });

const zStr = z.string().trim().min(1);

export const zEnv = z.object({
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
  YELLOW_SECRET_KEY: zStr,
  RED_SECRET_KEY: zStr,
  BLUE_SECRET_KEY: zStr,
  YELLOW1_AZURE_CLIENT_ID: z.uuid(),
  YELLOW1_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  YELLOW1_AZURE_CUSTOM_SCOPE: zStr,
  YELLOW1_AZURE_CLIENT_SECRET: zStr,
  YELLOW1_AZURE_EXPOSED_SCOPE: zStr,
  RED1_AZURE_CLIENT_ID: z.uuid(),
  RED1_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  RED1_AZURE_CUSTOM_SCOPE: zStr,
  RED1_AZURE_CLIENT_SECRET: zStr,
  RED1_AZURE_EXPOSED_SCOPE: zStr,
  BLUE1_AZURE_CLIENT_ID: z.uuid(),
  BLUE1_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  BLUE1_AZURE_CUSTOM_SCOPE: zStr,
  BLUE1_AZURE_CLIENT_SECRET: zStr,
  BLUE1_AZURE_EXPOSED_SCOPE: zStr,
  YELLOW2_AZURE_CLIENT_ID: z.uuid(),
  YELLOW2_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  YELLOW2_AZURE_CUSTOM_SCOPE: zStr,
  YELLOW2_AZURE_CLIENT_SECRET: zStr,
  YELLOW2_AZURE_EXPOSED_SCOPE: zStr,
  RED2_AZURE_CLIENT_ID: z.uuid(),
  RED2_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  RED2_AZURE_CUSTOM_SCOPE: zStr,
  RED2_AZURE_CLIENT_SECRET: zStr,
  RED2_AZURE_EXPOSED_SCOPE: zStr,
  BLUE2_AZURE_CLIENT_ID: z.uuid(),
  BLUE2_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  BLUE2_AZURE_CUSTOM_SCOPE: zStr,
  BLUE2_AZURE_CLIENT_SECRET: zStr,
  BLUE2_AZURE_EXPOSED_SCOPE: zStr,
});

const { data: parsedEnv, error: envError } = zEnv.safeParse(process.env);

if (envError) {
  console.error('❌ HonoJS App environment variables are invalid. Errors:', z.prettifyError(envError));
  process.exit(1);
}

export const env = {
  ...parsedEnv,
  SERVER_URL: parsedEnv.HONOJS_URL,
  SERVER_PORT: parsedEnv.HONOJS_PORT,
};

export const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
  honojs: env.HONOJS_URL,
};
