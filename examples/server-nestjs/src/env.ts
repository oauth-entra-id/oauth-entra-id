/** biome-ignore-all lint/style/noProcessEnv: env.ts file */
import dotenv from 'dotenv';
import { z } from 'zod/v4';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

export const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  TENANT_IN_USE: z.enum(['1', '2']).default('1'),
  EXPRESS_URL: z.url().default('https://localhost:3001'),
  EXPRESS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3001),
  NESTJS_URL: z.url().default('https://localhost:3002'),
  NESTJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3002),
  FASTIFY_URL: z.url().default('https://localhost:3003'),
  FASTIFY_PORT: zStr.regex(/^\d+$/).transform(Number).default(3003),
  HONOJS_URL: z.url().default('http://localhost:3004'),
  HONOJS_PORT: zStr.regex(/^\d+$/).transform(Number).default(3004),
  REACT_FRONTEND_URL: z.url().default('http://localhost:5000'),
  A_SECRET_KEY: zStr,
  A_AZURE_CLIENT_ID: z.uuid(),
  A_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  A_AZURE_CUSTOM_SCOPE: zStr,
  A_AZURE_CLIENT_SECRET: zStr,
  A_AZURE_EXPOSED_SCOPE: zStr,
  B_SECRET_KEY: zStr,
  B_AZURE_CLIENT_ID: z.uuid(),
  B_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  B_AZURE_CUSTOM_SCOPE: zStr,
  B_AZURE_CLIENT_SECRET: zStr,
  B_AZURE_EXPOSED_SCOPE: zStr,
  C_SECRET_KEY: zStr,
  C_AZURE_CLIENT_ID: z.uuid(),
  C_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  C_AZURE_CUSTOM_SCOPE: zStr,
  C_AZURE_CLIENT_SECRET: zStr,
  C_AZURE_EXPOSED_SCOPE: zStr,
  D_SECRET_KEY: zStr,
  D_AZURE_CLIENT_ID: z.uuid(),
  D_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  D_AZURE_CUSTOM_SCOPE: zStr,
  D_AZURE_CLIENT_SECRET: zStr,
  D_AZURE_EXPOSED_SCOPE: zStr,
  E_SECRET_KEY: zStr,
  E_AZURE_CLIENT_ID: z.uuid(),
  E_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  E_AZURE_CUSTOM_SCOPE: zStr,
  E_AZURE_CLIENT_SECRET: zStr,
  E_AZURE_EXPOSED_SCOPE: zStr,
  F_SECRET_KEY: zStr,
  F_AZURE_CLIENT_ID: z.uuid(),
  F_AZURE_TENANT_ID: z.union([z.uuid(), z.literal('common')]),
  F_AZURE_CUSTOM_SCOPE: zStr,
  F_AZURE_CLIENT_SECRET: zStr,
  F_AZURE_EXPOSED_SCOPE: zStr,
});

const { data: parsedEnv, error: envError } = zEnv.safeParse(process.env);

if (envError) {
  console.error('❌ NestJS App environment variables are invalid. Errors:', z.prettifyError(envError));
  process.exit(1);
}

const isFirstTenant = parsedEnv.TENANT_IN_USE === '1';

export const env = {
  ...parsedEnv,
  SERVER_URL: parsedEnv.NESTJS_URL,
  SERVER_PORT: parsedEnv.NESTJS_PORT,
  BLUE_SECRET_KEY: isFirstTenant ? parsedEnv.A_SECRET_KEY : parsedEnv.D_SECRET_KEY,
  AZURE_BLUE_CLIENT_ID: isFirstTenant ? parsedEnv.A_AZURE_CLIENT_ID : parsedEnv.D_AZURE_CLIENT_ID,
  AZURE_BLUE_TENANT_ID: isFirstTenant ? parsedEnv.A_AZURE_TENANT_ID : parsedEnv.D_AZURE_TENANT_ID,
  AZURE_BLUE_CUSTOM_SCOPE: isFirstTenant ? parsedEnv.A_AZURE_CUSTOM_SCOPE : parsedEnv.D_AZURE_CUSTOM_SCOPE,
  AZURE_BLUE_CLIENT_SECRET: isFirstTenant ? parsedEnv.A_AZURE_CLIENT_SECRET : parsedEnv.D_AZURE_CLIENT_SECRET,
  AZURE_BLUE_EXPOSED_SCOPE: isFirstTenant ? parsedEnv.A_AZURE_EXPOSED_SCOPE : parsedEnv.D_AZURE_EXPOSED_SCOPE,
  RED_SECRET_KEY: isFirstTenant ? parsedEnv.B_SECRET_KEY : parsedEnv.E_SECRET_KEY,
  AZURE_RED_CLIENT_ID: isFirstTenant ? parsedEnv.B_AZURE_CLIENT_ID : parsedEnv.E_AZURE_CLIENT_ID,
  AZURE_RED_TENANT_ID: isFirstTenant ? parsedEnv.B_AZURE_TENANT_ID : parsedEnv.E_AZURE_TENANT_ID,
  AZURE_RED_CUSTOM_SCOPE: isFirstTenant ? parsedEnv.B_AZURE_CUSTOM_SCOPE : parsedEnv.E_AZURE_CUSTOM_SCOPE,
  AZURE_RED_CLIENT_SECRET: isFirstTenant ? parsedEnv.B_AZURE_CLIENT_SECRET : parsedEnv.E_AZURE_CLIENT_SECRET,
  AZURE_RED_EXPOSED_SCOPE: isFirstTenant ? parsedEnv.B_AZURE_EXPOSED_SCOPE : parsedEnv.E_AZURE_EXPOSED_SCOPE,
  YELLOW_SECRET_KEY: isFirstTenant ? parsedEnv.C_SECRET_KEY : parsedEnv.F_SECRET_KEY,
  AZURE_YELLOW_CLIENT_ID: isFirstTenant ? parsedEnv.C_AZURE_CLIENT_ID : parsedEnv.F_AZURE_CLIENT_ID,
  AZURE_YELLOW_TENANT_ID: isFirstTenant ? parsedEnv.C_AZURE_TENANT_ID : parsedEnv.F_AZURE_TENANT_ID,
  AZURE_YELLOW_CUSTOM_SCOPE: isFirstTenant ? parsedEnv.C_AZURE_CUSTOM_SCOPE : parsedEnv.F_AZURE_CUSTOM_SCOPE,
  AZURE_YELLOW_CLIENT_SECRET: isFirstTenant ? parsedEnv.C_AZURE_CLIENT_SECRET : parsedEnv.F_AZURE_CLIENT_SECRET,
  AZURE_YELLOW_EXPOSED_SCOPE: isFirstTenant ? parsedEnv.C_AZURE_EXPOSED_SCOPE : parsedEnv.F_AZURE_EXPOSED_SCOPE,
};

export const serversMap = {
  express: env.EXPRESS_URL,
  nestjs: env.NESTJS_URL,
  fastify: env.FASTIFY_URL,
  honojs: env.HONOJS_URL,
};
