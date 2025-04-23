import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: '../../.env' });
if (!process.env.NODE_ENV) dotenv.config();

const zStr = z.string().trim().min(1);

const zEnv = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  HONOJS_URL: zStr.url().default('http://localhost:3004'),
  HONOJS_PORT: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(3004),
  REACT_FRONTEND_URL: zStr.url().default('http://localhost:5000'),
  PROXIES: z.union([z.number().nonnegative(), zStr.regex(/^\d+$/).transform(Number)]).default(0),
  BLUE_SECRET_KEY: zStr,
  BLUE_AZURE_CLIENT_ID: zStr.uuid(),
  BLUE_AZURE_TENANT_ID: zStr.uuid(),
  BLUE_AZURE_CLIENT_SCOPE: zStr,
  BLUE_AZURE_CLIENT_SECRET: zStr,
  RED_SECRET_KEY: zStr,
  RED_AZURE_CLIENT_ID: zStr.uuid(),
  RED_AZURE_TENANT_ID: zStr.uuid(),
  RED_AZURE_CLIENT_SCOPE: zStr,
  RED_AZURE_CLIENT_SECRET: zStr,
  YELLOW_SECRET_KEY: zStr,
  YELLOW_AZURE_CLIENT_ID: zStr.uuid(),
  YELLOW_AZURE_TENANT_ID: zStr.uuid(),
  YELLOW_AZURE_CLIENT_SCOPE: zStr,
  YELLOW_AZURE_CLIENT_SECRET: zStr,
});

const parsedEnv = zEnv.safeParse(process.env);

if (parsedEnv.error) {
  console.error('❌ HonoJS App environment variables are invalid. Errors:', parsedEnv.error.format());
  process.exit(1);
}

export const env = {
  ...parsedEnv.data,
  SERVER_URL: parsedEnv.data.HONOJS_URL,
  SERVER_PORT: parsedEnv.data.HONOJS_PORT,
};
