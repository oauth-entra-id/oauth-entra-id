import { z } from 'zod';

const zStr = z.string().trim();

const zEnv = z.object({
  VITE_EXPRESS_URL: zStr.url().default('https://localhost:3001'),
  VITE_FASTIFY_URL: zStr.url().default('https://localhost:3002'),
  VITE_NESTJS_URL: zStr.url().default('https://localhost:3003'),
  VITE_HONOJS_URL: zStr.url().default('https://localhost:3004'),
});

const parsedEnv = zEnv.safeParse(import.meta.env);

if (!parsedEnv.success) {
  throw new Error(`❌ Invalid environment variables: ${parsedEnv.error.format()}`);
}

export const {
  VITE_HONOJS_URL: HONOJS_SERVER,
  VITE_EXPRESS_URL: EXPRESS_SERVER,
  VITE_FASTIFY_URL: FASTIFY_SERVER,
  VITE_NESTJS_URL: NESTJS_SERVER,
} = parsedEnv.data;
