import { z } from 'zod';

const zUrl = z.string().trim().url().min(1);

const zEnv = z.object({
  VITE_EXPRESS_URL: zUrl,
  VITE_NESTJS_URL: zUrl,
  VITE_FASTIFY_URL: zUrl,
  VITE_HONOJS_URL: zUrl,
});

const parsedEnv = zEnv.safeParse(import.meta.env);

if (!parsedEnv.success) {
  throw new Error(`❌ Invalid environment variables: ${parsedEnv.error.format()}`);
}

export const {
  VITE_EXPRESS_URL: EXPRESS_SERVER,
  VITE_NESTJS_URL: NESTJS_SERVER,
  VITE_FASTIFY_URL: FASTIFY_SERVER,
  VITE_HONOJS_URL: HONOJS_SERVER,
} = parsedEnv.data;
