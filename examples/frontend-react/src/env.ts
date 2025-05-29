import { z } from 'zod/v4';
import { zUrl } from './lib/zod';

const zEnv = z.object({
  VITE_EXPRESS_URL: zUrl,
  VITE_NESTJS_URL: zUrl,
  VITE_FASTIFY_URL: zUrl,
  VITE_HONOJS_URL: zUrl,
});

const parsedEnv = zEnv.safeParse(import.meta.env);

if (parsedEnv.error) {
  throw new Error(`❌ Invalid environment variables: ${parsedEnv.error.format()}`);
}

export const env = {
  EXPRESS_SERVER: parsedEnv.data.VITE_EXPRESS_URL,
  NESTJS_SERVER: parsedEnv.data.VITE_NESTJS_URL,
  FASTIFY_SERVER: parsedEnv.data.VITE_FASTIFY_URL,
  HONOJS_SERVER: parsedEnv.data.VITE_HONOJS_URL,
};
