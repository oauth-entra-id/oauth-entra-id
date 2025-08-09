import { z } from 'zod';
import { zUrl } from './lib/zod';

const zEnv = z.object({
  VITE_EXPRESS_URL: zUrl,
  VITE_NESTJS_URL: zUrl,
  VITE_FASTIFY_URL: zUrl,
  VITE_HONOJS_URL: zUrl,
});

const { data: parsedEnv, error: envError } = zEnv.safeParse(import.meta.env);

if (envError) {
  throw new Error(`❌ Invalid environment variables: ${z.prettifyError(envError)}`);
}

export const env = {
  EXPRESS_SERVER: parsedEnv.VITE_EXPRESS_URL,
  NESTJS_SERVER: parsedEnv.VITE_NESTJS_URL,
  FASTIFY_SERVER: parsedEnv.VITE_FASTIFY_URL,
  HONOJS_SERVER: parsedEnv.VITE_HONOJS_URL,
};
