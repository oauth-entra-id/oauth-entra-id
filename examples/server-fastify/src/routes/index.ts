import type { FastifyInstance } from 'fastify';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter = async (app: FastifyInstance) => {
  await app.register(publicRouter, { prefix: '/' });
  await app.register(authRouter, { prefix: '/auth' });
  await app.register(protectedRouter, { prefix: '/protected' });
};
