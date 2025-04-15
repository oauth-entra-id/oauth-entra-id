import type { FastifyInstance } from 'fastify';
import protectRoute from '~/middlewares/require-authentication';

export const protectedRouter = async (app: FastifyInstance) => {
  app.addHook('preHandler', protectRoute);
  app.get('/user-info', (req, reply) => {
    return { user: req.userInfo };
  });
};
