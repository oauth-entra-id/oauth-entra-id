import type { FastifyInstance } from 'fastify';
import { env } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => {
    return { message: 'Hello World' };
  });

  app.get('/health', (req, reply) => {
    reply.status(200).send('OK');
  });

  app.get('/app-id', () => {
    return { appId: env.AZURE.clientId };
  });
};
