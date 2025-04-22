import type { FastifyInstance } from 'fastify';
import { env } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => {
    return { message: 'Hello World' };
  });

  app.get('/health', (req, reply) => {
    reply.status(200).send('OK');
  });

  app.get('/app-info', () => {
    return {
      current: 'red',
      blue: env.AZURE_BLUE.clientId,
      red: env.AZURE_RED.clientId,
      yellow: env.AZURE_YELLOW.clientId,
    };
  });
};
