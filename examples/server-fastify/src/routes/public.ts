import type { FastifyInstance } from 'fastify';
import { env } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => ({ message: 'Hello World' }));

  app.get('/health', () => 'OK');

  app.get('/app-info', () => ({
    current: 'red',
    blue: env.AZURE_BLUE_CLIENT_ID,
    red: env.AZURE_RED_CLIENT_ID,
    yellow: env.AZURE_YELLOW_CLIENT_ID,
  }));
};
