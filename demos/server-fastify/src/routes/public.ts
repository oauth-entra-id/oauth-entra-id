import type { FastifyInstance } from 'fastify';
import { env } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => ({ message: 'Hello World' }));

  app.get('/health', () => 'OK');

  app.get('/app-info', () => ({
    current: 'red',
    blue: env.BLUE_AZURE_CLIENT_ID,
    red: env.RED_AZURE_CLIENT_ID,
    yellow: env.YELLOW_AZURE_CLIENT_ID,
  }));
};
