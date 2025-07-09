import type { FastifyInstance } from 'fastify';
import { env } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => ({ message: 'Hello World' }));

  app.get('/health', () => 'OK');

  app.get('/app-info', () => ({
    current: 'red',
    blue: { '1': env.BLUE1_AZURE_CLIENT_ID, '2': env.BLUE2_AZURE_CLIENT_ID },
    red: { '1': env.RED1_AZURE_CLIENT_ID, '2': env.RED2_AZURE_CLIENT_ID },
    yellow: { '1': env.YELLOW1_AZURE_CLIENT_ID, '2': env.YELLOW2_AZURE_CLIENT_ID },
  }));
};
