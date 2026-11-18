import type { FastifyInstance } from 'fastify';
import { getRegistrationIds } from '~/env';

export const publicRouter = async (app: FastifyInstance) => {
  app.get('/', () => ({ message: 'Hello World' }));

  app.get('/health', () => 'OK');

  app.get('/app-info', () => ({ current: 'red', ...getRegistrationIds() }));
};
