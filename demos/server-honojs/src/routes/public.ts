import { Hono } from 'hono';
import { env } from '~/env';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => c.json({ message: 'Hello World' }));
publicRouter.get('/health', (c) => c.text('OK'));
publicRouter.get('/app-info', (c) =>
  c.json({
    current: 'blue',
    blue: env.AZURE_BLUE.clientId,
    red: env.AZURE_RED.clientId,
    yellow: env.AZURE_YELLOW.clientId,
  }),
);
