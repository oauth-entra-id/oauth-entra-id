import { Hono } from 'hono';
import { env } from '~/env';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => c.json({ message: 'Hello World' }));
publicRouter.get('/health', (c) => c.text('OK'));
publicRouter.get('/app-info', (c) =>
  c.json({
    current: 'blue',
    blue: env.BLUE_AZURE_CLIENT_ID,
    red: env.RED_AZURE_CLIENT_ID,
    yellow: env.YELLOW_AZURE_CLIENT_ID,
  }),
);
