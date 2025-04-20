import { Hono } from 'hono';
import { env } from '~/env';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => c.json({ message: 'Hello World' }));
publicRouter.get('/health', (c) => c.text('OK'));
publicRouter.get('/app-id', (c) => c.json({ appId: env.AZURE.clientId }));
