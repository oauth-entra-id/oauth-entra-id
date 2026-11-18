import { Hono } from 'hono';
import { getRegistrationIds } from '~/env';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => c.json({ message: 'Hello World' }));
publicRouter.get('/health', (c) => c.text('OK'));
publicRouter.get('/app-info', (c) => c.json({ current: 'blue', ...getRegistrationIds() }));
