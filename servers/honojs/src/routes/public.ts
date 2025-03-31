import { Hono } from 'hono';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => {
  return c.json({ message: 'Hello World' });
});

publicRouter.get('/health', (c) => {
  return c.text('OK');
});
