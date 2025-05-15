import { Hono } from 'hono';
import { env } from '~/env';
import { oauthProvider } from '~/oauth';

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

publicRouter.get('/test', async (c) => {
  const [result, results] = await Promise.all([
    oauthProvider.getB2BToken({ b2bServiceName: 'express' }),
    oauthProvider.getB2BToken({ b2bServiceNames: ['nestjs', 'fastify'] }),
  ]);

  return c.json({
    result,
    results,
  });
});
