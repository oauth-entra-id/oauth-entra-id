import { Hono } from 'hono';
import { getCookie } from 'hono/cookie';
import { oauthProvider } from '~/oauth';

export const publicRouter = new Hono();

publicRouter.get('/', (c) => {
  return c.json({ message: 'Hello World' });
});

publicRouter.get('/health', (c) => {
  return c.text('OK');
});

publicRouter.get('/test', async (c) => {
  const { refreshTokenName } = oauthProvider.getCookieNames();
  const refreshToken = getCookie(c, refreshTokenName);
  const msalResponse = await oauthProvider.refreshAccessToken(refreshToken as string);
  return c.json(msalResponse);
});
