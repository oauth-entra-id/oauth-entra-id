import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { requireAuthentication } from '~/middlewares/require-authentication';
import { oauthProvider } from '~/oauth';

export const protectedRouter = new Hono();

protectedRouter.get('/user-info', requireAuthentication, (c) => {
  return c.json({ user: c.var.userInfo });
});

protectedRouter.post('/on-behalf-of', requireAuthentication, async (c) => {
  const { name } = await c.req.json();
  const { accessToken, refreshToken } = await oauthProvider.getTokenOnBehalfOf({
    accessToken: c.var.msal.microsoftToken,
    serviceName: name,
  });
  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.json({ message: 'Tokens set' });
});
