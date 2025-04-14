import { Hono } from 'hono';
import { requireAuthentication } from '~/middlewares/require-authentication';
import { oauthProvider } from '~/oauth';

export const protectedRouter = new Hono();

protectedRouter.get('/user-info', requireAuthentication, (c) => {
  return c.json({ user: c.var.userInfo });
});

protectedRouter.get('/test', requireAuthentication, async (c) => {
  const newToken = await oauthProvider.getTokenRemotely({
    accessToken: c.var.msal.microsoftToken,
    scopeOfRemoteServer: process.env.AZURE_CLIENT_SCOPES as string,
  });
  return c.json(newToken);
});
