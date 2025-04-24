import { zValidator } from '@hono/zod-validator';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { z } from 'zod';
import { type RequireAuthentication, requireAuthentication } from '~/middlewares/require-authentication';
import { oauthProvider } from '~/oauth';

export const protectedRouter = new Hono<RequireAuthentication>();

protectedRouter.use(requireAuthentication);

protectedRouter.get('/user-info', (c) => {
  return c.json({ user: c.var.userInfo });
});

const zOnBehalfOf = z.object({
  serviceNames: z.array(z.string()),
});

protectedRouter.post('/on-behalf-of', zValidator('json', zOnBehalfOf), async (c) => {
  const { serviceNames } = c.req.valid('json');
  const results = await oauthProvider.getTokenOnBehalfOf({
    accessToken: c.var.msal.microsoftToken,
    serviceNames,
  });
  for (const result of results) {
    const { accessToken, refreshToken } = result;
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  }
  return c.json({ tokensSet: results.length });
});
