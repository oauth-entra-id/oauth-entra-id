import { zValidator } from '@hono/zod-validator';
import { Hono } from 'hono';
import { setCookie } from 'hono/cookie';
import { z } from 'zod';
import { type ProtectRoute, protectRoute } from '~/middlewares/protect-route';
import { oauthProvider } from '~/oauth';

const zSchemas = {
  onBehalfOf: z.object({
    serviceNames: z.array(z.string()),
  }),
};

export const protectedRouter = new Hono<ProtectRoute>();

protectedRouter.use(protectRoute);

protectedRouter.get('/user-info', (c) => {
  return c.json({ user: c.get('userInfo') });
});

protectedRouter.post('/on-behalf-of', zValidator('json', zSchemas.onBehalfOf), async (c) => {
  const { serviceNames } = c.req.valid('json');
  const results = await oauthProvider.getTokenOnBehalfOf({
    accessToken: c.get('microsoftInfo').rawAccessToken,
    serviceNames,
  });
  for (const result of results) {
    const { accessToken, refreshToken } = result;
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  }
  return c.json({ tokensSet: results.length });
});
