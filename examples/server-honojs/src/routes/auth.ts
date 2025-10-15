import { zValidator } from '@hono/zod-validator';
import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { z } from 'zod';
import { oauthProvider } from '~/oauth';

const zSchemas = {
  authenticate: z
    .object({
      loginPrompt: z.enum(['email', 'select-account', 'sso']).optional(),
      email: z.email().optional(),
      frontendUrl: z.url().optional(),
      azureId: z.uuid().optional(),
    })
    .optional(),
  callback: z.object({
    code: z.string(),
    state: z.string(),
  }),
  logout: z
    .object({
      frontendUrl: z.url().optional(),
      azureId: z.uuid().optional(),
    })
    .optional(),
};

export const authRouter = new Hono();

authRouter.post('/authenticate', zValidator('json', zSchemas.authenticate), async (c) => {
  const body = c.req.valid('json');

  const { authUrl } = await oauthProvider.getAuthUrl({
    loginPrompt: body?.loginPrompt,
    email: body?.email,
    frontendUrl: body?.frontendUrl,
    azureId: body?.azureId,
  });

  return c.json({ url: authUrl });
});

authRouter.post('/callback', zValidator('form', zSchemas.callback), async (c) => {
  const { code, state } = c.req.valid('form');
  const { accessToken, refreshToken, frontendUrl } = await oauthProvider.getTokenByCode({ code, state });

  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(frontendUrl, 303);
});

authRouter.post('/logout', zValidator('json', zSchemas.logout), async (c) => {
  const body = c.req.valid('json');
  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = await oauthProvider.getLogoutUrl({
    frontendUrl: body?.frontendUrl,
    azureId: body?.azureId,
  });

  deleteCookie(c, deleteAccessToken.name, deleteAccessToken.options);
  deleteCookie(c, deleteRefreshToken.name, deleteRefreshToken.options);
  return c.json({ url: logoutUrl });
});
