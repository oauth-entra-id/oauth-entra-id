import { zValidator } from '@hono/zod-validator';
import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { z } from 'zod';
import { oauthProvider } from '~/oauth';

export const authRouter = new Hono();

const zAuthenticate = z
  .object({
    loginPrompt: z.enum(['email', 'select-account', 'sso']).optional(),
    email: z.string().email().optional(),
    frontendUrl: z.string().url().optional(),
  })
  .optional();

authRouter.post('/authenticate', zValidator('json', zAuthenticate), async (c) => {
  const body = c.req.valid('json');
  const { url } = await oauthProvider.getAuthUrl({
    loginPrompt: body?.loginPrompt,
    email: body?.email,
    frontendUrl: body?.frontendUrl,
  });
  return c.json({ url });
});

const zCallback = z.object({
  code: z.string(),
  state: z.string(),
});

authRouter.post('/callback', zValidator('form', zCallback), async (c) => {
  const { code, state } = c.req.valid('form');
  const { url, accessToken, refreshToken } = await oauthProvider.getTokenByCode({ code, state });

  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(url);
});

const zLogout = z
  .object({
    frontendUrl: z.string().url().optional(),
  })
  .optional();

authRouter.post('/logout', zValidator('json', zLogout), async (c) => {
  const body = c.req.valid('json');
  const { url, accessToken, refreshToken } = oauthProvider.getLogoutUrl({ frontendUrl: body?.frontendUrl });

  deleteCookie(c, accessToken.name, accessToken.options);
  deleteCookie(c, refreshToken.name, refreshToken.options);
  return c.json({ url });
});
