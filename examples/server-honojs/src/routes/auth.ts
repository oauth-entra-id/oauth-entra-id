import { zValidator } from '@hono/zod-validator';
import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod/v4';
import { oauthProvider } from '~/oauth';

const zSchemas = {
  authenticate: z
    .object({
      loginPrompt: z.enum(['email', 'select-account', 'sso']).optional(),
      email: z.email().optional(),
      frontendUrl: z.url().optional(),
    })
    .optional(),
  callback: z.object({ code: z.string(), state: z.string() }),
  logout: z.object({ frontendUrl: z.url().optional() }).optional(),
};

export const authRouter = new Hono();

authRouter.post('/authenticate', zValidator('json', zSchemas.authenticate), async (c) => {
  const body = c.req.valid('json');

  const { authUrl, error } = await oauthProvider.getAuthUrl({
    loginPrompt: body?.loginPrompt,
    email: body?.email,
    frontendUrl: body?.frontendUrl,
  });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });

  return c.json({ url: authUrl });
});

authRouter.post('/callback', zValidator('form', zSchemas.callback), async (c) => {
  const { code, state } = c.req.valid('form');
  const { accessToken, refreshToken, frontendUrl, error } = await oauthProvider.getTokenByCode({ code, state });
  if (error) {
    console.error('Error during OAuth callback:', error);
    throw new HTTPException(error.statusCode, { message: error.message });
  }

  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(frontendUrl);
});

authRouter.post('/logout', zValidator('json', zSchemas.logout), async (c) => {
  const body = c.req.valid('json');
  const { logoutUrl, deleteAccessToken, deleteRefreshToken, error } = oauthProvider.getLogoutUrl({
    frontendUrl: body?.frontendUrl,
  });

  if (error) throw new HTTPException(error.statusCode, { message: error.message });

  deleteCookie(c, deleteAccessToken.name, deleteAccessToken.options);
  deleteCookie(c, deleteRefreshToken.name, deleteRefreshToken.options);
  return c.json({ url: logoutUrl });
});
