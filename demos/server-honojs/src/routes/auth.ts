import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { oauthProvider } from '~/oauth';

export const authRouter = new Hono();

authRouter.post('/authenticate', async (c) => {
  const isJson = c.req.header('content-type')?.includes('application/json');
  const body = isJson ? await c.req.json() : {};
  const params = isJson ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};
  const { url } = await oauthProvider.getAuthUrl(params);
  return c.json({ url });
});

authRouter.post('/callback', async (c) => {
  if (!c.req.header('content-type')?.includes('application/x-www-form-urlencoded'))
    throw new HTTPException(400, { message: 'Invalid content type' });

  const { code, state } = await c.req.parseBody();
  const { url, accessToken, refreshToken, msalResponse } = await oauthProvider.getTokenByCode({
    code: code as string,
    state: state as string,
  });

  console.log(msalResponse.accessToken);

  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(url);
});

authRouter.post('/logout', async (c) => {
  const isJson = c.req.header('content-type')?.includes('application/json');
  const body = isJson ? await c.req.json() : {};
  const params = isJson ? { frontendUrl: body.frontendUrl } : {};
  const { url, accessToken, refreshToken } = oauthProvider.getLogoutUrl(params);

  deleteCookie(c, accessToken.name, accessToken.options);
  deleteCookie(c, refreshToken.name, refreshToken.options);
  return c.json({ url });
});
