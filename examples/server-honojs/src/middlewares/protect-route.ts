import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { type Metadata, OAuthError } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';
import { getRandomNumber } from '~/utils/generate';

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  // Check for Bearer token in Authorization header for B2B requests
  const authHeader = c.req.header('Authorization');
  if (oauthProvider.settings.acceptB2BRequests && authHeader) {
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
    const bearer = await oauthProvider.verifyAccessToken(token);
    if (bearer.error) throw new OAuthError(bearer.error);
    setUserInfo(c, bearer.meta);
    return await next();
  }

  // Normal requests with access and refresh tokens in cookies
  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const at = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (at.success) {
    c.set('accessTokenInfo', { jwt: at.rawJwt, payload: at.payload });
    if (at.hasInjectedData) {
      setUserInfo(c, at.meta, at.injectedData);
      return await next();
    }

    const inj = await oauthProvider.tryInjectData({ accessToken: at.rawJwt, data: getRandomNumber() });
    if (inj.success) setCookie(c, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    setUserInfo(c, at.meta, inj.injectedData);
    return await next();
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw new OAuthError(rt.error);
  c.set('accessTokenInfo', { jwt: rt.rawJwt, payload: rt.payload });

  const inj = await oauthProvider.tryInjectData({ accessToken: rt.rawJwt, data: getRandomNumber() });
  const final = inj.success ? inj.newAccessToken : rt.newAccessToken;

  setCookie(c, final.name, final.value, final.options);
  if (rt.newRefreshToken) setCookie(c, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);

  setUserInfo(c, rt.meta, inj.injectedData);
  return await next();
});

function setUserInfo(c: Context, meta: Metadata, injectedData?: { randomNumber: number }) {
  c.set('userInfo', {
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? { isApp: true as const, appId: meta.appId as string }
      : { isApp: false as const, name: meta.name as string, email: meta.email as string, injectedData }),
  });
}

export type ProtectRoute = {
  Variables: {
    accessTokenInfo: { jwt: string; payload: Record<string, unknown> };
    userInfo: { uniqueId: string; roles: string[] } & (
      | { isApp: false; name: string; email: string; injectedData?: { randomNumber: number } }
      | { isApp: true; appId: string }
    );
  };
};
