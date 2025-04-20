import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { oauthProvider } from '~/oauth';

type RequireAuthentication = {
  msal: {
    microsoftToken: string;
    payload: Record<string, unknown>;
  };
  userInfo: {
    uniqueId: string;
    roles: string[];
    name: string;
    email: string;
  };
};

export const requireAuthentication = createMiddleware<{ Variables: RequireAuthentication }>(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);

  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  const microsoftInfo = await oauthProvider.verifyAccessToken(accessToken);
  if (microsoftInfo) {
    c.set('msal', microsoftInfo);
    c.set('userInfo', {
      uniqueId: microsoftInfo.payload.oid,
      roles: microsoftInfo.payload.roles,
      name: microsoftInfo.payload.name,
      email: microsoftInfo.payload.preferred_username,
    });

    await next();
    return;
  }
  if (!refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  const newTokens = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokens) throw new HTTPException(401, { message: 'Unauthorized' });
  const { newAccessToken, newRefreshToken, msal } = newTokens;
  setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  c.set('msal', msal);
  c.set('userInfo', {
    uniqueId: msal.payload.oid,
    roles: msal.payload.roles,
    name: msal.payload.name,
    email: msal.payload.preferred_username,
  });

  await next();
});
