import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { oauthProvider } from '~/oauth';

export type ProtectRoute = {
  Variables: {
    microsoftInfo: {
      rawAccessToken: string;
      accessTokenPayload: Record<string, unknown>;
    };
    userInfo: {
      uniqueId: string;
      roles: string[];
      name: string;
      email: string;
    };
  };
};

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);

  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  if (accessToken) {
    const tokenInfo = await oauthProvider.verifyAccessToken(accessToken);
    if (tokenInfo) {
      c.set('microsoftInfo', tokenInfo.microsoftInfo);
      c.set('userInfo', {
        uniqueId: tokenInfo.microsoftInfo.accessTokenPayload.oid,
        roles: tokenInfo.microsoftInfo.accessTokenPayload.roles,
        name: tokenInfo.microsoftInfo.accessTokenPayload.name,
        email: tokenInfo.microsoftInfo.accessTokenPayload.preferred_username,
      });

      await next();
      return;
    }
  }
  if (!refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) throw new HTTPException(401, { message: 'Unauthorized' });

  const { newAccessToken, newRefreshToken, microsoftInfo } = newTokensInfo;
  setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  c.set('microsoftInfo', microsoftInfo);
  c.set('userInfo', {
    uniqueId: microsoftInfo.accessTokenPayload.oid,
    roles: microsoftInfo.accessTokenPayload.roles,
    name: microsoftInfo.accessTokenPayload.name,
    email: microsoftInfo.accessTokenPayload.preferred_username,
  });

  await next();
});
