import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import type { JwtPayload } from 'oauth-entra-id';
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
      injectedData?: {
        randomNumber: number;
      };
    };
  };
};

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const tokenInfo = accessToken ? await oauthProvider.verifyAccessToken(accessToken) : null;
  if (tokenInfo) {
    c.set('microsoftInfo', tokenInfo.microsoftInfo);
    if (tokenInfo.injectedData) {
      setUserInfo(c, tokenInfo.microsoftInfo.accessTokenPayload, tokenInfo.injectedData as { randomNumber: number });
    } else {
      const randomNumber = getRandomNumber();
      const newAccessToken = oauthProvider.injectData({
        accessToken: tokenInfo.microsoftInfo.rawAccessToken,
        data: { randomNumber },
      });
      if (newAccessToken) setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
      setUserInfo(c, tokenInfo.microsoftInfo.accessTokenPayload, newAccessToken ? { randomNumber } : undefined);
    }

    await next();
    return;
  }

  if (!refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) throw new HTTPException(401, { message: 'Unauthorized' });

  const { newAccessToken, newRefreshToken, microsoftInfo } = newTokensInfo;
  c.set('microsoftInfo', microsoftInfo);

  const randomNumber = getRandomNumber();
  const newerAccessToken = oauthProvider.injectData({
    accessToken: microsoftInfo.rawAccessToken,
    data: { randomNumber },
  });

  const finalAccessToken = newerAccessToken ?? newAccessToken;

  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  setUserInfo(c, microsoftInfo.accessTokenPayload, newerAccessToken ? { randomNumber } : undefined);

  await next();
});

function setUserInfo(c: Context, payload: JwtPayload, injectedData?: { randomNumber: number }) {
  c.set('userInfo', {
    uniqueId: payload.oid,
    roles: payload.roles,
    name: payload.name,
    email: payload.preferred_username,
    injectedData,
  });
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
