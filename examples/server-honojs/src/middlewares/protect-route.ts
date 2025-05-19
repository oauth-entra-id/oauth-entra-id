import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import type { JwtPayload } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';

export type ProtectRoute = {
  Variables: {
    accessTokenInfo: {
      jwt: string;
      payload: Record<string, unknown>;
    };
    userInfo:
      | {
          isB2B: false;
          uniqueId: string;
          roles: string[];
          name: string;
          email: string;
          injectedData?: {
            randomNumber: number;
          };
        }
      | { isB2B: true; uniqueId: string; roles: string[]; appId: string };
  };
};

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const authorizationHeader = c.req.header('Authorization');

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (!bearerInfo) throw new HTTPException(401, { message: 'Unauthorized' });

    setUserInfo(c, { payload: bearerInfo.payload, isB2B: true });

    return await next();
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const tokenInfo = await oauthProvider.verifyAccessToken(accessToken);
  if (tokenInfo) {
    c.set('accessTokenInfo', { jwt: tokenInfo.jwtAccessToken, payload: tokenInfo.payload });
    const injectedData = tokenInfo.injectedData
      ? (tokenInfo.injectedData as { randomNumber: number })
      : { randomNumber: getRandomNumber() };

    if (!tokenInfo.injectedData) {
      const newAccessToken = oauthProvider.injectData({ accessToken: tokenInfo.jwtAccessToken, data: injectedData });
      if (!newAccessToken) {
        setUserInfo(c, { payload: tokenInfo.payload });
        return await next();
      }
      setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
    }

    setUserInfo(c, { payload: tokenInfo.payload, injectedData });
    return await next();
  }

  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) throw new HTTPException(401, { message: 'Unauthorized' });

  const { jwtAccessToken, payload, newAccessToken, newRefreshToken } = newTokensInfo;
  c.set('accessTokenInfo', { jwt: jwtAccessToken, payload });

  const injectedData = { randomNumber: getRandomNumber() };
  const newerAccessToken = oauthProvider.injectData({ accessToken: jwtAccessToken, data: injectedData });

  const finalAccessToken = newerAccessToken ?? newAccessToken;

  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  setUserInfo(c, { payload, injectedData: newerAccessToken ? injectedData : undefined });
  return await next();
});

function setUserInfo(
  c: Context,
  { payload, injectedData, isB2B }: { payload: JwtPayload; injectedData?: { randomNumber: number }; isB2B?: boolean },
) {
  c.set(
    'userInfo',
    isB2B
      ? { isB2B: true, uniqueId: payload.oid, roles: payload.roles, appId: payload.appid }
      : {
          isB2B: false,
          uniqueId: payload.oid,
          roles: payload.roles,
          name: payload.name,
          email: payload.preferred_username,
          injectedData,
        },
  );
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
