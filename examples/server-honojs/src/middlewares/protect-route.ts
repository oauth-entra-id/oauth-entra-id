import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import type { JwtPayload } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const authorizationHeader = c.req.header('Authorization');

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfo.error) throw new HTTPException(bearerInfo.error.statusCode, { message: bearerInfo.error.message });

    setUserInfo(c, { payload: bearerInfo.payload, isApp: true });

    return await next();
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const accessTokenInfo = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (!accessTokenInfo.error) {
    c.set('accessTokenInfo', { jwt: accessTokenInfo.rawAccessToken, payload: accessTokenInfo.payload });
    const injectedData = accessTokenInfo.injectedData ?? { randomNumber: getRandomNumber() };

    if (accessTokenInfo.injectedData) {
      setUserInfo(c, { payload: accessTokenInfo.payload, injectedData });
      return await next();
    }

    const { injectedAccessToken, success } = oauthProvider.injectData({
      accessToken: accessTokenInfo.rawAccessToken,
      data: injectedData,
    });

    if (success) {
      setCookie(c, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
      setUserInfo(c, { payload: accessTokenInfo.payload, injectedData });
      return await next();
    }

    setUserInfo(c, { payload: accessTokenInfo.payload, injectedData });
    return await next();
  }

  const refreshTokenInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (refreshTokenInfo.error) {
    throw new HTTPException(refreshTokenInfo.error.statusCode, { message: refreshTokenInfo.error.message });
  }
  const { newTokens } = refreshTokenInfo;

  c.set('accessTokenInfo', { jwt: refreshTokenInfo.rawAccessToken, payload: refreshTokenInfo.payload });

  const injectedData = { randomNumber: getRandomNumber() };
  const { injectedAccessToken, success } = oauthProvider.injectData({
    accessToken: refreshTokenInfo.rawAccessToken,
    data: injectedData,
  });

  const finalAccessToken = success ? injectedAccessToken : newTokens.accessToken;

  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newTokens.refreshToken) {
    setCookie(c, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  setUserInfo(c, { payload: refreshTokenInfo.payload, injectedData });
  return await next();
});

function setUserInfo(
  c: Context,
  params: { payload: JwtPayload; injectedData?: { randomNumber: number }; isApp?: boolean },
) {
  c.set(
    'userInfo',
    params.isApp
      ? { isApp: true, uniqueId: params.payload.oid, roles: params.payload.roles, appId: params.payload.appid }
      : {
          isApp: false,
          uniqueId: params.payload.oid,
          roles: params.payload.roles,
          name: params.payload.name,
          email: params.payload.preferred_username,
          injectedData: params.injectedData,
        },
  );
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}

export type ProtectRoute = {
  Variables: {
    accessTokenInfo: {
      jwt: string;
      payload: Record<string, unknown>;
    };
    userInfo:
      | {
          isApp: false;
          uniqueId: string;
          roles: string[];
          name: string;
          email: string;
          injectedData?: {
            randomNumber: number;
          };
        }
      | { isApp: true; uniqueId: string; roles: string[]; appId: string };
  };
};
