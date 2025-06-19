import type { Context } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';
import { type JwtPayload, OAuthError } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const authorizationHeader = c.req.header('Authorization');

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfo.error) throw new OAuthError(bearerInfo.error);

    setUserInfo(c, { payload: bearerInfo.payload, isApp: true });

    return await next();
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const accessTokenInfo = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (accessTokenInfo.success) {
    c.set('accessTokenInfo', { jwt: accessTokenInfo.rawAccessToken, payload: accessTokenInfo.payload });
    if (accessTokenInfo.hasInjectedData) {
      setUserInfo(c, { payload: accessTokenInfo.payload, injectedData: accessTokenInfo.injectedData });
      return await next();
    }

    const { injectedAccessToken, success, injectedData } = await oauthProvider.tryInjectData({
      accessToken: accessTokenInfo.rawAccessToken,
      data: { randomNumber: getRandomNumber() },
    });

    if (success) setCookie(c, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    setUserInfo(c, { payload: accessTokenInfo.payload, injectedData });
    return await next();
  }

  const refreshTokenInfo = await oauthProvider.tryRefreshTokens(refreshToken);
  if (refreshTokenInfo.error) throw new OAuthError(refreshTokenInfo.error);
  const { newTokens } = refreshTokenInfo;

  c.set('accessTokenInfo', { jwt: refreshTokenInfo.rawAccessToken, payload: refreshTokenInfo.payload });

  const { injectedAccessToken, success, injectedData } = await oauthProvider.tryInjectData({
    accessToken: refreshTokenInfo.rawAccessToken,
    data: { randomNumber: getRandomNumber() },
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
