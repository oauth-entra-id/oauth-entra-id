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
    const { error: bearerError, payload: bearerPayload } = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerError) throw new HTTPException(bearerError.statusCode, { message: bearerError.message });

    setUserInfo(c, { payload: bearerPayload, isApp: true });

    return await next();
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const {
    error: accessTokenError,
    rawAccessToken: cookieRawAt,
    payload: cookiePayload,
    injectedData: cookieInjectedData,
  } = await oauthProvider.verifyAccessToken(accessToken);
  if (!accessTokenError) {
    c.set('accessTokenInfo', { jwt: cookieRawAt, payload: cookiePayload });
    const injectedData = cookieInjectedData
      ? (cookieInjectedData as { randomNumber: number })
      : { randomNumber: getRandomNumber() };

    if (!cookieInjectedData) {
      const { error: injectedError, injectedAccessToken } = oauthProvider.injectData({
        accessToken: cookieRawAt,
        data: injectedData,
      });
      if (injectedError) {
        setUserInfo(c, { payload: cookiePayload });
        return await next();
      }
      setCookie(c, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    }

    setUserInfo(c, { payload: cookiePayload, injectedData });
    return await next();
  }

  const {
    error: newTokensError,
    newTokens,
    rawAccessToken,
    payload,
  } = await oauthProvider.getTokenByRefresh(refreshToken);
  if (newTokensError) throw new HTTPException(newTokensError.statusCode, { message: newTokensError.message });

  c.set('accessTokenInfo', { jwt: rawAccessToken, payload });

  const injectedData = { randomNumber: getRandomNumber() };
  const { injectedAccessToken } = oauthProvider.injectData({ accessToken: rawAccessToken, data: injectedData });

  const finalAccessToken = injectedAccessToken ?? newTokens.accessToken;

  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newTokens.refreshToken) {
    setCookie(c, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  setUserInfo(c, { payload, injectedData: injectedAccessToken ? injectedData : undefined });
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
