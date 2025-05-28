import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import { getCookie, setCookie } from './cookie-parser';
import type { InjectDataFunction, UserInfo } from './types';

export async function sharedIsAuthenticated(
  req: Request,
  res: Response,
): Promise<{ userInfo: UserInfo; injectData: InjectDataFunction }> {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
      status: 500,
    });
  }

  const oauthProvider = req.oauthProvider;

  const InjectDataFunction = async <T extends object = Record<any, string>>(accessToken: string, data: T) => {
    const { injectedAccessToken, success } = await oauthProvider.injectData({ accessToken, data });
    if (success) setCookie(res, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    if (req.userInfo?.isApp === false) {
      req.userInfo = { ...req.userInfo, injectedData: data };
    }
  };

  // Check for Bearer token in Authorization header for B2B requests
  const authorizationHeader = req.headers.authorization;
  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfo.error) throw new OAuthError(bearerInfo.error);

    const userInfo = getUserInfo({ payload: bearerInfo.payload, isApp: true });

    req.accessTokenInfo = { jwt: bearerInfo.rawAccessToken, payload: bearerInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => Promise.resolve() };
  }

  // Check for access and refresh tokens in cookies
  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError('nullish_value', {
      error: 'Unauthorized',
      description: 'Access token and refresh token are required for authentication',
      status: 401,
    });
  }

  const accessTokenInfo = await oauthProvider.verifyAccessToken(cookieAccessToken);

  if (!accessTokenInfo.error) {
    const userInfo = getUserInfo({ payload: accessTokenInfo.payload, injectedData: accessTokenInfo.injectedData });

    req.accessTokenInfo = { jwt: accessTokenInfo.rawAccessToken, payload: accessTokenInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => InjectDataFunction(accessTokenInfo.rawAccessToken, data) };
  }

  const refreshTokenInfo = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  //TODO: check this error
  if (refreshTokenInfo.error) throw new OAuthError(refreshTokenInfo.error);
  const { newTokens } = refreshTokenInfo;

  setCookie(res, newTokens.accessToken.name, newTokens.accessToken.value, newTokens.accessToken.options);
  if (newTokens.refreshToken) {
    setCookie(res, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  const userInfo = getUserInfo({ payload: refreshTokenInfo.payload, isApp: false });
  req.accessTokenInfo = { jwt: refreshTokenInfo.rawAccessToken, payload: refreshTokenInfo.payload };
  req.userInfo = userInfo;

  return { userInfo, injectData: (data) => InjectDataFunction(refreshTokenInfo.rawAccessToken, data) };
}

function getUserInfo<T extends object = Record<any, string>>({
  payload,
  injectedData,
  isApp,
}: { payload: JwtPayload; injectedData?: T; isApp?: boolean }) {
  return isApp
    ? ({
        isApp: true,
        uniqueId: payload.oid,
        roles: payload.roles,
        appId: payload.azp,
      } as const)
    : ({
        isApp: false,
        uniqueId: payload.oid,
        roles: payload.roles,
        name: payload.name,
        email: payload.preferred_username,
        injectedData,
      } as const);
}
