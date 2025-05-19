import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
import { debugLog } from '~/utils/misc';
import { getCookie, setCookie } from './cookie-parser';
import type { InjectDataFunction, UserInfo } from './types';

export async function sharedIsAuthenticated(
  req: Request,
  res: Response,
): Promise<{ userInfo: UserInfo; injectData: InjectDataFunction }> {
  const localDebug = (message: string) => {
    debugLog({
      condition: req.oauthProvider.settings.debug,
      funcName: req.serverType === 'express' ? 'protectRoute' : 'isAuthenticated',
      message,
    });
  };

  const oauthProvider = req.oauthProvider;
  if (oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError(500, { message: 'Invalid session type', description: 'Session type must be cookie-session' });
  }

  const InjectDataFunction = (accessToken: string, data: InjectedData) => {
    const newAccessToken = oauthProvider.injectData({ accessToken, data });
    if (newAccessToken) setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
    if (req.userInfo?.isB2B === false) req.userInfo = { ...req.userInfo, injectedData: data };
  };

  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (!bearerInfo) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    const userInfo = getUserInfo({ payload: bearerInfo.payload, isB2B: true });

    req.accessTokenInfo = { jwt: bearerInfo.jwtAccessToken, payload: bearerInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => null };
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);
  localDebug(`Cookies: ${accessTokenName}=${!!cookieAccessToken}, ${refreshTokenName}=${!!cookieRefreshToken}`);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token and refresh token' });
  }

  const tokenInfo = await oauthProvider.verifyAccessToken(cookieAccessToken);

  if (tokenInfo) {
    const userInfo = getUserInfo({ payload: tokenInfo.payload, injectedData: tokenInfo.injectedData });

    req.accessTokenInfo = { jwt: tokenInfo.jwtAccessToken, payload: tokenInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => InjectDataFunction(tokenInfo.jwtAccessToken, data) };
  }

  const newTokensInfo = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  if (!newTokensInfo) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });
  const { jwtAccessToken, payload, newAccessToken, newRefreshToken } = newTokensInfo;

  setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(res, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  const userInfo = getUserInfo({ payload, isB2B: false });
  req.accessTokenInfo = { jwt: jwtAccessToken, payload };
  req.userInfo = userInfo;

  return { userInfo, injectData: (data) => InjectDataFunction(newAccessToken.value, data) };
}

function getUserInfo({
  payload,
  injectedData,
  isB2B,
}: { payload: JwtPayload; injectedData?: InjectedData; isB2B?: boolean }) {
  return isB2B
    ? ({
        isB2B: true,
        uniqueId: payload.oid,
        roles: payload.roles,
        appId: payload.azp,
      } as const)
    : ({
        isB2B: false,
        uniqueId: payload.oid,
        roles: payload.roles,
        name: payload.name,
        email: payload.preferred_username,
        injectedData,
      } as const);
}
