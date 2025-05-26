import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
import { $logger } from '~/utils/misc';
import { getCookie, setCookie } from './cookie-parser';
import type { InjectDataFunction, UserInfo } from './types';

export async function sharedIsAuthenticated(
  req: Request,
  res: Response,
): Promise<{ userInfo: UserInfo; injectData: InjectDataFunction }> {
  const oauthProvider = req.oauthProvider;

  if (oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
    });
  }

  const InjectDataFunction = (accessToken: string, data: InjectedData) => {
    const { result: newAccessToken } = oauthProvider.injectData({ accessToken, data });
    if (newAccessToken) setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
    if (req.userInfo?.isApp === false) req.userInfo = { ...req.userInfo, injectedData: data };
  };

  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const { result: bearerInfo, error: bearerError } = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerError) throw new OAuthError(bearerError);

    const userInfo = getUserInfo({ payload: bearerInfo.payload, isApp: true });

    req.accessTokenInfo = { jwt: bearerInfo.rawAccessToken, payload: bearerInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => null };
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError('nullish_value', {
      error: 'Unauthorized',
      description: 'Access token and refresh token are required for authentication',
    });
  }

  const { result: tokenInfo } = await oauthProvider.verifyAccessToken(cookieAccessToken);

  if (tokenInfo) {
    const userInfo = getUserInfo({ payload: tokenInfo.payload, injectedData: tokenInfo.injectedData });

    req.accessTokenInfo = { jwt: tokenInfo.rawAccessToken, payload: tokenInfo.payload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => InjectDataFunction(tokenInfo.rawAccessToken, data) };
  }

  const { result: newTokensInfo, error: newTokensError } = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  if (newTokensError) throw new OAuthError(newTokensError);
  const { rawAccessToken, payload, newAccessToken, newRefreshToken } = newTokensInfo;

  setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(res, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  const userInfo = getUserInfo({ payload, isApp: false });
  req.accessTokenInfo = { jwt: rawAccessToken, payload };
  req.userInfo = userInfo;

  return { userInfo, injectData: (data) => InjectDataFunction(newAccessToken.value, data) };
}

function getUserInfo({
  payload,
  injectedData,
  isApp,
}: { payload: JwtPayload; injectedData?: InjectedData; isApp?: boolean }) {
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
