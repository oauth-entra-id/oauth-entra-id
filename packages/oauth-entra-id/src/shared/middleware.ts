import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
import { debugLog } from '~/utils/debugLog';
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

  const InjectDataFunction = (accessToken: string, data: InjectedData) => {
    const newAccessToken = oauthProvider.injectData({ accessToken, data });
    if (newAccessToken) setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
    if (req.userInfo?.isB2B === false) req.userInfo = { ...req.userInfo, injectedData: data };
  };

  if (oauthProvider.settings.isB2BEnabled || oauthProvider.settings.sessionType === 'bearer-token') {
    const bearerAccessToken = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.split(' ')[1]
      : undefined;

    if (!bearerAccessToken) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token' });
    }

    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (!bearerInfo) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    const userInfo = getUserInfo({ payload: bearerInfo.microsoftInfo.accessTokenPayload, isB2B: bearerInfo.isB2B });

    req.microsoftInfo = bearerInfo.microsoftInfo;
    req.userInfo = userInfo;
    return {
      userInfo,
      injectData: (data) => (bearerInfo.isB2B ? null : InjectDataFunction(bearerAccessToken, data)),
    };
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);
  localDebug(`Cookies: ${accessTokenName}=${!!cookieAccessToken}, ${refreshTokenName}=${!!cookieRefreshToken}`);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token and refresh token' });
  }

  const tokenInfo = cookieAccessToken ? await oauthProvider.verifyAccessToken(cookieAccessToken) : null;

  if (tokenInfo) {
    const userInfo = getUserInfo({
      payload: tokenInfo.microsoftInfo.accessTokenPayload,
      injectedData: tokenInfo.injectedData,
    });

    req.microsoftInfo = tokenInfo.microsoftInfo;
    req.userInfo = userInfo;
    return {
      userInfo,
      injectData: (data) => InjectDataFunction(tokenInfo.microsoftInfo.rawAccessToken, data),
    };
  }

  if (!cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No refresh token' });
  }

  const newTokensInfo = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  if (!newTokensInfo) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });
  }

  const { newAccessToken, newRefreshToken, microsoftInfo } = newTokensInfo;

  setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(res, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  const userInfo = getUserInfo({ payload: microsoftInfo.accessTokenPayload, isB2B: false });
  req.microsoftInfo = microsoftInfo;
  req.userInfo = userInfo;
  return {
    userInfo,
    injectData: (data) => InjectDataFunction(newAccessToken.value, data),
  };
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
