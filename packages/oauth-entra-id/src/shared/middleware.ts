import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
import { debugLog } from '~/utils/debugLog';
import { getCookie, setCookie } from './cookie-parser';

export async function sharedIsAuthenticated(req: Request, res: Response) {
  const localDebug = (message: string) => {
    debugLog({
      condition: req.oauthProvider.settings.debug,
      funcName: req.serverType === 'express' ? 'protectRoute' : 'isAuthenticated',
      message,
    });
  };

  const oauthProvider = req.oauthProvider;

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

    req.microsoftInfo = bearerInfo.microsoftInfo;
    req.userInfo = getUserInfo({ payload: bearerInfo.microsoftInfo.accessTokenPayload, isB2B: bearerInfo.isB2B });
    return true;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);
  localDebug(`Cookies: ${accessTokenName}=${!!cookieAccessToken}, ${refreshTokenName}=${!!cookieRefreshToken}`);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token and refresh token' });
  }

  if (cookieAccessToken) {
    const tokenInfo = await oauthProvider.verifyAccessToken(cookieAccessToken);
    if (tokenInfo) {
      req.microsoftInfo = tokenInfo.microsoftInfo;
      req.userInfo = getUserInfo({
        payload: tokenInfo.microsoftInfo.accessTokenPayload,
        injectedData: tokenInfo.injectedData,
      });
      return true;
    }
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

  req.microsoftInfo = microsoftInfo;
  req.userInfo = getUserInfo({ payload: microsoftInfo.accessTokenPayload, isB2B: false });
  return true;
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
