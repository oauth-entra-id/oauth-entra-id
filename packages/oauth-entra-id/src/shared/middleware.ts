import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import { debugLog } from '~/utils/debugLog';
import { getCookie } from './cookie-parser';

export const sharedIsAuthenticated = async (req: Request, res: Response) => {
  const oauthProvider = req.oauthProvider;
  const localDebug = (message: string) => {
    const funcName = req.serverType === 'express' ? 'protectRoute' : 'isAuthenticated';
    debugLog({ condition: oauthProvider.options.debug, funcName, message });
  };

  // B2B Part:
  if (oauthProvider.options.areOtherSystemsAllowed && req.headers.authorization?.startsWith('Bearer ')) {
    const authorizationJwt = req.headers.authorization.split(' ')[1];
    localDebug(`authorizationJwt: ${!!authorizationJwt}`);
    if (!authorizationJwt) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    const microsoftInfo = await oauthProvider.verifyAccessToken(authorizationJwt);
    if (!microsoftInfo) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    const isAnotherSystem = microsoftInfo.payload.aud !== microsoftInfo.payload.azp;
    localDebug(`isAnotherSystem: ${isAnotherSystem}`);
    if (!isAnotherSystem) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'The token used is not from another system' });
    }

    req.msal = microsoftInfo;
    req.userInfo = getUserInfo({ payload: microsoftInfo.payload, isOtherApp: true });
    return true;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessTokenCookie = getCookie(req, accessTokenName);
  const refreshTokenCookie = getCookie(req, refreshTokenName);

  localDebug(`Cookies: ${accessTokenName}=${!!accessTokenCookie}, ${refreshTokenName}=${!!refreshTokenCookie}`);
  if (!accessTokenCookie && !refreshTokenCookie) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token or refresh token' });
  }

  if (accessTokenCookie) {
    const microsoftInfo = await oauthProvider.verifyAccessToken(accessTokenCookie);
    if (microsoftInfo) {
      req.msal = microsoftInfo;
      req.userInfo = getUserInfo({ payload: microsoftInfo.payload, isOtherApp: false });
      return true;
    }
  }

  localDebug('Access token is invalid, trying to refresh it...');
  if (!refreshTokenCookie) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No refresh token' });
  }

  const newTokens = await oauthProvider.getTokenByRefresh(refreshTokenCookie);
  if (!newTokens) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });
  }

  localDebug('Access token refreshed successfully');

  const { newAccessToken, newRefreshToken, msal } = newTokens;
  res.cookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) res.cookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  req.msal = msal;
  req.userInfo = getUserInfo({ payload: msal.payload, isOtherApp: false });
  return true;
};

function getUserInfo({ payload, isOtherApp }: { payload: JwtPayload; isOtherApp: boolean }) {
  return isOtherApp
    ? ({
        isOtherApp: true,
        uniqueId: payload.oid,
        roles: payload.roles,
        appId: payload.azp,
      } as const)
    : ({
        isOtherApp: false,
        uniqueId: payload.oid,
        roles: payload.roles,
        name: payload.name,
        email: payload.preferred_username,
      } as const);
}
