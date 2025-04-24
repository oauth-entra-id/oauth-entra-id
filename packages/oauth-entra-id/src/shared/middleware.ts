import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import { debugLog } from '~/utils/misc';

export const sharedRequireAuthentication = async (req: Request, res: Response) => {
  const localDebug = (message: string) => {
    debugLog({
      condition: req.oauthProvider.options.debug,
      funcName: req.serverType === 'express' ? 'requireAuthentication' : 'isAuthenticated',
      message,
    });
  };

  if (req.allowOtherSystems && req.headers.authorization?.startsWith('Bearer ')) {
    const authorizationJwt = req.headers.authorization.split(' ')[1];
    localDebug(`authorizationJwt: ${!!authorizationJwt}`);
    if (!authorizationJwt) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    const microsoftInfo = await req.oauthProvider.verifyAccessToken(authorizationJwt);
    if (!microsoftInfo) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });

    const isAnotherSystem = microsoftInfo.payload.aud !== microsoftInfo.payload.azp;
    localDebug(`isAnotherSystem: ${isAnotherSystem}`);
    if (!isAnotherSystem) {
      throw new OAuthError(401, {
        message: 'Unauthorized',
        description: 'The token used is not from another system',
      });
    }

    req.msal = microsoftInfo;
    req.userInfo = getUserInfo({ payload: microsoftInfo.payload, isFromAnotherApp: true });
    return true;
  }

  const { accessTokenName, refreshTokenName } = req.oauthProvider.getCookieNames();
  const accessTokenCookie = req.cookies[accessTokenName] as string | undefined;
  const refreshTokenCookie = req.cookies[refreshTokenName] as string | undefined;

  localDebug(`Cookies: ${accessTokenName}=${!!accessTokenCookie}, ${refreshTokenName}=${!!refreshTokenCookie}`);
  if (!accessTokenCookie && !refreshTokenCookie) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token or refresh token' });
  }

  if (accessTokenCookie) {
    const microsoftInfo = await req.oauthProvider.verifyAccessToken(accessTokenCookie);
    if (microsoftInfo) {
      req.msal = microsoftInfo;
      req.userInfo = getUserInfo({ payload: microsoftInfo.payload, isFromAnotherApp: false });
      return true;
    }
  }

  localDebug('Access token is invalid, trying to refresh it...');
  if (!refreshTokenCookie) throw new OAuthError(401, { message: 'Unauthorized', description: 'No refresh token' });

  const newTokens = await req.oauthProvider.getTokenByRefresh(refreshTokenCookie);
  if (!newTokens) throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });
  const { newAccessToken, newRefreshToken, msal } = newTokens;
  localDebug('Access token refreshed successfully');

  res.cookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) res.cookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  req.msal = msal;
  req.userInfo = getUserInfo({ payload: msal.payload, isFromAnotherApp: false });
  return true;
};

function getUserInfo({ payload, isFromAnotherApp }: { payload: JwtPayload; isFromAnotherApp: boolean }) {
  return isFromAnotherApp
    ? ({
        isFromAnotherApp: true,
        uniqueId: payload.oid,
        roles: payload.roles,
        appId: payload.azp,
      } as const)
    : ({
        isFromAnotherApp: false,
        uniqueId: payload.oid,
        roles: payload.roles,
        name: payload.name,
        email: payload.preferred_username,
      } as const);
}
