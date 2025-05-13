import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
import { debugLog } from '~/utils/debugLog';
import { getCookie, setCookie } from './cookie-parser';

export async function sharedIsAuthenticated(req: Request, res: Response) {
  const localDebug = getLocalDebug(req);
  const oauthProvider = req.oauthProvider;

  const bearerAccessToken = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.split(' ')[1]
    : undefined;

  const bearerInfo = await checkAuthorizationToken({ bearerAccessToken, oauthProvider });
  if (bearerInfo) {
    req.msal = bearerInfo.msal;
    req.userInfo = bearerInfo.userInfo;
    return true;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const cookieAccessToken = getCookie(req, accessTokenName);
  const cookieRefreshToken = getCookie(req, refreshTokenName);
  localDebug(`Cookies: ${accessTokenName}=${!!cookieAccessToken}, ${refreshTokenName}=${!!cookieRefreshToken}`);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token and refresh token' });
  }

  const accessTokenInfo = await checkAccessToken({ cookieAccessToken, oauthProvider });
  if (accessTokenInfo) {
    req.msal = accessTokenInfo.msal;
    req.userInfo = accessTokenInfo.userInfo;
    return true;
  }

  if (!cookieRefreshToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'No refresh token' });
  }

  const { newAccessToken, newRefreshToken, msal } = await refreshTokens({ cookieRefreshToken, oauthProvider });
  setCookie(res, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(res, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  req.msal = msal;
  req.userInfo = getUserInfo({ payload: msal.payload, isOtherApp: false });
  return true;
}

async function checkAuthorizationToken({
  bearerAccessToken,
  oauthProvider,
}: {
  bearerAccessToken: string | undefined;
  oauthProvider: OAuthProvider;
}) {
  if (oauthProvider.settings.areOtherSystemsAllowed) {
    if (!bearerAccessToken) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'No access token' });
    }

    const microsoftInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (!microsoftInfo) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
    }

    const isAnotherSystem = microsoftInfo.payload.aud !== microsoftInfo.payload.azp;
    if (!isAnotherSystem) {
      throw new OAuthError(401, { message: 'Unauthorized', description: 'The token used is not from another system' });
    }

    return {
      msal: { microsoftToken: bearerAccessToken, payload: microsoftInfo.payload },
      userInfo: getUserInfo({ payload: microsoftInfo.payload, isOtherApp: true }),
    };
  }
}

async function checkAccessToken({
  cookieAccessToken,
  oauthProvider,
}: {
  cookieAccessToken: string | undefined;
  oauthProvider: OAuthProvider;
}) {
  if (cookieAccessToken) {
    const microsoftInfo = await oauthProvider.verifyAccessToken(cookieAccessToken);
    if (microsoftInfo) {
      return {
        msal: { microsoftToken: microsoftInfo.microsoftToken, payload: microsoftInfo.payload },
        userInfo: getUserInfo({
          payload: microsoftInfo.payload,
          injectedData: microsoftInfo.injectedData,
          isOtherApp: false,
        }),
      };
    }
  }
}

async function refreshTokens({
  cookieRefreshToken,
  oauthProvider,
}: {
  cookieRefreshToken: string;
  oauthProvider: OAuthProvider;
}) {
  const newTokens = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  if (!newTokens) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid refresh token' });
  }
  return {
    newAccessToken: newTokens.newAccessToken,
    newRefreshToken: newTokens.newRefreshToken,
    msal: newTokens.msal,
  };
}

function getUserInfo({
  payload,
  injectedData,
  isOtherApp,
}: { payload: JwtPayload; injectedData?: InjectedData; isOtherApp: boolean }) {
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
        injectedData,
      } as const);
}

function getLocalDebug(req: Request) {
  return (message: string) =>
    debugLog({
      condition: req.oauthProvider.settings.debug,
      funcName: req.serverType === 'express' ? 'protectRoute' : 'isAuthenticated',
      message,
    });
}
