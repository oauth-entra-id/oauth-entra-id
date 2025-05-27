import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { OAuthError } from '~/error';
import type { InjectedData } from '~/types';
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

  const InjectDataFunction = (accessToken: string, data: InjectedData) => {
    const { injectedAccessToken, error } = oauthProvider.injectData({ accessToken, data });
    if (!error) setCookie(res, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    if (req.userInfo?.isApp === false) req.userInfo = { ...req.userInfo, injectedData: data };
  };

  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const {
      error: bearerError,
      payload: bearerPayload,
      rawAccessToken: bearerRawAt,
    } = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerError) throw new OAuthError(bearerError);

    const userInfo = getUserInfo({ payload: bearerPayload, isApp: true });

    req.accessTokenInfo = { jwt: bearerRawAt, payload: bearerPayload };
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
      status: 401,
    });
  }

  const {
    error: accessTokenError,
    rawAccessToken: cookieRawAt,
    payload: cookiePayload,
    injectedData: cookieInjectedData,
  } = await oauthProvider.verifyAccessToken(cookieAccessToken);

  if (!accessTokenError) {
    const userInfo = getUserInfo({ payload: cookiePayload, injectedData: cookieInjectedData });

    req.accessTokenInfo = { jwt: cookieRawAt, payload: cookiePayload };
    req.userInfo = userInfo;

    return { userInfo, injectData: (data) => InjectDataFunction(cookieRawAt, data) };
  }

  const {
    error: newTokensError,
    newTokens,
    rawAccessToken,
    payload,
  } = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  //TODO: check this error
  if (newTokensError) throw new OAuthError(newTokensError);

  setCookie(res, newTokens.accessToken.name, newTokens.accessToken.value, newTokens.accessToken.options);
  if (newTokens.refreshToken) {
    setCookie(res, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  const userInfo = getUserInfo({ payload, isApp: false });
  req.accessTokenInfo = { jwt: rawAccessToken, payload };
  req.userInfo = userInfo;

  return { userInfo, injectData: (data) => InjectDataFunction(rawAccessToken, data) };
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
