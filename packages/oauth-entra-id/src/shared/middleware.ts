import type { Request, Response } from 'express';
import type { JwtPayload } from 'jsonwebtoken';
import { $err, $ok, OAuthError } from '~/error';
import { $getCookie, $setCookie } from './cookie-parser';
import type { InjectDataFunction, UserInfo } from './types';

/**
 * Validates or refreshes a session cookie, attaches `userInfo`, and returns an InjectDataFunction for adding metadata to the access token.
 *
 * @throws {OAuthError} on misconfiguration, missing tokens, or verification failure
 */
export async function $sharedMiddleware(
  req: Request,
  res: Response,
): Promise<{ userInfo: UserInfo; injectData: InjectDataFunction }> {
  const oauthProvider = req.oauthProvider;

  const InjectDataFunction = async <T extends object = Record<any, string>>(accessToken: string, data: T) => {
    const { injectedAccessToken, error } = await oauthProvider.injectData({ accessToken, data });
    if (error) return $err(error);
    if (req.userInfo?.isApp === false) {
      $setCookie(res, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
      req.userInfo = { ...req.userInfo, injectedData: data };
      return $ok();
    }
    return $err('bad_request', { error: 'Invalid user type', description: 'Injecting data is only supported users' });
  };

  // Check for Bearer token in Authorization header for B2B requests
  const authorizationHeader = req.headers.authorization;
  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfo.error) throw new OAuthError(bearerInfo.error);

    const userInfo = $setUserInfo(req, { payload: bearerInfo.payload, isApp: true });

    req.accessTokenInfo = { jwt: bearerInfo.rawAccessToken, payload: bearerInfo.payload };

    return {
      userInfo,
      injectData: (data) =>
        Promise.resolve(
          $err('bad_request', {
            error: 'Injecting data is not supported for B2B requests',
            description: 'Injecting data is only supported for user type',
          }),
        ),
    };
  }

  // Check for access and refresh tokens in cookies
  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const cookieAccessToken = $getCookie(req, accessTokenName);
  const cookieRefreshToken = $getCookie(req, refreshTokenName);

  if (!cookieAccessToken && !cookieRefreshToken) {
    throw new OAuthError('nullish_value', {
      error: 'Unauthorized',
      description: 'Access token and refresh token are required for authentication',
      status: 401,
    });
  }

  const accessTokenInfo = await oauthProvider.verifyAccessToken(cookieAccessToken);

  if (accessTokenInfo.success) {
    req.accessTokenInfo = { jwt: accessTokenInfo.rawAccessToken, payload: accessTokenInfo.payload };
    const userInfo = $setUserInfo(req, {
      payload: accessTokenInfo.payload,
      injectedData: accessTokenInfo.injectedData,
    });

    return { userInfo, injectData: (data) => InjectDataFunction(accessTokenInfo.rawAccessToken, data) };
  }

  const refreshTokenInfo = await oauthProvider.getTokenByRefresh(cookieRefreshToken);
  if (refreshTokenInfo.error) throw new OAuthError(refreshTokenInfo.error);
  const { newTokens } = refreshTokenInfo;

  $setCookie(res, newTokens.accessToken.name, newTokens.accessToken.value, newTokens.accessToken.options);
  if (newTokens.refreshToken) {
    $setCookie(res, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  const userInfo = $setUserInfo(req, { payload: refreshTokenInfo.payload, isApp: false });
  req.accessTokenInfo = { jwt: refreshTokenInfo.rawAccessToken, payload: refreshTokenInfo.payload };

  return { userInfo, injectData: (data) => InjectDataFunction(refreshTokenInfo.rawAccessToken, data) };
}

function $setUserInfo<T extends object = Record<any, string>>(
  req: Request,
  params: { payload: JwtPayload; injectedData?: T; isApp?: boolean },
) {
  const userInfo = params.isApp
    ? ({
        isApp: true,
        uniqueId: params.payload.oid,
        roles: params.payload.roles,
        appId: params.payload.azp,
      } as const)
    : ({
        isApp: false,
        uniqueId: params.payload.oid,
        roles: params.payload.roles,
        name: params.payload.name,
        email: params.payload.preferred_username,
        injectedData: params.injectedData,
      } as const);

  req.userInfo = userInfo;
  return userInfo;
}
