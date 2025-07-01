import type { Request, Response } from 'express';
import { $err, $ok, OAuthError, type Result } from '~/error';
import type { Metadata } from '~/types';
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
): Promise<{ userInfo: UserInfo; tryInjectData: InjectDataFunction }> {
  const oauthProvider = req.oauthProvider;

  const InjectFunc = async <T extends object = Record<any, string>>(
    accessToken: string,
    data: T,
  ): Promise<Result<{ injectedData: T }>> => {
    const inj = await oauthProvider.tryInjectData({ accessToken, data });
    if (inj.error) return $err(inj.error);
    if (req.userInfo?.isApp !== false) {
      return $err('bad_request', { error: 'Invalid user type', description: 'Injecting data is only supported users' });
    }
    $setCookie(res, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    req.userInfo = { ...req.userInfo, injectedData: data };
    return $ok({ injectedData: data });
  };

  // Check for Bearer token in Authorization header for B2B requests
  const authHeader = req.headers.authorization;
  if (oauthProvider.settings.acceptB2BRequests && authHeader) {
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
    const bearerAt = await oauthProvider.verifyAccessToken(token);
    if (bearerAt.error) throw new OAuthError(bearerAt.error);

    const userInfo = $setUserInfo(req, bearerAt.meta);
    req.accessTokenInfo = { jwt: bearerAt.rawJwt, payload: bearerAt.payload };

    return {
      userInfo,
      tryInjectData: (data) =>
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
  const accessToken = $getCookie(req, accessTokenName);
  const refreshToken = $getCookie(req, refreshTokenName);

  if (!accessToken && !refreshToken) {
    throw new OAuthError('nullish_value', {
      error: 'Unauthorized',
      description: 'Access token and refresh token are required for authentication',
      status: 401,
    });
  }

  const at = await oauthProvider.verifyAccessToken(accessToken);

  if (at.success) {
    req.accessTokenInfo = { jwt: at.rawJwt, payload: at.payload };
    const userInfo = $setUserInfo(req, at.meta, at.injectedData);

    return { userInfo, tryInjectData: (data) => InjectFunc(at.rawJwt, data) };
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw new OAuthError(rt.error);

  $setCookie(res, rt.newAccessToken.name, rt.newAccessToken.value, rt.newAccessToken.options);
  if (rt.newRefreshToken) {
    $setCookie(res, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);
  }

  const userInfo = $setUserInfo(req, rt.meta);
  req.accessTokenInfo = { jwt: rt.rawAccessToken, payload: rt.payload };

  return { userInfo, tryInjectData: (data) => InjectFunc(rt.rawAccessToken, data) };
}

function $setUserInfo<T extends object = Record<any, string>>(req: Request, meta: Metadata, injectedData?: T) {
  const userInfo = {
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? {
          isApp: true as const,
          appId: meta.appId as string,
        }
      : {
          isApp: false as const,
          name: meta.name as string,
          email: meta.email as string,
          injectedData,
        }),
  };

  req.userInfo = userInfo;
  return userInfo;
}
