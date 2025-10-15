import type { Request, Response } from 'express';
import { deleteCookie, getCookie, setCookie } from 'modern-cookies';
import { $err, $ok, type ErrorStruct, OAuthError, type Result } from '~/error';
import type { JwtPayload, Metadata } from '~/types';
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
  const b2b = await $checkB2BToken(req);
  if (b2b.error) throw new OAuthError(b2b.error);
  if (b2b.userInfo) {
    return {
      userInfo: b2b.userInfo,
      tryInjectData: (_data) =>
        Promise.resolve(
          $err({ msg: 'Invalid user type', desc: 'Injecting data is only supported for user-based sessions' }),
        ),
    };
  }

  const injectFunc = $createInjectFunc(req, res);
  const { cookies } = req.oauthProvider.settings;

  let firstError: ErrorStruct | null = null;
  for (const { accessTokenName, refreshTokenName } of cookies.cookieNames) {
    const cookie = await $checkCookieTokens(req, res, injectFunc, accessTokenName, refreshTokenName);
    if (cookie.error) {
      if (!firstError) firstError = cookie.error;
      continue;
    }

    for (const { azureId, accessTokenName, refreshTokenName } of cookies.cookieNames) {
      if (azureId === cookie.userInfo.azureId) continue;
      deleteCookie(res, accessTokenName, cookies.deleteOptions);
      deleteCookie(res, refreshTokenName, cookies.deleteOptions);
    }

    return { userInfo: cookie.userInfo, tryInjectData: cookie.tryInjectData };
  }

  throw new OAuthError(firstError ?? $err({ msg: 'Unauthorized', desc: 'Tokens are invalid or missing', status: 401 }));
}

function $createInjectFunc(req: Request, res: Response) {
  return async <T extends object = Record<string, any>>(
    accessToken: string,
    data: T,
  ): Promise<Result<{ injectedData: T }>> => {
    const inj = await req.oauthProvider.tryInjectData({ accessToken, data });
    if (inj.error) return $err(inj.error);
    if (req.userInfo?.isApp !== false) {
      return $err({ msg: 'Invalid user type', desc: 'Injecting data is only supported for user-based sessions' });
    }
    setCookie(res, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    req.userInfo = { ...req.userInfo, injectedData: data };
    return $ok({ injectedData: data });
  };
}

async function $checkB2BToken(req: Request): Promise<Result<{ userInfo: UserInfo | undefined }>> {
  const authHeader = req.headers.authorization;
  if (!req.oauthProvider.settings.acceptB2BRequests || !authHeader) return $ok({ userInfo: undefined });

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
  const bearer = await req.oauthProvider.verifyAccessToken(token);
  if (bearer.error) return $err(bearer.error);
  return $ok({ userInfo: $userInfo(req, bearer.meta, bearer.rawJwt, bearer.payload) });
}

async function $checkCookieTokens(
  req: Request,
  res: Response,
  injectFunc: ReturnType<typeof $createInjectFunc>,
  accessTokenName: string,
  refreshTokenName: string,
): Promise<Result<{ azureId: string; userInfo: UserInfo; tryInjectData: InjectDataFunction }>> {
  const accessToken = getCookie(req, accessTokenName);
  const refreshToken = getCookie(req, refreshTokenName);
  if (!accessToken && !refreshToken) {
    return $err({ msg: 'Unauthorized', desc: 'Access token and refresh token are both missing', status: 401 });
  }

  const at = await req.oauthProvider.verifyAccessToken(accessToken);
  if (at.error && !refreshToken) return $err(at.error);
  if (at.success) {
    return $ok({
      azureId: at.meta.azureId as string,
      userInfo: $userInfo(req, at.meta, at.rawJwt, at.payload, at.injectedData),
      tryInjectData: (data: Record<string, any>) => injectFunc(at.rawJwt, data),
    });
  }

  const rt = await req.oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) return $err(rt.error);

  setCookie(res, rt.newAccessToken.name, rt.newAccessToken.value, rt.newAccessToken.options);
  if (rt.newRefreshToken) setCookie(res, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);

  return $ok({
    azureId: rt.meta.azureId as string,
    userInfo: $userInfo(req, rt.meta, rt.rawJwt, rt.payload),
    tryInjectData: (data: Record<string, any>) => injectFunc(rt.rawJwt, data),
  });
}

function $userInfo<T extends object = Record<string, any>>(
  req: Request,
  meta: Metadata,
  rawJwt: string,
  payload: JwtPayload,
  injectedData?: T,
): UserInfo {
  const userInfo: UserInfo = {
    azureId: meta.azureId as string,
    tenantId: meta.tenantId as string,
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? { isApp: true as const, appId: meta.appId as string }
      : { isApp: false as const, name: meta.name as string, email: meta.email as string, injectedData }),
  } as const;

  req.userInfo = userInfo;
  req.accessTokenInfo = { jwt: rawJwt, payload: payload, meta: meta };

  return userInfo;
}
