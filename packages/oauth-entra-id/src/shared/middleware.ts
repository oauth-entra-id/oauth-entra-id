import type { Request, Response } from 'express';
import { $err, $ok, OAuthError, type Result, type ResultErr } from '~/error';
import type { JwtPayload, Metadata } from '~/types';
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
  const b2b = await $checkB2BToken(req);
  if (b2b.error) throw new OAuthError(b2b.error);
  if (b2b.userInfo) {
    return {
      userInfo: b2b.userInfo,
      tryInjectData: (_data) =>
        Promise.resolve(
          $err('bad_request', {
            error: 'Invalid user type',
            description: 'Injecting data is only supported for user-based sessions',
          }),
        ),
    };
  }

  const injectFunc = $createInjectFunc(req, res);

  let firstError: ResultErr | null = null;
  for (const { accessToken, refreshToken } of req.oauthProvider.settings.cookies.cookieNames) {
    const cookie = await $checkCookieTokens(req, res, injectFunc, accessToken, refreshToken);
    if (cookie.error) {
      if (!firstError) firstError = cookie.error;
      continue;
    }
    return { userInfo: cookie.userInfo, tryInjectData: cookie.tryInjectData };
  }

  throw new OAuthError(
    firstError
      ? firstError
      : $err('jwt_error', {
          error: 'Unauthorized',
          description: 'Tokens are invalid or missing',
          status: 401,
        }),
  );
}

function $createInjectFunc(req: Request, res: Response) {
  return async <T extends object = Record<string, any>>(
    accessToken: string,
    data: T,
  ): Promise<Result<{ injectedData: T }>> => {
    const inj = await req.oauthProvider.tryInjectData({ accessToken, data });
    if (inj.error) return $err(inj.error);
    if (req.userInfo?.isApp !== false) {
      return $err('bad_request', {
        error: 'Invalid user type',
        description: 'Injecting data is only supported for user-based sessions',
      });
    }
    $setCookie(res, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
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
): Promise<Result<{ userInfo: UserInfo; tryInjectData: InjectDataFunction }>> {
  const accessToken = $getCookie(req, accessTokenName);
  const refreshToken = $getCookie(req, refreshTokenName);
  if (!accessToken && !refreshToken) {
    return $err('nullish_value', {
      error: 'Unauthorized',
      description: 'Access token and refresh token are both missing',
      status: 401,
    });
  }

  const at = await req.oauthProvider.verifyAccessToken(accessToken);
  if (at.error && !refreshToken) return $err(at.error);
  if (at.success) {
    return $ok({
      userInfo: $userInfo(req, at.meta, at.rawJwt, at.payload, at.injectedData),
      tryInjectData: (data: Record<string, any>) => injectFunc(at.rawJwt, data),
    });
  }

  const rt = await req.oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) return $err(rt.error);

  $setCookie(res, rt.newAccessToken.name, rt.newAccessToken.value, rt.newAccessToken.options);
  if (rt.newRefreshToken) {
    $setCookie(res, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);
  }

  return $ok({
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
      : {
          isApp: false as const,
          name: meta.name as string,
          email: meta.email as string,
          injectedData,
        }),
  } as const;

  req.userInfo = userInfo;
  req.accessTokenInfo = { jwt: rawJwt, payload: payload };

  return userInfo;
}
