import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import { type JwtPayload, type Metadata, OAuthError } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';
import { getRandomNumber } from '~/utils/generate';

export const protectRoute = createMiddleware<ProtectRoute>(async (c, next) => {
  const b2bSuccess = await checkB2BToken(c);
  if (b2bSuccess) return await next();

  const { cookies } = oauthProvider.settings;
  let firstError: string | null = null;
  for (const { accessTokenName, refreshTokenName } of cookies.cookieNames) {
    const cookie = await checkCookieTokens(c, accessTokenName, refreshTokenName);
    if (cookie.error) {
      if (!firstError) firstError = cookie.error;
      continue;
    }

    for (const { azureId, accessTokenName, refreshTokenName } of cookies.cookieNames) {
      if (azureId === cookie.azureId) continue;
      deleteCookie(c, accessTokenName, cookies.deleteOptions);
      deleteCookie(c, refreshTokenName, cookies.deleteOptions);
    }

    return await next();
  }
  throw new OAuthError({ msg: 'Unauthorized', desc: firstError ?? 'Tokens are invalid or missing', status: 401 });
});

async function checkB2BToken(c: Context): Promise<boolean> {
  const authHeader = c.req.header('Authorization');
  if (!oauthProvider.settings.acceptB2BRequests || !authHeader) return false;

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
  const bearer = await oauthProvider.verifyAccessToken(token);
  if (bearer.error) throw new OAuthError(bearer.error);
  setUserInfo(c, bearer.meta, bearer.rawJwt, bearer.payload);
  return true;
}

async function checkCookieTokens(
  c: Context,
  accessTokenName: string,
  refreshTokenName: string,
): Promise<{ error: string; azureId?: undefined } | { error?: undefined; azureId: string }> {
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) return { error: 'Access token and refresh token are both missing' };

  const at = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (at.success) {
    if (at.hasInjectedData) {
      setUserInfo(c, at.meta, at.rawJwt, at.payload, at.injectedData);
      return { azureId: at.meta.azureId as string };
    }

    const inj = await oauthProvider.tryInjectData({ accessToken: at.rawJwt, data: getRandomNumber() });
    if (inj.success) setCookie(c, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    setUserInfo(c, at.meta, at.rawJwt, at.payload, inj.injectedData);
    return { azureId: at.meta.azureId as string };
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) return { error: rt.error.description || 'Failed to refresh tokens' };

  const inj = await oauthProvider.tryInjectData({ accessToken: rt.rawJwt, data: getRandomNumber() });
  const final = inj.success ? inj : rt;

  setCookie(c, final.newAccessToken.name, final.newAccessToken.value, final.newAccessToken.options);
  setCookie(c, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);

  setUserInfo(c, rt.meta, rt.rawJwt, rt.payload, inj.injectedData);
  return { azureId: rt.meta.azureId as string };
}

function setUserInfo(
  c: Context,
  meta: Metadata,
  rawJwt: string,
  payload: JwtPayload,
  injectedData?: { randomNumber: number },
) {
  c.set('userInfo', {
    azureId: meta.azureId as string,
    tenantId: meta.tenantId as string,
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? { isApp: true as const, appId: meta.appId as string }
      : { isApp: false as const, name: meta.name as string, email: meta.email as string, injectedData }),
  });
  c.set('accessTokenInfo', { jwt: rawJwt, payload: payload, meta: meta });
}

export type ProtectRoute = {
  Variables: {
    accessTokenInfo: { jwt: string; payload: Record<string, unknown>; meta: Metadata };
    userInfo: { azureId: string; tenantId: string; uniqueId: string; roles: string[] } & (
      | { isApp: false; name: string; email: string; injectedData?: { randomNumber: number } }
      | { isApp: true; appId: string }
    );
  };
};
