import type { FastifyReply, FastifyRequest } from 'fastify';
import { type JwtPayload, type Metadata, OAuthError } from 'oauth-entra-id';
import { oauthProvider } from '~/oauth';
import { getRandomNumber } from '~/utils/generate';

export async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const b2bSuccess = await checkB2BToken(req);
  if (b2bSuccess) return;

  const { cookies } = oauthProvider.settings;
  let firstError: string | null = null;
  for (const { accessTokenName, refreshTokenName } of cookies.cookieNames) {
    const cookie = await checkCookieTokens(req, reply, accessTokenName, refreshTokenName);
    if (cookie.error) {
      if (!firstError) firstError = cookie.error;
      continue;
    }

    for (const { azureId, accessTokenName, refreshTokenName } of cookies.cookieNames) {
      if (azureId === cookie.azureId) continue;
      reply.setCookie(accessTokenName, '', cookies.deleteOptions);
      reply.setCookie(refreshTokenName, '', cookies.deleteOptions);
    }

    return;
  }
  throw new OAuthError('jwt_error', {
    error: 'Unauthorized',
    description: firstError ?? 'Tokens are invalid or missing',
    status: 401,
  });
}

async function checkB2BToken(req: FastifyRequest): Promise<boolean> {
  const authHeader = req.headers.authorization;
  if (!oauthProvider.settings.acceptB2BRequests || !authHeader) return false;

  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
  const bearer = await oauthProvider.verifyAccessToken(token);
  if (bearer.error) throw new OAuthError(bearer.error);
  setUserInfo(req, bearer.meta, bearer.rawJwt, bearer.payload);
  return true;
}

async function checkCookieTokens(
  req: FastifyRequest,
  reply: FastifyReply,
  accessTokenName: string,
  refreshTokenName: string,
): Promise<{ error: string; azureId?: undefined } | { error?: undefined; azureId: string }> {
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) return { error: 'Access token and refresh token are both missing' };

  const at = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (at.success) {
    if (at.hasInjectedData) {
      setUserInfo(req, at.meta, at.rawJwt, at.payload, at.injectedData);
      return { azureId: at.meta.azureId as string };
    }

    const inj = await oauthProvider.tryInjectData({ accessToken: at.rawJwt, data: getRandomNumber() });
    if (inj.success) reply.setCookie(inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    setUserInfo(req, at.meta, at.rawJwt, at.payload, inj.injectedData);
    return { azureId: at.meta.azureId as string };
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) return { error: rt.error.description || 'Failed to refresh tokens' };

  const inj = await oauthProvider.tryInjectData({ accessToken: rt.rawJwt, data: getRandomNumber() });
  const final = inj.success ? inj.newAccessToken : rt.newAccessToken;

  reply.setCookie(final.name, final.value, final.options);
  if (rt.newRefreshToken) {
    reply.setCookie(rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);
  }

  setUserInfo(req, rt.meta, rt.rawJwt, rt.payload, inj.injectedData);
  return { azureId: rt.meta.azureId as string };
}

function setUserInfo(
  req: FastifyRequest,
  meta: Metadata,
  rawJwt: string,
  payload: JwtPayload,
  injectedData?: { randomNumber: number },
) {
  req.userInfo = {
    azureId: meta.azureId as string,
    tenantId: meta.tenantId as string,
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? { isApp: true as const, appId: meta.appId as string }
      : { isApp: false as const, name: meta.name as string, email: meta.email as string, injectedData }),
  };
  req.accessTokenInfo = { jwt: rawJwt, payload: payload, meta: meta };
}

declare module 'fastify' {
  interface FastifyRequest {
    accessTokenInfo: { jwt: string; payload: Record<string, unknown>; meta: Metadata };
    userInfo: { azureId: string; tenantId: string; uniqueId: string; roles: string[] } & (
      | { isApp: false; name: string; email: string; injectedData?: { randomNumber: number } }
      | { isApp: true; appId: string }
    );
  }
}
