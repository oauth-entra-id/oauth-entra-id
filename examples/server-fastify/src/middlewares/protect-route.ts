import type { FastifyReply, FastifyRequest } from 'fastify';
import { type Metadata, OAuthError } from 'oauth-entra-id';
import { HttpException } from '~/error/HttpException';
import { oauthProvider } from '~/oauth';
import { getRandomNumber } from '~/utils/generate';

export async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  // Check for Bearer token in Authorization header for B2B requests
  const authHeader = req.headers.authorization;
  if (oauthProvider.settings.acceptB2BRequests && authHeader) {
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
    const bearer = await oauthProvider.verifyAccessToken(token);
    if (bearer.error) throw new OAuthError(bearer.error);
    setUserInfo(req, bearer.meta);
    return;
  }

  // Normal requests with access and refresh tokens in cookies
  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) throw new HttpException('Unauthorized', 401);

  const at = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (at.success) {
    req.accessTokenInfo = { jwt: at.rawJwt, payload: at.payload };
    if (at.hasInjectedData) {
      setUserInfo(req, at.meta, at.injectedData);
      return;
    }

    const inj = await oauthProvider.tryInjectData({ accessToken: at.rawJwt, data: getRandomNumber() });
    if (inj.success) reply.setCookie(inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    setUserInfo(req, at.meta, inj.injectedData);
    return;
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw new OAuthError(rt.error);
  req.accessTokenInfo = { jwt: rt.rawJwt, payload: rt.payload };

  const inj = await oauthProvider.tryInjectData({ accessToken: rt.rawJwt, data: getRandomNumber() });
  const final = inj.success ? inj.newAccessToken : rt.newAccessToken;

  reply.setCookie(final.name, final.value, final.options);
  if (rt.newRefreshToken) {
    reply.setCookie(rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);
  }

  setUserInfo(req, rt.meta, inj.injectedData);
  return;
}

function setUserInfo(req: FastifyRequest, meta: Metadata, injectedData?: { randomNumber: number }) {
  req.userInfo = {
    uniqueId: meta.uniqueId as string,
    roles: meta.roles as string[],
    ...(meta.isApp
      ? { isApp: true as const, appId: meta.appId as string }
      : { isApp: false as const, name: meta.name as string, email: meta.email as string, injectedData }),
  };
}

declare module 'fastify' {
  interface FastifyRequest {
    accessTokenInfo: { jwt: string; payload: Record<string, unknown> };
    userInfo: { uniqueId: string; roles: string[] } & (
      | { isApp: false; name: string; email: string; injectedData?: { randomNumber: number } }
      | { isApp: true; appId: string }
    );
  }
}
