import type { FastifyReply, FastifyRequest } from 'fastify';
import { oauthProvider } from '../oauth';

declare module 'fastify' {
  interface FastifyRequest {
    microsoftInfo: {
      rawAccessToken: string;
      accessTokenPayload: Record<string, unknown>;
    };
    userInfo: {
      uniqueId: string;
      roles: string[];
      name: string;
      email: string;
    };
  }
}

export default async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  if (accessToken) {
    const tokenInfo = await oauthProvider.verifyAccessToken(accessToken);
    if (tokenInfo) {
      req.microsoftInfo = tokenInfo.microsoftInfo;
      req.userInfo = {
        uniqueId: tokenInfo.microsoftInfo.accessTokenPayload.oid,
        roles: tokenInfo.microsoftInfo.accessTokenPayload.roles,
        name: tokenInfo.microsoftInfo.accessTokenPayload.name,
        email: tokenInfo.microsoftInfo.accessTokenPayload.preferred_username,
      };
      return;
    }
  }

  if (!refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });
  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  const { newAccessToken, newRefreshToken, microsoftInfo } = newTokensInfo;
  reply.setCookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) reply.setCookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);

  req.microsoftInfo = microsoftInfo;
  req.userInfo = {
    uniqueId: microsoftInfo.accessTokenPayload.oid,
    roles: microsoftInfo.accessTokenPayload.roles,
    name: microsoftInfo.accessTokenPayload.name,
    email: microsoftInfo.accessTokenPayload.preferred_username,
  };
}
