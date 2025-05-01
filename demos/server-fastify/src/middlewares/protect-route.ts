import type { FastifyReply, FastifyRequest } from 'fastify';
import { oauthProvider } from '../oauth';

declare module 'fastify' {
  interface FastifyRequest {
    msal: {
      microsoftToken: string;
      payload: Record<string, unknown>;
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
    const microsoftInfo = await oauthProvider.verifyAccessToken(accessToken);
    if (microsoftInfo) {
      req.msal = microsoftInfo;
      req.userInfo = {
        uniqueId: microsoftInfo.payload.oid,
        roles: microsoftInfo.payload.roles,
        name: microsoftInfo.payload.name,
        email: microsoftInfo.payload.preferred_username,
      };
      return;
    }
  }

  if (!refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });
  const newTokens = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokens) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });
  const { newAccessToken, newRefreshToken, msal } = newTokens;
  reply.setCookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) reply.setCookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  req.msal = msal;
  req.userInfo = {
    uniqueId: msal.payload.oid,
    roles: msal.payload.roles,
    name: msal.payload.name,
    email: msal.payload.preferred_username,
  };
}
