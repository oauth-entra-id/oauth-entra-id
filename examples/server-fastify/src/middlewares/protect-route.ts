import type { FastifyReply, FastifyRequest } from 'fastify';
import type { JwtPayload } from 'oauth-entra-id/*';
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
      injectedData?: {
        randomNumber: number;
      };
    };
  }
}

export default async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  const tokenInfo = accessToken ? await oauthProvider.verifyAccessToken(accessToken) : null;
  if (tokenInfo) {
    req.microsoftInfo = tokenInfo.microsoftInfo;
    if (tokenInfo.injectedData) {
      setUserInfo(req, tokenInfo.microsoftInfo.accessTokenPayload, tokenInfo.injectedData as { randomNumber: number });
    } else {
      const randomNumber = getRandomNumber();
      const newAccessToken = oauthProvider.injectData({
        accessToken: tokenInfo.microsoftInfo.rawAccessToken,
        data: { randomNumber },
      });
      if (newAccessToken) reply.setCookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
      setUserInfo(req, tokenInfo.microsoftInfo.accessTokenPayload, newAccessToken ? { randomNumber } : undefined);
    }
    return;
  }

  if (!refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  const { newAccessToken, newRefreshToken, microsoftInfo } = newTokensInfo;
  req.microsoftInfo = microsoftInfo;

  const randomNumber = getRandomNumber();
  const newerAccessToken = oauthProvider.injectData({
    accessToken: newTokensInfo.microsoftInfo.rawAccessToken,
    data: { randomNumber },
  });

  const finalAccessToken = newerAccessToken ?? newAccessToken;

  reply.setCookie(finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newRefreshToken) reply.setCookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  setUserInfo(req, microsoftInfo.accessTokenPayload, newerAccessToken ? { randomNumber } : undefined);
}

function setUserInfo(req: FastifyRequest, payload: JwtPayload, injectedData?: { randomNumber: number }) {
  req.userInfo = {
    uniqueId: payload.oid,
    roles: payload.roles,
    name: payload.name,
    email: payload.preferred_username,
    injectedData,
  };
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}
