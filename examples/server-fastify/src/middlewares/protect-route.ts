import type { FastifyReply, FastifyRequest } from 'fastify';
import type { JwtPayload } from 'oauth-entra-id/*';
import { HttpException } from '~/error/HttpException';
import { oauthProvider } from '../oauth';

declare module 'fastify' {
  interface FastifyRequest {
    microsoftInfo: {
      rawAccessToken: string;
      accessTokenPayload: Record<string, unknown>;
    };
    userInfo:
      | {
          isB2B: false;
          uniqueId: string;
          roles: string[];
          name: string;
          email: string;
          injectedData?: {
            randomNumber: number;
          };
        }
      | { isB2B: true; uniqueId: string; roles: string[]; appId: string };
  }
}

export default async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.isB2BEnabled && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    if (!bearerAccessToken) throw new HttpException('Unauthorized', 401);

    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (!bearerInfo) throw new HttpException('Unauthorized', 401);

    setUserInfo(req, { payload: bearerInfo.microsoftInfo.accessTokenPayload, isB2B: true });

    return;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) return reply.status(401).send({ error: 'Unauthorized', statusCode: 401 });

  const tokenInfo = accessToken ? await oauthProvider.verifyAccessToken(accessToken) : null;
  if (tokenInfo) {
    req.microsoftInfo = tokenInfo.microsoftInfo;
    if (tokenInfo.injectedData) {
      setUserInfo(req, {
        payload: tokenInfo.microsoftInfo.accessTokenPayload,
        injectedData: tokenInfo.injectedData as { randomNumber: number },
      });
    } else {
      const randomNumber = getRandomNumber();
      const newAccessToken = oauthProvider.injectData({
        accessToken: tokenInfo.microsoftInfo.rawAccessToken,
        data: { randomNumber },
      });
      if (newAccessToken) reply.setCookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
      setUserInfo(req, {
        payload: tokenInfo.microsoftInfo.accessTokenPayload,
        injectedData: newAccessToken ? { randomNumber } : undefined,
      });
    }
    return;
  }

  if (!refreshToken) throw new HttpException('Unauthorized', 401);

  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) throw new HttpException('Unauthorized', 401);

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
  setUserInfo(req, {
    payload: microsoftInfo.accessTokenPayload,
    injectedData: newerAccessToken ? { randomNumber } : undefined,
  });
}

function setUserInfo(
  req: FastifyRequest,
  { payload, injectedData, isB2B }: { payload: JwtPayload; injectedData?: { randomNumber: number }; isB2B?: boolean },
) {
  req.userInfo = isB2B
    ? { isB2B: true, uniqueId: payload.oid, roles: payload.roles, appId: payload.appid }
    : {
        isB2B: false,
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
