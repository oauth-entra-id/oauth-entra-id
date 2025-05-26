import type { FastifyReply, FastifyRequest } from 'fastify';
import type { JwtPayload } from 'oauth-entra-id/*';
import { HttpException } from '~/error/HttpException';
import { oauthProvider } from '../oauth';

declare module 'fastify' {
  interface FastifyRequest {
    accessTokenInfo: {
      jwt: string;
      payload: Record<string, unknown>;
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

export async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const { result: bearerInfo, error: bearerInfoError } = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfoError) throw new HttpException(bearerInfoError.message, bearerInfoError.statusCode);

    setUserInfo(req, { payload: bearerInfo.payload, isB2B: true });

    return;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) throw new HttpException('Unauthorized', 401);

  const { result: tokenInfo } = await oauthProvider.verifyAccessToken(accessToken);
  if (tokenInfo) {
    req.accessTokenInfo = { jwt: tokenInfo.rawAccessToken, payload: tokenInfo.payload };
    const injectedData = tokenInfo.injectedData
      ? (tokenInfo.injectedData as { randomNumber: number })
      : { randomNumber: getRandomNumber() };

    if (!tokenInfo.injectedData) {
      const { result: newAccessToken } = oauthProvider.injectData({
        accessToken: tokenInfo.rawAccessToken,
        data: injectedData,
      });
      if (!newAccessToken) {
        setUserInfo(req, { payload: tokenInfo.payload });
        return;
      }
      reply.setCookie(newAccessToken.name, newAccessToken.value, newAccessToken.options);
    }

    setUserInfo(req, { payload: tokenInfo.payload, injectedData });

    return;
  }

  const { result: newTokensInfo, error: newTokensInfoError } = await oauthProvider.getTokenByRefresh(refreshToken);
  if (newTokensInfoError) throw new HttpException(newTokensInfoError.message, newTokensInfoError.statusCode);

  const { rawAccessToken, payload, newAccessToken, newRefreshToken } = newTokensInfo;
  req.accessTokenInfo = { jwt: rawAccessToken, payload };

  const injectedData = { randomNumber: getRandomNumber() };
  const { result: newerAccessToken } = oauthProvider.injectData({ accessToken: rawAccessToken, data: injectedData });

  const finalAccessToken = newerAccessToken ?? newAccessToken;

  reply.setCookie(finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newRefreshToken) reply.setCookie(newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  setUserInfo(req, { payload, injectedData: newerAccessToken ? injectedData : undefined });

  return;
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
