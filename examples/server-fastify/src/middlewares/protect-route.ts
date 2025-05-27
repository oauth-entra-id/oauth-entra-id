import type { FastifyReply, FastifyRequest } from 'fastify';
import type { JwtPayload } from 'oauth-entra-id/*';
import { HttpException } from '~/error/HttpException';
import { oauthProvider } from '../oauth';

export async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const bearerInfo = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerInfo.error) throw new HttpException(bearerInfo.error.message, bearerInfo.error.statusCode);

    setUserInfo(req, { payload: bearerInfo.payload, isApp: true });

    return;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) throw new HttpException('Unauthorized', 401);

  const accessTokenInfo = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (!accessTokenInfo.error) {
    req.accessTokenInfo = { jwt: accessTokenInfo.rawAccessToken, payload: accessTokenInfo.payload };
    const injectedData = accessTokenInfo.injectedData ?? { randomNumber: getRandomNumber() };

    if (accessTokenInfo.injectedData) {
      setUserInfo(req, { payload: accessTokenInfo.payload, injectedData });
      return;
    }

    const { injectedAccessToken, success } = oauthProvider.injectData({
      accessToken: accessTokenInfo.rawAccessToken,
      data: injectedData,
    });

    if (success) {
      reply.setCookie(injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
      setUserInfo(req, { payload: accessTokenInfo.payload, injectedData });
      return;
    }

    setUserInfo(req, { payload: accessTokenInfo.payload, injectedData });
    return;
  }

  const refreshTokenInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (refreshTokenInfo.error) {
    throw new HttpException(refreshTokenInfo.error.message, refreshTokenInfo.error.statusCode);
  }
  const { newTokens } = refreshTokenInfo;

  req.accessTokenInfo = { jwt: refreshTokenInfo.rawAccessToken, payload: refreshTokenInfo.payload };

  const injectedData = { randomNumber: getRandomNumber() };
  const { injectedAccessToken, success } = oauthProvider.injectData({
    accessToken: refreshTokenInfo.rawAccessToken,
    data: injectedData,
  });

  const finalAccessToken = success ? injectedAccessToken : newTokens.accessToken;

  reply.setCookie(finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newTokens.refreshToken) {
    reply.setCookie(newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }
  setUserInfo(req, { payload: refreshTokenInfo.payload, injectedData });

  return;
}

function setUserInfo(
  req: FastifyRequest,
  params: { payload: JwtPayload; injectedData?: { randomNumber: number }; isApp?: boolean },
) {
  req.userInfo = params.isApp
    ? { isApp: true, uniqueId: params.payload.oid, roles: params.payload.roles, appId: params.payload.appid }
    : {
        isApp: false,
        uniqueId: params.payload.oid,
        roles: params.payload.roles,
        name: params.payload.name,
        email: params.payload.preferred_username,
        injectedData: params.injectedData,
      };
}

function getRandomNumber() {
  return Math.floor(Math.random() * 100);
}

declare module 'fastify' {
  interface FastifyRequest {
    accessTokenInfo: {
      jwt: string;
      payload: Record<string, unknown>;
    };
    userInfo:
      | {
          isApp: false;
          uniqueId: string;
          roles: string[];
          name: string;
          email: string;
          injectedData?: {
            randomNumber: number;
          };
        }
      | { isApp: true; uniqueId: string; roles: string[]; appId: string };
  }
}
