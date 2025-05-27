import type { FastifyReply, FastifyRequest } from 'fastify';
import type { JwtPayload } from 'oauth-entra-id/*';
import { HttpException } from '~/error/HttpException';
import { oauthProvider } from '../oauth';

export async function protectRoute(req: FastifyRequest, reply: FastifyReply) {
  const authorizationHeader = req.headers.authorization;

  if (oauthProvider.settings.acceptB2BRequests && authorizationHeader) {
    const bearerAccessToken = authorizationHeader.startsWith('Bearer ') ? authorizationHeader.split(' ')[1] : undefined;
    const { error: bearerError, payload: bearerPayload } = await oauthProvider.verifyAccessToken(bearerAccessToken);
    if (bearerError) throw new HttpException(bearerError.message, bearerError.statusCode);

    setUserInfo(req, { payload: bearerPayload, isApp: true });

    return;
  }

  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = req.cookies[accessTokenName];
  const refreshToken = req.cookies[refreshTokenName];
  if (!accessToken && !refreshToken) throw new HttpException('Unauthorized', 401);

  const {
    error: accessTokenError,
    rawAccessToken: cookieRawAt,
    payload: cookiePayload,
    injectedData: cookieInjectedData,
  } = await oauthProvider.verifyAccessToken(accessToken);
  if (!accessTokenError) {
    req.accessTokenInfo = { jwt: cookieRawAt, payload: cookiePayload };
    const injectedData = cookieInjectedData
      ? (cookieInjectedData as { randomNumber: number })
      : { randomNumber: getRandomNumber() };

    if (!cookieInjectedData) {
      const { error: injectedError, injectedAccessToken } = oauthProvider.injectData({
        accessToken: cookieRawAt,
        data: injectedData,
      });
      if (injectedError) {
        setUserInfo(req, { payload: cookiePayload });
        return;
      }
      reply.setCookie(injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    }

    setUserInfo(req, { payload: cookiePayload, injectedData });

    return;
  }

  const {
    error: newTokensError,
    newTokens,
    rawAccessToken,
    payload,
  } = await oauthProvider.getTokenByRefresh(refreshToken);
  if (newTokensError) throw new HttpException(newTokensError.message, newTokensError.statusCode);

  req.accessTokenInfo = { jwt: rawAccessToken, payload };

  const injectedData = { randomNumber: getRandomNumber() };
  const { injectedAccessToken } = oauthProvider.injectData({ accessToken: rawAccessToken, data: injectedData });

  const finalAccessToken = injectedAccessToken ?? newTokens.accessToken;

  reply.setCookie(finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newTokens.refreshToken) {
    reply.setCookie(newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }
  setUserInfo(req, { payload, injectedData: injectedAccessToken ? injectedData : undefined });

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
