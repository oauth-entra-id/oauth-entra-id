import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import { setCookie } from './cookie-parser';
import type { Endpoints } from './types';

export async function sharedHandleAuthentication(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError(500, {
      message: 'Invalid session type',
      description: 'Session type must be cookie-session',
    });
  }

  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};

  const { authUrl } = await req.oauthProvider.getAuthUrl(params);

  res.status(200).json({ url: authUrl });
}

export async function sharedHandleCallback(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError(500, {
      message: 'Invalid session type',
      description: 'Session type must be cookie-session',
    });
  }

  const body = req.body as Endpoints['Callback'] | undefined;
  if (!body) throw new OAuthError(400, { message: 'Invalid params', description: 'Body must contain code and state' });

  const { frontendUrl, accessToken, refreshToken } = await req.oauthProvider.getTokenByCode({
    code: body.code,
    state: body.state,
  });

  setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(res, refreshToken.name, refreshToken.value, refreshToken.options);
  res.redirect(frontendUrl);
}

export function sharedHandleLogout(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError(500, {
      message: 'Invalid session type',
      description: 'Session type must be cookie-session',
    });
  }

  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl } : {};

  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = req.oauthProvider.getLogoutUrl(params);

  setCookie(res, deleteAccessToken.name, deleteAccessToken.value, deleteAccessToken.options);
  setCookie(res, deleteRefreshToken.name, deleteRefreshToken.value, deleteRefreshToken.options);
  res.status(200).json({ url: logoutUrl });
}

export async function sharedHandleOnBehalfOf(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError(500, {
      message: 'Invalid session type',
      description: 'Session type must be cookie-session',
    });
  }

  const body = req.body as Endpoints['OnBehalfOf'] | undefined;
  if (!body) throw new OAuthError(400, { message: 'Invalid params', description: 'Body must contain serviceNames' });

  if (!req.accessTokenInfo?.jwt) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
  }

  if (req.userInfo?.isB2B === true) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'B2B users cannot use OBO' });
  }

  const results = await req.oauthProvider.getTokenOnBehalfOf({
    clientIds: body.clientIds,
    accessToken: req.accessTokenInfo.jwt,
  });

  for (const { accessToken } of results) {
    setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
}
