import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import { setCookie } from './cookie-parser';
import type { Endpoints } from './types';

export async function sharedHandleAuthentication(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
      status: 500,
    });
  }

  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};

  const { authUrl, error } = await req.oauthProvider.getAuthUrl(params);
  if (error) throw new OAuthError(error);

  res.status(200).json({ url: authUrl });
}

export async function sharedHandleCallback(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
      status: 500,
    });
  }

  const body = req.body as Endpoints['Callback'] | undefined;
  if (!body) {
    throw new OAuthError('bad_request', { error: 'Invalid params', description: 'Body must contain code and state' });
  }

  const { accessToken, refreshToken, frontendUrl, error } = await req.oauthProvider.getTokenByCode({
    code: body.code,
    state: body.state,
  });
  if (error) throw new OAuthError(error);

  setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(res, refreshToken.name, refreshToken.value, refreshToken.options);
  res.redirect(frontendUrl);
}

export function sharedHandleLogout(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
      status: 500,
    });
  }

  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl } : {};

  const { logoutUrl, deleteAccessToken, deleteRefreshToken, error } = req.oauthProvider.getLogoutUrl(params);
  if (error) throw new OAuthError(error);

  setCookie(res, deleteAccessToken.name, deleteAccessToken.value, deleteAccessToken.options);
  setCookie(res, deleteRefreshToken.name, deleteRefreshToken.value, deleteRefreshToken.options);
  res.status(200).json({ url: logoutUrl });
}

export async function sharedHandleOnBehalfOf(req: Request, res: Response) {
  if (req.oauthProvider.settings.sessionType !== 'cookie-session') {
    throw new OAuthError('misconfiguration', {
      error: 'Invalid session type',
      description: 'Session type must be cookie-session',
      status: 500,
    });
  }

  const body = req.body as Endpoints['OnBehalfOf'] | undefined;
  if (!body) {
    throw new OAuthError('bad_request', { error: 'Invalid params', description: 'Body must contain serviceNames' });
  }

  if (!req.accessTokenInfo?.jwt) {
    throw new OAuthError('jwt_error', {
      error: 'Unauthorized',
      description: 'Access token is required for on-behalf-of requests',
    });
  }

  if (req.userInfo?.isApp === true) {
    throw new OAuthError('bad_request', {
      error: 'Invalid user type',
      description: 'On-behalf-of requests are not allowed for app users',
    });
  }

  const { results, error } = await req.oauthProvider.getTokenOnBehalfOf({
    serviceNames: body.serviceNames,
    accessToken: req.accessTokenInfo.jwt,
  });

  if (error) throw new OAuthError(error);

  for (const { accessToken } of results) {
    setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
}
