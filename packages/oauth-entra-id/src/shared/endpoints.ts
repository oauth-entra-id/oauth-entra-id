import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import type { Endpoints } from '~/types';
import { setCookie } from './cookie-parser';

export async function sharedHandleAuthentication(req: Request, res: Response) {
  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};

  const { authUrl } = await req.oauthProvider.getAuthUrl(params);

  res.status(200).json({ url: authUrl });
}

export async function sharedHandleCallback(req: Request, res: Response) {
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

export async function sharedHandleLogout(req: Request, res: Response) {
  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl } : {};

  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = req.oauthProvider.getLogoutUrl(params);

  setCookie(res, deleteAccessToken.name, deleteAccessToken.value, deleteAccessToken.options);
  setCookie(res, deleteRefreshToken.name, deleteRefreshToken.value, deleteRefreshToken.options);
  res.status(200).json({ url: logoutUrl });
}

export async function sharedHandleOnBehalfOf(req: Request, res: Response) {
  const body = req.body as Endpoints['OnBehalfOf'] | undefined;
  if (!body) throw new OAuthError(400, { message: 'Invalid params', description: 'Body must contain serviceNames' });

  if (!req.msal?.microsoftToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
  }

  const results = await req.oauthProvider.getTokenOnBehalfOf({
    serviceNames: body.serviceNames,
    accessToken: req.msal.microsoftToken,
  });

  for (const { accessToken, refreshToken } of results) {
    setCookie(res, accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) setCookie(res, refreshToken.name, refreshToken.value, refreshToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
}
