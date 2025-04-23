import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import type { Endpoints } from '~/types';

export const sharedHandleAuthentication = async (req: Request, res: Response) => {
  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};

  const { url } = await req.oauthProvider.getAuthUrl(params);

  res.status(200).json({ url });
};

export const sharedHandleCallback = async (req: Request, res: Response) => {
  const body = req.body as Endpoints['Callback'] | undefined;
  if (!body) throw new OAuthError(400, { message: 'Invalid params', description: 'Body must contain code and state' });

  const { url, accessToken, refreshToken } = await req.oauthProvider.getTokenByCode({
    code: body.code,
    state: body.state,
  });

  res.cookie(accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) res.cookie(refreshToken.name, refreshToken.value, refreshToken.options);
  res.redirect(url);
};

export const sharedHandleLogout = (req: Request, res: Response) => {
  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl } : {};

  const { url, accessToken, refreshToken } = req.oauthProvider.getLogoutUrl(params);

  res.cookie(accessToken.name, accessToken.value, accessToken.options);
  res.cookie(refreshToken.name, refreshToken.value, refreshToken.options);
  res.status(200).json({ url });
};

//TODO: add service names directly

export const sharedHandleOnBehalfOf = async (req: Request, res: Response) => {
  const body = req.body as Endpoints['OnBehalfOf'] | undefined;
  if (!body) throw new OAuthError(400, { message: 'Invalid params', description: 'Body must contain serviceNames' });

  if (!req.msal?.microsoftToken) {
    throw new OAuthError(401, { message: 'Unauthorized', description: 'Invalid access token' });
  }

  const results = await req.oauthProvider.getTokenOnBehalfOf({
    serviceNames: body.serviceNames,
    accessToken: req.msal.microsoftToken,
  });

  for (const result of results) {
    const { accessToken, refreshToken } = result;
    res.cookie(accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) res.cookie(refreshToken.name, refreshToken.value, refreshToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
};
