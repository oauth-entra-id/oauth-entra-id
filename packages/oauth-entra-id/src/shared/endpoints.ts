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
  const params = { code: body.code, state: body.state };

  const { url, accessToken, refreshToken } = await req.oauthProvider.getTokenByCode(params);

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
