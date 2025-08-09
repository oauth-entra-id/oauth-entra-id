import type { Request, Response } from 'express';
import { deleteCookie, setCookie } from 'modern-cookies';
import { OAuthError } from '~/error';
import type { Endpoints } from './types';

/**
 * Initiates the OAuth login flow by returning an authorization URL.
 *
 * @throws {OAuthError} if sessionType ≠ 'cookie-session' or MSAL errors occur
 */
export async function $sharedHandleAuthentication(req: Request, res: Response) {
  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body
    ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl, azureId: body.azureId }
    : {};

  const { authUrl } = await req.oauthProvider.getAuthUrl(params);

  res.status(200).json({ url: authUrl });
}

/**
 * Initiates the OAuth login flow by returning an authorization URL.
 *
 * @throws {OAuthError} if sessionType ≠ 'cookie-session' or MSAL errors occur
 */
export async function $sharedHandleCallback(req: Request, res: Response) {
  const body = req.body as Endpoints['Callback'] | undefined;
  if (!body) throw new OAuthError({ msg: 'Invalid params', desc: 'Body must contain code and state' });

  const { accessToken, refreshToken, frontendUrl } = await req.oauthProvider.getTokenByCode({
    code: body.code,
    state: body.state,
  });

  setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(res, refreshToken.name, refreshToken.value, refreshToken.options);
  res.redirect(303, frontendUrl);
}

/**
 * Clears session cookies and returns the Azure logout URL.
 *
 * @throws {OAuthError} on misconfiguration or invalid params
 */
export async function $sharedHandleLogout(req: Request, res: Response) {
  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl, azureId: body.azureId } : {};

  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = await req.oauthProvider.getLogoutUrl(params);

  deleteCookie(res, deleteRefreshToken.name, deleteRefreshToken.options);
  deleteCookie(res, deleteAccessToken.name, deleteAccessToken.options);
  res.status(200).json({ url: logoutUrl });
}

/**
 * Executes the On-Behalf-Of flow: acquires downstream tokens,
 * sets service cookies, and returns the count of tokens set.
 *
 * @throws {OAuthError} on misconfiguration, missing access token, or forbidden app contexts
 */
export async function $sharedHandleOnBehalfOf(req: Request, res: Response) {
  const body = req.body as Endpoints['OnBehalfOf'] | undefined;
  if (!body) throw new OAuthError({ msg: 'Invalid params', desc: 'Body must contain serviceNames' });

  if (!req.accessTokenInfo?.jwt) {
    throw new OAuthError({
      msg: 'Unauthorized',
      desc: 'Access token is required for on-behalf-of requests',
      status: 401,
    });
  }

  if (req.userInfo?.isApp === true) {
    throw new OAuthError({
      msg: 'Forbidden',
      desc: 'On-behalf-of requests are not allowed for app users',
      status: 403,
    });
  }

  const { results } = await req.oauthProvider.getTokenOnBehalfOf({
    services: body.services,
    accessToken: req.accessTokenInfo.jwt,
    azureId: body.azureId,
  });

  for (const { accessToken } of results) {
    setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
}
