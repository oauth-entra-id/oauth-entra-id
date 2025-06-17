import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import { $setCookie } from './cookie-parser';
import type { Endpoints } from './types';

/**
 * Initiates the OAuth login flow by returning an authorization URL.
 *
 * @throws {OAuthError} if sessionType ≠ 'cookie-session' or MSAL errors occur
 */
export async function $sharedHandleAuthentication(req: Request, res: Response) {
  const body = req.body as Endpoints['Authenticate'] | undefined;
  const params = body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {};

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
  if (!body) {
    throw new OAuthError('bad_request', { error: 'Invalid params', description: 'Body must contain code and state' });
  }

  const { accessToken, refreshToken, frontendUrl } = await req.oauthProvider.getTokenByCode({
    code: body.code,
    state: body.state,
  });

  $setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) $setCookie(res, refreshToken.name, refreshToken.value, refreshToken.options);
  res.redirect(frontendUrl);
}

/**
 * Clears session cookies and returns the Azure logout URL.
 *
 * @throws {OAuthError} on misconfiguration or invalid params
 */
export async function $sharedHandleLogout(req: Request, res: Response) {
  const body = req.body as Endpoints['Logout'] | undefined;
  const params = body ? { frontendUrl: body.frontendUrl } : {};

  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = await req.oauthProvider.getLogoutUrl(params);

  $setCookie(res, deleteAccessToken.name, deleteAccessToken.value, deleteAccessToken.options);
  $setCookie(res, deleteRefreshToken.name, deleteRefreshToken.value, deleteRefreshToken.options);
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
  if (!body) {
    throw new OAuthError('bad_request', { error: 'Invalid params', description: 'Body must contain serviceNames' });
  }

  if (!req.accessTokenInfo?.jwt) {
    throw new OAuthError('jwt_error', {
      error: 'Unauthorized',
      description: 'Access token is required for on-behalf-of requests',
      status: 401,
    });
  }

  if (req.userInfo?.isApp === true) {
    throw new OAuthError('bad_request', {
      error: 'Forbidden',
      description: 'On-behalf-of requests are not allowed for app users',
      status: 403,
    });
  }

  const { results } = await req.oauthProvider.getTokenOnBehalfOf({
    serviceNames: body.serviceNames,
    accessToken: req.accessTokenInfo.jwt,
  });

  for (const { accessToken } of results) {
    $setCookie(res, accessToken.name, accessToken.value, accessToken.options);
  }

  res.status(200).json({ tokensSet: results.length });
}
