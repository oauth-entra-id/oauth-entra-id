import '~/shared/types';
import type { NextFunction, Request, Response } from 'express';
import { OAuthProvider } from '~/core';
import { OAuthError } from '~/error';
import {
  $sharedHandleAuthentication,
  $sharedHandleCallback,
  $sharedHandleLogout,
  $sharedHandleOnBehalfOf,
} from '~/shared/endpoints';
import { $sharedMiddleware } from '~/shared/middleware';
import type { CallbackFunction } from '~/shared/types';
import type { OAuthConfig } from '~/types';

const ERROR_MESSAGE = 'Make sure you used Express export and you used authConfig';

let globalExpressOAuthProvider: OAuthProvider | null = null;

/**
 * Factory that binds a singleton OAuthProvider to every Express request.
 *
 * @param config  OAuthConfig for your Microsoft Entra ID app.
 */
export function authConfig(config: OAuthConfig) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!globalExpressOAuthProvider) {
      globalExpressOAuthProvider = new OAuthProvider(config);
    }

    req.oauthProvider = globalExpressOAuthProvider;
    req.serverType = 'express';

    next();
  };
}

/**
 * Route handler that begins the OAuth flow by sending back authentication PKCE-based URL.
 *
 * ### Body:
 * - `loginPrompt` (optional) - Overrides the default login prompt behavior, can be `email`, `select_account`, or `sso`.
 * - `email` (optional) - Pre-fills the email field in the login form.
 * - `frontendUrl` (optional) - Redirects to this URL after successful login.
 *
 * @throws {OAuthError} if there is any issue.
 */
export function handleAuthentication() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') {
        throw new OAuthError('misconfiguration', { error: ERROR_MESSAGE, status: 500 });
      }
      await $sharedHandleAuthentication(req, res);
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Route handler that processes the OAuth callback after user authentication.
 *
 * ### Body:
 * - `code` - The authorization code received from Microsoft.
 * - `state` - The state parameter received from Microsoft, used to prevent CSRF attacks and store session state.
 *
 * @throws {OAuthError} if there is any issue.
 */
export function handleCallback() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') {
        throw new OAuthError('misconfiguration', { error: ERROR_MESSAGE, status: 500 });
      }
      await $sharedHandleCallback(req, res);
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Route handler that clears session cookies and returns the Azure logout URL.
 *
 * ### Body:
 * - `frontendUrl` (optional) - Overrides the default redirect URL after logout.
 *
 * @throws {OAuthError} if there is any issue.
 */
export function handleLogout() {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') {
        throw new OAuthError('misconfiguration', { error: ERROR_MESSAGE, status: 500 });
      }
      $sharedHandleLogout(req, res);
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Route handler that processes on-behalf-of requests to obtain an access token for a service principal.
 *
 * ### Body:
 * - `serviceNames` - An array of service names for which the access token is requested.
 *
 * @throws {OAuthError} if there is any issue.
 */
export function handleOnBehalfOf() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') {
        throw new OAuthError('misconfiguration', { error: ERROR_MESSAGE, status: 500 });
      }
      await $sharedHandleOnBehalfOf(req, res);
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Middleware that protects a route by ensuring the user is authenticated.
 *
 * ### What it does:
 * - If `acceptB2BRequests` is enabled:
 *  - Checks for a Bearer token in the Authorization header.
 *  - Verifies the token and attaches user info to the request.
 * - If not:
 *  - Validate the users access token cookie.
 *  - If valid, attaches user info to the request.
 *  - If invalid, it looks for a refresh token cookie and attempts to refresh the session.
 *  - If the refresh is successful, it sets new cookies and attaches user info to the request.
 *  - If the refresh fails, it throws an error.
 *
 * @param cb (optional) - A callback function that gives access to user info and an inject data function. Fires after the user is authenticated.
 *
 * @throws {OAuthError} if there is any issue with the configuration or authentication.
 */
export function protectRoute(cb?: CallbackFunction) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') {
        throw new OAuthError('misconfiguration', { error: ERROR_MESSAGE, status: 500 });
      }
      const { userInfo, injectData } = await $sharedMiddleware(req, res);
      if (cb) await cb({ userInfo, injectData });
      next();
    } catch (err) {
      next(err);
    }
  };
}
