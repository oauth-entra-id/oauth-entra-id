import '~/shared/types';
import type { NextFunction, Request, Response } from 'express';
import { OAuthProvider } from '~/core';
import { OAuthError } from '~/error';
import {
  sharedHandleAuthentication,
  sharedHandleCallback,
  sharedHandleLogout,
  sharedHandleOnBehalfOf,
} from '~/shared/endpoints';
import { sharedIsAuthenticated } from '~/shared/middleware';
import type { CallbackFunction } from '~/shared/types';
import type { OAuthConfig } from '~/types';

const ERROR_MESSAGE = 'Make sure you used Express export and you used authConfig';

let globalExpressOAuthProvider: OAuthProvider | null = null;

/**
 * Configures and initializes the OAuthProvider for Express.
 *
 * Attaches the OAuthProvider instance to the Express request object,
 * allowing route handlers and middleware to access it.
 *
 * @param config - The full configuration used to initialize the OAuthProvider.
 * @returns Express middleware function.
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
 * Express route handler to generate an authentication URL.
 *
 * Optional Request Body:
 * - `loginPrompt` (optional): `'email'` | `'select-account'` | `'sso'`
 * - `email` (optional): `string`
 * - `frontendUrl` (optional): `string`
 *
 * @throws {OAuthError} If authentication setup fails, an error is passed to `next`.
 */
export async function handleAuthentication(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.oauthProvider || req.serverType !== 'express') throw new OAuthError(500, ERROR_MESSAGE);
    await sharedHandleAuthentication(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Express route handler to exchange an authorization code for tokens.
 * After the exchange, it stores the tokens in cookies and redirects the user back to the frontend.
 *
 * Expected Request Body:
 * - `code`: `string`
 * - `state`: `string`
 *
 * @throws {OAuthError} If token exchange fails, an error is passed to `next`.
 */
export async function handleCallback(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.oauthProvider || req.serverType !== 'express') throw new OAuthError(500, ERROR_MESSAGE);
    await sharedHandleCallback(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Express route handler to log out a user by clearing cookies and generating a logout URL.
 *
 * Optional Request Body:
 * - `frontendUrl` (optional): `string`
 *
 * @throws {OAuthError} If logout fails, an error is passed to `next`.
 */
export function handleLogout(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.oauthProvider || req.serverType !== 'express') throw new OAuthError(500, ERROR_MESSAGE);
    sharedHandleLogout(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Express route handler to obtain tokens on behalf of another system.
 *
 * Expected Request Body:
 * - `serviceNames`: `string[]`
 *
 * @throws {OAuthError} If token exchange fails, an error is passed to `next`.
 */
export function handleOnBehalfOf(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.oauthProvider || req.serverType !== 'express') throw new OAuthError(500, ERROR_MESSAGE);
    sharedHandleOnBehalfOf(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware to protect routes by checking user authentication status.
 *
 * Authentication Flow:
 * - If `allowOtherSystems` is **enabled**:
 *   - Checks for a Bearer token in the `Authorization` header.
 *   - If the token is **valid** and from **another system**, the request proceeds.
 *   - If the token is **valid** but from the **same system**, an error is thrown.
 *   - If the token is **invalid**, an error is thrown.
 *   - If no token is present, it falls back to checking cookies.
 *
 * - If `allowOtherSystems` is **disabled** or no Bearer token is found:
 *   - If the user has a **valid access token**, the request proceeds.
 *   - If the user has an **invalid or missing access token** but a **valid refresh token**:
 *     - The tokens are refreshed, and the request proceeds.
 *   - If **both tokens are invalid or missing**, an error is thrown.
 *
 * @throws {OAuthError} If authentication fails, an error is passed to the `next` function.
 */
export function protectRoute(cb?: CallbackFunction) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.oauthProvider || req.serverType !== 'express') throw new OAuthError(500, ERROR_MESSAGE);
      const { userInfo, injectData } = await sharedIsAuthenticated(req, res);
      next();
      if (cb) await cb({ userInfo, injectData });
    } catch (err) {
      next(err);
    }
  };
}
