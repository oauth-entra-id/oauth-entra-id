import '~/shared/request-extension';
import type { Request, Response, NextFunction } from 'express';
import { OAuthProvider, type OAuthConfig } from './core/OAuthProvider';
import { OAuthError } from './core/OAuthError';
import { sharedHandleAuthentication, sharedHandleCallback, sharedHandleLogout } from './shared/endpoints';
import { sharedRequireAuthentication } from './shared/middleware';

let globalExpressOAuthProvider: OAuthProvider | null = null;

/**
 * Middleware to configure the OAuthProvider for Express.
 *
 * This middleware initializes and attaches an `OAuthProvider` instance
 * to the `req` object, making it accessible in subsequent middleware
 * and route handlers.
 *
 * ### Behavior:
 * - Ensures `cookie-parser` middleware is present.
 * - Initializes `OAuthProvider` if not already created.
 *
 * @param config - OAuth configuration with an optional flag to allow other systems.
 */
export function authConfig(config: OAuthConfig & { allowOtherSystems?: boolean }) {
  const { allowOtherSystems, ...configuration } = config;

  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.cookies) throw new OAuthError(500, 'Missing cookie-parser middleware');
    if (!globalExpressOAuthProvider) {
      globalExpressOAuthProvider = new OAuthProvider(configuration);
    }

    if (globalExpressOAuthProvider.debug) console.log(`[oauth-entra-id] allowOtherSystems: ${!!allowOtherSystems}`);

    req.oauthProvider = globalExpressOAuthProvider;
    req.serverType = 'express';
    req.areOtherSystemsAllowed = !!allowOtherSystems;

    next();
  };
}

/**
 * Express route handler to generate an authentication URL for OAuth.
 *
 * ### Expected Request Body:
 * - `loginPrompt` (optional): `'email'` | `'select-account'` | `'sso'`
 * - `email` (optional): `string`
 * - `frontendUrl`: `string` (required)
 *
 * @throws {OAuthError} If authentication setup fails, an error is passed to `next`.
 */
export async function handleAuthentication(req: Request, res: Response, next: NextFunction) {
  try {
    await sharedHandleAuthentication('express')(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Express route handler to exchange an authorization code for tokens.
 * After the exchange, it stores the tokens in cookies and redirects the user back to the frontend.
 *
 * ### Expected Request Body:
 * - `code`: `string` (required)
 * - `state`: `string` (required)
 *
 * @throws {OAuthError} If token exchange fails, an error is passed to `next`.
 */
export async function handleCallback(req: Request, res: Response, next: NextFunction) {
  try {
    await sharedHandleCallback('express')(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Express route handler to log out a user by clearing cookies and generating a logout URL.
 *
 * ### Expected Request Body:
 * - `frontendUrl` (optional): `string`
 *
 * @throws {OAuthError} If logout fails, an error is passed to `next`.
 */
export function handleLogout(req: Request, res: Response, next: NextFunction) {
  try {
    sharedHandleLogout('express')(req, res);
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware to require authentication for Express routes.
 *
 * ### Authentication Flow:
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

export async function requireAuthentication(req: Request, res: Response, next: NextFunction) {
  try {
    const isAuth = await sharedRequireAuthentication('express')(req, res);
    if (isAuth) {
      next();
      return;
    }
    throw new OAuthError(401, 'Unauthorized');
  } catch (err) {
    next(err);
  }
}
