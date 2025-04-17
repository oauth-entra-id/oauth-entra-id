import './types';
import type { NextFunction, Request, Response } from 'express';
import { OAuthProvider } from './OAuthProvider';
import { OAuthError } from './error';
import { sharedHandleAuthentication, sharedHandleCallback, sharedHandleLogout } from './shared/endpoints';
import { sharedRequireAuthentication } from './shared/middleware';
import type { OAuthConfig } from './types';
import { debugLog } from './utils/utils';

let globalNestjsOAuthProvider: OAuthProvider | null = null;

/**
 * Middleware to configure the OAuthProvider for NestJS.
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
    if (!globalNestjsOAuthProvider) {
      globalNestjsOAuthProvider = new OAuthProvider(configuration);
    }

    debugLog({
      condition: !!globalNestjsOAuthProvider.debug,
      funcName: 'authConfig',
      message: `allowOtherSystems: ${!!allowOtherSystems}`,
    });

    req.oauthProvider = globalNestjsOAuthProvider;
    req.serverType = 'nestjs';
    req.areOtherSystemsAllowed = !!allowOtherSystems;

    next();
  };
}

/**
 * NestJS route handler to generate an authentication URL for OAuth.
 *
 * ### Expected Request Body:
 * - `loginPrompt` (optional): `'email'` | `'select-account'` | `'sso'`
 * - `email` (optional): `string`
 * - `frontendUrl`: `string` (required)
 *
 * @throws {OAuthError} If authentication setup fails, an error is thrown.
 */
export async function handleAuthentication(req: Request, res: Response) {
  try {
    await sharedHandleAuthentication('nestjs')(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * NestJS route handler to exchange an OAuth code for an access token.
 *
 * ### Expected Request Body:
 * - `code`: `string`
 * - `state`: `string`
 *
 * @throws {OAuthError} If callback setup fails, an error is thrown.
 */
export async function handleCallback(req: Request, res: Response) {
  try {
    await sharedHandleCallback('nestjs')(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * NestJS route handler to log out a user by clearing cookies and generating a logout URL.
 *
 * ### Expected Request Body:
 * - `frontendUrl`: `string`
 *
 * @throws {OAuthError} If logout setup fails, an error is thrown.
 */
export function handleLogout(req: Request, res: Response) {
  try {
    sharedHandleLogout('nestjs')(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * Middleware to check and require authentication for NestJS routes.
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
export async function isAuthenticated(req: Request, res: Response) {
  try {
    return await sharedRequireAuthentication('nestjs')(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}
