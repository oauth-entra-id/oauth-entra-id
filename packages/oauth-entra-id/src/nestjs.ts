import './types';
import type { NextFunction, Request, Response } from 'express';
import { OAuthProvider } from './core';
import { OAuthError } from './error';
import {
  sharedHandleAuthentication,
  sharedHandleCallback,
  sharedHandleLogout,
  sharedHandleOnBehalfOf,
} from './shared/endpoints';
import { sharedRequireAuthentication } from './shared/middleware';
import type { OAuthConfig } from './types';

const ERROR_MESSAGE = 'Make sure you used NestJS export and you used authConfig';

let globalNestjsOAuthProvider: OAuthProvider | null = null;

/**
 * Configures and initializes the OAuthProvider for NestJS.
 *
 * Attaches the OAuthProvider instance to the NestJS request object,
 * allowing route handlers and middleware to access it.
 *
 * @param config - The full configuration used to initialize the OAuthProvider.
 * @returns NestJS middleware function.
 * @throws {OAuthError} If `cookie-parser` middleware has not been set up.
 */
export function authConfig(config: OAuthConfig) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.cookies) {
      throw new OAuthError(500, 'Missing cookie-parser middleware');
    }

    if (!globalNestjsOAuthProvider) {
      globalNestjsOAuthProvider = new OAuthProvider(config);
    }

    req.oauthProvider = globalNestjsOAuthProvider;
    req.serverType = 'nestjs';

    next();
  };
}

/**
 * NestJS route handler to generate an authentication URL.
 *
 * Optional Request Body:
 * - `loginPrompt` (optional): `'email'` | `'select-account'` | `'sso'`
 * - `email` (optional): `string`
 * - `frontendUrl` (optional): `string`
 *
 * @throws {OAuthError} If authentication setup fails, an error is thrown.
 */
export async function handleAuthentication(req: Request, res: Response) {
  try {
    if (!req.oauthProvider || req.serverType !== 'nestjs') throw new OAuthError(500, ERROR_MESSAGE);
    await sharedHandleAuthentication(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * NestJS route handler to exchange an authorization code for tokens.
 * After the exchange, it stores the tokens in cookies and redirects the user back to the frontend.
 *
 * Expected Request Body:
 * - `code`: `string`
 * - `state`: `string`
 *
 * @throws {OAuthError} If callback setup fails, an error is thrown.
 */
export async function handleCallback(req: Request, res: Response) {
  try {
    if (!req.oauthProvider || req.serverType !== 'nestjs') throw new OAuthError(500, ERROR_MESSAGE);
    await sharedHandleCallback(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * NestJS route handler to log out a user by clearing cookies and generating a logout URL.
 *
 * Optional Request Body:
 * - `frontendUrl` (optional): `string`
 *
 * @throws {OAuthError} If logout setup fails, an error is thrown.
 */
export function handleLogout(req: Request, res: Response) {
  try {
    if (!req.oauthProvider || req.serverType !== 'nestjs') throw new OAuthError(500, ERROR_MESSAGE);
    sharedHandleLogout(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * NestJS route handler to handle On-Behalf-Of token exchange.
 *
 * Expected Request Body:
 * - `serviceNames`: `string[]`
 *
 * @throws {OAuthError} If On-Behalf-Of setup fails, an error is thrown.
 */
export function handleOnBehalfOf(req: Request, res: Response) {
  try {
    if (!req.oauthProvider || req.serverType !== 'nestjs') throw new OAuthError(500, ERROR_MESSAGE);
    sharedHandleOnBehalfOf(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}

/**
 * Middleware to check and require authentication for NestJS routes.
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
 * @returns `true` if authentication succeeded, otherwise throws an `OAuthError`.
 * @throws {OAuthError} If authentication fails.
 */
export async function isAuthenticated(req: Request, res: Response) {
  try {
    if (!req.oauthProvider || req.serverType !== 'nestjs') throw new OAuthError(500, ERROR_MESSAGE);
    return await sharedRequireAuthentication(req, res);
  } catch (err) {
    if (err instanceof OAuthError) throw err;
    if (err instanceof Error) throw new OAuthError(500, err.message);
    throw new OAuthError(500, { message: 'Something went wrong', description: err as string });
  }
}
