import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import { cookieNameRegex, cookieValueRegex } from '~/utils/regex';
import type { CookieParserOptions } from './types';

export function getCookie(req: Request, name: string): string | undefined {
  const cookies = req.get('cookie');
  if (!cookieNameRegex.test(name)) {
    throw new OAuthError(400, { message: 'Bad cookie name', description: 'Invalid cookie name' });
  }

  if (!cookies || cookies.length === 0 || cookies.indexOf(name) === -1) {
    return undefined;
  }

  for (const pair of cookies.split('; ')) {
    if (pair.indexOf(name) === -1) {
      continue;
    }

    const trimmed = pair.trim();
    const valueStartPos = trimmed.indexOf('=');

    if (valueStartPos === -1) {
      continue;
    }

    const cookieName = trimmed.substring(0, valueStartPos).trim();
    if (cookieName !== name) {
      continue;
    }

    let cookieValue = trimmed.substring(valueStartPos + 1).trim();
    if (cookieValue.startsWith('"') && cookieValue.endsWith('"')) {
      cookieValue = cookieValue.slice(1, -1);
    }

    if (!cookieValueRegex.test(cookieValue)) {
      return undefined;
    }

    return decodeURIComponent(cookieValue);
  }

  return undefined;
}

export function setCookie(res: Response, name: string, value: string, options: CookieParserOptions) {
  if (!cookieNameRegex.test(name)) {
    throw new OAuthError(400, { message: 'Bad cookie name', description: 'Invalid cookie name' });
  }

  if (value !== '' && !cookieValueRegex.test(value)) {
    throw new OAuthError(400, { message: 'Bad cookie value', description: 'Invalid cookie value' });
  }

  let cookieOptions = {
    ...options,
    maxAge: options.maxAge !== undefined ? options.maxAge * 1000 : undefined,
  };

  if (name.startsWith('__Secure-')) {
    cookieOptions = {
      ...cookieOptions,
      path: '/',
      secure: true,
    };
  } else if (name.startsWith('__Host-')) {
    cookieOptions = {
      ...cookieOptions,
      path: '/',
      secure: true,
      domain: undefined,
    };
  }

  res.cookie(name, value, cookieOptions);
}
