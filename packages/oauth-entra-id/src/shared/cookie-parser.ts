import type { Request, Response } from 'express';
import { OAuthError } from '~/error';
import { base64urlWithDotRegex } from '~/utils/zod';
import type { CookieParserOptions } from './types';

export function $getCookie(req: Request, name: string): string | undefined {
  const cookies = req.get('cookie');
  if (!base64urlWithDotRegex.test(name)) {
    return undefined;
  }

  if (!cookies || cookies.length === 0 || cookies.indexOf(name) === -1) {
    return undefined;
  }

  for (let pair of cookies.split('; ')) {
    if (pair.indexOf(name) === -1) {
      continue;
    }

    pair = pair.trim();
    const valueStartPos = pair.indexOf('=');

    if (valueStartPos === -1) {
      continue;
    }

    const cookieName = pair.substring(0, valueStartPos).trim();
    if (cookieName !== name) {
      continue;
    }

    let cookieValue = pair.substring(valueStartPos + 1).trim();
    if (cookieValue.startsWith('"') && cookieValue.endsWith('"')) {
      cookieValue = cookieValue.slice(1, -1);
    }

    if (!base64urlWithDotRegex.test(cookieValue)) {
      return undefined;
    }

    return decodeURIComponent(cookieValue);
  }

  return undefined;
}

export function $setCookie(res: Response, name: string, value: string, options: CookieParserOptions) {
  if (!base64urlWithDotRegex.test(name)) {
    throw new OAuthError('bad_request', {
      error: 'Invalid cookie name',
      description: 'Cookie name does not match the required pattern',
    });
  }

  if (value !== '' && !base64urlWithDotRegex.test(value)) {
    throw new OAuthError('bad_request', {
      error: 'Invalid cookie value',
      description: 'Cookie value does not match the required pattern',
    });
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
