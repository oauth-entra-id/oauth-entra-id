import { $isPlainObject } from './utils/zod';

export type HttpErrorCodes = 400 | 401 | 403 | 500;

export type ErrorTypes =
  | 'internal'
  | 'nullish_value'
  | 'bad_request'
  | 'invalid_format'
  | 'misconfiguration'
  | 'crypto_error'
  | 'jwt_error';

export interface ResultErr {
  readonly type: ErrorTypes;
  readonly message: string;
  readonly description?: string;
  readonly statusCode: HttpErrorCodes;
}

export type Result<T, E = ResultErr> = T extends object
  ?
      | ({ readonly [K in keyof T]: T[K] } & { readonly success: true; readonly error?: undefined })
      | ({ readonly [K in keyof T]?: undefined } & { readonly success: false; readonly error: E })
  :
      | { readonly success: true; readonly result: T; readonly error?: undefined }
      | { readonly success: false; readonly error: E; readonly result?: undefined };

export function $ok<T>(result?: T): Result<T> {
  if ($isPlainObject(result)) return { success: true, ...(result as T & object) } as Result<T>;
  return { success: true, result } as Result<T>;
}

export function $err(
  type: ErrorTypes,
  details: { error: string; description?: string; status?: HttpErrorCodes },
): Result<never, ResultErr>;
export function $err(err: ResultErr): Result<never, ResultErr>;
export function $err(err: OAuthError): Result<never, ResultErr>;
export function $err(
  typeOrErr: ErrorTypes | ResultErr | OAuthError,
  details?: { error: string; description?: string; status?: HttpErrorCodes },
): Result<never, ResultErr> {
  if (typeof typeOrErr === 'string') {
    return {
      success: false,
      error: {
        type: typeOrErr,
        message: details?.error ?? 'An error occurred',
        description: details?.description,
        statusCode: details?.status ?? 400,
      },
    } as Result<never, ResultErr>;
  }

  if (typeOrErr instanceof OAuthError) {
    return {
      success: false,
      error: {
        type: typeOrErr.type,
        message: typeOrErr.message,
        description: typeOrErr.description,
        statusCode: typeOrErr.statusCode,
      },
    } as Result<never, ResultErr>;
  }

  return { success: false, error: typeOrErr } as Result<never, ResultErr>;
}

/**
 * Custom error class for handling OAuth-related errors.
 *
 * This error is designed for use in OAuth authentication flows,
 * providing an HTTP status code, a message, and an optional description.
 *
 * @extends {Error}
 */
export class OAuthError extends Error {
  readonly type: ErrorTypes;
  readonly statusCode: HttpErrorCodes;
  readonly description: string | undefined;

  constructor(err: ResultErr);
  constructor(err: Result<never, ResultErr>);
  constructor(type: ErrorTypes, details: { error: string; description?: string; status?: HttpErrorCodes });
  constructor(
    errOrType: ErrorTypes | ResultErr | Result<never, ResultErr>,
    details?: { error: string; description?: string; status?: HttpErrorCodes },
  ) {
    if (typeof errOrType === 'string') {
      super(details?.error ?? 'An error occurred');
      this.type = errOrType;
      this.statusCode = details?.status ?? 400;
      this.description = details?.description;
    } else if ('error' in errOrType && 'success' in errOrType && errOrType.success === false) {
      super((errOrType.error as ResultErr).message);
      this.type = (errOrType.error as ResultErr).type;
      this.statusCode = (errOrType.error as ResultErr).statusCode;
      this.description = (errOrType.error as ResultErr).description;
    } else {
      super(errOrType.message);
      this.type = errOrType.type;
      this.statusCode = errOrType.statusCode;
      this.description = errOrType.description;
    }
    this.name = 'OAuthError';

    Object.setPrototypeOf(this, new.target.prototype);
    Error.captureStackTrace(this, this.constructor);
  }
}
