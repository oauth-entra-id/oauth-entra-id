import { $isObj } from './utils/zod';

export type HttpErrorCodes = 400 | 401 | 403 | 500;

export interface ResultErr {
  readonly message: string;
  readonly description: string;
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
  if ($isObj(result)) {
    return { success: true, ...(result as object) } as Result<T>;
  }
  return { success: true, result } as Result<T>;
}

export function $err(err: { msg: string; desc: string; status?: HttpErrorCodes }): Result<never, ResultErr>;
export function $err(err: ResultErr): Result<never, ResultErr>;
export function $err(err: OAuthError): Result<never, ResultErr>;
export function $err(
  err: { msg: string; desc: string; status?: HttpErrorCodes } | ResultErr | OAuthError,
): Result<never, ResultErr> {
  if (err instanceof OAuthError) {
    return {
      success: false,
      error: { message: err.message, description: err.description, statusCode: err.statusCode },
    } as Result<never, ResultErr>;
  }

  return {
    success: false,
    error:
      'msg' in err && 'desc' in err
        ? { message: err.msg, description: err.desc, statusCode: err.status ?? 400 }
        : { message: err.message, description: err.description, statusCode: err.statusCode ?? 400 },
  } as Result<never, ResultErr>;
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
  readonly statusCode: HttpErrorCodes;
  readonly description: string;

  constructor(err: ResultErr);
  constructor(err: Result<never, ResultErr>);
  constructor(err: { msg: string; desc: string; status?: HttpErrorCodes });
  constructor(err: { msg: string; desc: string; status?: HttpErrorCodes } | ResultErr | Result<never, ResultErr>) {
    if ('error' in err && 'success' in err) {
      super((err.error as ResultErr).message);
      this.statusCode = (err.error as ResultErr).statusCode;
      this.description = (err.error as ResultErr).description;
    } else if ('msg' in err && 'desc' in err) {
      super(err.msg);
      this.statusCode = err.status ?? 400;
      this.description = err.desc;
    } else if ('message' in err && 'description' in err && 'statusCode' in err) {
      super(err.message);
      this.statusCode = err.statusCode;
      this.description = err.description;
    } else {
      super('An unknown error occurred');
      this.statusCode = 500;
      this.description = 'An unknown error occurred';
    }
    this.name = 'OAuthError';

    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
  }
}
