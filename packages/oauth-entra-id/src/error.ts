import { ZodError } from 'zod';
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

export function $stringErr(err: unknown): string {
  switch (true) {
    case err instanceof OAuthError:
      return `OAuthError: ${err.message} (${err.statusCode}) - ${err.description}`;
    case err instanceof ZodError:
      return `ZodError (Schema Validation): ${err.issues
        .map((issue) => `${issue.path.length > 0 ? issue.path.join('.') : 'root'}: ${issue.message}`)
        .join('. ')}`;
    case err instanceof Error:
      return `Error ${err.name}: ${err.message} - ${err.stack ?? 'No stack trace available'}`;
    case typeof err === 'string':
      return `String Error: ${err}`;
    case typeof err === 'object' && err !== null:
      switch (true) {
        case 'success' in err &&
          err.success === false &&
          'error' in err &&
          typeof err.error === 'object' &&
          err.error &&
          'message' in err.error &&
          'description' in err.error:
          return `ResultErr Error: ${err.error.message}${'statusCode' in err.error ? ` (${err.error.statusCode})` : ''} - ${err.error.description}`;
        case 'message' in err && 'description' in err:
          return `ResultErr Error: ${err.message}${'statusCode' in err ? ` (${err.statusCode})` : ''} - ${err.description}`;
        case 'msg' in err && 'desc' in err:
          return `ResultErr Error: ${err.msg}${'status' in err ? ` (${err.status})` : ''} - ${err.desc}`;
        default:
          try {
            return `Object Error: ${JSON.stringify(err, (_, v) => (typeof v === 'bigint' ? v.toString() : v))}`;
          } catch {
            return `Object Error: [Unserializable] ${String(err)}`;
          }
      }
    default:
      return `Unknown Error: ${String(err)}`;
  }
}
