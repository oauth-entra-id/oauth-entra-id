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

export type Result<T, E = ResultErr> = T extends void
  ? { readonly success: true; readonly error?: undefined } | { readonly success: false; readonly error: E }
  : T extends object
    ?
        | ({ readonly [K in keyof T]: T[K] } & { readonly success: true; readonly error?: undefined })
        | ({ readonly [K in keyof T]?: undefined } & { readonly success: false; readonly error: E })
    :
        | { readonly success: true; readonly result: T; readonly error?: undefined }
        | { readonly success: false; readonly error: E; readonly result?: undefined };

function $isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

export function $ok(): Result<void>;
export function $ok<T>(result: T): Result<T>;
// biome-ignore lint/suspicious/noConfusingVoidType: <explanation>
export function $ok<T>(result?: T): Result<T | void> {
  if (result === undefined) return { success: true } as Result<void>;
  if ($isPlainObject(result)) return { success: true, ...(result as T & object) } as Result<T>;
  return { success: true, result } as Result<T>;
}

export function $err(
  type: ErrorTypes,
  details: { error: string; description?: string; status?: HttpErrorCodes },
): Result<never, ResultErr>;
export function $err(err: ResultErr): Result<never, ResultErr>;
export function $err(
  typeOrErr: ErrorTypes | ResultErr,
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
  constructor(type: ErrorTypes, details: { error: string; description?: string; status?: HttpErrorCodes });
  constructor(
    typeOrErr: ErrorTypes | ResultErr,
    details?: { error: string; description?: string; status?: HttpErrorCodes },
  ) {
    if (typeof typeOrErr === 'string') {
      super(details?.error ?? 'An error occurred');
      this.type = typeOrErr;
      this.statusCode = details?.status ?? 400;
      this.description = details?.description;
    } else {
      super(typeOrErr.message);
      this.type = typeOrErr.type;
      this.statusCode = typeOrErr.statusCode;
      this.description = typeOrErr.description;
    }
    this.name = 'OAuthError';

    Object.setPrototypeOf(this, new.target.prototype);
    Error.captureStackTrace(this, this.constructor);
  }
}
