export type HttpErrorCodes = 400 | 401 | 403 | 500;
export type ErrorTypes =
  | 'internal_error'
  | 'nullish_value'
  | 'input'
  | 'format'
  | 'config'
  | 'cryptography'
  | 'serialization'
  | 'jwt_error';

export interface OAuthErr {
  readonly type: ErrorTypes;
  readonly message: string;
  readonly description?: string;
  readonly statusCode: HttpErrorCodes;
}

export type Result<T, E = OAuthErr> =
  | {
      readonly success: true;
      readonly result: T;
      readonly error?: undefined;
    }
  | {
      readonly success: false;
      readonly error: E;
      readonly result?: undefined;
    };

export function $ok<T>(result: T): Result<T> {
  return { success: true, result } as const;
}

export function $err(
  type: ErrorTypes,
  details: { error: string; description?: string },
  status: HttpErrorCodes = 400,
): Result<never, OAuthErr> {
  return {
    success: false,
    error: { type, message: details.error, description: details.description, statusCode: status },
  } satisfies Result<never, OAuthErr>;
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

  constructor(errorResult: OAuthErr);
  constructor(type: ErrorTypes, details: { error: string; description?: string }, status?: HttpErrorCodes);
  constructor(
    typeOrErrorResult: ErrorTypes | OAuthErr,
    details?: { error: string; description?: string },
    status: HttpErrorCodes = 400,
  ) {
    if (typeof typeOrErrorResult === 'string') {
      super(details?.error ?? 'An error occurred');
      this.type = typeOrErrorResult;
      this.statusCode = status;
      this.description = details?.description;
    } else {
      super(typeOrErrorResult.message);
      this.type = typeOrErrorResult.type;
      this.statusCode = typeOrErrorResult.statusCode;
      this.description = typeOrErrorResult.description;
    }
    this.name = 'OAuthError';
    // Object.setPrototypeOf(this, new.target.prototype);
    // Error.captureStackTrace(this, this.constructor);
  }
}
