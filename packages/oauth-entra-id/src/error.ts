export type Result<T, E = OAuthErr> =
  | {
      success: true;
      result: T;
    }
  | {
      success: false;
      error: E;
    };

export type HttpErrorCodes = 400 | 401 | 403 | 500;
export type ErrorTypes = (string & {}) | 'null_value' | 'encrypt_error' | 'decrypt_error' | 'jwt_error';

export interface OAuthErr {
  readonly type: ErrorTypes;
  readonly message: string;
  readonly description?: string;
  readonly statusCode: HttpErrorCodes;
}

export function $ok<T>(result: T): Result<T> {
  return { success: true, result } as const;
}

export function $err(
  type: ErrorTypes,
  { error, description }: { error: string; description?: string },
  status: HttpErrorCodes = 400,
): Result<never, OAuthErr> {
  return {
    success: false,
    error: { type, message: error, description, statusCode: status },
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
  /**
   * The HTTP status code representing the type of OAuth error.
   * @readonly
   * @type {400 | 401 | 403 | 500}
   */
  readonly statusCode: HttpErrorCodes;

  /**
   * A more detailed description of the error (if provided).
   * Shouldn't be sent to the client in a production environment.
   * @readonly
   * @type {string | undefined}
   */
  readonly description: string | undefined;

  /**
   * Creates an instance of `OAuthError`.
   *
   * @param {400 | 401 | 403 | 500} statusCode - The HTTP status code for the error.
   * @param {string | { message: string; description?: string }} errMessage - The error message or an object containing message and optional description.
   */
  constructor(statusCode: HttpErrorCodes, errMessage: string | { message: string; description: string }) {
    super(typeof errMessage === 'string' ? errMessage : errMessage.message);

    Object.setPrototypeOf(this, new.target.prototype);
    Error.captureStackTrace(this, this.constructor);

    this.name = 'OAuthError';
    this.statusCode = statusCode;
    this.description = typeof errMessage === 'string' ? undefined : errMessage.description;
  }
}
