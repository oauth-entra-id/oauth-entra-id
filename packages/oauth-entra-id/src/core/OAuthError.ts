type ErrorHttpCodes = 400 | 401 | 403 | 500;

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
  readonly statusCode: ErrorHttpCodes;

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
  constructor(statusCode: ErrorHttpCodes, errMessage: string | { message: string; description: string }) {
    super(typeof errMessage === 'string' ? errMessage : errMessage.message);

    Object.setPrototypeOf(this, new.target.prototype);
    Error.captureStackTrace(this, this.constructor);

    this.name = 'OAuthError';
    this.statusCode = statusCode;
    this.description = typeof errMessage === 'string' ? undefined : errMessage.description;
  }
}
