import { ZodError } from 'zod';
import { OAuthError } from 'oauth-entra-id';

export class HttpException extends Error {
  readonly statusCode: number;

  constructor(err: unknown, defaultStatusCode = 500) {
    let message = 'Something went wrong...';
    let statusCode = defaultStatusCode;

    if (typeof err === 'string') {
      message = err;
    } else if (err instanceof HttpException || err instanceof OAuthError) {
      message = err.message;
      statusCode = err.statusCode;
    } else if (err instanceof ZodError) {
      message = err.issues.map((issue) => issue.message).join(', ');
      statusCode = 400;
    } else if (err instanceof Error) {
      message = err.message;
    } else if (typeof err === 'object' && err !== null) {
      const error = err as { message?: string; statusCode?: number };
      if (error.message && typeof error.message === 'string') message = error.message;
      if (error.statusCode && typeof error.statusCode === 'number') statusCode = error.statusCode;
    }

    super(message);
    this.statusCode = statusCode;
    this.name = 'HttpException';
  }
}
