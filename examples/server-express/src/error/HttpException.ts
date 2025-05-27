import { OAuthError } from 'oauth-entra-id';
import { env } from '~/env';

export class HttpException extends Error {
  readonly statusCode: number;
  readonly description?: string;

  constructor(err: unknown, defaultStatusCode = 500) {
    let statusCode = defaultStatusCode;
    let message = 'Something went wrong...';
    let description: string | undefined;

    switch (true) {
      case typeof err === 'string': {
        message = err;
        break;
      }
      case err instanceof OAuthError: {
        message = err.message;
        statusCode = err.statusCode;
        description = env.NODE_ENV === 'development' ? err.description : undefined;
        break;
      }
      case err instanceof Error: {
        message = err.message;
        if (err.name === 'SyntaxError') {
          message = 'Invalid Syntax';
          statusCode = 400;
        }
        break;
      }
      default: {
        if (typeof err === 'object' && err !== null) {
          const error = err as { message?: string; statusCode?: number };
          if (error.message && typeof error.message === 'string') message = error.message;
          if (error.statusCode && typeof error.statusCode === 'number') statusCode = error.statusCode;
        }
      }
    }

    super(message);
    this.statusCode = statusCode;
    this.name = 'HttpException';
    this.description = description;
  }
}
