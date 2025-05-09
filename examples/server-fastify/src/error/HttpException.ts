import { OAuthError } from 'oauth-entra-id';
import { ZodError } from 'zod';
import { env } from '~/env';

export class HttpException extends Error {
  readonly statusCode: number;
  readonly description?: string;

  constructor(err: unknown, defaultStatusCode = 500) {
    let statusCode = defaultStatusCode;
    let message = 'Something went wrong...';
    let description: string | undefined;

    if (typeof err === 'string') {
      message = err;
    } else if (err instanceof HttpException) {
      message = err.message;
      statusCode = err.statusCode;
    } else if (err instanceof OAuthError) {
      message = err.message;
      statusCode = err.statusCode;
      description = env.NODE_ENV === 'development' ? err.description : undefined;
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
    this.description = description;
  }
}
