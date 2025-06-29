import { HTTPException } from 'hono/http-exception';
import type { StatusCode } from 'hono/utils/http-status';
import { OAuthError } from 'oauth-entra-id';
import { env } from '~/env';

export function errorFilter(err: unknown): { statusCode: StatusCode; message: string; description?: string } {
  let statusCode: StatusCode = 500;
  let message = 'Something went wrong...';
  let description: string | undefined;

  switch (true) {
    case typeof err === 'string': {
      message = err;
      break;
    }
    case err instanceof OAuthError: {
      message = err.message;
      statusCode = err.statusCode as StatusCode;
      description = env.NODE_ENV === 'development' ? err.description : undefined;
      break;
    }
    case err instanceof HTTPException: {
      message = err.message;
      statusCode = err.status;
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
    case typeof err === 'object' && err !== null: {
      const error = err as { message?: string; statusCode?: number };
      if (error.message && typeof error.message === 'string') message = error.message;
      if (error.statusCode && typeof error.statusCode === 'number') statusCode = error.statusCode as StatusCode;
      break;
    }
  }

  return { statusCode, message, description };
}
