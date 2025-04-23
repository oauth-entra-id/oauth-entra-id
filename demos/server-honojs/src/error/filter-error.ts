import { HTTPException } from 'hono/http-exception';
import type { StatusCode } from 'hono/utils/http-status';
import { OAuthError } from 'oauth-entra-id';
import { ZodError } from 'zod';

export function errorFilter(err: unknown): { statusCode: StatusCode; message: string } {
  let statusCode: StatusCode = 500;
  let message = 'Something went wrong...';

  // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
  switch (true) {
    case typeof err === 'string': {
      message = err;
      break;
    }
    case err instanceof OAuthError: {
      message = err.message;
      statusCode = err.statusCode as StatusCode;
      console.log(err.description);
      break;
    }
    case err instanceof HTTPException: {
      message = err.message;
      statusCode = err.status;
      break;
    }
    case err instanceof ZodError: {
      const errors = err.errors.map((error) => error.message).join(', ');
      statusCode = 400;
      message = errors;
      if (errors.toLowerCase().includes('required')) {
        message = 'Some field is missing';
      }
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
  }

  return { statusCode, message };
}
