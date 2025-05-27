import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import { OAuthError } from 'oauth-entra-id';
import { env } from '~/env';

@Catch()
export class ErrorCatcher implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    let statusCode = 500;
    let message = 'Something went wrong...';
    let description: string | undefined;

    switch (true) {
      case typeof exception === 'string': {
        message = exception;
        break;
      }
      case exception instanceof OAuthError: {
        message = exception.message;
        statusCode = exception.statusCode;
        description = env.NODE_ENV === 'development' ? exception.description : undefined;
        break;
      }
      case exception instanceof HttpException: {
        message = exception.message;
        statusCode = exception.getStatus();
        break;
      }
      case exception instanceof Error: {
        message = exception.message;
        if (exception.name === 'SyntaxError') {
          message = 'Invalid Syntax';
          statusCode = 400;
        }
        break;
      }
      case typeof exception === 'object' && exception !== null: {
        const error = exception as { message?: string; statusCode?: number };
        if (error.message && typeof error.message === 'string') message = error.message;
        if (error.statusCode && typeof error.statusCode === 'number') statusCode = error.statusCode;
        break;
      }
    }

    httpAdapter.reply(ctx.getResponse(), { error: message, statusCode, description }, statusCode);
  }
}
