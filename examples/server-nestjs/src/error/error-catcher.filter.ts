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

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      message = exception.message;
    } else if (exception instanceof OAuthError) {
      statusCode = exception.statusCode;
      message = exception.message;
      description = env.NODE_ENV === 'development' ? exception.description : undefined;
    } else if (exception instanceof Error) {
      message = exception.message;
    }

    httpAdapter.reply(ctx.getResponse(), { error: message, statusCode, description }, statusCode);
  }
}
