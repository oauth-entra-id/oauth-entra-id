import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { OAuthError } from 'oauth-entra-id';

@Catch()
export class ErrorCatcher implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    let statusCode = 500;
    let message = 'Something went wrong...';

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      message = exception.message;
    } else if (exception instanceof OAuthError) {
      statusCode = exception.statusCode;
      message = exception.message;
    } else if (exception instanceof Error) {
      message = exception.message;
    }

    const responseBody = {
      error: message,
      statusCode,
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, statusCode);
  }
}
