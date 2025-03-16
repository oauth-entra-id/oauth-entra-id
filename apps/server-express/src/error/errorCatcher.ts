import type { ErrorRequestHandler } from 'express';
import { NODE_ENV } from '~/env';
import { HttpException } from './HttpException';

export const errorCatcher: ErrorRequestHandler = (err, _req, res, _next): void => {
  const { message, statusCode } = new HttpException(err);
  if (NODE_ENV === 'development' && ![401, 403, 404].includes(statusCode)) console.error(err);
  if (NODE_ENV === 'production' && [401, 403].includes(statusCode)) {
    res.status(404).json({ error: 'Not Found', statusCode: 404 });
    return;
  }
  res.status(statusCode).json({ error: message, statusCode });
};
