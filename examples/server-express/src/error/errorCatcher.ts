import type { ErrorRequestHandler } from 'express';
import { HttpException } from './HttpException';

export const errorCatcher: ErrorRequestHandler = (err, _req, res, _next) => {
  const { message, statusCode, description } = new HttpException(err);
  res.status(statusCode).json({ error: message, statusCode, description });
};
