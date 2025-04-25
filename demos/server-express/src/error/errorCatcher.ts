import type { ErrorRequestHandler } from 'express';
import { HttpException } from './HttpException';

export const errorCatcher: ErrorRequestHandler = (err, req, res, next) => {
  const { message, statusCode, description } = new HttpException(err);
  res.status(statusCode).json({ error: message, statusCode, description });
};
