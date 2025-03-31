import type { Request, Response, NextFunction } from 'express';
import { HttpException } from '~/error/HttpException';

export const notFound = (_req: Request, _res: Response, _next: NextFunction) => {
  throw new HttpException('Not Found', 404);
};
