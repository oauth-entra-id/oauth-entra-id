import type { NextFunction, Request, Response } from 'express';
import { HttpException } from '~/error/HttpException';

export const notFound = (req: Request, res: Response, next: NextFunction) => {
  throw new HttpException('Not Found', 404);
};
