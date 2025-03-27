import type { Request, Response, NextFunction } from 'express';

export function tryCatch(func: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await func(req, res, next);
    } catch (error) {
      next(error);
    }
  };
}
