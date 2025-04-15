import express from 'express';
import type { Request, Response, Router } from 'express';

export const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', (req: Request, res: Response) => {
  res.status(200).json({ user: req.userInfo });
});
