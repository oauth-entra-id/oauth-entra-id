import express from 'express';
import type { Router, Request, Response } from 'express';

export const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', (req: Request, res: Response) => {
  res.status(200).json({ user: req.userInfo });
});
