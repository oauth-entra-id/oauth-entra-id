import express from 'express';
import type { Router, Request, Response } from 'express';

export const publicRouter: Router = express.Router();

publicRouter.get('/', (req: Request, res: Response) => {
  res.status(200).json({ message: 'Hello World!' });
});

publicRouter.get('/health', (req: Request, res: Response) => {
  res.status(200).send('OK');
});
