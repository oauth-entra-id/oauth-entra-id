import express from 'express';
import type { Request, Response, Router } from 'express';
import { env } from '~/env';

export const publicRouter: Router = express.Router();

publicRouter.get('/', (req: Request, res: Response) => {
  res.status(200).json({ message: 'Hello World!' });
});

publicRouter.get('/health', (req: Request, res: Response) => {
  res.status(200).send('OK');
});

publicRouter.get('/app-id', (req: Request, res: Response) => {
  res.status(200).send({ appId: env.AZURE.clientId });
});
