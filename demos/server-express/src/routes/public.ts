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

publicRouter.get('/app-info', (req: Request, res: Response) => {
  res.status(200).send({
    current: 'yellow',
    blue: env.AZURE_BLUE.clientId,
    red: env.AZURE_RED.clientId,
    yellow: env.AZURE_YELLOW.clientId,
  });
});
