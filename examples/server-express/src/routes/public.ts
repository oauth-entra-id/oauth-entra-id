import express, { type Router } from 'express';
import { getRegistrationIds } from '~/env';

export const publicRouter: Router = express.Router();

publicRouter.get('/', (req, res) => {
  res.status(200).json({ message: 'Hello World' });
});

publicRouter.get('/health', (req, res) => {
  res.status(200).send('OK');
});

publicRouter.get('/app-info', (req, res) => {
  res.status(200).send({ current: 'yellow', ...getRegistrationIds() });
});
