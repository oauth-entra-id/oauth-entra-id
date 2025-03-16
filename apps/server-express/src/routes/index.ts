import express, { type Router } from 'express';
import { publicRouter } from './public';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { requireAuthentication } from 'oauth-entra-id/express';

export const routesRouter: Router = express.Router();

routesRouter.use('/', publicRouter);

routesRouter.use('/auth', authRouter);

routesRouter.use('/protected', requireAuthentication, protectedRouter);
