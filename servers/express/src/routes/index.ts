import express, { type Router } from 'express';
import { requireAuthentication } from 'oauth-entra-id/express';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter: Router = express.Router();

routesRouter.use('/', publicRouter);
routesRouter.use('/auth', authRouter);
routesRouter.use('/protected', requireAuthentication, protectedRouter);
