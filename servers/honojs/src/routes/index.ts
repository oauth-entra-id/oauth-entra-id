import { Hono } from 'hono';
import { authRouter } from './auth';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter = new Hono();

routesRouter.route('/', publicRouter);
routesRouter.route('/auth', authRouter);
routesRouter.route('/protected', protectedRouter);
