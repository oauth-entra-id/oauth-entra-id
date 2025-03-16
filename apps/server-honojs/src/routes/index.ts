import { Hono } from 'hono';
import { publicRouter } from './public';
import { authRouter } from './auth';
import { protectedRouter } from './protected';

export const routesRouter = new Hono();

routesRouter.route('/', publicRouter);

routesRouter.route('/auth', authRouter);

routesRouter.route('/protected', protectedRouter);
