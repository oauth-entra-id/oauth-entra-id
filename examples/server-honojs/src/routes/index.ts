import { Hono } from 'hono';
import { authRouter } from './auth';
import { liteRouter } from './lite';
import { mobileAuthRouter, mobileProtectedRouter } from './mobile';
import { protectedRouter } from './protected';
import { publicRouter } from './public';

export const routesRouter = new Hono();

routesRouter.route('/', publicRouter);
routesRouter.route('/auth', authRouter);
routesRouter.route('/auth/mobile', mobileAuthRouter);
routesRouter.route('/lite', liteRouter);
// Registered before '/protected' on purpose: the cookie middleware of that router must not wrap the Bearer routes.
routesRouter.route('/protected/mobile', mobileProtectedRouter);
routesRouter.route('/protected', protectedRouter);
