import { Elysia } from 'elysia';
import { authRouter } from './auth';
import { publicRouter } from './public';

export const routesRouter = new Elysia();

routesRouter.use(publicRouter);

routesRouter.use(authRouter);
