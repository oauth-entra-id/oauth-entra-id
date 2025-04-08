import { Elysia } from 'elysia';

export const publicRouter = new Elysia();

publicRouter.get('/', { message: 'Hello World' });
publicRouter.get('/health', () => 'OK');
