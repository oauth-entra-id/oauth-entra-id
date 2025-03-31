import { Hono } from 'hono';
import { requireAuthentication } from '~/middlewares/require-authentication';

export const protectedRouter = new Hono();

protectedRouter.get('/user-info', requireAuthentication, (c) => {
  return c.json({ user: c.var.userInfo });
});
