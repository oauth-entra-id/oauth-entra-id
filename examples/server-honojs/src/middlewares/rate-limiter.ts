import { getConnInfo } from '@hono/node-server/conninfo';
import { rateLimiter as rateLimiterMiddleware } from 'hono-rate-limiter';
import { every } from 'hono/combine';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';

const checkIp = createMiddleware(async (c, next) => {
  const connInfo = getConnInfo(c);
  const ip = connInfo.remote.address || c.req.header('x-forwarded-for');
  if (!ip) throw new HTTPException(400, { message: 'IP not found' });
  c.set('ip', ip);
  await next();
});

interface RateLimiterOptions {
  windowSec: number;
  limit: number;
}

export const rateLimiter = (options: RateLimiterOptions = { windowSec: 2 * 60, limit: 100 }) => {
  return every(
    checkIp,
    rateLimiterMiddleware({
      windowMs: options.windowSec * 1000,
      limit: options.limit,
      standardHeaders: 'draft-6',
      keyGenerator: (c) => c.var.ip,
      handler: (_c) => {
        throw new HTTPException(429, { message: 'Too many requests' });
      },
    }),
  );
};
