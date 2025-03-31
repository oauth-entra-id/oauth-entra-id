import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { logger } from 'hono/logger';
import { REACT_FRONTEND_URL, HONOJS_URL } from './env';
import { routesRouter } from './routes';
import { errorFilter } from './error/filter-error';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { rateLimiter } from './middlewares/rate-limiter';

export function createApp() {
  const app = new Hono();

  app.use(
    cors({
      origin: [HONOJS_URL, REACT_FRONTEND_URL],
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    }),
  );

  app.use(
    secureHeaders({
      contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'"],
        fontSrc: ["'self'"],
        mediaSrc: ["'self'"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
      xXssProtection: '1; mode=block',
    }),
  );

  app.use(rateLimiter());
  app.use(logger());

  app.route(new URL(HONOJS_URL).pathname, routesRouter);

  app.onError((err, c) => {
    const { statusCode, message } = errorFilter(err);
    return c.json({ error: message }, statusCode as ContentfulStatusCode);
  });

  app.notFound((c) => c.json({ error: 'Not found' }, 404));

  return app;
}
