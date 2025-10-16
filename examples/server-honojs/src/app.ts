import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { env } from './env';
import { errorFilter } from './error/filter-error';
import { rateLimiter } from './middlewares/rate-limiter';
import { routesRouter } from './routes';

export function createApp() {
  const app = new Hono();

  app.use(
    cors({
      origin: [env.SERVER_URL, env.REACT_FRONTEND_URL, env.FASTIFY_URL],
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    }),
  );

  app.use(secureHeaders(secureHeadersConfig));
  app.use(rateLimiter());
  app.use(logger());

  app.route(new URL(env.SERVER_URL).pathname, routesRouter);

  app.notFound((c) => c.json({ error: 'Not found' }, 404));

  app.onError((err, c) => {
    const { statusCode, message, description } = errorFilter(err);
    return c.json({ error: message, statusCode, description }, statusCode as ContentfulStatusCode);
  });

  return app;
}

const secureHeadersConfig = {
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
  strictTransportSecurity: 'max-age=62899200; includeSubDomains; preload',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'no-referrer',
  xPermittedCrossDomainPolicies: 'none',
  xFrameOptions: 'DENY',
};
