import { logger } from '@chneau/elysia-logger';
import { cors } from '@elysiajs/cors';
import { node } from '@elysiajs/node';
import { Elysia } from 'elysia';
import { helmet } from 'elysia-helmet';
import { env } from './env';
import { routesRouter } from './routes';

export function createApp() {
  const app = new Elysia({ adapter: node() });

  app.use(
    cors({
      origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    }),
  );

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"], //'www.google-analytics.com'
          styleSrc: ["'self'"], //'fonts.googleapis.com'
          imgSrc: ["'self'"],
          fontSrc: ["'self'"], //'fonts.gstatic.com'
          mediaSrc: ["'self'"],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          frameSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: {
        maxAge: 2 * 365 * 24 * 60 * 60,
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      referrerPolicy: { policy: 'no-referrer' },
      xPermittedCrossDomainPolicies: {
        permittedPolicies: 'none',
      },
      xXssProtection: true,
    }),
  );

  //TODO: Fix rate limit

  app.use(logger());

  app.use(routesRouter);

  return app;
}
