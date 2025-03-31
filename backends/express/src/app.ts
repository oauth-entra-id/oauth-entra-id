import express, { type Application } from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import rateLimiter from 'express-rate-limit';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/express';
import { AZURE, SECRET_KEY, REACT_FRONTEND_URL, PROXIES, EXPRESS_URL, NODE_ENV } from './env';
import { notFound } from './middlewares/not-found';
import { routesRouter } from './routes';
import { errorCatcher } from './error/errorCatcher';

export default function createApp(): Application {
  const app = express();

  if (NODE_ENV === 'production' && PROXIES) {
    app.set('trust proxy', PROXIES);
  }

  app.disable('x-powered-by');
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use(
    cors({
      origin: [EXPRESS_URL, REACT_FRONTEND_URL],
      methods: 'GET,POST,PUT,DELETE,OPTIONS',
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

  app.use(
    rateLimiter({
      windowMs: 60 * 1000,
      limit: 20,
      skip: (req) => req.ip === '127.0.0.6',
      handler: (req, res) => {
        res.status(429).json({ error: 'Too many requests from this IP, please try again after a break' });
      },
    }),
  );

  if (NODE_ENV === 'production') {
    app.get('/', (_req, res) => {
      res.sendStatus(200);
    });
  }
  app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.use(cookieParser());

  app.use(
    authConfig({
      azure: AZURE,
      frontendUrl: REACT_FRONTEND_URL,
      serverFullCallbackUrl: `${EXPRESS_URL}/auth/callback`,
      secretKey: SECRET_KEY,
    }),
  );

  app.use(new URL(EXPRESS_URL).pathname, routesRouter);

  app.use('*', notFound);

  app.use(errorCatcher);

  return app;
}
