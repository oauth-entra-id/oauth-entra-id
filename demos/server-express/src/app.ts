import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Application } from 'express';
import rateLimiter from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/express';
import { env } from './env';
import { errorCatcher } from './error/errorCatcher';
import { notFound } from './middlewares/not-found';
import { routesRouter } from './routes';

export default function createApp(): Application {
  const app = express();

  if (env.NODE_ENV === 'production' && env.PROXIES) {
    app.set('trust proxy', env.PROXIES);
  }

  app.disable('x-powered-by');
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use(
    cors({
      origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
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

  if (env.NODE_ENV === 'production') {
    app.get('/', (_req, res) => {
      res.sendStatus(200);
    });
  }
  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.use(cookieParser());

  app.use(
    authConfig({
      azure: env.AZURE_YELLOW,
      frontendUrl: env.REACT_FRONTEND_URL,
      serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET_KEY_YELLOW,
    }),
  );

  app.use(new URL(env.SERVER_URL).pathname, routesRouter);

  app.use('*', notFound);

  app.use(errorCatcher);

  return app;
}
