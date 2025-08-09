import cors from 'cors';
import type { Application, NextFunction, Request, Response } from 'express';
import express from 'express';
import rateLimiter from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/express';
import { env } from './env';
import { HttpException } from './error/HttpException';
import { notFound } from './middlewares/not-found';
import { oauthConfig } from './oauth';
import { routesRouter } from './routes';

export default function createApp(): Application {
  const app = express();

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
      limit: 100,
      skip: (req) => req.ip === '127.0.0.6',
      handler: (_req, res) => {
        res.status(429).json({ error: 'Too many requests from this IP, please try again after a break' });
      },
    }),
  );

  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.use(authConfig(oauthConfig));

  app.use(new URL(env.SERVER_URL).pathname, routesRouter);

  app.use(notFound);

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const { message, statusCode, description } = new HttpException(err);
    res.status(statusCode).json({ error: message, statusCode, description });
  });

  return app;
}
