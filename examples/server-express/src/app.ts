import cors from 'cors';
import type { Application, NextFunction, Request, Response } from 'express';
import express from 'express';
import rateLimiter, { type Options as rateLimitOptions } from 'express-rate-limit';
import helmet, { type HelmetOptions } from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/express';
import { env } from './env';
import { HttpException } from './error/HttpException';
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

  app.use(helmet(helmetConfig));
  app.use(rateLimiter(rateLimitConfig));
  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));
  app.use(authConfig(oauthConfig));

  app.use(new URL(env.SERVER_URL).pathname, routesRouter);

  app.use((req, res, next) => {
    throw new HttpException('Not Found', 404);
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    const { message, statusCode, description } = new HttpException(err);
    res.status(statusCode).json({ error: message, statusCode, description });
  });

  return app;
}

const helmetConfig: HelmetOptions = {
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
};

const rateLimitConfig: Partial<rateLimitOptions> = {
  windowMs: 60 * 1000,
  limit: 100,
  skip: (req: Request) => req.ip === '127.0.0.6',
  handler: (req: Request, res: Response) => {
    res.status(429).json({ error: 'Too many requests from this IP, please try again after a break' });
  },
};
