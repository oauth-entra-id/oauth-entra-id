import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import type { Application, NextFunction, Request, Response } from 'express';
import rateLimiter from 'express-rate-limit';
import helmet from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/express';
import { env } from './env';
import { HttpException } from './error/HttpException';
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
      azure: {
        clientId: env.YELLOW_AZURE_CLIENT_ID,
        tenantId: env.YELLOW_AZURE_TENANT_ID,
        scopes: [env.YELLOW_AZURE_CLIENT_SCOPE],
        secret: env.YELLOW_AZURE_CLIENT_SECRET,
      },
      frontendUrl: env.REACT_FRONTEND_URL,
      serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.YELLOW_SECRET_KEY,
      advanced: {
        onBehalfOfServices: [
          {
            serviceName: 'blue',
            scope: env.BLUE_AZURE_CLIENT_SCOPE,
            secretKey: env.BLUE_SECRET_KEY,
            isHttps: env.NODE_ENV !== 'development',
            isSameSite: env.NODE_ENV !== 'development',
          },
          {
            serviceName: 'red',
            scope: env.RED_AZURE_CLIENT_SCOPE,
            secretKey: env.RED_SECRET_KEY,
            isHttps: env.NODE_ENV !== 'development',
            isSameSite: env.NODE_ENV !== 'development',
          },
        ],
      },
    }),
  );

  app.use(new URL(env.SERVER_URL).pathname, routesRouter);

  app.use('*', notFound);

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    const { message, statusCode, description } = new HttpException(err);
    res.status(statusCode).json({ error: message, statusCode, description });
  });

  return app;
}
