import cookieParser from '@fastify/cookie';
import cors from '@fastify/cors';
import formBody from '@fastify/formbody';
import helmet from '@fastify/helmet';
import rateLimiter from '@fastify/rate-limit';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import Fastify from 'fastify';
import { env } from './env';
import { HttpException } from './error/HttpException';
import { routesRouter } from './routes';

export default async function createApp() {
  const app = Fastify({
    logger: true,
    trustProxy: env.NODE_ENV === 'production' && env.PROXIES ? env.PROXIES : false,
  }).withTypeProvider<TypeBoxTypeProvider>();

  await app.register(cors, {
    origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  await app.register(helmet, {
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
  });

  await app.register(rateLimiter, {
    max: 20,
    timeWindow: 60 * 1000,
    allowList: ['127.0.0.6'],
    errorResponseBuilder: (_req, _context) => {
      return {
        error: 'Too many requests from this IP, please try again after a break',
        statusCode: 429,
      };
    },
  });

  await app.register(formBody);
  await app.register(cookieParser);

  await app.register(routesRouter, { prefix: new URL(env.SERVER_URL).pathname });

  app.setErrorHandler((error, req, reply) => {
    const { message, statusCode, description } = new HttpException(error);
    reply.status(statusCode).send({ error: message, statusCode, description });
  });

  return app;
}
