import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimiter from '@fastify/rate-limit';
import cookieParser from '@fastify/cookie';
import formBody from '@fastify/formbody';
import { FASTIFY_URL, NODE_ENV, PROXIES, REACT_FRONTEND_URL } from './env';
import baseRoute from './routes';
import { HttpException } from './error/HttpException';

export default async function createApp() {
  const app = Fastify({
    logger: true,
    trustProxy: NODE_ENV === 'production' && PROXIES ? PROXIES : false,
  });

  app.setErrorHandler((error, req, reply) => {
    const { message, statusCode } = new HttpException(error);
    if (NODE_ENV === 'development' && ![401, 403, 404].includes(statusCode)) console.error(error);
    if (NODE_ENV === 'production' && [401, 403].includes(statusCode)) {
      reply.status(404).send({ error: 'Not Found', statusCode: 404 });
      return;
    }
    reply.status(statusCode).send({ error: message, statusCode });
  });

  await app.register(cors, {
    origin: [FASTIFY_URL, REACT_FRONTEND_URL],
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
    xXssProtection: true,
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

  await app.register(baseRoute, { prefix: new URL(FASTIFY_URL).pathname });

  return app;
}
