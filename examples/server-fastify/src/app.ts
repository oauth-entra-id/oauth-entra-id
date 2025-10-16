import cookieParser from '@fastify/cookie';
import cors from '@fastify/cors';
import formBody from '@fastify/formbody';
import helmet, { type FastifyHelmetOptions } from '@fastify/helmet';
import rateLimiter from '@fastify/rate-limit';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { env } from './env';
import { HttpException } from './error/HttpException';
import { routesRouter } from './routes';

export default async function createApp() {
  const app = Fastify({ logger: true }).withTypeProvider<TypeBoxTypeProvider>();

  await app.register(cors, {
    origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  await app.register(helmet, helmetConfig);
  await app.register(rateLimiter, rateLimitConfig);

  app.addHook('preParsing', async (req, _reply, payload) => {
    const contentType = req.headers['content-type'];
    if ((!contentType || contentType.includes('application/json')) && !req.body) {
      req.body = {};
    }
    return payload;
  });

  await app.register(formBody);
  await app.register(cookieParser);

  await app.register(routesRouter, { prefix: new URL(env.SERVER_URL).pathname });

  app.setNotFoundHandler((req: FastifyRequest, reply: FastifyReply) => {
    reply.status(404).send({ error: 'Not Found', statusCode: 404 });
  });

  app.setErrorHandler((error: unknown, req: FastifyRequest, reply: FastifyReply) => {
    const { message, statusCode, description } = new HttpException(error);
    reply.status(statusCode).send({ error: message, statusCode, description });
  });

  return app;
}

const helmetConfig: FastifyHelmetOptions = {
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

const rateLimitConfig = {
  max: 100,
  timeWindow: 60 * 1000,
  allowList: ['127.0.0.6'],
  errorResponseBuilder: (req: FastifyRequest, context: unknown) => {
    return {
      error: 'Too many requests from this IP, please try again after a break',
      statusCode: 429,
    };
  },
};
