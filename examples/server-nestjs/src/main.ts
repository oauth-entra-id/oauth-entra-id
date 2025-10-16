import { ValidationPipe } from '@nestjs/common';
import { HttpAdapterHost, NestFactory, Reflector } from '@nestjs/core';
import helmet, { type HelmetOptions } from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/nestjs';
import { AppModule } from './app.module';
import { env } from './env';
import { ErrorCatcher } from './error/error-catcher.filter';
import { ProtectRoute } from './guards/protect-route.guard';
import { oauthConfig } from './oauth';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  app.use(helmet(helmetConfig));
  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));
  app.use(authConfig(oauthConfig));

  app.setGlobalPrefix(new URL(env.SERVER_URL).pathname);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: false, transform: true }));

  const reflector = app.get(Reflector);
  app.useGlobalGuards(new ProtectRoute(reflector));

  const httpAdapter = app.get(HttpAdapterHost);
  app.useGlobalFilters(new ErrorCatcher(httpAdapter));

  await app.listen(env.SERVER_PORT);

  console.log(
    '============= 🪺  NestJS Server 🪺  =============\n',
    `🚀 Server runs on: ${env.SERVER_URL}\n`,
    `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
    '==============================================',
  );
}

bootstrap();

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
