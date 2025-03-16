import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { authConfig } from 'oauth-entra-id/nestjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import morgan from 'morgan';
import { NODE_ENV, NESTJS_PORT, NESTJS_PROXIES, NESTJS_URL, NESTJS_FRONTEND_URL, NESTJS_SECRET, AZURE } from './env';
import { AppModule } from './app.module';
import { ErrorCatcher } from './error/error-catcher.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  if (NODE_ENV === 'production' && NESTJS_PROXIES) {
    app.getHttpAdapter().getInstance().set('trust proxy', NESTJS_PROXIES);
  }

  app.enableCors({
    origin: [NESTJS_URL, NESTJS_FRONTEND_URL],
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });
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

  app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.setGlobalPrefix(new URL(NESTJS_URL).pathname);

  app.use(cookieParser());
  app.use(
    authConfig({
      azure: AZURE,
      frontendUrl: NESTJS_FRONTEND_URL,
      serverFullCallbackUrl: `${NESTJS_URL}/auth/callback`,
      secretKey: NESTJS_SECRET,
    }),
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: false,
      transform: true,
      validateCustomDecorators: true,
    }),
  );

  const httpAdapter = app.get(HttpAdapterHost);

  app.useGlobalFilters(new ErrorCatcher(httpAdapter));

  await app.listen(NESTJS_PORT);

  console.log(
    '============= 🪺  NestJS Server 🪺  =============\n',
    `🚀 Server runs on: ${NESTJS_URL}\n`,
    `👤 Client is set to: ${NESTJS_FRONTEND_URL}\n`,
    '==============================================',
  );
}

bootstrap();
