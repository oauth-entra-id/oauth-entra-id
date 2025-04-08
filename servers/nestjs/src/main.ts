import { ValidationPipe } from '@nestjs/common';
import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import morgan from 'morgan';
import { authConfig } from 'oauth-entra-id/nestjs';
import { AppModule } from './app.module';
import { env } from './env';
import { ErrorCatcher } from './error/error-catcher.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  if (env.NODE_ENV === 'production' && env.PROXIES) {
    app.getHttpAdapter().getInstance().set('trust proxy', env.PROXIES);
  }

  app.enableCors({
    origin: [env.SERVER_URL, env.REACT_FRONTEND_URL],
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

  app.use(morgan(env.NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.setGlobalPrefix(new URL(env.SERVER_URL).pathname);

  app.use(cookieParser());
  app.use(
    authConfig({
      azure: env.AZURE,
      frontendUrl: env.REACT_FRONTEND_URL,
      serverFullCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET_KEY,
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

  await app.listen(env.SERVER_PORT);

  console.log(
    '============= 🪺  NestJS Server 🪺  =============\n',
    `🚀 Server runs on: ${env.SERVER_URL}\n`,
    `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
    '==============================================',
  );
}

bootstrap();
