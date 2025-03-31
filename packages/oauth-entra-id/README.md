# 🎯 OAuth Entra ID 🎯

## Overview 🪟

This package simplifies integrating OAuth 2.0 with Microsoft Entra ID in Node.js applications. It provides secure utilities to implement the OAuth 2.0 Authorization Code Grant flow with PKCE, abstracting away authentication complexities. Designed to work with every Node.js framework, the package offers ready-to-use functions for secure user authentication and access control.

## Installation 🚀

```bash
npm install oauth-entra-id
```

## Implementation 🛠️

There are demos for each framework in the `apps` directory.

### _Express_ 📫

For Express, import from `oauth-entra-id/express` to integrate OAuth2.0 easily and securely.

1. Install `cookie-parser` and `cors` packages:

```bash
npm install cookie-parser cors

# For TypeScript
npm install --save-dev @types/cookie-parser @types/cors
```

2. Import `authConfig` and configure it in the root of your Express app:

- `azure` - Azure parameters: `clientId`, `tenantId`, `clientScopes`, and `clientSecret`.
- `frontendUrl` - The frontend URL of the application for redirection.
- `serverFullCallbackUrl` - matching the redirect URI in Azure, for example: `http://localhost:3000/auth/callback`.
- `secretKey` - 32 characters long secret key for encryption.
- `loginPrompt` (optional, default: sso) - can be `"email" | "select-account" | "sso"`.
- `debug` (optional, default: false) - to enable debug logs.
- `allowOtherSystems` (optional, default: false) - allow authentication for other systems (via Authorization header).

```typescript
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { authConfig } from 'oauth-entra-id/express';
import env from './env';

function bootstrap() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(
    cors({
      origin: env.FRONTEND_URL,
      methods: 'GET,POST,PUT,DELETE,OPTIONS',
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    }),
  );
  // Other configurations...
  app.use(cookieParser());

  app.use(
    authConfig({
      azure: {
        clientId: env.AZURE_CLIENT_ID,
        tenantId: env.AZURE_TENANT_ID,
        clientScopes: env.AZURE_CLIENT_SCOPES,
        clientSecret: env.AZURE_CLIENT_SECRET,
      },
      frontendUrl: env.FRONTEND_URL,
      serverFullCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET,
      loginPrompt: 'select-account', // Optional - default: "sso", can be "email" | "select-account" | "sso"
      debug: false, // Optional
      allowOtherSystems: false, // Optional
    }),
  );

  // Other configurations...
  const port = Number(env.PORT) || 3000;
  app.listen(port, () => {
    console.log(`🚀 Express server running at http://localhost:${port}`);
  });
}

bootstrap();
```

3. Define routes for `login`, `callback`, and `logout` using POST methods for security.

```typescript
import express, { type Router } from 'express';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/express';

export const authRouter: Router = express.Router();

// Generates the authentication URL
authRouter.post('/authenticate', handleAuthentication);

// Exchanges the code from Microsoft for tokens
authRouter.post('/callback', handleCallback);

// Clears cookies and sends back a URL to let the user logout from Microsoft
authRouter.post('/logout', handleLogout);
```

4. Secure routes with `requireAuthentication` and use the user information:

```typescript
import express from 'express';
import type { Router, Request, Response } from 'express';
import { requireAuthentication } from 'oauth-entra-id/express';

const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', requireAuthentication, (req: Request, res: Response) => {
  res.status(200).json({ message: 'You view a protected route :)', user: req.userInfo });
});
```

- **NOTE**: Make sure you have `errorCatcher` middleware for your application to catch errors, since the package will throw `OAuthError` within the `next` function in case of any error.

### _NestJS_ 🪺

1. Install `cookie-parser` package:

```bash
npm install cookie-parser

# For TypeScript
npm install --save-dev @types/cookie-parser
```

2. Import `authConfig` in NestJS, the parameters are similar parameters as [Express](#express-)

```typescript
import { NestFactory } from '@nestjs/core';
import { authConfig } from 'oauth-entra-id/nestjs';
import { AppModule } from './app.module';
import env from './env';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: env.FRONTEND_URL,
    methods: 'GET,POST,PUT,DELETE,OPTIONS',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });
  // Other configurations...
  app.use(cookieParser());

  app.use(
    authConfig({
      azure: {
        clientId: env.AZURE_CLIENT_ID,
        tenantId: env.AZURE_TENANT_ID,
        clientScopes: env.AZURE_CLIENT_SCOPES,
        clientSecret: env.AZURE_CLIENT_SECRET,
      },
      frontendUrl: env.FRONTEND_URL,
      serverFullCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET,
      loginPrompt: 'select-account', // Optional - default: "sso", can be "email" | "select-account" | "sso"
      debug: false, // Optional
      allowOtherSystems: false, // Optional
    }),
  );

  // Other configurations...
  const port = Number(env.PORT) || 3000;
  await app.listen(port);
  console.log(`🚀 NestJS server running on: http://localhost:${port}`);
}

bootstrap();
```

3. Set up a controller with routes for `login`, `callback`, and `logout`.

```typescript
import type { Request, Response } from 'express';
import { Controller, Req, Res, Post } from '@nestjs/common';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/nestjs';

@Controller('auth')
export class AuthController {
  // Generates the authentication URL
  @Post('authenticate')
  async generateAuthUrl(@Req() req: Request, @Res() res: Response) {
    await handleAuthentication(req, res);
  }

  // Exchanges the code from Microsoft for tokens
  @Post('callback')
  async exchangeCodeForToken(@Req() req: Request, @Res() res: Response) {
    await handleCallback(req, res);
  }

  // Clears cookies and sends back a URL to let the user logout from Microsoft
  @Post('logout')
  async generateLogoutUrl(@Req() req: Request, @Res() res: Response) {
    handleLogout(req, res);
  }
}
```

4. Create a guard to protect your routes and get the user information.

```typescript
import type { Request, Response } from 'express';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { isAuthenticated } from 'oauth-entra-id/nestjs';

@Injectable()
export class RequireAuthentication implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    return await isAuthenticated(req, res);
  }
}
```

5. Now you can use the `RequireAuthentication` to protect your routes and get the user information.

```typescript
import type { Request } from 'express';
import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { RequireAuthentication } from '~/guards/protect-route.guard';

@Controller('protected')
@UseGuards(RequireAuthentication)
export class ProtectedController {
  constructor() {}

  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { message: 'You view a protected route :)', user: req.userInfo };
  }
}
```

- **NOTE**: Make sure you have `errorFilter` that will catch `OAuthError`.

### _Core_ 🔧

The core utilities provide you the flexibility to integrate OAuth 2.0 with Entra ID in any Node.js framework.

Here is how to use the core package in your application (the following example uses HonoJS):

1. Create a global instance of OAuthProvider

```typescript
import { OAuthProvider } from 'oauth-entra-id';
import env from './env';

const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.AZURE_CLIENT_ID,
    tenantId: env.AZURE_TENANT_ID,
    clientScopes: env.AZURE_CLIENT_SCOPES,
    clientSecret: env.AZURE_CLIENT_SECRET,
  },
  frontendUrl: env.FRONTEND_URL,
  serverFullCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.SECRET,
  cookieTimeFrame: 'sec', // Optional - default: "ms" can be "ms" | "sec"
  loginPrompt: 'select-account', // Optional - default: "sso", can be "email" | "select-account" | "sso"
  debug: false, // Optional
});
```

2. Create 3 routes for `login`, `callback`, and `logout`.

```typescript
import { Hono } from 'hono';
import { setCookie, deleteCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { oauthProvider } from './oauthProvider';

export const authRouter = new Hono();

authRouter.post('/authenticate', async (c) => {
  const { loginPrompt, email, frontendUrl } = await c.req.json();

  const { authUrl } = await oauthProvider.generateAuthUrl({ loginPrompt, email, frontendUrl });

  return c.json({ url: authUrl });
});

authRouter.post('/callback', async (c) => {
  if (!c.req.header('content-type')?.includes('application/x-www-form-urlencoded')) {
    throw new HTTPException(400, { message: 'Invalid content type' });
  }

  const { code, state } = await c.req.parseBody();

  const { frontendUrl, accessToken, refreshToken } = await oauthProvider.exchangeCodeForToken({ code, state });

  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(frontendUrl);
});

authRouter.post('/logout', async (c) => {
  const { frontendUrl } = await c.req.json();

  const { logoutUrl, accessToken, refreshToken } = oauthProvider.getLogoutUrl({ frontendUrl });

  deleteCookie(c, accessToken.name, accessToken.options);
  deleteCookie(c, refreshToken.name, refreshToken.options);
  return c.json({ url: logoutUrl });
});
```

3. Secure your routes using a middleware.

```typescript
import { createMiddleware } from 'hono/factory';
import { getCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { oauthProvider } from './oauthProvider';

type RequireAuthentication = {
  userInfo: {
    uniqueId: string;
    roles: string[];
    name: string;
    email: string;
  };
};

export const requireAuthentication = createMiddleware<{ Variables: RequireAuthentication }>(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);

  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  const microsoftInfo = await oauthProvider.verifyAccessToken(accessToken);
  if (microsoftInfo) {
    c.set('userInfo', {
      uniqueId: microsoftInfo.payload.oid,
      roles: microsoftInfo.payload.roles,
      name: microsoftInfo.payload.name,
      email: microsoftInfo.payload.preferred_username,
    });

    await next();
    return;
  }
  if (!refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });
  const newTokens = await oauthProvider.refreshAccessToken(refreshToken);
  if (!newTokens) throw new HTTPException(401, { message: 'Unauthorized' });
  const { newAccessToken, newRefreshToken, msal } = newTokens;
  setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  c.set('userInfo', {
    uniqueId: msal.payload.oid,
    roles: msal.payload.roles,
    name: msal.payload.name,
    email: msal.payload.preferred_username,
  });

  await next();
});
```

4. Use the middleware to protect your routes and access the user information.

```typescript
import { Hono } from 'hono';
import { protectRoute } from './protect-route';

export const protectedRouter = new Hono();

protectedRouter.get('/user-info', protectRoute, (c) => {
  return c.json({ message: 'You view a protected route :)', user: c.var.userInfo });
});
```

- **NOTE**: Make sure you have `errorFilter` that will catch `OAuthError`, an example is available in NestJS demo.

## Notes❗

- **TSConfig**: Make sure you set the `module` is not `commonjs` in your `tsconfig.json`. Our recommendation is to set `module` to `node16` and `target` to `es6`.
- **Frontend Cookies** - Make sure to include credentials with every request from the frontend to the backend.

```typescript
// Fetch API
fetch('http://localhost:3000/protected/user-info', {
  method: 'GET',
  credentials: 'include',
});

// Axios
const axiosInstance = axios.create({
  withCredentials: true,
});

axiosInstance.get('http://localhost:3000/protected/user-info');
```

- **NestJS**: The package uses the `express` instance of NestJS, so make sure to use the `express` instance for the package to work, or use the core utilities.
