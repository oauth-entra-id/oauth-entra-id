# 💯 OAuth Entra ID 💯

## Overview 🪟

`oauth-entra-id` is a framework-agnostic package that provides a secure and simple way to implement OAuth 2.0 authentication and authorization with Microsoft Entra ID (formerly Azure AD). It abstracts away the complexity of OAuth 2.0, allowing developers to focus on building their applications without worrying about the underlying authentication and authorization mechanisms.

## Installation 🚀

```bash
npm install oauth-entra-id
```

## Features 📦


- 🔐 Secure backend-driven OAuth 2.0 Authorization Code Grant flow with PKCE (Proof Key for Code Exchange).
- 🍪 Cookie-based authentication.
- 🔄️ Access token and refresh token management (including token rotation).
- ✅ Built-in validation for Microsoft-issued JWTs using Entra ID public keys.
- 📢 Supports On-Behalf-Of (OBO) flow.

## Architecture 🏗️

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/oauth-entra-id-flow.png)

## Configuration ⚙️

- `azure` - Azure parameters:
  - `clientId` - The client ID of your Azure application.
  - `tenantId` - `common` for multi-tenant applications or your tenant ID for single-tenant applications.
  - `scopes` - The scopes you want to request from Microsoft Entra ID. For example: `["openid", "profile", "offline_access"]`.
  - `clientSecret` - The client secret of your Azure application.
- `frontendUrl` - The frontend URL(s) of the application for redirection. It can be a single URL or an array of URLs.
- `serverCallbackUrl` - The URL of your server's callback endpoint. This should match the redirect URI you set in Azure. For example: `http://localhost:3000/auth/callback`.
- `secretKey` - A 32-character long secret key for encryption. This key is used to encrypt the cookies and should be kept secret.
- `advanced` - Advanced configuration options:
  - `loginPrompt` - The login prompt type. It can be `"email" | "select-account" | "sso"` (default: `"sso"`).
  - `allowOtherSystems` - Allow authentication for other systems (via Authorization header). Default: `false`.
  - `debug` - Enable debug logs. Default: `false`.
  - `cookies` - Cookie configuration options:
    - `timeUnit` - The time unit for the cookie expiry. It can be `"ms" | "sec"` (default: `"sec"`).
    - `disableHttps` - Disable Secure cookie enforcement. Default: `false`.
    - `disableSameSite` - Disable SameSite cookie attribute. Default: `false`.
    - `accessTokenExpiry` - The expiry time for the access token cookie in seconds (default: 1 hour).
    - `refreshTokenExpiry` - The expiry time for the refresh token cookie in seconds (default: 1 month).
  - `onBehalfOfServices` - An array of configurations for On-Behalf-Of services:
    - `serviceName` - Unique name for the service.
    - `scope` - The scope for the service. For example: `api://some-service/.default`.
    - `secretKey` - The secret key to encrypt the tokens for the service.
    - `isHttps` - Whether the service uses HTTPS or not.
    - `isSameSite` - Whether to use SameSite cookie attribute or not.
    - `accessTokenExpiry` - The expiry time for the access token in seconds (default: 1 hour).
    - `refreshTokenExpiry` - The expiry time for the refresh token in seconds (default: 1 month).

```typescript
export interface OAuthConfig {
  azure: {
    clientId: string;
    tenantId: string;
    scopes: string[];
    clientSecret: string;
  };
  frontendUrl: string | string[];
  serverCallbackUrl: string;
  secretKey: string;
  advanced?: {
    loginPrompt?: "email" | "select-account" | "sso"; // default: "sso"
    allowOtherSystems?: boolean; //default: false
    debug?: boolean;
    cookies?:{
      timeUnit?: "ms" | "sec"; // default: "sec"
      disableHttps?: boolean; //default: false
      disableSameSite?: boolean; //default: false
      accessTokenExpiry?: number; //default: 1 hour
      refreshTokenExpiry?: number; //default: 1 month
    }
    onBehalfOfServices?: {
      serviceName: string;
      scope: string;
      secretKey: string;
      isHttps: boolean;
      isSameSite: boolean;
      accessTokenExpiry?: number; //default: 1 hour
      refreshTokenExpiry?: number; //default: 1 month
    }[];
  };
}
```

## Usage 🎯

The package provides three main modules for different frameworks:
- `oauth-entra-id` - Core package for any TS/JS framework (e.g., Express, NestJS, HonoJS, Fastify, etc.). jump to **[Core](#usage---core-)**.
- `oauth-entra-id/express` - For Express.js applications (recommended). Jump to **[Express](#usage---express-)**.
- `oauth-entra-id/nestjs` - For NestJS applications (recommended). Jump to **[NestJS](#usage---nestjs-)**.

## Usage - Core 🧱

The core package provides the flexibility to integrate OAuth 2.0 with Entra ID in any Node.js framework.

Let's start by creating a global instance of `OAuthProvider` in your application. This instance will be used to handle authentication, token exchange, and other OAuth-related operations.

```typescript
import { OAuthProvider } from 'oauth-entra-id';
import env from './env';

const oauthProvider = new OAuthProvider({
  azure: {
    clientId: env.AZURE_CLIENT_ID,
    tenantId: env.AZURE_TENANT_ID,
    scopes: [env.AZURE_CLIENT_SCOPE],
    clientSecret: env.AZURE_CLIENT_SECRET,
  },
  frontendUrl: env.FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  secretKey: env.SECRET,
});
```

### Core Methods:

#### `getAuthUrl()`
Generates a Microsoft authentication URL for the user to log in. It accepts an optional `params` object with the following properties:
- `loginPrompt` (optional) - Login prompt type, to override the default value.
- `email` (optional) - If email is provided, the login prompt will be set to `email` and the email will be pre-filled in the login form.
- `frontendUrl` (optional) - The frontend URL to redirect the user after authentication.

Authenticate HonoJS example:
```typescript
app.post('/authenticate', async (c) => {
  const { loginPrompt, email, frontendUrl } = await c.req.json();
  const { authUrl } = await oauthProvider.getAuthUrl({ loginPrompt, email, frontendUrl });
  return c.json({ url:authUrl });
});
```

#### `getTokenByCode()`
Exchanges the authorization code for access and refresh tokens. It accepts an object with the following properties:
- `code` - The authorization code received from Microsoft.
- `state` - The state parameter received from Microsoft.

Callback HonoJS example:
```typescript
app.post('/callback', async (c) => {
  const { code, state } = await c.req.parseBody();
  const { frontendUrl, accessToken, refreshToken } = await oauthProvider.getTokenByCode({ code, state });
  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) {
    setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  }
  return c.redirect(frontendUrl);
})
```

#### `getLogoutUrl()`
Generates a logout URL for the user to log out from Microsoft. It accepts an optional `params` object with the following properties:
- `frontendUrl` (optional) - The frontend URL to redirect the user after logout.

Logout HonoJS example:
```typescript
app.post('/logout', async (c) => {
  const { frontendUrl } = await c.req.json();
  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = oauthProvider.getLogoutUrl({ frontendUrl });
  deleteCookie(c, deleteAccessToken.name, deleteAccessToken.options);
  deleteCookie(c, deleteRefreshToken.name, deleteRefreshToken.options);
  return c.json({ url:logoutUrl });
});
```

#### `getCookieNames()`
Returns the names of the access and refresh token cookies. This is useful for deleting the cookies on logout.

#### `verifyAccessToken()`
Verifies the access token received from Microsoft either encrypted or unencrypted. It accepts an `accessToken` string and returns the decoded token payload if valid.

#### `getTokenByRefresh()`
Verifies and uses the refresh token to get new set of access and refresh tokens. It accepts an `refreshToken` string and returns a set of new tokens.

Protect Middleware HonoJS example:
```typescript
export const protectRoute = createMiddleware(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);

  if (!accessToken && !refreshToken) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  if (accessToken) {
    const microsoftInfo = await oauthProvider.verifyAccessToken(accessToken);
    if (microsoftInfo) {
      c.set('userInfo', {
        accessToken: msal.microsoftToken,
        uniqueId: microsoftInfo.payload.oid,
        roles: microsoftInfo.payload.roles,
        name: microsoftInfo.payload.name,
        email: microsoftInfo.payload.preferred_username,
      });

      await next();
      return;
    }
  }

  if (!refreshToken) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const newTokens = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokens) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }

  const { newAccessToken, newRefreshToken, msal } = newTokens;
  setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
  if (newRefreshToken) {
    setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  }
  c.set('userInfo', {
    accessToken: msal.microsoftToken,
    uniqueId: msal.payload.oid,
    roles: msal.payload.roles,
    name: msal.payload.name,
    email: msal.payload.preferred_username,
  });

  await next();
});
```

#### `getOnBehalfOfToken()`
Generates an On Behalf Of (OBO) tokens for a specific services. It accepts an object with the following properties:
- `accessToken` - The access token received from Microsoft.
- `serviceNames` - an array of service names that were configured in the `onBehalfOfServices` array in the `advanced` configuration.

On Behalf Of HonoJS example:
```typescript
app.post('/on-behalf-of', protectRoute, async (c) => {
  const { serviceNames } = await c.req.json();
  const accessToken = c.get('userInfo').accessToken;
  const results = await oauthProvider.getOnBehalfOfToken({ accessToken, serviceNames });

  for (const result of results) {
    const { accessToken, refreshToken } = result;
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) {
      setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
    }
  }

  return c.json({ message: 'On Behalf Of tokens generated successfully' });
});
```

## Usage - Express 📫

When using the package with Express, you should import from `oauth-entra-id/express` to easily integrate OAuth2.0.

Also, you need to install `cors` package:

```bash
npm install cors

# For TypeScript
npm install --save-dev @types/cors
```

Then in the root of your Express app, import `authConfig` and configure it:

```typescript
import express from 'express';
import cors from 'cors';
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
      credentials: true, // <-- Allow credentials to be included in CORS requests
    }),
  );
  // Other configurations...

  app.use(
    authConfig({
      azure: {
        clientId: env.AZURE_CLIENT_ID,
        tenantId: env.AZURE_TENANT_ID,
        scopes: [env.AZURE_CLIENT_SCOPE],
        clientSecret: env.AZURE_CLIENT_SECRET,
      },
      frontendUrl: env.FRONTEND_URL,
      serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET,
    }),
  );

  // Here you can add your routes and other configurations

  const port = Number(env.PORT) || 3000;
  app.listen(port, () => {
    console.log(`🚀 Express server running at http://localhost:${port}`);
  });
}

bootstrap();
```

Now you can define your routes for `login`, `callback`, and `logout` using POST methods for security.

```typescript
import express, { type Router } from 'express';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/express';

export const authRouter: Router = express.Router();

authRouter.post('/authenticate', handleAuthentication); // Returns {url: authUrl}
authRouter.post('/callback', handleCallback); // Set tokens in cookies and redirect to frontendUrl
authRouter.post('/logout', handleLogout); // Delete cookies and returns {url: logoutUrl}
```

To secure your routes, you can use the `protectRoute` middleware and access the user information from the request object.

```typescript
import express from 'express';
import type { Router, Request, Response } from 'express';
import { protectRoute } from 'oauth-entra-id/express';

const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', protectRoute, (req: Request, res: Response) => {
  res.status(200).json({ message: 'Protected route :)', user: req.userInfo });
});
```

## Usage - NestJS 🪺
When using the package with NestJS, you should import from `oauth-entra-id/nestjs` to easily integrate OAuth2.0.

Then in the root of your NestJS app, import `authConfig` and configure it:

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
    credentials: true, // <-- Allow credentials to be included in CORS requests
  });
  // Other configurations...

  app.use(
    authConfig({
      azure: {
        clientId: env.AZURE_CLIENT_ID,
        tenantId: env.AZURE_TENANT_ID,
        scopes: [env.AZURE_CLIENT_SCOPE],
        clientSecret: env.AZURE_CLIENT_SECRET,
      },
      frontendUrl: env.FRONTEND_URL,
      serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
      secretKey: env.SECRET,
    }),
  );

  // Other configurations...
  const port = Number(env.PORT) || 3000;
  await app.listen(port);
  console.log(`🚀 NestJS server running on: http://localhost:${port}`);
}

bootstrap();
```

Now you can define your routes for `login`, `callback`, and `logout` using POST methods for security.

```typescript
import type { Request, Response } from 'express';
import { Controller, Req, Res, Post } from '@nestjs/common';
import { handleAuthentication, handleCallback, handleLogout } from 'oauth-entra-id/nestjs';

@Controller('auth')
export class AuthController {
  @Post('authenticate')
  async authenticate(@Req() req: Request, @Res() res: Response) {
    await handleAuthentication(req, res); // Returns {url: authUrl}
  }

  @Post('callback')
  async callback(@Req() req: Request, @Res() res: Response) {
    await handleCallback(req, res); // Set tokens in cookies and redirect to frontendUrl
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    handleLogout(req, res); // Delete cookies and returns {url: logoutUrl}
  }
}
```

Let's create the guard that will protect your routes while getting the user information.

```typescript
import type { Request, Response } from 'express';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { isAuthenticated } from 'oauth-entra-id/nestjs';

@Injectable()
export class ProtectRoute implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    return await isAuthenticated(req, res);
  }
}
```

Now you can use the `ProtectRoute` to protect your routes and get the user information.

```typescript
import type { Request } from 'express';
import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { ProtectRoute } from '../guards/protect-route.guard';

@Controller('protected')
@UseGuards(ProtectRoute)
export class ProtectedController {
  constructor() {}

  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { message: 'Protected route :)', user: req.userInfo };
  }
}
```

## Notes❗

- **CORS**: Make sure to set the `credentials` option to `true` in your CORS configuration. This allows cookies to be sent with cross-origin requests.
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
