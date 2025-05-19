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
- 📢 Supports B2B authentication and OBO (On-Behalf-Of) flow.

## Architecture 🏗️

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/oauth-entra-id-flow.png)

## Configuration ⚙️

```typescript
interface OAuthConfig {
  // Microsoft Entra ID configuration
  azure: {
    // Microsoft Entra ID client ID
    clientId: string;
    // Azure tenant ID or `'common'` for multi-tenant support
    tenantId: 'common' | string;
    // OAuth 2.0 scopes to request during authentication e.g., ["openid", "profile", "email"]
    scopes: string[];
    // Client secret associated with the Azure app registration
    clientSecret: string;
  };
  // Allowed frontend redirect URL(s)
  frontendUrl: string | string[];
  // The server-side callback URL (must match the one registered in Azure)
  serverCallbackUrl: string;
  // 32-byte encryption key used to encrypt/decrypt tokens
  secretKey: string;
  // Optional configuration for advanced features
  advanced?: {
    // Controls login UI behavior. Defaults to `'sso'`
    loginPrompt?: 'email' | 'select-account' | 'sso';
    // Session persistence method. Defaults to `'cookie-session'`
    sessionType?: 'cookie-session' | 'bearer-token';
    // Whether to accept tokens issued by other systems
    acceptB2BRequests?: boolean;
    // List of external B2B services to acquire tokens for
    b2bTargetedApps?: {
      // Unique identifier of the B2B app
      appName: string;
      // OAuth 2.0 scope to request for the app. Usually end with `/.default` to request all permissions
      scope: string;
    }[];
    // Enables verbose debug logging
    debug?: boolean;
    // Cookie behavior and expiration settings
    cookies?: {
      // Unit used for cookie expiration times. Defaults to `'sec'`
      timeUnit?: 'ms' | 'sec';
      // If true, disables HTTPS enforcement on cookies. Defaults to `false`
      disableHttps?: boolean;
      // If true, disables SameSite enforcement on cookies. Defaults to `false`
      disableSameSite?: boolean;
      // Max-age for access token cookies. Defaults to 1 hour
      accessTokenExpiry?: number;
      // Max-age for refresh token cookies. Defaults to 1 month
      refreshTokenExpiry?: number;
    };
    // Configuration for acquiring downstream tokens via the OBO flow
    downstreamServices?: {
      // Whether HTTPS is enforced
      areHttps: boolean;
      // Whether to enforce SameSite on OBO cookies
      areSameOrigin: boolean;
      // List of trusted services requiring On-Behalf-Of delegation
      services: {
        // Unique identifier of the downstream service
        serviceName: string;
        // OAuth 2.0 scope to request for the service. Usually end with `/.default` to request all permissions
        scope: string;
        // Encryption key used to encrypt tokens for this service
        secretKey: string;
        // Whether HTTPS is required when setting cookies for this service
        isHttps?: boolean;
        // Whether `SameSite` cookies should be enforced for this service
        isSameOrigin?: boolean;
        // Expiration for access token cookies (default from global if not set)
        accessTokenExpiry?: number;
        // Expiration for refresh token cookies (default from global if not set)
        refreshTokenExpiry?: number;
      }[];
    };
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

Example of creating a basic instance of `OAuthProvider`:

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

Generates a Microsoft authentication URL for the user to log in.

- receives an optional object with the following properties:
  - `loginPrompt` (optional) - Login prompt type, to override the default value.
  - `email` (optional) - If email is provided, the login prompt will be set to `email` and the email will be pre-filled in the login form.
  - `frontendUrl` (optional) - The frontend URL to redirect the user after authentication.
- returns an object with the following property:
  - `authUrl` - The URL to redirect the user for authentication.

Authenticate HonoJS example:

```typescript
app.post('/authenticate', async (c) => {
  const { loginPrompt, email, frontendUrl } = await c.req.json();
  const { authUrl } = await oauthProvider.getAuthUrl({ loginPrompt, email, frontendUrl });
  return c.json({ url: authUrl });
});
```

#### `getTokenByCode()`

Exchanges the authorization code for access and refresh tokens.

- receives a required object with the following properties:
  - `code` - The authorization code received from Microsoft.
  - `state` - The state parameter received from Microsoft.
- returns an object with the following properties:
  - `accessToken` - Access token object containing the token value, suggested name, and options.
  - `refreshToken` (optional) - Refresh token object containing the token value, suggested name, and options.
  - `frontendUrl` - The frontend URL to redirect the user after authentication.
  - `msalResponse` - The MSAL response object for extra information if needed.

Callback HonoJS example:

```typescript
app.post('/callback', async (c) => {
  const { code, state } = await c.req.parseBody();
  const { frontendUrl, accessToken, refreshToken } = await oauthProvider.getTokenByCode({ code, state });
  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(frontendUrl);
});
```

#### `getLogoutUrl()`

Generates a logout URL for the user to log out from Microsoft.

- receives an optional object with the following properties:
  - `frontendUrl` (optional) - The frontend URL to redirect the user after logout.
- returns an object with the following properties:
  - `logoutUrl` - The URL to redirect the user for logout.
  - `deleteAccessToken` - Access token cookie object containing the token name, value, and options.
  - `deleteRefreshToken` - Refresh token cookie object containing the token name, value, and options.

Logout HonoJS example:

```typescript
app.post('/logout', async (c) => {
  const { frontendUrl } = await c.req.json();
  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = oauthProvider.getLogoutUrl({ frontendUrl });
  deleteCookie(c, deleteAccessToken.name, deleteAccessToken.options);
  deleteCookie(c, deleteRefreshToken.name, deleteRefreshToken.options);
  return c.json({ url: logoutUrl });
});
```

#### `getCookieNames()`

Returns the names of the access and refresh token cookies. This is useful for deleting the cookies on logout.

- returns an object with the following properties:
  - `accessTokenName` - The name of the access token cookie.
  - `refreshTokenName` - The name of the refresh token cookie.

#### `verifyAccessToken()`

Verifies the access token received from Microsoft either encrypted or unencrypted.

- receives a `accessToken` string either encrypted or in JWT format.
- returns an object if the token is valid or `null` if invalid. The object contains the following properties:
  - `jwtAccessToken` - The access token in JWT format.
  - `payload` - The payload of the access token.
  - `injectedData` - If the token has been injected with extra data, it will be returned here.
  - `isB2B` - If the token is a B2B token, it will be `true`, otherwise `false`.

#### `injectData()`

Injects extra data into the access token. This is useful for embedding non-sensitive metadata into the token.

- receives an object with the following properties:
  - `accessToken` - The access token string either encrypted or in JWT format.
  - `data` - The data to inject into the token. This can be any object.
- returns an object of access token with suggested name and cookie options if valid, otherwise `null`.

#### `getTokenByRefresh()`

Verifies and uses the refresh token to get new set of access and refresh tokens.

- receives a `refreshToken` string.
- returns an object with the following properties:
  - `jwtAccessToken` - The access token in JWT format.
  - `payload` - The payload of the access token.
  - `newAccessToken` - New access token object containing the token value, suggested name, and options.
  - `newRefreshToken` (optional) - New refresh token object containing the token value, suggested name, and options.
  - `msalResponse` - The MSAL response object for extra information if needed.

Protect Middleware HonoJS example:
(implements getCookieNames, verifyAccessToken, injectData and getTokenByRefresh)

```typescript
export const protectRoute = createMiddleware(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.getCookieNames();
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const tokenInfo = await oauthProvider.verifyAccessToken(accessToken);
  if (tokenInfo) {
    const injectedData = tokenInfo.injectedData ? tokenInfo.injectedData : { randomNumber: getRandomNumber() };

    if (!tokenInfo.injectedData) {
      const newAccessToken = oauthProvider.injectData({ accessToken: tokenInfo.jwtAccessToken, data: injectedData });
      if (!newAccessToken) {
        c.set('userInfo', {
          uniqueId: tokenInfo.payload.oid,
          email: tokenInfo.payload.preferred_username,
          name: tokenInfo.payload.name,
        });
        return await next();
      }
      setCookie(c, newAccessToken.name, newAccessToken.value, newAccessToken.options);
    }

    c.set('userInfo', {
      uniqueId: tokenInfo.payload.oid,
      email: tokenInfo.payload.preferred_username,
      name: tokenInfo.payload.name,
      injectedData,
    });
    return await next();
  }

  const newTokensInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (!newTokensInfo) throw new HTTPException(401, { message: 'Unauthorized' });

  const { jwtAccessToken, payload, newAccessToken, newRefreshToken } = newTokensInfo;

  const injectedData = { randomNumber: getRandomNumber() };
  const newerAccessToken = oauthProvider.injectData({ accessToken: jwtAccessToken, data: injectedData });

  const finalAccessToken = newerAccessToken ?? newAccessToken;

  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newRefreshToken) setCookie(c, newRefreshToken.name, newRefreshToken.value, newRefreshToken.options);
  c.set('userInfo', {
    uniqueId: tokenInfo.payload.oid,
    email: tokenInfo.payload.preferred_username,
    name: tokenInfo.payload.name,
    injectedData: newerAccessToken ? injectedData : undefined,
  });

  return await next();
});
```

#### `getB2BToken()`

Generates a B2B token for a specific app.
Note: This method is only available if `b2bTargetedApps` is configured in the `advanced` section of the `OAuthConfig`.

- receives an object with the following properties:
  - `appName` or `appsNames` - The name of the B2B app to generate the token for.
- returns an object or an array of objects with the following properties:
  - `appName` - The name of the B2B app.
  - `appClientId` - The client ID of the B2B app.
  - `accessToken` - The B2B access token string.
  - `msalResponse` - The MSAL response object for extra information if needed.

B2B HonoJS example:

```typescript
protectedRouter.post('/get-b2b-info', async (c) => {
  const { appName } = await c.req.json();
  const { accessToken } = await oauthProvider.getB2BToken({ appName });
  const axiosResponse = await axios.get(env.OTHER_SERVER, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const { data, error } = zSchema.safeParse(axiosResponse.data);
  if (error) throw new HTTPException(500, { message: 'Invalid response from the other server' });
  return c.json(data);
});
```

#### `getTokenOnBehalfOf()`

Acquires tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.

- receives an object with the following properties:
  - `accessToken` - access token string either encrypted or in JWT format.
  - `serviceName` or `serviceNames` - The name of the downstream service or an array of service names to acquire tokens for.
- returns an object or an array of objects with the following properties:
  - `serviceName` - The name of the OBO service.
  - `serviceClientId` - The client ID of the OBO service.
  - `accessToken` - The OBO access token string.
  - `msalResponse` - The MSAL response object for extra information if needed.

On Behalf Of HonoJS example:

```typescript
app.post('/on-behalf-of', protectRoute, async (c) => {
  const { serviceNames } = await c.req.json();
  const accessToken = c.get('userInfo').accessToken;
  const results = await oauthProvider.getOnBehalfOfToken({ accessToken, serviceNames });

  for (const { accessToken } of results) {
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  }

  return c.json({ message: 'On Behalf Of tokens generated successfully' });
});
```

#### `settings`

You can access the settings of the `OAuthProvider` instance using the `settings` property. This is useful for debugging and logging purposes.

```typescript
interface OAuthSettings {
  sessionType: 'cookie-session' | 'bearer-token';
  loginPrompt: 'email' | 'select-account' | 'sso';
  acceptB2BRequests: boolean;
  isHttps: boolean;
  isSameSite: boolean;
  cookiesTimeUnit: 'ms' | 'sec';
  b2bApps?: string[];
  downstreamServices?: string[];
  accessTokenCookieExpiry: number;
  refreshTokenCookieExpiry: number;
  debug: boolean;
}
```

## Usage - Express 📫

When using the package with Express, you should import from `oauth-entra-id/express` to easily integrate OAuth2.0.

Note: you can use the core package with Express, but you will need to implement your own logic for handling authentication, token exchange, and other OAuth-related operations.

Also the oauthProvider instance is injected in the request object, so you can access it using `req.oauthProvider`.

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

To secure your routes, you can use the `protectRoute()` middleware and access the user information from the request object.

```typescript
import express from 'express';
import type { Router, Request, Response } from 'express';
import { protectRoute } from 'oauth-entra-id/express';

const protectedRouter: Router = express.Router();

protectedRouter.get('/user-info', protectRoute(), (req: Request, res: Response) => {
  res.status(200).json({ message: 'Protected route :)', user: req.userInfo });
});
```

## Usage - NestJS 🪺

When using the package with NestJS, you should import from `oauth-entra-id/nestjs` to easily integrate OAuth2.0.

Note: you can use the core package with NestJS, but you will need to implement your own logic for handling authentication, token exchange, and other OAuth-related operations.

Also the oauthProvider instance is injected in the request object, so you can access it using `req.oauthProvider`.

Start at the root of your NestJS app, import `authConfig` and configure it:

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
- **Express and NestJS Exports**: The package exports handleX functions for Express and NestJS. They work on a cookie-based session only. If you want to use bearer tokens, you need to implement your own logic using the core package.
- **TSConfig**: Make sure you set the `module` is not `commonjs` in your `tsconfig.json`. Our recommendation is to set `module` to `node16` and `target` to `es6`.
- **NestJS**: The package uses the `express` instance of NestJS, so make sure to use the `express` instance for the package to work, or use the core utilities.
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
