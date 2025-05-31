<p align="center">
  <img src="https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/banner.svg" align="center" alt="banner" />

  <h1 align="center" style="font-weight:800;">oauth-entra-id</h1>

  <p align="center">
    <span style="font-weight:800;">Simple</span> and <span style="font-weight:800;">Secure</span> Way <br/>
    to Implement <span style="font-weight:800;">OAuth 2.0</span> with <br/>
    <span style="font-weight:800;">Microsoft Entra ID</span>
  </p>
</p>

<br/>

<p align="center">
<a href="https://opensource.org/licenses/MIT" rel="nofollow"><img src="https://img.shields.io/github/license/oauth-entra-id/oauth-entra-id?color=DC343B" alt="License"></a>
<a href="https://www.npmjs.com/package/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/badge/version-2.0.0-0078D4" alt="Version"></a>
<a href="https://www.npmjs.com/package/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/npm/dm/oauth-entra-id.svg?color=03C03C" alt="npm"></a>
<a href="https://github.com/oauth-entra-id/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/github/stars/oauth-entra-id/oauth-entra-id" alt="stars"></a>

</p>

<br/>
<br/>

## About 📖

A lightweight, secure, and framework-agnostic wrapper for Microsoft Entra ID (Azure AD).
Built for simplicity, speed, and type safety. It abstracts away the complexity of OAuth 2.0, allowing developers to focus on building their applications without worrying about the underlying authentication and authorization mechanisms.

## Features 🌟

- 🔐 Secure backend-driven OAuth 2.0 Authorization Code Grant flow with PKCE.
- ⚡ Fast performance with minimal dependencies.
- 🍪 Built-in cookie-based authentication with token management and rotation.
- 📢 On-Behalf-Of (OBO) flow for downstream services
- 🤝 B2B app support (client credentials)
- 🧩 Fully typed results and errors via Result<T>
- 🦾 Framework-agnostic core (Express and NestJS bindings included)

## Getting Started 🚀

## Installation 🔥

```bash
npm install oauth-entra-id
```

## Azure Portal Setup 🛠️

Basic setup for Microsoft Entra ID (Azure AD):

1. Go to the [Azure Portal](https://portal.azure.com/).
2. Select your App registration or create a new one.
3. You can find the `Client ID` and `Tenant ID` in the app registration overview.
4. Under "Authentication", add a new platform:
   - Choose "Web" and set the redirect URI to your server callback URL (e.g., `https://your-server.com/auth/callback`).
5. Under "Certificates & secrets", create a new client secret and copy it. This will be your `clientSecret`.
6. To add scopes for your app you can either use one of the following methods:
   - Choose "API permissions" and add the required Microsoft Graph permissions (e.g., `openid`, `profile`, `email`).
   - Or, if you want you can create a custom scope for your app by going to "Expose an API" and defining a new scope (e.g., `api://<your-client-id>/access`).
7. Important step: go to "Manifest and edit the manifest file to set the `requestedAccessTokenVersion` to `2`. This is required for the package to work correctly with OAuth 2.0.
8. If you want to add roles you can do so by going to "App roles" and defining the roles you need. Make sure to assign these roles to users or groups in your Azure AD.

Setting up B2B app authentication:

1. Go to "App roles" and create a new app role for "Application" type.
2. Then go to "API permissions" add new permission and select the application that is allowed to authenticate to your app.
3. In the configuration of `OAuthConfig` of the first app, make sure to set the `acceptB2BRequests` property to `true`.
4. Then in the configuration of `OAuthConfig` of the second app, make sure to set the `b2bTargetedApps` property with the app name and scope of the first app, the scope should usually end with `/.default`.
5. That's it now the second app can authenticate to the first app using the client credentials flow.

Setting up On-Behalf-Of (OBO) flow for downstream services (works only if applications share the same tenant):

1. Go to "Expose an API" and create a new scope for your downstream service (e.g., `api://<your-client-id>/access`).
2. Then scroll down to "Authorized client applications" and add the client ID of the application that will be using the OBO flow.
3. In the configuration of `OAuthConfig` of the first app, make sure to set the `downstreamServices` property with the service name, scope, and `secretKey` of the downstream service, the scope should usually end with `/.default`.
4. That's it now the first app can acquire tokens for the downstream service using the OBO flow.

## Configuration ⚙️

```typescript
interface OAuthConfig {
  azure: {
    clientId: string;
    tenantId: 'common' | string; // 'common' for multi-tenant apps
    scopes: string[]; // e.g., ['openid', 'profile', 'email']
    clientSecret: string;
  };
  frontendUrl: string | string[]; // Allowed frontend redirect URL(s)
  serverCallbackUrl: string; // Server callback URL (must match the one registered in Azure)
  secretKey: string; // 32 character secret key
  advanced?: {
    loginPrompt?: 'email' | 'select-account' | 'sso'; //Defaults to `'sso'`
    sessionType?: 'cookie-session' | 'bearer-token'; // Defaults to `'cookie-session'`
    acceptB2BRequests?: boolean; // If true, allows B2B authentication. Defaults to `false`
    b2bTargetedApps?: Array<{
      appName: string; // Unique identifier of the B2B app
      scope: string; // Usually end with `/.default`
    }>;
    cookies?: {
      timeUnit?: 'ms' | 'sec'; // Defaults to `'sec'`
      disableHttps?: boolean;
      disableSameSite?: boolean;
      accessTokenExpiry?: number; // Defaults to 1 hour
      refreshTokenExpiry?: number; // Defaults to 30 days
    };
    downstreamServices?: {
      areHttps: boolean;
      areSameOrigin: boolean;
      services: Array<{
        serviceName: string; // Unique identifier of the downstream service
        scope: string; // Usually end with `/.default`
        secretKey: string; // 32 character secret key for the service
        isHttps?: boolean;
        isSameOrigin?: boolean;
        accessTokenExpiry?: number;
        refreshTokenExpiry?: number;
      }>;
    };
  };
}
```

### `Result<T>` Type 🧩

This package uses a custom `Result<T>` discriminated union to handle all async operations in a type-safe, exception-free way.

It provides a consistent pattern for returning both success and error states:

**Error Type:**

```typescript
type ResultErr = {
  type: ErrorTypes;
  message: string;
  description?: string;
  statusCode: HttpErrorCodes;
};
```

**Object Example:**

```typescript
type Result<{ x: string; y: number }> = { success: true; x: string; y: number } | { success: false; error: ResultErr };
```

**Primitive Example:**

```typescript
type Result<string> = { success: true; result: string } | { success: false; error: ResultErr };
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

### Core Methods (Examples with HonoJS) 🧩

#### `settings`

You can access the settings of the `OAuthProvider` instance using the `settings` property.

```typescript
interface OAuthSettings {
  readonly sessionType: 'cookie-session' | 'bearer-token';
  readonly loginPrompt: 'email' | 'select-account' | 'sso';
  readonly acceptB2BRequests: boolean;
  readonly b2bApps?: string[];
  readonly downstreamServices?: string[];
  readonly cookies: {
    readonly timeUnit: 'sec' | 'ms';
    readonly isSecure: boolean;
    readonly isSameSite: boolean;
    readonly accessTokenExpiry: number;
    readonly refreshTokenExpiry: number;
    readonly accessTokenName: string;
    readonly refreshTokenName: string;
  };
}
```

#### `getAuthUrl()`

Generate an OAuth2 authorization URL for user login (PKCE-backed).

Parameters:

- `params` (optional):
  - `loginPrompt` (optional) - Override the default prompt (`sso`|`email`|`select-account`).
  - `email` (optional) - Email address to pre-fill the login form.
  - `frontendUrl` (optional) - Frontend URL override to redirect the user after authentication.

Returns:

- Promise of a `Result` object:
  - `authUrl` - The URL to redirect the user for authentication.

```typescript
app.post('/authenticate', async (c) => {
  const { loginPrompt, email, frontendUrl } = await c.req.json();
  const { authUrl, error } = await oauthProvider.getAuthUrl({ loginPrompt, email, frontendUrl });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });
  return c.json({ url: authUrl });
});
```

#### `getTokenByCode()`

Exchange an authorization code for encrypted tokens and metadata

Parameters:

- `params`:
  - `code` - The authorization code received from the OAuth flow.
  - `state` - The state parameter received from Microsoft.

Returns:

- Promise of a `Result` object:
  - `accessToken` - Access token object containing the token value, suggested name, and options.
  - `refreshToken` (optional) - Refresh token object containing the token value, suggested name, and options.
  - `frontendUrl` - The frontend URL to redirect the user after authentication.
  - `msalResponse` - The MSAL response object for extra information if needed.

```typescript
app.post('/callback', async (c) => {
  const { code, state } = await c.req.parseBody();
  const { frontendUrl, accessToken, refreshToken, error } = await oauthProvider.getTokenByCode({ code, state });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });
  setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  if (refreshToken) setCookie(c, refreshToken.name, refreshToken.value, refreshToken.options);
  return c.redirect(frontendUrl);
});
```

#### `getLogoutUrl()`

Build a logout URL and cookie-deletion instructions.

Parameters:

- `params` (optional):
  - `frontendUrl` (optional) - Frontend URL override to redirect the user after log out.

Returns:

- A `Result` object:
  - `logoutUrl` - The URL to redirect the user for logout.
  - `deleteAccessToken` - Access token cookie object containing the token name, value, and options.
  - `deleteRefreshToken` - Refresh token cookie object containing the token name, value, and options.

```typescript
app.post('/logout', async (c) => {
  const { frontendUrl } = await c.req.json();
  const { logoutUrl, deleteAccessToken, deleteRefreshToken, error } = oauthProvider.getLogoutUrl({ frontendUrl });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });
  deleteCookie(c, deleteAccessToken.name, deleteAccessToken.options);
  deleteCookie(c, deleteRefreshToken.name, deleteRefreshToken.options);
  return c.json({ url: logoutUrl });
});
```

#### `verifyAccessToken<T>()`

Verify the access token (either encrypted or in JWT format) and extract its payload.
Make sure that user access tokens are encrypted and app tokens aren't.

Parameters:

- `accessToken` - The access token string either encrypted or in JWT format.

Returns:

- Promise of a `Result` object:
  - `payload` - The payload of the access token.
  - `rawAccessToken` - The access token in JWT format.
  - `injectedData` - If the token has been injected with extra data, it will be returned here with the type `T`.
  - `hasInjectedData` - If the token has injected data, this will be `true`. Otherwise, it will be `false`.
  - `isApp` - If the token is an app token, this will be `true`. Otherwise, it will be `false`.

`T` is a generic type if you want to specify the type of the injected data.
It will remain `undefined` if the token does not have injected data.

An example will be shown below.

#### `getTokenByRefresh()`

Verifies and uses the refresh token to get new set of access and refresh tokens.

Parameters:

- `refreshToken` - Encrypted refresh token string.

Returns:

- Promise of a `Result` object:
  - `newTokens` - An object containing:
    - `accessToken` - The new access token object containing the token value, suggested name, and options.
    - `refreshToken` - The new refresh token object containing the token value, suggested name, and options.
  - `payload` - The payload of the access token.
  - `rawAccessToken` - The access token in JWT format.
  - `msalResponse` - The MSAL response object for extra information if needed.

An example will be shown below.

#### `injectData<T>()`

Embed non-sensitive metadata into the access token.

Make sure not to inject sensitive data and also do not inject too much data, as it can lead to token size issues.

Parameters:

- `params`:
  - `accessToken` - The access token string either encrypted or in JWT format.
  - `data` - The data to inject into the token. This can be any object.

Returns:

- Promise of a `Result` object:
  - `injectedAccessToken` - The access token object containing the token value, suggested name, and options.
  - `injectedData` - The injected data of type `T`.

`T` is a generic type if you want to specify the type of the injected data.
It will be inferred from the `data` parameter.

An example of `verifyAccessToken`, `getTokenByRefresh`, and `injectData`:

```typescript
export const protectRoute = createMiddleware(async (c, next) => {
  const { accessTokenName, refreshTokenName } = oauthProvider.settings.cookies;
  const accessToken = getCookie(c, accessTokenName);
  const refreshToken = getCookie(c, refreshTokenName);
  if (!accessToken && !refreshToken) throw new HTTPException(401, { message: 'Unauthorized' });

  const accessTokenInfo = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (accessTokenInfo.success) {
    if (accessTokenInfo.hasInjectedData) {
      c.set('userInfo', {
        uniqueId: accessTokenInfo.payload.oid,
        email: accessTokenInfo.payload.preferred_username,
        name: accessTokenInfo.payload.name,
        injectedData: accessTokenInfo.injectedData,
      });
      return await next();
    }

    const { injectedAccessToken, success, injectedData } = await oauthProvider.injectData({
      accessToken: accessTokenInfo.rawAccessToken,
      data: { randomNumber: getRandomNumber() },
    });

    if (success) setCookie(c, injectedAccessToken.name, injectedAccessToken.value, injectedAccessToken.options);
    c.set('userInfo', {
      uniqueId: accessTokenInfo.payload.oid,
      email: accessTokenInfo.payload.preferred_username,
      name: accessTokenInfo.payload.name,
      injectedData: injectedData,
    });
    return await next();
  }

  const refreshTokenInfo = await oauthProvider.getTokenByRefresh(refreshToken);
  if (refreshTokenInfo.error) throw new OAuthError(refreshTokenInfo.error);
  const { newTokens } = refreshTokenInfo;

  const { injectedAccessToken, success, injectedData } = await oauthProvider.injectData({
    accessToken: refreshTokenInfo.rawAccessToken,
    data: { randomNumber: getRandomNumber() },
  });

  const finalAccessToken = success ? injectedAccessToken : newTokens.accessToken;
  setCookie(c, finalAccessToken.name, finalAccessToken.value, finalAccessToken.options);
  if (newTokens.refreshToken) {
    setCookie(c, newTokens.refreshToken.name, newTokens.refreshToken.value, newTokens.refreshToken.options);
  }

  c.set('userInfo', {
    uniqueId: refreshTokenInfo.payload.oid,
    email: refreshTokenInfo.payload.preferred_username,
    name: refreshTokenInfo.payload.name,
    injectedData: injectedData,
  });
  return await next();
});
```

#### `getB2BToken()`

Acquire an app token for a specific app, using the client credentials flow.

This method is useful for B2B applications that need to authenticate and authorize themselves against other services.

Note: This method is only available if `b2bTargetedApps` is configured in the `advanced` section of the `OAuthConfig`.

Parameters:

- `params`:
  - `appName` or `appsNames` - The name of the B2B app or an array of app names to generate tokens for.

Returns:

- Promise of a `Result` object:
  - `result` or `results` - An object or an array of objects (based on the parameters) containing:
    - `appName` - The name of the B2B app.
    - `clientId` - The client ID of the B2B app.
    - `accessToken` - The B2B access token string.
    - `msalResponse` - The MSAL response object for extra information if needed.

```typescript
protectedRouter.post('/get-b2b-info', async (c) => {
  const { appName } = await c.req.json();
  const { result, error } = await oauthProvider.getB2BToken({ appName });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });
  const axiosResponse = await axios.get(env.OTHER_SERVER, {
    headers: { Authorization: `Bearer ${result.accessToken}` },
  });
  const { data, error } = zSchema.safeParse(axiosResponse.data);
  if (error) throw new HTTPException(500, { message: 'Invalid response from the other server' });
  return c.json(data);
});
```

#### `getTokenOnBehalfOf()`

Acquire tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.

This method is useful for scenarios where your application needs to call downstream services on behalf of the user, using the user's access token.

Note: This method is only available if `downstreamServices` is configured in the `advanced` section of the `OAuthConfig`.

Parameters:

- `params`:
  - `accessToken` - The access token string either encrypted or in JWT format.
  - `serviceName` or `serviceNames` - The name of the downstream service or an array of service names to acquire tokens for.

Returns:

- Promise of a `Result` object or an array of objects (based on the parameters) containing:

  - `result` or `results` - An object or an array of objects (based on the parameters) with the following properties:
    - `serviceName` - The name of the OBO service.
    - `clientId` - The client ID of the OBO service.
    - `accessToken` - The OBO access token string.
    - `msalResponse` - The MSAL response object for extra information if needed.

```typescript
app.post('/on-behalf-of', protectRoute, async (c) => {
  const { serviceNames } = await c.req.json();
  const accessToken = c.get('userInfo').accessToken;
  const { results, error } = await oauthProvider.getOnBehalfOfToken({ accessToken, serviceNames });
  if (error) throw new HTTPException(error.statusCode, { message: error.message });

  for (const { accessToken } of results) {
    setCookie(c, accessToken.name, accessToken.value, accessToken.options);
  }

  return c.json({ message: 'On Behalf Of tokens generated successfully' });
});
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

authRouter.post('/authenticate', handleAuthentication()); // Returns {url: authUrl}
authRouter.post('/callback', handleCallback()); // Set tokens in cookies and redirect to frontendUrl
authRouter.post('/logout', handleLogout()); // Delete cookies and returns {url: logoutUrl}
```

To secure your routes, you can use the `protectRoute()` middleware and access the user information from the request object.

`protectRoute()` can receive an optional callback function that will be called with the user information after the authentication is verified. This is useful if you want to perform additional actions or validations based on the user information.

```typescript
import express, { type Router } from 'express';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { protectRoute } from 'oauth-entra-id/express';

const protectedRouter: Router = express.Router();

const callbackFunction: CallbackFunction = async ({ userInfo, injectData }) => {
  if (userInfo.isApp === false && !userInfo.injectedData) {
    const { error } = await injectData({ randomNumber: getRandomNumber() });
    if (error) throw new OAuthError(error);
  }
};

protectedRouter.use(protectRoute(callbackFunction));

protectedRouter.get('/user-info', (req: Request, res: Response) => {
  res.status(200).json({ message: 'Protected route :)', user: req.userInfo });
});

protectedRoute.post('/on-behalf-of', sharedHandleOnBehalfOf());
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

`isAuthenticated()` can receive an optional callback function that will be called with the user information after the authentication is verified. This is useful if you want to perform additional actions or validations based on the user information.

```typescript
import type { Request, Response } from 'express';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { type CallbackFunction, OAuthError } from 'oauth-entra-id';
import { isAuthenticated } from 'oauth-entra-id/nestjs';

const callbackFunction: CallbackFunction = async ({ userInfo, injectData }) => {
  if (userInfo.isApp === false && !userInfo.injectedData) {
    const { error } = await injectData({ randomNumber: getRandomNumber() });
    if (error) throw new OAuthError(error);
  }
};

@Injectable()
export class ProtectRoute implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    return await isAuthenticated(req, res, callbackFunction);
  }
}
```

Now you can use the `ProtectRoute` to protect your routes and get the user information.

```typescript
import type { Request } from 'express';
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
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

  @Post('on-behalf-of')
  async onBehalfOf(@Req() req: Request, @Res() res: Response) {
    await handleOnBehalfOf(req, res);
  }
}
```

## Demo Apps 👀

You can explore the demo apps to see how to integrate the package into your applications.

- [React Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/frontend-react/) 🖥️ - React 19 frontend showcasing best practices for frontend integration in an OAuth 2.0 cookie-based flow.

  > React 19, TanStack Router, TanStack Query (React Query), TanStack Form, Zustand, Tailwind, ShadCN Components, Axios and Zod.

- [Express Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-express/) 📫- Express server, implements `oauth-entra-id/express` for authentication.
- [NestJS Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-nestjs/) 🪺 - NestJS server, implements `oauth-entra-id/nestjs` for authentication.
- [HonoJS Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-honojs/) 🔥 - HonoJS server, implements authentication using the core utilities of the package.
- [Fastify Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-fastify/) ⚡ - Fastify server, implements authentication using the core utilities of the package.

> In each server demo you get a fully working server and these features implemented:
> Auth flows and protected routes, Input validation, Security HTTP Headers, CORS, Rate limiting, Logging, Error handling, and more.

## Architecture 🏗️

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/flow.png)

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

## License 📜

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).
