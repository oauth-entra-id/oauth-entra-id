<p align="center">
  <img src="https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/banner.svg" align="center" alt="banner" />

  <h1 align="center" style="font-weight:900;">oauth-entra-id</h1>

  <p align="center">
    A secure, performant, and feature-rich</br>
    OAuth 2.0 integration for Microsoft Entra ID <br/>
    fully abstracted and production-ready.
  </p>
</p>

<p align="center">
<a href="https://opensource.org/licenses/MIT" rel="nofollow"><img src="https://img.shields.io/github/license/oauth-entra-id/oauth-entra-id?color=DC343B" alt="License"></a>
<a href="https://www.npmjs.com/package/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/npm/v/oauth-entra-id?color=0078D4" alt="npm version"></a>
<a href="https://www.npmjs.com/package/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/npm/dy/oauth-entra-id.svg?color=03C03C" alt="npm downloads"></a>
<a href="https://github.com/oauth-entra-id/oauth-entra-id" rel="nofollow"><img src="https://img.shields.io/github/stars/oauth-entra-id/oauth-entra-id" alt="stars"></a>

</p>

## About 📖

A secure, performant, and feature-rich OAuth 2.0 integration for Microsoft Entra ID — fully abstracted and production-ready.

This library simplifies the Authorization Code Grant flow (with PKCE), token rotation, B2B authentication, and the On-Behalf-Of (OBO) flow with a strong focus on type safety, security and performance.

Designed to be framework-agnostic and developer-friendly, it eliminates the complexity of managing Microsoft Entra ID authentication — so you can focus on building your application, not your auth layer.

## Features 🌟

- 🔐 **Secure & Performant OAuth 2.0** – Backend-driven Authorization Code Flow with PKCE, built for production environments with a focus on security, speed, and reliability.
- 🦾 **Cross-Runtime, Framework-Agnostic Core** – Framework-agnostic and supports different runtimes (Node.js, Deno, and Bun) with official bindings for Express and NestJS.
- 🍪 **Cookie-Based Authentication** – Secure session management with HttpOnly cookies and automatic token rotation.
- 📢 **On-Behalf-Of (OBO) Flow** – Access downstream services using delegated user credentials with the OBO flow.
- 🤝 **B2B Application Support** – Authenticate service-to-service with the client credentials flow, including built-in caching for B2B tokens.
- 👥 **Multi-Tenant & Multi-App Support** – Handle multiple Azure App Registrations across tenants (a uniquely supported feature).
- 💉 **Inject & Compress Metadata** – Inject non-sensitive custom metadata directly into access tokens, with built-in compression to reduce payload size.
- ⚙️ **Highly Configurable** – Fine-tune encryption, token expiration, login prompts, cookie behavior, frontend URLs, and more.
- 🪶 **Lite Provider Mode** – Lightweight variant for services that only need JWT verification and B2B token generation.
- 📱 **Mobile-Ready** – Native app support via secure `ticket` mechanism.

## Getting Started 🚀

## Installation 🔥

```bash
npm install oauth-entra-id
```

Requires:

- Node.js v16 or higher (We recommend using the latest LTS version)
- Deno v2 or higher
- Bun v1.0 or higher

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
   - Or, if you want you can create a custom scope for your app by going to "Expose an API" and defining a new scope (e.g., `api://<your-client-id>/access`) (recommended).
7. Important step: go to "Manifest and edit the manifest file to set the `requestedAccessTokenVersion` to `2`. This is required for the package to work correctly with OAuth 2.0.
8. If you want to add roles you can do so by going to "App roles" and defining the roles you need. Make sure to assign these roles to users or groups in your Azure AD.

Setting up B2B app authentication:

1. Go to "App roles" and create a new app role for "Application" type.
2. Then go to "API permissions" add new permission and select the application that is allowed to authenticate to your app.
3. In the configuration of `OAuthConfig` of the first app, make sure to set the `acceptB2BRequests` property to `true`.
4. Then in the configuration of `OAuthConfig` of the second app, make sure to set the `b2bApps` property with the app name and scope of the first app, the scope should usually end with `/.default`.
5. That's it now the second app can authenticate to the first app using the client credentials flow.

Setting up On-Behalf-Of (OBO) flow for downstream services (works only if applications share the same tenant):

1. Go to "Expose an API" and create a new scope for your downstream service (e.g., `api://<your-client-id>/access`).
2. Then scroll down to "Authorized client applications" and add the client ID of the application that will be using the OBO flow.
3. In the configuration of `OAuthConfig` of the first app, make sure to set the `downstreamServices` property with the service name, scope, and `encryptionKey` of the downstream service, the scope should usually end with `/.default`.
4. That's it now the first app can acquire tokens for the downstream service using the OBO flow.

## Configuration ⚙️

```typescript
export interface OAuthConfig {
  azure: OneOrMore<{
    clientId: string; // Client ID from Azure App registration
    tenantId: string; // 'common' for multi-tenant apps or your specific tenant ID
    scopes: string[]; // e.g., ['openid', 'profile', 'email']
    clientSecret: string; // Client secret from Azure App registration

    // Optional for On-Behalf-Of (OBO) flow
    downstreamServices?: Array<{
      serviceName: string; // Unique identifier of the downstream service
      scope: string; // Usually ends with `/.default`
      serviceUrl: string | string[]; // URL(s) of the downstream service
      encryptionKey: string; // 32 character encryption key for the service
      cryptoType?: 'node' | 'web-api'; // Defaults to 'node'
      accessTokenExpiry?: number; // Defaults to 1 hour
    }>;

    // Optional for B2B apps
    b2bApps?: Array<{
      appName: string; // Unique identifier of the B2B app
      scope: string; // Usually ends with `/.default`
    }>;
  }>;
  frontendUrl: string | string[]; // Allowed frontend redirect URL(s)
  serverCallbackUrl: string; // Server callback URL (must match the one registered in Azure)
  encryptionKey: string; // 32 character encryption key for the access and refresh tokens

  // Optional advanced settings
  advanced?: {
    loginPrompt?: 'email' | 'select-account' | 'sso'; // Defaults to 'sso'
    acceptB2BRequests?: boolean; // If true, allows B2B authentication. Defaults to `false`
    cryptoType?: 'node' | 'web-api'; // Defaults to 'node'
    disableCompression?: boolean; //Whether to disable compression for access tokens. Defaults to `false`
    cookies?: {
      timeUnit?: 'ms' | 'sec'; // Defaults to 'sec'
      disableSecure?: boolean;
      disableSameSite?: boolean;
      accessTokenExpiry?: number; // Expiry time in seconds for access tokens. Defaults to 1 hour
      refreshTokenExpiry?: number; // Expiry time in seconds for refresh tokens. Defaults to 30 days
    };
  };
}
```

### Error Handling ⚠️

This package uses a custom `Result<T>` discriminated union to handle async operations in a type-safe, exception-free way.
If the method returns this type make sure to handle the error case or check if the `success` property is `true` before accessing the result.
Usually methods with this return type will start with the prefix `try` or `verify`, indicating that they may fail and return an error.

If the return type is not `Result<T>`, it will throw an `OAuthError` with a specific error type and message.

Both `ResultErr` and `OAuthError` give you the following properties:

- `type` - The type of the error for example `nullish_value`
- `message` - A human-readable error message that can be shown to the user.
- `statusCode` - The HTTP status code for the error, useful for API responses.
- `description` - A detailed description of the error, useful for debugging. Don't show this to the user, to avoid leaking sensitive information.

## Usage 🎯

The package provides three main modules for different frameworks:

- `oauth-entra-id` - Core package for any TS/JS framework (e.g., Express, NestJS, HonoJS, Fastify, etc.). jump to **[Core](#usage---core-)**.
- `oauth-entra-id/express` - For Express.js applications (recommended). Jump to **[Express](#usage---express-)**.
- `oauth-entra-id/nestjs` - For NestJS applications (recommended). Jump to **[NestJS](#usage---nestjs-)**.

There is another provider called `LiteProvider`, that you can import from the core package. This class has 2 methods `verifyJwt` and `tryGetB2BToken`(which is the same as the normal method).
You can use this provider if your server is a B2B only server with unencrypted JWT tokens, and you don't need the full OAuth 2.0 flow.

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
  encryptionKey: env.SECRET,
});
```

### Core Methods (Examples with HonoJS) 🧩

#### `settings`

You can access the settings of the `OAuthProvider` instance using the `settings` property.

```typescript
interface OAuthSettings {
  readonly loginPrompt: 'email' | 'select-account' | 'sso';
  readonly acceptB2BRequests: boolean;
  readonly b2bApps: string[] | undefined;
  readonly downstreamServices: string[] | undefined;
  readonly disableCompression: boolean;
  readonly cryptoType: 'node' | 'web-api';
  readonly azures: Array<{ azureId: string; tenantId: string }>;
  readonly cookies: {
    readonly timeUnit: 'sec' | 'ms';
    readonly isSecure: boolean;
    readonly isSameSite: boolean;
    readonly accessTokenExpiry: number;
    readonly accessTokenName: string;
    readonly refreshTokenExpiry: number;
    readonly refreshTokenName: string;
    readonly cookieNames: Array<{ azureId: string; accessTokenName: string; refreshTokenName: string }>;
    readonly deleteOptions: {
      readonly maxAge: 0;
      readonly httpOnly: true;
      readonly secure: boolean;
      readonly path: '/';
      readonly sameSite: 'strict' | 'none' | undefined;
    };
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
  - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one).

Returns:

- Promise of an object:
  - `authUrl` - The URL to redirect the user for authentication.
  - `ticket` - A unique ticket for the authentication session, this is used for bearer flow only.

```typescript
app.post('/authenticate', async (c) => {
  const { loginPrompt, email, frontendUrl } = await c.req.json();
  const { authUrl } = await oauthProvider.getAuthUrl({ loginPrompt, email, frontendUrl });
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

- Promise of an object:
  - `accessToken` - Access token object containing the token value, suggested name, and options.
  - `refreshToken` (optional) - Refresh token object containing the token value, suggested name, and options.
  - `frontendUrl` - The frontend URL to redirect the user after authentication.
  - `ticketId` - Ticket ID useful for bearer flow, store the tokens in a cache or database with a key based on this ticket ID. Later you can use this ticket ID to retrieve the tokens.
  - `msalResponse` - The MSAL response object for extra information if needed.

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

Build a logout URL and cookie-deletion instructions.

Parameters:

- `params` (optional):

  - `frontendUrl` (optional) - Frontend URL override to redirect the user after log out.
  - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one).
    Returns:

- Promise of an object:
  - `logoutUrl` - The URL to redirect the user for logout.
  - `deleteAccessToken` - Access token cookie object containing the token name, value, and options.
  - `deleteRefreshToken` - Refresh token cookie object containing the token name, value, and options.

```typescript
app.post('/logout', async (c) => {
  const { frontendUrl } = await c.req.json();
  const { logoutUrl, deleteAccessToken, deleteRefreshToken } = await oauthProvider.getLogoutUrl({ frontendUrl });
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
  - `meta` - Metadata about the user that has been extracted from the payload.
  - `payload` - The payload of the access token.
  - `rawJwt` - The access token in JWT format.
  - `injectedData` - If the token has been injected with extra data, it will be returned here with the type `T`.
  - `hasInjectedData` - If the token has injected data, this will be `true`. Otherwise, it will be `false`.

`T` is a generic type if you want to specify the type of the injected data.
It will remain `undefined` if the token does not have injected data.

An example will be shown below.

#### `tryRefreshTokens()`

Verifies and uses the refresh token to get new set of access and refresh tokens.

Parameters:

- `refreshToken` - Encrypted refresh token string.

Returns:

- Promise of a `Result` object:
  - `newAccessToken` - The new access token object containing the token value, suggested name, and options.
  - `newRefreshToken` - The new refresh token object containing the token value, suggested name, and options.
  - `meta` - Metadata about the user that has been extracted from the payload.
  - `payload` - The payload of the access token.
  - `rawJwt` - The access token in JWT format.
  - `msalResponse` - The MSAL response object for extra information if needed.

An example will be shown below.

#### `tryInjectData<T>()`

Inject non-sensitive metadata into the access token.

Make sure not to inject sensitive data and also do not inject too much data, as it can lead to token size issues.

Parameters:

- `params`:
  - `accessToken` - The access token string either encrypted or in JWT format.
  - `data` - The data to inject into the token. This can be any object.

Returns:

- Promise of a `Result` object:
  - `newAccessToken` - New access token that has been injected with the data.
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

  const at = await oauthProvider.verifyAccessToken<{ randomNumber: number }>(accessToken);
  if (at.success) {
    if (at.hasInjectedData) {
      c.set('userInfo', {
        uniqueId: at.meta.uniqueId,
        email: at.meta.email,
        name: at.meta.name,
        injectedData: at.injectedData,
      });
      return await next();
    }

    const inj = await oauthProvider.tryInjectData({ accessToken: at.rawJwt, data: getRandomNumber() });
    if (inj.success) setCookie(c, inj.newAccessToken.name, inj.newAccessToken.value, inj.newAccessToken.options);
    c.set('userInfo', {
      uniqueId: at.meta.uniqueId,
      email: at.meta.email,
      name: at.meta.name,
      injectedData: inj.injectedData,
    });
    return await next();
  }

  const rt = await oauthProvider.tryRefreshTokens(refreshToken);
  if (rt.error) throw new HttpException(rt.error.statusCode, { message: rt.error.message });

  const inj = await oauthProvider.tryInjectData({ accessToken: rt.rawJwt, data: getRandomNumber() });
  const final = inj.success ? inj.newAccessToken : rt.newAccessToken;

  setCookie(c, final.name, final.value, final.options);
  if (rt.newRefreshToken) setCookie(c, rt.newRefreshToken.name, rt.newRefreshToken.value, rt.newRefreshToken.options);

  c.set('userInfo', {
    uniqueId: rt.meta.uniqueId,
    email: rt.meta.email,
    name: rt.meta.name,
    injectedData: inj.injectedData,
  });
  return await next();
});
```

#### `tryDecryptTicket()`

Decrypts a ticket and returns the ticket ID.
Useful for bearer flow.

Parameters:

- `ticket` - The ticket string to decrypt.

Returns:

- Promise of a `Result` object:
  - `ticketId` - The decrypted ticket ID.

#### `tryGetB2BToken()`

Acquire an app token for a specific app, using the client credentials flow.
Caches tokens for better performance.

This method is useful for B2B applications that need to authenticate and authorize themselves against other services.

Note: This method is only available if `b2bTargetedApps` is configured in the `advanced` section of the `OAuthConfig`.

Parameters:

- `params`:
  - `app` or `apps` - The name of the B2B app or an array of app names to generate tokens for.
  - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one).

Returns:

- Promise of a `Result` of an object with:
  - `result` or `results` - An object or an array of objects (based on the parameters) containing:
    - `appName` - The name of the B2B app.
    - `clientId` - The client ID of the B2B app.
    - `token` - The B2B access token string.
    - `msalResponse` - The MSAL response object for extra information if needed.
    - `isCached` - A boolean indicating if the token was cached or not.
    - `expiresAt` - The expiration time of the token minus 5 minutes.

```typescript
protectedRouter.post('/get-b2b-info', async (c) => {
  const { app } = await c.req.json();
  const { result, error } = await oauthProvider.tryGetB2BToken({ app });
  if (error) throw new HttpException(error.statusCode, { message: error.message });

  const res = await axios.get(env.OTHER_SERVER, {
    headers: { Authorization: `Bearer ${result.token}` },
  });
  return c.json({ data: res.data });
});
```

#### `getTokenOnBehalfOf()`

Acquire tokens for trusted downstream services via the On-Behalf-Of (OBO) flow.

This method is useful for scenarios where your application needs to call downstream services on behalf of the user, using the user's access token.

Note: This method is only available if `downstreamServices` is configured in the `advanced` section of the `OAuthConfig`.

Parameters:

- `params`:
  - `accessToken` - The access token string either encrypted or in JWT format.
  - `service` or `services` - The name of the downstream service or an array of service names to acquire tokens for.
  - `azureId` (optional) - Azure configuration ID to use, relevant if multiple Azure configurations (Defaults to the first one).

Returns:

- Promise of an object or an array of objects (based on the parameters) containing:

  - `result` or `results` - An object or an array of objects (based on the parameters) with the following properties:
    - `serviceName` - The name of the OBO service.
    - `clientId` - The client ID of the OBO service.
    - `accessToken` - The OBO access token string.
    - `msalResponse` - The MSAL response object for extra information if needed.

```typescript
app.post('/on-behalf-of', protectRoute, async (c) => {
  const { services } = await c.req.json();
  const accessToken = c.get('userInfo').accessToken;
  const { results } = await oauthProvider.getOnBehalfOfToken({ accessToken, services });

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
      encryptionKey: env.SECRET,
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

To secure your routes, you can use the `protectRoute()` middleware.

`protectRoute()` attaches `userInfo` to the request object, which contains the user information extracted from the access token.

`protectRoute()` can receive an optional callback function that will be called with the user information after the authentication is verified. This is useful if you want to perform additional actions or validations based on the user information.

```typescript
import express, { type Router } from 'express';
import { protectRoute } from 'oauth-entra-id/express';

const protectedRouter: Router = express.Router();

protectedRouter.use(protectRoute());

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
      encryptionKey: env.SECRET,
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
    await handleLogout(req, res); // Delete cookies and returns {url: logoutUrl}
  }
}
```

Let's create the guard that will protect your routes while getting the user information.

`isAuthenticated()` attaches `userInfo` to the request object, which contains the user information extracted from the access token.

`isAuthenticated()` can receive an optional callback function that will be called with the user information after the authentication is verified. This is useful if you want to perform additional actions or validations based on the user information.

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
import { handleOnBehalfOf } from 'oauth-entra-id/nestjs';
import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { ProtectRoute } from '../guards/protect-route.guard';

@Controller('protected')
@UseGuards(ProtectRoute) // You can also apply the guard for specific routes, controller, or globally (you would need to write the logic in the guard)
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

  > React 19, React Router, TanStack Query (React Query), TanStack Form, Zustand, Tailwind, ShadCN Components, Axios and Zod.

- [Express Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-express/) 📫- Express server, implements `oauth-entra-id/express` for authentication.
- [NestJS Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-nestjs/) 🪺 - NestJS server, implements `oauth-entra-id/nestjs` for authentication.
- [HonoJS Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-honojs/) 🔥 - HonoJS server, implements authentication using the core utilities of the package.
- [Fastify Demo App](https://github.com/oauth-entra-id/oauth-entra-id/tree/main/examples/server-fastify/) ⚡ - Fastify server, implements authentication using the core utilities of the package.

> In each server demo you get a fully working server and these features implemented:
> Auth flows and protected routes, Input validation, HTTP Security Headers, CORS, Rate limiting, Logging, Error handling, and more.

## Architecture 🏗️

### Browser Authentication Flow 🚪

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/browser-authentication-flow.png)

### Browser Middleware Flow ✅

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/browser-middleware-flow.png)

Note: You should create a protected endpoint as shown `/user-info` to verify that the user is authenticated and get his information. If not redirect the user to the login page or fetch the authentication URL from the server and redirect the user to it.

### Browser On-Behalf-Of Flow 🌊

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/browser-on-behalf-of-flow.png)

### Mobile Authentication Flow 🚪

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/mobile-authentication-flow.png)

### Mobile Middleware Flow ✅

![oauth-entra-id-flow](https://github.com/oauth-entra-id/oauth-entra-id/blob/main/assets/mobile-middleware-flow.png)

## Notes❗

- **CORS**: Make sure to set the `credentials` option to `true` in your CORS configuration. This allows cookies to be sent with cross-origin requests.
- **Bearer Authentication (not B2B)**: The package exports `handleX` functions for Express and NestJS. They work on a cookie-based session for users and bearer tokens for b2b requests. But if you want to use bearer tokens for user authentication, you need to implement your own logic using the core package.
- **TSConfig**: Make sure that your `tsconfig.json` doesn't have `module: commonjs`. If so the following will work for you just fine: `module: node16` and `target: es6`.
- **NestJS**: The NestJS export package uses the `express` instance of NestJS, so make sure to use the `express` instance for the package to work, or use the core utilities.
- **Cookies** - Make sure you include with every request to the server the user's cookies. Another note is remember that the cookies are `HttpOnly` so you can't access them from the client-side JavaScript.

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

Thank you!
