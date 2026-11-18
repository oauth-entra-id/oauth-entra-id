# Demo apps

Four example servers (Express, NestJS, Fastify, HonoJS) and a React demo site show how to use `oauth-entra-id` for browser and mobile authentication, on-behalf-of (OBO) and app-to-app (B2B) calls.

The demo and [automatic tests](../e2eTests/README.md) use the same server routes. They can use different Entra environments as long as each is configured for the flows below.

## What the demo shows

The framework picker changes which backend the React site talks to. The backend's colour identifies its Entra app registration:

| Colour | Server |
| --- | --- |
| yellow | Express |
| red | NestJS and Fastify |
| blue | HonoJS |

Switching from Express to HonoJS changes both the backend and the registration. Switching from NestJS to Fastify changes the backend but keeps the same red registration. Each server still has its own callback URLs. The optional **1 / 2** picker selects a registration set, independently of the framework picker.

| Demo control | What it demonstrates |
| --- | --- |
| **Sign in / Single Sign-On** | Sign in with Microsoft and view your account. Browser mode uses cookies for the session; the SSO switch controls whether sign-in can reuse an existing Microsoft session. |
| **Mobile app mode** | Simulates a mobile app in the browser: sign in through Microsoft, then exchange a login ticket for access and refresh tokens. Protected requests use a bearer token instead of browser session cookies. |
| **Get Tokens (OBO)** | The backend exchanges the signed-in user's token for one meant for a downstream service. Targets are grouped by colour: for example, Express can get a user token for red that NestJS and Fastify both accept. |
| **Get Data (B2B)** | The backend calls a specific server using an app token, not the user's identity. Targets are individual frameworks, so NestJS can call Fastify even though both use the same red registration. |
| **Logout** | Ends the demo session and signs out of Microsoft. |

The servers also have a `/lite` route group that uses the package's `LiteProvider`: `GET /lite/b2b-info` verifies a plain app token, and `POST /lite/get-b2b-info` with `{ "app": "<server>" }` gets an app token for another server and calls its `/lite/b2b-info`. It uses the first registration set and the same B2B permissions as the demo's Get Data (B2B).

The **LiteProvider** side of the demo tries these routes by hand, without signing in. The switch at the top of the page chooses what the demo shows: **OAuthProvider** is the full demo described above, **LiteProvider** is a separate page that only has the lite tests. The tests run against the server chosen in the picker:

| Lite control | What it demonstrates |
| --- | --- |
| **Run all checks** / **Check** | Sends no token, an empty bearer, garbage and a token that is too long to the server's `/lite/b2b-info` (expected 401), and an unknown or missing server to `/lite/get-b2b-info` (expected 400). Each row shows ✅ or ❌ with the status. |
| **Your login token (encrypted)** | Only in Mobile app mode after signing in with OAuthProvider: the login token is encrypted, so lite refuses it (401). In browser mode the token is in an HttpOnly cookie the page cannot read. |
| **Get Lite Data** | The selected server gets an app token with the lite provider and calls the target's lite route. Shows the data, whether the token was cached (click again to see it) and `expiresAt`. |

Tampered and wrong-audience app tokens, and the checks of a configuration with or without a secret, are only covered by the [automatic tests](../e2eTests/README.md), because the page must never hold an app token or a secret.

## The Entra ID tenant

Configure the three app registrations above in one tenant.

Every registration needs:

1. **Redirect URIs** (platform "Web"): the URL of each of its servers plus `/auth/callback` (browser login) and plus `/auth/mobile/callback` (mobile login). With the default URLs, yellow has `http://localhost:3001/auth/callback` and `http://localhost:3001/auth/mobile/callback`, red has the same two for ports `3002` and `3003`, blue for port `3004`.
2. **A client secret** (Certificates & secrets).
3. **Access token version 2**: in the Manifest set `requestedAccessTokenVersion` to `2`.
4. **Expose an API**: a scope users sign in with (for example `api://<client-id>/access`), and the application ID URI, so that `api://<client-id>/.default` can be requested.
5. **OBO** (the signed-in user's token is exchanged for a token of another app): under "Authorized client applications" of each app add the other two apps, with its scope.
6. **B2B** (a server calls another server with its own app token): on each app create an app role of type Application, and give every app that calls it that permission with admin consent. The calls are yellow, red and blue to each other, and also red to red (NestJS and Fastify call each other).
7. **A test user** in the tenant that can sign in.

The package README describes the same steps in general terms, see "Azure Portal Setup" in the [package README](../packages/oauth-entra-id/README.md).

## Trying it by hand

1. Copy [`.env.example`](../.env.example) to `.env` in the repository root and fill it in. Copy [`frontend-react/.env.example`](./frontend-react/.env.example) to `frontend-react/.env`.
2. `pnpm install`, then `pnpm dev` in the repository root. It starts the four servers and the React demo.
3. Open http://localhost:5000, choose a server and sign in. Try the controls described in [What the demo shows](#what-the-demo-shows).

### A second tenant (optional)

Another set of the three app registrations, for example in a second tenant, can be added with the `YELLOW2_*`, `RED2_*` and `BLUE2_*` variables. It is all or nothing: fifteen values, see `.env.example`. When it is set the demo shows a 1 / 2 switch to choose the registration, otherwise the switch is not there. The automatic tests only use the first registration.

## The automatic tests

See the [E2E tests README](../e2eTests/README.md) for setup, commands, flow coverage and CI configuration.

[`e2eTests`](../e2eTests) runs the same servers and demo against a real tenant, with the same three app registrations. Copy `e2eTests/.env.live.example` to `e2eTests/.env.live`, fill in the registrations and the test user, then run `pnpm test` in the repository root. The tests start the servers and the demo themselves.
