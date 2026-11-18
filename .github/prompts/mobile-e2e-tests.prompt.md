---
description: "Use when: implementing or extending the mobile (ticket + Bearer) end-to-end tests of oauth-entra-id with Playwright, using the React demo in Mobile mode and the /auth/mobile + /protected/mobile routes of the four example servers. No package source changes, browser example untouched."
name: "Mobile E2E Tests"
argument-hint: "Step or spec to work on (e.g. 'verify real login', 'step 5 helpers', '06-mobile-login', 'all')"
agent: "agent"
---

# Mission

Create end-to-end tests for the **mobile flow** of the `oauth-entra-id` package on all four example servers (Express, NestJS, Fastify, HonoJS). They mirror the existing **browser** flow tests (`01-login` .. `05-logout`), which are complete and must stay untouched, and add one mobile-only spec for the ticket/refresh/Bearer protocol.

All tests must run with the existing single command from the repo root:

```
pnpm run test
```

(`pnpm run test` builds the package and example servers, then runs `playwright test`; every spec under `e2eTests/tests` runs automatically.)

User request for this run: ${input:scope:Step or spec to work on - leave empty for all remaining steps in order}

## Hard constraints

- **Do NOT change the package source** (`packages/oauth-entra-id/src/**`). Use only its public API. Everything else may change: `examples/*`, `e2eTests/*`, `.github/workflows/e2e-tests.yml`.
- **Use the package the way it is meant to be used.** The example servers are the "real app" the tests run against. Never replace a package handler/middleware in an example just to make a test pass; if a flow cannot be built the documented way, stop and ask the user. Entra ID changes (redirect URIs) are allowed but must be requested from the user, never assumed.
- **The browser example must stay exactly as it is.** Mobile is purely additive: no browser route, `handleX`, `protectRoute`, `isAuthenticated`, guard, controller or middleware may change (`git diff` of those files must stay empty; the only edits to existing server files are env additions, the provider config in `oauth.ts`, and the route mounts).
- **Do NOT modify the existing browser specs** `e2eTests/tests/01..05-*.spec.ts` or change the behavior of the React demo when Mobile mode is off.
- Library: **Playwright Test only** (already used). No Maestro/Appium/Detox/vitest. Mobile is **simulated**: the example website (React demo) in phone-emulated browsers (`devices['Pixel 7']`) with a real Microsoft sign-in, plus a cookie-less HTTP client for protocol tests.
- Live Microsoft login is used like in the existing tests (`e2eTests/.env.live`, never commit secrets). Never print tokens, tickets or passwords in logs/assertion messages (the reporter redacts JWT-like and 60+ char strings, keep messages generic anyway).
- Follow the repo style (Biome: `pnpm check`), TypeScript strict, comments only where needed. Prefer the existing helpers over new ones.

## What the tests must prove (package code, not the examples)

- The goal is to test the **package**. The example servers and the demo are only a vehicle to drive it. Do not add example features for which the package has no function (e.g. no injected data over Bearer: `tryInjectData` only returns a new token and the package defines no mobile way to deliver it; injection stays covered by the browser flow).
- Example-only logic is test infrastructure and gets **no tests of its own**: the ticket cache (single use, TTL, "not ready" 404), the demo's interceptors (refresh-once-and-retry, per-colour token choice), the route glue and the `withStatus` wrappers. Such behavior may only appear as a precondition to drive a flow, never as the thing under test.
- Assertions target what the package produces or decides: the ticket and `ticketId` binding (`getAuthUrl`, `getTokenByCode`, `tryDecryptTicket`), encrypted tokens (not JWT-shaped), `verifyAccessToken` (valid, tampered, wrong key, wrong type, app token refused, unencrypted user JWT refused), `tryRefreshTokens` (valid, rotation, invalid), `getTokenOnBehalfOf`, `tryGetB2BToken`, `getLogoutUrl`, the frontend whitelist (403), and the PKCE/authorize URL.

## Route map (mirrors the browser structure)

| Purpose | Browser | Mobile |
|---|---|---|
| login URL | `POST /auth/authenticate` | `POST /auth/mobile/login` (returns `{ url, ticket }`) |
| Microsoft callback | `POST /auth/callback` | `POST /auth/mobile/callback` |
| ticket exchange | - | `POST /auth/mobile/token` |
| refresh | middleware (cookies) | `POST /auth/mobile/refresh` |
| logout | `POST /auth/logout` | `POST /auth/mobile/logout` |
| who am I | `GET /protected/user-info` | `GET /protected/mobile/user-info` |
| OBO | `POST /protected/on-behalf-of` | `POST /protected/mobile/on-behalf-of` |
| B2B call | `POST /protected/get-b2b-info` | `POST /protected/mobile/get-b2b-info` |

## Why the mobile flow has its own provider and callback

README: "if you want to use bearer tokens for user authentication, you need to implement your own logic using the core package" (the `handleX` functions are cookie sessions + Bearer for B2B). Facts from the code:
- `handleCallback` calls `getTokenByCode()` but discards `ticketId` and always sets cookies, so it cannot serve a mobile login.
- A provider has exactly one `serverCallbackUrl`, sent as `redirect_uri` when the login URL is built and again when the code is exchanged; it must match a registered Entra redirect URI.
- The `state` is encrypted and the `code` is single use, so one callback route cannot first look at the login type and then choose a handler.

Therefore each server has a second provider, `mobileOAuthProvider` (same Azure registrations, same keys, so the tokens are the same encrypted tokens), with `serverCallbackUrl = <server>/auth/mobile/callback`, `frontendUrl = MOBILE_RETURN_URL` (React origin + `/mobile-return`, host already whitelisted) and `acceptB2BRequests: false` (so `verifyAccessToken` itself refuses app tokens on the mobile routes). The browser provider and routes are untouched.

**Entra ID requirement:** `<server>/auth/mobile/callback` must be a registered redirect URI (Web platform): `http://localhost:3001/auth/mobile/callback` (yellow app, Express), `http://localhost:3002/auth/mobile/callback` and `http://localhost:3003/auth/mobile/callback` (red app, NestJS and Fastify), `http://localhost:3004/auth/mobile/callback` (blue app, HonoJS). The same URIs are used in CI (same registrations). Status: the user was asked and will register them (the path was changed from `/mobile/callback` to `/auth/mobile/callback` after the first request, the user must be told the new path); do not run real mobile logins before they confirm. Without them Microsoft refuses the login with a redirect URI mismatch.

## What the package gives (mobile building blocks)

Read before coding: [core.ts](../../packages/oauth-entra-id/src/core.ts), [middleware.ts](../../packages/oauth-entra-id/src/shared/middleware.ts), [endpoints.ts](../../packages/oauth-entra-id/src/shared/endpoints.ts), [README](../../packages/oauth-entra-id/README.md) (ticket / bearer flow), diagrams `assets/mobile-authentication-flow.png` and `assets/mobile-middleware-flow.png`.

- `getAuthUrl()` returns `{ authUrl, ticket }` (ticket = encrypted UUID; the same `ticketId` is inside the encrypted PKCE state).
- `getTokenByCode()` returns `{ accessToken, refreshToken, frontendUrl, ticketId, msalResponse }`. The package is **stateless**: the server caches the tokens by `ticketId` itself (README: "store the tokens in a cache or database with a key based on this ticket ID").
- `tryDecryptTicket(ticket)` returns `{ ticketId }`.
- `verifyAccessToken()` accepts an **encrypted user token** (an unencrypted user JWT is refused, app tokens are refused when `acceptB2BRequests` is false).
- `tryRefreshTokens(refreshToken)` returns new access/refresh tokens (cookie-shaped objects; mobile uses only `.value`).
- `getTokenOnBehalfOf()` returns cookie-shaped objects per downstream service; mobile returns only `name`/`value` in the body.

## Browser vs mobile (what differs)

| Aspect | Browser | Mobile |
|---|---|---|
| Provider / callback | `oauthProvider` (or `authConfig` adapter), `/auth/callback` | `mobileOAuthProvider`, `/auth/mobile/callback` |
| Token carrier | HttpOnly cookies `at-/rt-<clientId>` | JSON body, then `Authorization: Bearer` |
| Ticket | ignored | links the system-browser callback to the app |
| Callback | sets cookies, 303 to frontend | caches tokens by `ticketId`, no cookies, 303 to return URL |
| Refresh | automatic in middleware | app calls `/auth/mobile/refresh` after a 401 and retries |
| Injected data | added on cookie path | not used on the mobile routes (profile shows "None") |
| Logout | deletes cookies | app clears its storage; stateless, old access token stays valid until expiry |

## How the redirect imitates a mobile app

Real app: the app opens the login URL in the system browser (Chrome Custom Tab / ASWebAuthenticationSession); Microsoft POSTs `code`+`state` to the server callback; the server answers `303` to the return address; the OS delivers that address (a deep link such as `myapp://auth/return`) to the app, which then exchanges its ticket. Browser and app are separate processes with separate storage; only the ticket links them.

Simulation:
- **Server side is identical to the real thing:** the mobile callback answers `303` with no `Set-Cookie`, `Location` = the return URL, and the tokens wait in the cache for the ticket.
- **The OS hand-off is played by the test:** use TWO browser contexts, both `devices['Pixel 7']`. The **app** context runs the demo in Mobile mode (no Microsoft cookies). The **system browser** context carries the Microsoft session (`microsoftSession` storage state). In the app context intercept the navigation to `login.microsoftonline.com` (`page.route`, read the URL, abort), open that URL in the system-browser context and sign in with `signInAtMicrosoft`; there fulfil the return URL with an empty page and record the `303` callback response (no `Set-Cookie`). Then play the deep link: `appPage.goto(<frontend>/mobile-return)`; the demo exchanges the ticket it kept in its own storage.
- A custom scheme is not used because Chromium cannot follow it (the package would accept `myapp://auth/return` if its host were whitelisted in the mobile provider; verified in-process earlier).

## Deliverables

### A. Example servers, all four (STATUS: DONE; offline-verified, real login pending Entra URIs)

Each server has `src/routes/mobile.ts` exporting `mobileAuthRouter` and `mobileProtectedRouter` (NestJS: `src/modules/mobile/` with `MobileAuthController` at `auth/mobile`, `MobileProtectedController` at `protected/mobile`, `MobileBearerGuard`, `MobileService`), plus `mobileOAuthProvider` in `oauth.ts`, `utils/mobile-tickets.ts` (in-memory single-use TTL cache, comment that production needs Redis/DB) and env `MOBILE_RETURN_PATH` (default `/mobile-return`), `MOBILE_TICKET_TTL_SEC` (default 120), derived `MOBILE_RETURN_URL`. Mounting: `/auth/mobile` next to `/auth`; `/protected/mobile` is mounted BEFORE `/protected` on Express and HonoJS (their `/protected` mount has a cookie middleware that would otherwise wrap the Bearer routes; verified: the mobile 401 body comes from the Bearer check), Fastify and NestJS separate the two by plugin encapsulation / `@Public()` + `MobileBearerGuard`.
- `POST /auth/mobile/login` -> `getAuthUrl()` -> `{ url, ticket }` (`Cache-Control: no-store`); unlisted `frontendUrl` -> 403; invalid input 4xx.
- `POST /auth/mobile/callback` (Microsoft form_post) -> `getTokenByCode()`, cache by `ticketId`, no cookies, `303` to the return URL; bad input 4xx.
- `POST /auth/mobile/token` `{ ticket }` -> `tryDecryptTicket()` -> pop from cache -> `{ accessToken, refreshToken }`; garbage 400, not ready/expired/used 404 (example cache behavior, not a test target).
- `POST /auth/mobile/refresh` `{ refreshToken }` -> `tryRefreshTokens()` -> `{ accessToken, refreshToken }`; garbage 401.
- `POST /auth/mobile/logout` -> `getLogoutUrl()` -> `{ url }`.
- Bearer-protected (own check with `mobileOAuthProvider.verifyAccessToken`, 401 on failure, never the cookie middleware): `GET /protected/mobile/user-info` -> `{ user }` (same shape as the browser route, no `injectedData`); `POST /protected/mobile/on-behalf-of` `{ services }` -> `{ tokens: [{ serviceName, name, value }] }`; `POST /protected/mobile/get-b2b-info` `{ app }` (server-side B2B call, same targets as the browser route).
- Because the package leaves `statusCode` undefined for errors created without a `status` key, the mobile routes wrap errors with a fallback (400, 401 for refresh/Bearer).
- Nest imports that Nest needs as values carry `// biome-ignore lint/style/useImportType: NestJS` per import (Biome's auto-fix otherwise turns them into type imports and the server fails to start).

### B. React demo `examples/frontend-react` (STATUS: DONE, typechecked; Mobile mode real-login verified earlier on HonoJS/Fastify with an earlier shared-callback design, must be re-verified with the final design)

- Switch with the accessible name **"Mobile app mode"** (role `switch`) on the login page, off by default, persisted in localStorage `mobile-mode`. Works on all four servers.
- Storage contract (used by the tests): localStorage `mobile-ticket` = ticket string (removed after exchange); localStorage `mobile-tokens` = JSON `{ accessToken, refreshToken, mainColor: 'blue'|'red'|'yellow', services: { [serviceName]: token } }`. `mainColor` is the colour of the server the user logged in to; `services` holds on-behalf-of tokens.
- Page `/mobile-return` exchanges the ticket, stores the session, goes home. `lib/axios.ts` interceptors: no cookies; in Mobile mode user/B2B/OBO calls go to `/protected/mobile/*`; the server of the current colour gets the token it accepts (access token for `mainColor`, the OBO token for another colour, nothing when there is none, so that server answers guest like in browser mode); on a 401 for a request sent with the main access token it refreshes once (`/auth/mobile/refresh`, shared by concurrent requests) and retries; a failed refresh clears the stored session. Requests sent without a token never trigger a refresh.
- Mobile logout (`/auth/mobile/logout`, clears storage, opens the Microsoft logout URL), mobile "Get Tokens" (`/protected/mobile/on-behalf-of`, values saved in `services`).
- Existing page texts and roles are unchanged, so the `Site` page object keeps working.

### C. e2eTests (STATUS: DONE, all six mobile specs written, 38 tests)

Implemented (do not redo): `src/env.ts` exports `mobileReturnPath`/`mobileTicketTtlSec`; `src/servers.ts` passes them to the servers; `src/mobile-api-client.ts` (`MobileApi` cookie-less HTTP client, `fetchAppToken` real client-credentials token from Entra, `looksLikeJwt`, `tamper`); `src/pages/mobile-app-page.ts` (`MobileSite extends Site`, `MicrosoftUrls`); `src/pages/mobile-device.ts` (`SystemBrowser`, `Phone`); `src/fixtures.ts` (`phone: Phones` with `knownToMicrosoft()` / `signedIn(server, { freshMicrosoftSession })`, `mobileApi`, both reusing the cached `microsoftSession`); specs `06`..`11`; CI matrix; `.env.live.example` note. The notes below describe the design that was built.

Design: a phone is two Pixel 7 browser contexts. The app context runs the demo in Mobile mode; every navigation of the app to Microsoft is stopped (`MicrosoftUrls.block`) and the address is opened in the system-browser context (which carries the Microsoft session), where `signInAtMicrosoft` runs; there the return page is fulfilled with an empty page and the `303` callback response is recorded; then `MobileSite.openDeepLink()` plays the deep link by opening `/mobile-return` in the app context. Logout: the app's Microsoft logout address is captured the same way and opened in the system browser.

Files (as built):
```
e2eTests/
  src/
    mobile-api-client.ts, pages/mobile-app-page.ts, pages/mobile-device.ts, fixtures.ts (extended)
  tests/
    01..05                           unchanged (browser)
    06-mobile-login.spec.ts          6 tests   mirrors 01-login
    07-mobile-session.spec.ts        4 tests   mirrors 02-session
    08-mobile-obo.spec.ts            4 tests   mirrors 03-obo
    09-mobile-b2b.spec.ts            8 tests   mirrors 04-b2b (+ a real app token is refused on the mobile route)
    10-mobile-logout.spec.ts         4 tests   mirrors 05-logout
    11-mobile-ticket.spec.ts         12 tests  package-level ticket/refresh/Bearer protocol
```
Not built (optional, ask first): `forge.ts` (genuinely expired token via an in-process provider).
```
e2eTests/
  src/
    env.ts                           mobile tests loop over `serverNames` (all four)
    pages/mobile-app-page.ts         NEW  class MobileSite extends Site: enableMobileMode(),
                                     storedTokens(), corruptAccessToken(), corruptRefreshToken(),
                                     restartApp() (new page, same context storage),
                                     observed requests (Authorization present, no session Cookie)
    mobile-api-client.ts             NEW  cookie-less HTTP client (playwright request.newContext()):
                                     login(), exchange(ticket), refresh(token), get(path, token),
                                     assertNoCookies()
    forge.ts                         OPTIONAL real expired-token forging (see below, ask first)
    fixtures.ts                      extend: factory for contexts with device options;
                                     keep `site` (desktop); add `phone`: app context (Pixel 7, MobileSite,
                                     mobile mode on) + system-browser context (Pixel 7 + cached
                                     microsoftSession) and `signedIn(server, { freshMicrosoftSession? })`
                                     that performs the two-context sign-in described above
  tests/
    01..05                           unchanged (browser)
    06-mobile-login.spec.ts          mirrors 01-login
    07-mobile-session.spec.ts        mirrors 02-session
    08-mobile-obo.spec.ts            mirrors 03-obo
    09-mobile-b2b.spec.ts            mirrors 04-b2b
    10-mobile-logout.spec.ts         mirrors 05-logout
    11-mobile-ticket.spec.ts         mobile-only protocol tests
```

Keep the flat `NN-<flow>.spec.ts` naming: the reporter derives the flow name from the file name and the CI matrix runs `tests/[0-9][0-9]-<flow>.spec.ts`. Reuse the existing style: `for (const server of serverNames)` loops, `test.step`, `expect.soft` for field groups.

### D. CI

Add `mobile-login, mobile-session, mobile-obo, mobile-b2b, mobile-logout, mobile-ticket` to `matrix.flow` in `.github/workflows/e2e-tests.yml`. Nothing else changes (same secrets and registrations; the new redirect URIs must exist in Entra).

### E. Docs

Short note in e2eTests docs/README: mobile is simulated (phone-profile Chromium, two contexts, demo Mobile mode); why mobile has its own provider/callback and needs the `/auth/mobile/callback` redirect URIs; what it proves and what it does not (no real iOS/Android browser, deep link played by the test, storage is browser storage).

## Tests to write (`[x4]` = once per server: Express, NestJS, Fastify, HonoJS)

Remember the rule above: every assertion should be about package behavior; example-only behavior (cache, interceptors, route glue) is at most a precondition.

**06-mobile-login** (mirrors 01-login)
- [x4] Microsoft sign-in in Mobile mode (two-context flow) shows my account: email, azure, tenant, unique id (guid), name; injected data is "None".
- [x4] the system browser holds no session cookie for the server and the callback answered `303` without `Set-Cookie`; the app context has stored tokens that are encrypted (not JWT-shaped), no `at-`/`rt-` cookies, no token text visible to the page; API calls carry `Authorization: Bearer` and no `Cookie` header; `mobile-ticket` is gone.
- [x4] reload stays signed in; `/protected/mobile/user-info` answers 200 with the stored token and the right email.
- Sign in with email (`login_hint`, `prompt=login`) once; SSO off (`prompt=select_account`) once, checked on the authorize URL captured in the app context; also assert `redirect_uri` is the server's `/auth/mobile/callback`.

**07-mobile-session** (mirrors 02-session)
- [x4] "app restart" (new page, same storage) and reload keep the session.
- [x4] corrupted access token + valid refresh token -> 401 -> the app gets new tokens from `tryRefreshTokens` (they are stored and work) -> page still connected. Do not assert how many refresh calls the demo makes.
- [x4] both tokens corrupted -> guest page, storage cleared, `/protected/mobile/user-info` 401.
- Optional (needs `forge.ts`): a genuinely expired access token behaves like the corrupted one.

**08-mobile-obo** (mirrors 03-obo)
- [x4] "Get Tokens" for one downstream service and for all others: values come back in the body (no Set-Cookie, no cookies set), are stored in `services`, each downstream server accepts its token as Bearer on `/protected/mobile/user-info` (200, azure = that service's client id), and a server of a colour without a token answers guest while the session survives.

**09-mobile-b2b** (mirrors 04-b2b)
- [x4] "Get Data" reaches every other server using the user's Bearer token (pokemon text + toast like 04).
- [x4] an app (B2B) token on `/protected/mobile/user-info` is refused (403), a user token works.

**10-mobile-logout** (mirrors 05-logout; sign in with `freshMicrosoftSession: true` like 05, because the Microsoft sign-out ends the shared Microsoft session)
- [x4] Logout clears storage, the app opens the Microsoft logout page of the tenant (`/<tenant>/oauth2/v2.0/logout`, `post_logout_redirect_uri` contains the frontend origin; deliver that URL to the system-browser context), shows guest after reload; after finishing the Microsoft sign-out Microsoft asks for sign-in again.

**11-mobile-ticket** (mobile-only, cookie-less client; one real login through the phone fixture for the success paths)
- [x4] login returns `{ url, ticket }`: Microsoft authorize URL with PKCE `S256`, `response_mode=form_post`, `redirect_uri` = server `/auth/mobile/callback`; ticket is not a JWT; two calls give different tickets.
- [x4] ticket exchange (package side): garbage / empty / tampered ticket -> 4xx (`tryDecryptTicket`); a ticket made by a server of a DIFFERENT colour (different key) -> 4xx. Do not test single use, TTL or "not ready yet": that is the example cache, not the package.
- [x4] refresh route: valid -> new tokens work on `/protected/mobile/user-info`; chain of 3; missing / empty / garbage / tampered / access token used as refresh token -> 4xx (401 for token problems).
- [x4] Bearer matrix on `/protected/mobile/user-info`: valid 200; no header, `Basic x`, `Bearer ` (empty), garbage, tampered, refresh token as access token -> 401; a token of a different colour -> 401. Mark lowercase `bearer` as `[characterise]`.
- [x4] the browser routes still work in the same run (cookie login unaffected by the mobile provider).
- Two parallel logins (two phone contexts, same user) get different tickets and tokens; each ticket returns only its own tokens.

Mark tests that only pin current behavior with `[characterise]` in the title so they can be reviewed as a list of decisions.

## Technique notes

- Keep request counts low: the example servers rate-limit (e.g. HonoJS 100 requests / 2 min per IP). Do protocol checks with few requests; log in once per server per worker (cached fixtures) and reuse tokens for read-only tests.
- Microsoft sign-in: reuse `signInAtMicrosoft` from [microsoft.ts](../../e2eTests/src/pages/microsoft.ts) and the cached `microsoftSession` storage state (it ignores the `localhost` cookies, so the app context never inherits a session).
- Optional `forge.ts` (real expiry without waiting an hour): needs fixed throwaway encryption keys shared by the servers and the tests (Playwright workers re-evaluate the config, so the current per-process random keys would differ), `oauth-entra-id` as an `e2eTests` workspace dependency, an in-process `OAuthProvider` with the same config/keys, decrypt the real token -> re-encrypt with `accessTokenExpiry: 1`, wait 2 s. Only add it if the user confirms.
- Repo gotchas: Microsoft's email page has an invisible decoy password input (use the existing helper in `microsoft.ts`); to list tests without running them use `pnpm --filter e2e-tests exec playwright test --list --reporter=list`; without real credentials the suite can only be type-checked/listed; NestJS has no `typecheck` script (`pnpm --filter server-nestjs exec tsc --noEmit`); `pnpm biome check --fix` rewrites Nest value imports to type imports unless each has the per-import ignore comment; do not create temp files with `create` on an existing path, and do not run a delete and a create of the same path in parallel.

## Implementation plan (my steps, in order)

**Status:** Steps 0-7 DONE (servers, demo, real-login verification, e2e helpers, six specs, CI matrix). Step 8 (full `pnpm run test`) is the last check. The old design tree below under "C" is superseded by the "as built" block.

Verified so far (do not redo): `pnpm run test:build` passes; typecheck of the demo, all four servers (Nest via `tsc --noEmit`) and e2eTests passes; `pnpm biome check examples e2eTests` is clean; an offline smoke script (88 checks on the four servers: login/ticket/refresh/callback/Bearer/OBO/B2B routes without a token, authorize URL `redirect_uri` = `/auth/mobile/callback`, old flat `/mobile/*` paths gone, browser `authenticate` and `/protected/user-info` unchanged) passed; the mobile 401 on Express, NestJS and HonoJS comes from the Bearer check, not the cookie middleware; the existing browser specs 01-05 passed on all four servers (22 tests) before the route split and are re-run after it (see the last summary); `packages/` untouched. The smoke scripts live in the Copilot session folder, not in the repo.

Findings to report in the final summary:
1. The package leaves `statusCode` undefined for errors created without a `status` key (`error.ts`), so malformed callback input answers 200 (HonoJS, NestJS) or 500 (Express, Fastify) on the shipped browser callbacks; the mobile routes work around it. Do not pin a status on the browser callback.
2. `handleCallback`/`handleAuthentication` drop the ticket, which is why mobile needs its own provider and callback (a second redirect URI per server).
3. Logout is stateless.
4. A custom deep-link scheme (`myapp://auth/return`) is accepted by `getAuthUrl()` when its host is whitelisted (verified in-process), a non-listed host gives 403.
5. NestJS has no `typecheck` script.
6. Injected data is not part of the mobile flow by decision: the package has `tryInjectData` (returns a new encrypted token) but defines no mobile way to deliver it, so nothing was added to the examples; it is covered by the browser flow.

Track the steps as todos (SQL todos table, one per step, with dependencies) and mark each done only after its check passes. Stop and report if a check fails twice with different approaches.

**Step 4b - Verify the real mobile login (after the user confirms the redirect URIs).** Use a throwaway Playwright probe spec (delete it afterwards): for each of the four servers sign in in Mobile mode, assert connected, tokens stored and encrypted, no session cookies, ticket removed; then HonoJS login + Get Tokens(red) -> Fastify/NestJS accept the session on `/protected/mobile/user-info`. If Microsoft reports a redirect URI mismatch, the URIs are not (yet) registered: stop and tell the user.

**Step 5 - e2e helpers.** `mobile-api-client.ts`, `mobile-app-page.ts`, fixtures (`phone` with the two contexts). Check: `pnpm --filter e2e-tests run typecheck`; `playwright test --list --reporter=list` still lists 01-05 unchanged.

**Step 6 - Specs, one at a time, run each before the next** (needs `.env.live`): `06-mobile-login` (HonoJS first, then the others) -> `11-mobile-ticket` -> `07-mobile-session` -> `08-mobile-obo` -> `09-mobile-b2b` -> `10-mobile-logout`. Check per spec: `pnpm --filter e2e-tests exec playwright test tests/<file>` passes; no token/ticket text in the output; each `[characterise]` test documents what the code does.

**Step 7 - CI + docs.** Add the 6 flows to `matrix.flow`; add the e2e note. Check: workflow YAML valid, the glob `tests/[0-9][0-9]-<flow>.spec.ts` matches each new file name.

**Step 8 - Final verification.** `pnpm typecheck`, `pnpm check`, `pnpm run test:build`, `playwright test --list`, then the new specs together and, if time allows, `pnpm run test` end to end (01-05 still pass); `git status`/`git diff --stat` shows nothing under `packages/` and no change to browser route/middleware/guard files. Report: files changed, tests per spec, what ran, what did not, `[characterise]` findings, open decisions.

## Working method

1. Follow the implementation plan above; keep the existing style.
2. Work in phases, each leaving `pnpm run test` green for what exists.
3. Ask the user before: adding the OPTIONAL forge technique, changing anything not listed here, changing Entra ID settings, or deviating from the constraints.
4. Verify with the smallest commands: `pnpm --filter e2e-tests run typecheck`, `pnpm check`, `pnpm run test:build`, then the single spec. If real Microsoft credentials or the redirect URIs are unavailable, say clearly which tests were only type-checked/listed and not executed.
5. Finish with a summary: files changed, tests added (names/count per spec), what was run, what was not, and any `[characterise]` findings.

## Definition of done

- Every browser flow (login, session, obo, b2b, logout) has a mobile counterpart, plus `11-mobile-ticket`; they run for all four servers where marked `[x4]`.
- `pnpm run test` runs browser + mobile tests together; the CI matrix includes the new flows.
- Package source untouched; browser routes of the examples untouched; existing browser specs untouched and passing; the demo behaves exactly as before with Mobile mode off.
- `pnpm typecheck`, `pnpm check` and `pnpm run test:build` pass for everything touched.
- No secrets or tokens in code, logs or commits.

## Other rules

- Do not commit or push unless the user asks. Do not delete or rewrite the planning files in the repo root (`tests-plan.txt`, `mobile-testing-plan.txt`, `mobile-e2e-options.txt`).
- Microsoft's sign-in pages may look different with a phone user agent. If the existing helpers in `microsoft.ts` fail only in the phone context, report it and propose the smallest change (or fall back to the desktop user agent with a phone viewport) before editing that helper.
- No `.env.example`, README or unit tests exist for the examples today; do not invent them. The two new env variables have defaults, so nothing needs to be set by hand.
