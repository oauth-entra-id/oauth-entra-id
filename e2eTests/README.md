# End-to-end tests

Playwright tests for the `oauth-entra-id` package using real Microsoft Entra ID authentication. They run automatically on pull requests and can also be run locally while developing the package.

The example servers and React site are tools for exercising the package, not the subject of the tests. Manual testing and automatic testing use the same example routes and flows; neither requires a special implementation of the package.

## Requirements

- Node.js 22.18 or later and the repository's pnpm version.
- Three app registrations in one Entra tenant: yellow (Express), red (NestJS and Fastify), and blue (HonoJS).
- A test account in that tenant that can complete the automated sign-in without additional interactive challenges.
- Browser and mobile callback URIs, exposed scopes, OBO permissions and B2B permissions configured as described in the [demo tenant setup](../examples/README.md#the-entra-id-tenant).

The suite uses the first registration of each colour (`*1_AZURE_*`). A second tenant is not required. The examples optionally support a second registration set for manual testing, but the suite does not repeat the flows against it.

## Local setup

Run these commands from the repository root:

```powershell
pnpm install --frozen-lockfile
pnpm --filter e2e-tests run browsers
Copy-Item e2eTests\.env.live.example e2eTests\.env.live
```

Fill in your new local file using [the env template](./.env.live.example):

- The four server URLs and React frontend URL. Each must use `http://localhost:<port>` without a trailing slash. Use distinct, available ports.
- The client ID, tenant ID, custom scope, client secret and exposed scope for each of the three apps.
- `E2E_USER_EMAIL` and `E2E_USER_PASSWORD`.

The custom scope is the delegated scope used for user sign-in, such as `api://<client-id>/access`. The exposed scope value is the resource's `.default` scope, such as `api://<client-id>/.default`; it is not a second scope to create in Entra.

Environment variables already set in the shell take precedence over the local file. Keep credentials out of source control; `.env.live` is git-ignored.

The suite starts and stops its own four servers and Vite frontend. Stop any manually running examples on the same ports before testing. You do not need to configure the root or frontend `.env` files for an e2e run.

## Running tests

From the repository root:

| Command | Runs |
| --- | --- |
| `pnpm test` | All flows |
| `pnpm test:headed` | All flows with visible browser windows |
| `pnpm test:browser` | Browser flows (`01` through `05`) |
| `pnpm test:browser:headed` | Browser flows with visible browser windows |
| `pnpm test:mobile` | Mobile flows, including ticket and parameter checks |
| `pnpm test:mobile:headed` | Mobile flows with visible browser windows |

These scripts build the package and example servers before running Playwright.

For a focused run, build first, then select a spec or test title:

```powershell
pnpm run test:build
pnpm --filter e2e-tests exec playwright test 08-mobile-obo
pnpm --filter e2e-tests exec playwright test 08-mobile-obo --grep "HonoJS"
```

Rebuild after changing package or server code. Direct Playwright commands do not build it for you.

List tests without starting the servers or running authentication:

```powershell
pnpm --filter e2e-tests exec playwright test --list --reporter=list
```

Listing still loads the configuration, so the environment must be populated.

## Flows

| Spec | Package behaviour exercised |
| --- | --- |
| [01-login](./tests/01-login.spec.ts) | Browser login, account metadata, injected data, cookies and login prompts |
| [02-session](./tests/02-session.spec.ts) | Browser session persistence, silent refresh and tampered cookies |
| [03-obo](./tests/03-obo.spec.ts) | Downstream user tokens accepted by their services |
| [04-b2b](./tests/04-b2b.spec.ts) | App-to-app calls and rejection of invalid or wrong-audience app tokens |
| [05-logout](./tests/05-logout.spec.ts) | Cookie deletion and Microsoft sign-out |
| [06-mobile-login](./tests/06-mobile-login.spec.ts) | Ticket-based login, encrypted tokens, metadata and login prompts |
| [07-mobile-session](./tests/07-mobile-session.spec.ts) | Mobile session persistence, explicit refresh and tampered tokens |
| [08-mobile-obo](./tests/08-mobile-obo.spec.ts) | Downstream bearer tokens and OBO error cases |
| [09-mobile-b2b](./tests/09-mobile-b2b.spec.ts) | App-to-app calls and refusal of app tokens where B2B is disabled |
| [10-mobile-logout](./tests/10-mobile-logout.spec.ts) | Mobile logout and Microsoft sign-out |
| [11-mobile-ticket](./tests/11-mobile-ticket.spec.ts) | PKCE request parameters, tickets, token-type separation and repeated refresh |
| [12-mobile-params](./tests/12-mobile-params.spec.ts) | Login options, frontend host whitelist and invalid callback state/code |
| [13-lite](./tests/13-lite.spec.ts) | `LiteProvider`: plain app token verification, B2B tokens with caching and expiry, and configurations with and without a secret |

This is integration coverage of these behaviours, not a claim that every exported method or configuration option is tested.

## How the suite works

- [Environment validation](./src/env.ts) loads the local env file and checks the required settings.
- [Server setup](./src/servers.ts) launches the built examples with generated encryption keys. An isolated working directory keeps the manual setup's root `.env` out of the run.
- [Fixtures](./src/fixtures.ts) create isolated browser contexts and reuse a worker's Microsoft session to reduce repeated credential entry. Logout tests can request a fresh session.
- [Page helpers](./src/pages) drive the demo and Microsoft pages.
- [Mobile API client](./src/mobile-api-client.ts) makes direct HTTP calls for protocol checks.

Mobile testing uses two browser contexts: the demo represents the app, while a separate system browser visits Microsoft. It is not a native mobile app or device test.

Each Playwright invocation uses one Chromium worker with no retries. Traces, screenshots and video are disabled. The [reporter](./src/reporter.ts) prints failures with their stage and category, followed by a per-flow summary.

## Pull-request CI

The [E2E workflow](../.github/workflows/e2e-tests.yml) runs each flow as a separate matrix job and combines the outcome in the `e2e` job.

Repository configuration must supply:

- **Actions variables:** `EXPRESS_URL`, `NESTJS_URL`, `FASTIFY_URL`, `HONOJS_URL`, `REACT_FRONTEND_URL`.
- **Actions secrets:** the fifteen `*1_AZURE_*` values and `E2E_USER_EMAIL` / `E2E_USER_PASSWORD`, using the names in [the env template](./.env.live.example).

The callback URLs registered in Entra must match the CI URLs as well as any local URLs you use. Fork pull requests normally cannot access repository secrets, so they cannot run this live-tenant suite without an appropriate trusted workflow.

When adding a spec named `NN-<flow>.spec.ts`, also add `<flow>` to `matrix.flow` in the workflow. Use `mobile-` in the flow name when it should be included by `test:mobile`.

## Troubleshooting

- **Missing or invalid environment variables:** check the names in `.env.live` and any shell overrides.
- **A server is already running:** stop your manual demo or choose different ports; the suite does not reuse existing servers.
- **Redirect URI mismatch:** register the exact browser and mobile callback paths for each server on its app registration. Red needs callbacks for both NestJS and Fastify.
- **Consent or permission errors:** check the OBO delegated permissions, B2B application permissions and admin consent in the [tenant checklist](../examples/README.md#the-entra-id-tenant).
- **Microsoft asks for MFA or another interactive challenge:** the automated login helper does not handle arbitrary tenant policies or account setup prompts.
- **Changes do not appear in a focused run:** rebuild the package and servers before invoking Playwright directly.

