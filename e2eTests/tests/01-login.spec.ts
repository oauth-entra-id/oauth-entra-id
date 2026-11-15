import { liveEnv, serverNames, servers, short } from '../src/env';
import { expect, test } from '../src/fixtures';
import { signInPrompt } from '../src/pages/microsoft';

const env = liveEnv();
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

for (const server of serverNames) {
  test(`${servers[server].label}: signing in with Microsoft shows my account`, async ({ site }) => {
    const { user } = env;
    const registration = env.apps[servers[server].color];
    const app = await site.signedIn(server);
    let injected: number | undefined;

    await test.step('the page shows my account and the app registration', async () => {
      const profile = await app.profile();
      injected = profile.injected;
      expect.soft(profile.email.toLowerCase()).toBe(user.email.toLowerCase());
      expect.soft(profile.azure).toBe(short(registration.clientId));
      expect.soft(profile.tenant).toBe(short(registration.tenantId));
      expect.soft(profile.uniqueId).toMatch(guid);
      expect.soft(profile.name).not.toBe('');
      expect.soft(profile.injected, 'injected data').toBeDefined();
    });

    await test.step('the browser holds HttpOnly session cookies for this registration', async () => {
      for (const prefix of ['at', 'rt']) {
        const cookie = await app.cookie(`${prefix}-${registration.clientId}`);
        expect.soft(cookie?.httpOnly, `${prefix} cookie is HttpOnly`).toBe(true);
        expect.soft(cookie?.path, `${prefix} cookie path`).toBe('/');
      }
    });

    await test.step('no token or cookie value is visible to the page', async () => {
      const visible = await app.browserStorage();
      expect(/eyJ[\w-]+\.[\w-]+\./.test(visible), 'a token is visible to the page').toBe(false);
      for (const cookie of await app.sessionCookies()) {
        expect(visible.includes(cookie.value), `the value of cookie ${cookie.name} is visible to the page`).toBe(false);
      }
    });

    await test.step('reloading keeps me signed in with the same injected data', async () => {
      await app.reload();
      await app.expectConnected();
      expect((await app.profile()).injected).toBe(injected);
    });

    await test.step('the protected address answers with my account', async () => {
      const response = await app.visit(`${env.servers[server].url}/protected/user-info`);
      expect(response.status).toBe(200);
      expect(JSON.parse(response.text).user.email.toLowerCase()).toBe(user.email.toLowerCase());
    });
  });
}

test('Express: Sign In with Email gives Microsoft my email and asks me to sign in again', async ({ site }) => {
  const { user } = env;
  const app = await site.knownToMicrosoft();

  await test.step('Sign In with Email on Express while Microsoft already knows me', async () => {
    await app.open('express');
    await app.clickSignInWithEmail(user.email);
  });

  await test.step('Microsoft gets my email and asks for my credentials again', async () => {
    const authorizeUrl = new URL(app.page.url());
    expect(authorizeUrl.searchParams.get('login_hint')).toBe(user.email);
    expect(authorizeUrl.searchParams.get('prompt')).toBe('login');
    await expect(signInPrompt(app.page, user)).toBeVisible();
  });

  await test.step('after signing in again the page shows my account', async () => {
    await app.completeMicrosoftSignIn();
    await app.expectConnected();
    expect((await app.profile()).email.toLowerCase()).toBe(user.email.toLowerCase());
  });
});

test('HonoJS: with Single Sign-On off Microsoft shows the account picker', async ({ site }) => {
  const { user } = env;
  const app = await site.knownToMicrosoft();

  await test.step('turn Single Sign-On off on HonoJS and sign in with Microsoft', async () => {
    await app.open('honojs');
    await app.setSingleSignOn(false);
    await app.clickMicrosoft();
  });

  await test.step('Microsoft asks me to pick an account although it knows me', async () => {
    expect(new URL(app.page.url()).searchParams.get('prompt')).toBe('select_account');
    await expect(app.page.getByText(/pick an account/i)).toBeVisible();
  });

  await test.step('after picking my account the page shows my account', async () => {
    await app.completeMicrosoftSignIn();
    await app.expectConnected();
    expect((await app.profile()).email.toLowerCase()).toBe(user.email.toLowerCase());
  });
});
