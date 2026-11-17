import { liveEnv, serverNames, servers, short } from '../src/env';
import { expect, test } from '../src/fixtures';
import { looksLikeJwt } from '../src/mobile-api-client';
import { signInPrompt } from '../src/pages/microsoft';

const env = liveEnv();
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

for (const server of serverNames) {
  test(`${servers[server].label}: signing in from the phone shows my account`, async ({ phone, mobileApi }) => {
    const { user } = env;
    const registration = env.apps[servers[server].color];
    const { app, systemBrowser } = await phone.signedIn(server);

    await test.step('the app shows my account and the app registration', async () => {
      const profile = await app.profile();
      expect.soft(profile.email.toLowerCase()).toBe(user.email.toLowerCase());
      expect.soft(profile.azure).toBe(short(registration.clientId));
      expect.soft(profile.tenant).toBe(short(registration.tenantId));
      expect.soft(profile.uniqueId).toMatch(guid);
      expect.soft(profile.name).not.toBe('');
    });

    const tokens = await app.storedTokens();

    await test.step('the app got encrypted tokens', async () => {
      expect.soft(tokens?.accessToken, 'access token').toBeTruthy();
      expect.soft(tokens?.refreshToken, 'refresh token').toBeTruthy();
      expect.soft(looksLikeJwt(tokens?.accessToken ?? ''), 'the access token is a plain JWT').toBe(false);
    });

    await test.step('the system browser was sent back to the frontend of the login', async () => {
      expect.soft(systemBrowser.callbackLocation ?? '').toContain(env.frontend.origin);
    });

    await test.step('reloading keeps me signed in', async () => {
      await app.reload();
      await app.expectConnected();
    });

    await test.step('the protected address answers with my account', async () => {
      const response = await mobileApi(server).userInfo(tokens?.accessToken);
      expect(response.status()).toBe(200);
      expect((await response.json()).user.email.toLowerCase()).toBe(user.email.toLowerCase());
    });
  });
}

test('Express: Sign In with Email gives Microsoft my email and asks me to sign in again', async ({ phone }) => {
  const { user } = env;
  const device = await phone.knownToMicrosoft();
  const { app, systemBrowser } = device;
  let authorizeUrl = new URL(env.frontend.url);

  await test.step('Sign In with Email on Express while Microsoft already knows me', async () => {
    await app.open('express');
    await app.enableMobileMode();
    authorizeUrl = await app.startEmailLogin(user.email);
  });

  await test.step('Microsoft gets my email and the mobile callback, and asks for my credentials again', async () => {
    expect(authorizeUrl.searchParams.get('login_hint')).toBe(user.email);
    expect(authorizeUrl.searchParams.get('prompt')).toBe('login');
    expect(authorizeUrl.searchParams.get('redirect_uri')).toBe(`${env.servers.express.url}/auth/mobile/callback`);
    await systemBrowser.open(authorizeUrl);
    await expect(signInPrompt(systemBrowser.page, user)).toBeVisible();
  });

  await test.step('after signing in again the app shows my account', async () => {
    await device.completeLogin();
    expect((await app.profile()).email.toLowerCase()).toBe(user.email.toLowerCase());
  });
});

test('HonoJS: with Single Sign-On off Microsoft shows the account picker', async ({ phone }) => {
  const { user } = env;
  const device = await phone.knownToMicrosoft();
  const { app, systemBrowser } = device;
  let authorizeUrl = new URL(env.frontend.url);

  await test.step('turn Single Sign-On off on HonoJS and sign in with Microsoft', async () => {
    await app.open('honojs');
    await app.enableMobileMode();
    await app.setSingleSignOn(false);
    authorizeUrl = await app.startMicrosoftLogin();
  });

  await test.step('Microsoft asks me to pick an account although it knows me', async () => {
    expect(authorizeUrl.searchParams.get('prompt')).toBe('select_account');
    await systemBrowser.open(authorizeUrl);
    await expect(systemBrowser.page.getByText(/pick an account/i)).toBeVisible();
  });

  await test.step('after picking my account the app shows my account', async () => {
    await device.completeLogin();
    expect((await app.profile()).email.toLowerCase()).toBe(user.email.toLowerCase());
  });
});
