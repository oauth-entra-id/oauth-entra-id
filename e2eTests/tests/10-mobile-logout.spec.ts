import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { finishMicrosoftSignOut, microsoftHost, signInPrompt } from '../src/pages/microsoft';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: Logout ends my session here and at Microsoft`, async ({ phone }) => {
    const { user } = env;
    const registration = env.apps[servers[server].color];
    const { app, systemBrowser } = await phone.signedIn(server, { freshMicrosoftSession: true });

    const logoutUrl = await app.signOut();

    await test.step('the app opens the Microsoft logout page of my tenant', async () => {
      expect(logoutUrl.hostname).toBe(microsoftHost);
      expect(logoutUrl.pathname).toBe(`/${registration.tenantId}/oauth2/v2.0/logout`);
      expect(logoutUrl.searchParams.get('post_logout_redirect_uri') ?? '').toContain(env.frontend.origin);
    });

    await test.step('after finishing the Microsoft sign-out in the phone browser, Microsoft asks me to sign in again', async () => {
      await app.expectGuest();
      await systemBrowser.open(logoutUrl);
      await finishMicrosoftSignOut(systemBrowser.page, user, env.frontend.origin);
      await systemBrowser.open(await app.startMicrosoftLogin());
      await expect(signInPrompt(systemBrowser.page, user)).toBeVisible();
    });
  });
}
