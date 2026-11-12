import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { finishMicrosoftSignOut, microsoftHost, signInPrompt } from '../src/pages/microsoft';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: Logout ends my session here and at Microsoft`, async ({ site }) => {
    const { user } = env;
    const registration = env.apps[servers[server].color];
    const userInfoUrl = `${env.servers[server].url}/protected/user-info`;
    const app = await site.signedIn(server, { freshMicrosoftSession: true });

    const { tab, logoutUrl } = await app.logout();

    await test.step('a new tab opens the Microsoft logout page of my tenant', async () => {
      expect(logoutUrl.hostname).toBe(microsoftHost);
      expect(logoutUrl.pathname).toBe(`/${registration.tenantId}/oauth2/v2.0/logout`);
      expect(logoutUrl.searchParams.get('post_logout_redirect_uri') ?? '').toContain(env.frontend.origin);
    });

    await test.step('the site shows the guest page and my cookies are gone', async () => {
      await app.expectGuest();
      expect((await app.sessionCookies()).map((cookie) => cookie.name)).toEqual([]);
      await app.reload();
      await app.expectGuest();
      expect((await app.visit(userInfoUrl)).status).toBe(401);
    });

    await test.step('after finishing the Microsoft sign-out, Microsoft asks me to sign in again', async () => {
      await finishMicrosoftSignOut(tab, user, env.frontend.origin);
      await tab.close();
      await app.clickMicrosoft();
      await expect(signInPrompt(app.page, user)).toBeVisible();
    });
  });
}
