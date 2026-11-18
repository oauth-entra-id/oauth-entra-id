import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { microsoftHost } from '../src/pages/microsoft';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: Logout ends my session and opens the Microsoft logout page of my tenant`, async ({
    phone,
  }) => {
    const registration = env.apps[servers[server].color];
    const { app } = await phone.signedIn(server, { freshMicrosoftSession: true });

    const logoutUrl = await app.signOut();

    await test.step('the app opens the Microsoft logout page of my tenant', async () => {
      expect(logoutUrl.hostname).toBe(microsoftHost);
      expect(logoutUrl.pathname).toBe(`/${registration.tenantId}/oauth2/v2.0/logout`);
      expect(logoutUrl.searchParams.get('post_logout_redirect_uri') ?? '').toContain(env.frontend.origin);
    });

    await test.step('the app shows the guest page', async () => {
      await app.expectGuest();
    });
  });
}
