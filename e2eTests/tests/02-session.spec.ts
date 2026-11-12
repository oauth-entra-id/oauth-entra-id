import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: the session survives reloads and silent refresh, and tampered cookies end it`, async ({
    site,
  }) => {
    const app = await site.signedIn(server);
    const { clientId } = env.apps[servers[server].color];
    const accessCookie = `at-${clientId}`;
    const refreshCookie = `rt-${clientId}`;
    const userInfoUrl = `${env.servers[server].url}/protected/user-info`;
    let injected: number | undefined;

    await test.step('reloading keeps me signed in with the same injected data', async () => {
      injected = (await app.profile()).injected;
      expect(injected, 'injected data').toBeDefined();
      await app.reload();
      await app.expectConnected();
      expect((await app.profile()).injected).toBe(injected);
    });

    await test.step('without the access cookie the server refreshes my session silently', async () => {
      await app.removeCookie(accessCookie);
      expect(await app.hasCookie(accessCookie), 'the access cookie is removed').toBe(false);
      await app.reload();
      await app.expectConnected();
      expect(await app.hasCookie(accessCookie), 'the access cookie is set again').toBe(true);
      expect(await app.hasCookie(refreshCookie), 'the refresh cookie is still set').toBe(true);
      expect((await app.profile()).injected, 'injected data after refresh').toBeDefined();
      expect((await app.visit(userInfoUrl)).status).toBe(200);
    });

    await test.step('tampered cookies end my session', async () => {
      await app.tamperCookie(accessCookie);
      await app.tamperCookie(refreshCookie);
      await app.reload();
      await app.expectGuest();
      expect((await app.visit(userInfoUrl)).status).toBe(401);
    });
  });
}
