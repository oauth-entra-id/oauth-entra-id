import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: Get Data reaches every other server with a B2B token`, async ({ site }) => {
    const app = await site.signedIn(server);

    for (const target of serverNames.filter((name) => name !== server)) {
      await test.step(`B2B data from ${target}`, async () => {
        await app.getB2BData(target);
      });
    }

    await test.step('the app-only route refuses a signed-in person', async () => {
      const serverUrl = env.servers[server].url;
      const signedIn = await app.visit(`${serverUrl}/protected/user-info`);
      expect(signedIn.status, 'I am still signed in on this server').toBe(200);
      const response = await app.visit(`${serverUrl}/protected/b2b-info`);
      expect([401, 403]).toContain(response.status);
    });
  });
}
