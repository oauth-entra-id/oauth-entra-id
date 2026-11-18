import { type Color, colors, liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { fetchAppToken, tamper } from '../src/mobile-api-client';

const env = liveEnv();

for (const server of serverNames) {
  test(`${servers[server].label}: the B2B route accepts an app token made for it and nothing else`, async ({
    request,
  }) => {
    const own = servers[server].color;
    const [caller, otherService] = colors.filter((color) => color !== own) as [Color, Color];
    const url = `${env.servers[server].url}/protected/b2b-info`;
    const get = (token?: string) =>
      request.get(url, { headers: token === undefined ? {} : { Authorization: `Bearer ${token}` } });

    const forMe = await fetchAppToken(request, caller, own);
    const forAnother = await fetchAppToken(request, caller, otherService);

    await test.step('an app token made for this server is accepted', async () => {
      expect((await get(forMe)).status()).toBe(200);
    });

    await test.step('tokens that are not an app token made for this server are refused', async () => {
      const refused: Array<[string, string | undefined]> = [
        ['no token', undefined],
        ['garbage', 'garbage'],
        ['a tampered app token', tamper(forMe)],
        [`an app token made for the ${otherService} service`, forAnother],
      ];
      for (const [name, token] of refused) {
        expect([401, 403], `status of ${name}`).toContain((await get(token)).status());
      }
    });
  });
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
