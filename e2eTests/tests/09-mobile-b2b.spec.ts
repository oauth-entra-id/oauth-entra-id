import { colors, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { fetchAppToken } from '../src/mobile-api-client';

for (const server of serverNames) {
  test(`${servers[server].label}: Get Data reaches every other server with a B2B token`, async ({ phone }) => {
    const { app } = await phone.signedIn(server);

    for (const target of serverNames.filter((name) => name !== server)) {
      await test.step(`B2B data from ${target}`, async () => {
        await app.getB2BData(target);
      });
    }
  });

  test(`${servers[server].label}: the mobile routes refuse an app token that is not a signed-in person's`, async ({
    mobileApi,
    request,
  }) => {
    const api = mobileApi(server);
    const caller = colors.find((color) => color !== servers[server].color) ?? 'blue';
    const appToken = await fetchAppToken(request, caller, servers[server].color);

    await test.step('a real app token of another registration is refused (B2B requests are not accepted here)', async () => {
      expect((await api.userInfo(appToken)).status()).toBe(403);
    });
  });
}
