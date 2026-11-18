import { type Color, colors, liveEnv, serverNames, servers, short } from '../src/env';
import { expect, test } from '../src/fixtures';
import { looksLikeJwt } from '../src/mobile-api-client';
import type { MobileSite } from '../src/pages/mobile-app-page';

const env = liveEnv();

async function expectServersAccept(app: MobileSite, accepted: Color[]): Promise<void> {
  for (const server of serverNames) {
    const { color, label } = servers[server];
    const accepts = accepted.includes(color);
    await test.step(`${label} ${accepts ? 'accepts' : 'refuses'} my token`, async () => {
      await app.chooseServer(server);
      await app.reload();
      if (accepts) {
        await app.expectConnected();
        expect((await app.profile()).azure).toBe(short(env.apps[color].clientId));
      } else {
        await app.expectGuest();
      }
    });
  }
}

async function expectServiceTokens(app: MobileSite, downstream: Color[]): Promise<void> {
  const tokens = await app.storedTokens();
  expect(Object.keys(tokens?.services ?? {}).sort(), 'tokens kept by the app').toEqual([...downstream].sort());
  for (const color of downstream) {
    expect(looksLikeJwt(tokens?.services[color] ?? ''), `the ${color} service token is a plain JWT`).toBe(false);
  }
}

for (const server of serverNames) {
  test(`${servers[server].label}: Get Tokens creates downstream tokens that the downstream servers accept`, async ({
    phone,
  }) => {
    const { app } = await phone.signedIn(server);
    const own = servers[server].color;
    const others = colors.filter((color) => color !== own);
    const [first] = others as [Color, ...Color[]];

    await test.step(`one service (${first})`, async () => {
      await app.selectDownstream([first]);
      await app.getTokens();
      await app.expectToast('New token created!');
      await expectServiceTokens(app, [first]);
      await expectServersAccept(app, [own, first]);
    });

    await test.step(`all other services (${others.join(', ')})`, async () => {
      await app.chooseServer(server);
      await app.reload();
      await app.expectConnected();
      await app.selectDownstream(others);
      await app.getTokens();
      await app.expectToast(`${others.length} new tokens created!`);
      await expectServiceTokens(app, others);
      await expectServersAccept(app, [own, ...others]);
    });
  });

  test(`${servers[server].label}: on-behalf-of is refused for an unknown service and for tokens that are not mine`, async ({
    phone,
    mobileApi,
  }) => {
    const { app } = await phone.signedIn(server);
    const api = mobileApi(server);
    const tokens = await app.storedTokens();
    const other = colors.find((color) => color !== servers[server].color) ?? 'blue';

    const cases: Array<[string, string | undefined, Record<string, unknown>, number]> = [
      ['a service that is not configured', tokens?.accessToken, { services: ['unknown-service'] }, 400],
      ['no access token', undefined, { services: [other] }, 401],
      ['garbage as the access token', 'garbage', { services: [other] }, 401],
      ['the refresh token as the access token', tokens?.refreshToken, { services: [other] }, 401],
    ];
    for (const [name, accessToken, body, status] of cases) {
      await test.step(name, async () => {
        const response = await api.onBehalfOf(accessToken, body);
        expect(response.status(), `status of ${name}`).toBe(status);
        expect(await response.text(), 'tokens in the answer').not.toMatch(/"value"/);
      });
    }

    await test.step('my access token still gets a token for a configured service', async () => {
      const response = await api.onBehalfOf(tokens?.accessToken, { services: [other] });
      expect(response.status()).toBe(200);
      const { tokens: issued } = (await response.json()) as { tokens: Array<{ serviceName: string; value: string }> };
      expect(issued.map((token) => token.serviceName)).toEqual([other]);
      expect(looksLikeJwt(issued[0]?.value ?? ''), 'the service token is a plain JWT').toBe(false);
    });
  });
}
