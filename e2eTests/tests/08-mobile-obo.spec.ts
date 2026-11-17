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
}
