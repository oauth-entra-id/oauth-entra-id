import { type Color, colors, liveEnv, serverNames, servers, short } from '../src/env';
import { expect, test } from '../src/fixtures';
import type { Site } from '../src/pages/site';

const env = liveEnv();

async function expectServersAccept(app: Site, accepted: Color[]): Promise<void> {
  for (const server of serverNames) {
    const { color, label } = servers[server];
    const accepts = accepted.includes(color);
    await test.step(`${label} ${accepts ? 'accepts' : 'refuses'} my cookies`, async () => {
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

async function expectTokenCookies(app: Site, downstream: Color[]): Promise<void> {
  for (const color of downstream) {
    const cookie = await app.cookie(`at-${env.apps[color].clientId}`);
    expect(cookie?.httpOnly, `${color} service cookie is HttpOnly`).toBe(true);
  }
}

for (const server of serverNames) {
  test(`${servers[server].label}: Get Tokens creates downstream tokens that the downstream servers accept`, async ({
    site,
  }) => {
    const app = await site.signedIn(server);
    const own = servers[server].color;
    const others = colors.filter((color) => color !== own);
    const [first] = others as [Color, ...Color[]];

    await test.step(`one service (${first})`, async () => {
      await app.selectDownstream([first]);
      await app.getTokens();
      await app.expectToast('New token created!');
      await expectTokenCookies(app, [first]);
      await expectServersAccept(app, [own, first]);
    });

    await test.step(`all other services (${others.join(', ')})`, async () => {
      await app.chooseServer(server);
      await app.reload();
      await app.expectConnected();
      await app.selectDownstream(others);
      await app.getTokens();
      await app.expectToast(`${others.length} new tokens created!`);
      await expectTokenCookies(app, others);
      await expectServersAccept(app, [own, ...others]);
    });
  });
}
