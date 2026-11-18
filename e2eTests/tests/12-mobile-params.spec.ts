import { liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { tamper } from '../src/mobile-api-client';

const env = liveEnv();

for (const server of serverNames) {
  const { label } = servers[server];

  test(`${label}: the login options reach Microsoft as asked`, async ({ mobileApi }) => {
    const api = mobileApi(server);
    const { email } = env.user;

    const cases: Array<[string, Record<string, unknown>, { prompt: string | null; hint: string | null }]> = [
      ['by default Single Sign-On is used: no prompt, no hint', {}, { prompt: null, hint: null }],
      ['the account picker', { loginPrompt: 'select-account' }, { prompt: 'select_account', hint: null }],
      ['the email prompt', { loginPrompt: 'email', email }, { prompt: 'login', hint: email }],
      ['an email alone asks to sign in again', { email }, { prompt: 'login', hint: email }],
    ];
    for (const [name, body, expected] of cases) {
      await test.step(name, async () => {
        const { url } = await api.newLogin(body);
        expect.soft(url.searchParams.get('prompt'), 'prompt').toBe(expected.prompt);
        expect.soft(url.searchParams.get('login_hint'), 'login_hint').toBe(expected.hint);
      });
    }

    await test.step('the email prompt without an email is refused', async () => {
      const response = await api.login({ loginPrompt: 'email' });
      expect(response.status()).toBe(400);
      expect(await response.text()).not.toMatch(/login\.microsoftonline\.com/);
    });
  });

  test(`${label}: only a frontend URL of a listed host is accepted`, async ({ mobileApi }) => {
    const api = mobileApi(server);
    const listed = `${env.frontend.origin}/somewhere`;
    const unlisted = [
      ['another website', 'https://evil.example.com/'],
      ['the listed host on another port', `http://localhost:${env.frontend.port + 1}/`],
    ] as const;

    await test.step('a frontend URL of the listed host is accepted by login and logout', async () => {
      expect((await api.login({ frontendUrl: listed })).status()).toBe(200);
      const response = await api.logout({ frontendUrl: listed });
      expect(response.status()).toBe(200);
      const { url } = (await response.json()) as { url: string };
      expect(new URL(url).searchParams.get('post_logout_redirect_uri')).toBe(listed);
    });

    for (const [name, frontendUrl] of unlisted) {
      await test.step(`${name} is refused by login and logout`, async () => {
        const login = await api.login({ frontendUrl });
        expect(login.status(), 'login').toBe(403);
        expect(await login.text(), 'login answer').not.toMatch(/login\.microsoftonline\.com/);

        const logout = await api.logout({ frontendUrl });
        expect(logout.status(), 'logout').toBe(403);
        expect(await logout.text(), 'logout answer').not.toMatch(/login\.microsoftonline\.com/);
      });
    }
  });

  test(`${label}: the callback gives nothing for a state or a code that Microsoft did not give`, async ({
    mobileApi,
  }) => {
    const api = mobileApi(server);
    const otherServer = serverNames.find((name) => servers[name].color !== servers[server].color) ?? 'honojs';
    const { url, ticket } = await api.newLogin();
    const state = url.searchParams.get('state') ?? '';
    const foreignState = (await mobileApi(otherServer).newLogin()).url.searchParams.get('state') ?? '';

    const cases: Array<[string, Record<string, string>]> = [
      ['garbage as the state', { code: 'code', state: 'garbage' }],
      ['a tampered state', { code: 'code', state: tamper(state) }],
      [
        `a state of the ${servers[otherServer].label} server, which has another key`,
        { code: 'code', state: foreignState },
      ],
      ['a genuine state with a code that Microsoft never gave', { code: 'made-up-code', state }],
    ];
    for (const [name, form] of cases) {
      await test.step(name, async () => {
        const response = await api.callback(form);
        expect(response.status(), `status of ${name}`).toBeGreaterThanOrEqual(400);
        expect(response.status(), `status of ${name}`).toBeLessThan(500);
        expect(response.headers().location, 'redirect').toBeUndefined();
        expect(await response.text(), 'tokens in the answer').not.toMatch(/accessToken/);
      });
    }

    await test.step('no tokens wait for the ticket of that login', async () => {
      const response = await api.exchange({ ticket });
      expect(response.ok(), 'status of the exchange').toBe(false);
      expect(await response.text(), 'tokens in the answer').not.toMatch(/accessToken/);
    });
  });
}
