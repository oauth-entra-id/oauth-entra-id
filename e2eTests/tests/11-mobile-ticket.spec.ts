import { type Color, colors, liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { looksLikeJwt, tamper } from '../src/mobile-api-client';

const env = liveEnv();
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

for (const server of serverNames) {
  const { label, color } = servers[server];
  const registration = env.apps[color];

  test(`${label}: login gives the Microsoft address and a new ticket every time`, async ({ mobileApi }) => {
    const api = mobileApi(server);
    const first = await api.newLogin();
    const second = await api.newLogin();

    await test.step('the address is the authorization code request of my registration, secured with PKCE', async () => {
      const { url } = first;
      expect.soft(url.hostname).toBe('login.microsoftonline.com');
      expect.soft(url.pathname).toBe(`/${registration.tenantId}/oauth2/v2.0/authorize`);
      expect.soft(url.searchParams.get('client_id')).toBe(registration.clientId);
      expect.soft(url.searchParams.get('redirect_uri')).toBe(`${env.servers[server].url}/auth/mobile/callback`);
      expect.soft(url.searchParams.get('response_type')).toBe('code');
      expect.soft(url.searchParams.get('response_mode')).toBe('form_post');
      expect.soft(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect.soft(url.searchParams.get('code_challenge')).toMatch(/^[\w-]{43}$/);
      expect.soft(url.searchParams.get('nonce')).toMatch(guid);
      expect.soft(url.searchParams.get('state'), 'state').toBeTruthy();
    });

    await test.step('every login is new: ticket, state, nonce and code challenge differ', async () => {
      expect(second.ticket).not.toBe(first.ticket);
      for (const name of ['state', 'nonce', 'code_challenge']) {
        expect(second.url.searchParams.get(name), name).not.toBe(first.url.searchParams.get(name));
      }
    });

    await test.step('the ticket is encrypted, it is not a token', async () => {
      expect(first.ticket.length).toBeGreaterThan(40);
      expect(looksLikeJwt(first.ticket)).toBe(false);
    });
  });

  test(`${label}: tickets that are not mine or not intact are refused`, async ({ mobileApi }) => {
    const api = mobileApi(server);
    const otherServer = serverNames.find((name) => servers[name].color !== color) ?? 'honojs';
    const { ticket } = await api.newLogin();
    const foreign = (await mobileApi(otherServer).newLogin()).ticket;

    const cases: Array<[string, Record<string, unknown>]> = [
      ['no ticket', {}],
      ['an empty ticket', { ticket: '' }],
      ['garbage', { ticket: 'garbage' }],
      ['a tampered ticket', { ticket: tamper(ticket) }],
      [`a ticket of the ${servers[otherServer].label} server, which has another key`, { ticket: foreign }],
    ];
    for (const [name, body] of cases) {
      await test.step(name, async () => {
        const response = await api.exchange(body);
        expect([400, 401], `status of ${name}`).toContain(response.status());
        expect(await response.text(), 'tokens in the answer').not.toMatch(/accessToken/);
      });
    }
  });

  test(`${label}: refresh gives new working tokens, and only my access token is accepted`, async ({
    phone,
    mobileApi,
  }) => {
    const { app } = await phone.signedIn(server);
    const api = mobileApi(server);
    const tokens = await app.storedTokens();
    const other: Color = colors.find((name) => name !== color) ?? 'blue';
    let current = tokens?.refreshToken ?? '';

    await test.step('my access token is accepted, tokens that are not mine or not intact are refused', async () => {
      const accepted = await api.userInfo(tokens?.accessToken);
      expect(accepted.status()).toBe(200);
      expect((await accepted.json()).user.email.toLowerCase()).toBe(env.user.email.toLowerCase());

      await app.selectDownstream([other]);
      await app.getTokens();
      await app.expectToast('New token created!');
      const serviceToken = (await app.storedTokens())?.services[other];

      const refused: Array<[string, string | undefined]> = [
        ['no token', undefined],
        ['garbage', 'garbage'],
        ['a tampered token', tamper(tokens?.accessToken ?? '')],
        ['the refresh token', tokens?.refreshToken],
        [`a token for the ${other} service`, serviceToken],
      ];
      for (const [name, token] of refused) {
        expect((await api.userInfo(token)).status(), name).toBe(401);
      }
    });

    await test.step('refreshing again and again gives new tokens that work', async () => {
      for (let round = 1; round <= 3; round++) {
        const next = await api.refreshTokens(current);
        expect(next.accessToken, `access token ${round}`).toBeTruthy();
        expect(next.refreshToken, `refresh token ${round}`).not.toBe(current);
        expect(looksLikeJwt(next.accessToken), `access token ${round} is a plain JWT`).toBe(false);
        expect((await api.userInfo(next.accessToken)).status(), `access token ${round} works`).toBe(200);
        current = next.refreshToken;
      }
    });

    await test.step('a refresh is refused for anything that is not my refresh token', async () => {
      const cases: Array<[string, Record<string, unknown>]> = [
        ['no token', {}],
        ['an empty token', { refreshToken: '' }],
        ['garbage', { refreshToken: 'garbage' }],
        ['a tampered refresh token', { refreshToken: tamper(current) }],
        ['my access token', { refreshToken: tokens?.accessToken }],
      ];
      for (const [name, body] of cases) {
        const response = await api.refresh(body);
        expect([400, 401], `status of ${name}`).toContain(response.status());
        expect(await response.text(), 'tokens in the answer').not.toMatch(/accessToken/);
      }
    });
  });
}
