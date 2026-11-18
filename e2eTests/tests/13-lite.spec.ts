import { LiteProvider } from 'oauth-entra-id';
import { type Color, colors, liveEnv, serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { fetchAppToken, tamper } from '../src/mobile-api-client';

const env = liveEnv();

// Every example server has one LiteProvider (with a secret and B2B apps). It verifies plain app tokens on `/lite/b2b-info`
// and gets them for the other servers on `/lite/get-b2b-info`.
for (const server of serverNames) {
  const { label, color: own } = servers[server];
  const liteUrl = `${env.servers[server].url}/lite`;

  test(`${label}: the lite route accepts an app token made for it and nothing else`, async ({ request }) => {
    const [caller, otherService] = colors.filter((color) => color !== own) as [Color, Color];
    const get = (authorization?: string) =>
      request.get(`${liteUrl}/b2b-info`, {
        headers: authorization === undefined ? {} : { Authorization: authorization },
      });

    const forMe = await fetchAppToken(request, caller, own);
    const forAnother = await fetchAppToken(request, caller, otherService);

    await test.step('an app token made for this server is accepted and described', async () => {
      const response = await get(`Bearer ${forMe}`);
      expect(response.status()).toBe(200);
      const { server: answeredBy, meta } = (await response.json()) as {
        server: string;
        meta: { isApp: boolean; audience: string; tenantId: string; appId: string };
      };
      expect(answeredBy).toBe(server);
      expect(meta.isApp).toBe(true);
      expect(meta.audience).toBe(env.apps[own].clientId);
      expect(meta.tenantId).toBe(env.apps[own].tenantId);
      expect(meta.appId).toBe(env.apps[caller].clientId);
    });

    await test.step('anything else is refused as unauthorized', async () => {
      const refused: Array<[string, string | undefined]> = [
        ['no token', undefined],
        ['an empty bearer', 'Bearer '],
        ['garbage', 'Bearer garbage'],
        ['a token that is too long', `Bearer ${'a'.repeat(5000)}`],
        ['a tampered app token', `Bearer ${tamper(forMe)}`],
        [`an app token made for the ${otherService} service`, `Bearer ${forAnother}`],
      ];
      for (const [name, authorization] of refused) {
        expect((await get(authorization)).status(), `status of ${name}`).toBe(401);
      }
    });
  });

  test(`${label}: lite gets a B2B token for every other server and keeps it`, async ({ request }) => {
    const post = (data: unknown) => request.post(`${liteUrl}/get-b2b-info`, { data });
    const targets = serverNames.filter((name) => name !== server);

    for (const target of targets) {
      await test.step(`B2B data from ${target}`, async () => {
        const response = await post({ app: target });
        expect(response.status()).toBe(200);
        const body = (await response.json()) as { server: string; pokemon: string };
        expect(body.server).toBe(target);
        expect(body.pokemon).toBeTruthy();
      });
    }

    await test.step('the token is cached and keeps the same expiry', async () => {
      const first = (await (await post({ app: targets[0] })).json()) as { isCached: boolean; expiresAt: number };
      const second = (await (await post({ app: targets[0] })).json()) as { isCached: boolean; expiresAt: number };

      expect(second.isCached).toBe(true);
      expect(second.expiresAt).toBeGreaterThan(Date.now() / 1000);
      expect(second.expiresAt).toBeLessThan(Date.now() / 1000 + 24 * 60 * 60);
      expect(second.expiresAt).toBe(first.expiresAt);
    });
  });
}

// The package alone, no example server: how a LiteProvider behaves without a secret, and what it refuses.
test.describe('LiteProvider used directly', () => {
  const { clientId, tenantId } = env.apps.red;
  const b2bApps = [{ appName: 'blue', scope: 'api://blue/.default' }] as [{ appName: string; scope: string }];

  test('without a secret it verifies app tokens but cannot get B2B tokens', async ({ request }) => {
    const lite = new LiteProvider({ azure: { clientId, tenantId } });

    await test.step('a valid app token is verified', async () => {
      const { meta, error } = await lite.$verifyJwt(await fetchAppToken(request, 'yellow', 'red'));
      expect(error).toBeUndefined();
      expect(meta?.isApp).toBe(true);
      expect(meta?.audience).toBe(clientId);
    });

    await test.step('B2B tokens are not available', async () => {
      const { error } = await lite.tryGetB2BToken({ app: 'blue' });
      expect(error?.statusCode).toBe(500);
      expect(error?.description).toMatch(/not configured/i);
    });
  });

  test('with a secret and B2B apps, unknown apps and bad params are refused', async () => {
    const lite = new LiteProvider({ azure: { clientId, tenantId, clientSecret: 's'.repeat(40), b2bApps } });

    const unknown = await lite.tryGetB2BToken({ app: 'unknown' });
    expect(unknown.error?.statusCode).toBe(400);
    expect(unknown.error?.description).toMatch(/not found/i);

    const noApps = await lite.tryGetB2BToken({ apps: [] });
    expect(noApps.error?.statusCode).toBe(400);
  });

  test('the tenant must match, unless it is "common"', async ({ request }) => {
    const forMe = await fetchAppToken(request, 'yellow', 'red');
    const otherTenant = '00000000-0000-4000-8000-000000000000';

    const wrongTenant = await new LiteProvider({ azure: { clientId, tenantId: otherTenant } }).$verifyJwt(forMe);
    expect(wrongTenant.error?.statusCode).toBe(401);

    const anyTenant = await new LiteProvider({ azure: { clientId, tenantId: 'common' } }).$verifyJwt(forMe);
    expect(anyTenant.error).toBeUndefined();
  });

  // A real token is rebuilt so that everything the package reads (key ID, tenant, issuer, audience) is genuine, and
  // only the part that proves who made it is forged. The package must refuse every one of them.
  test('a token with a real payload but a forged signature or algorithm is refused', async ({ request }) => {
    const lite = new LiteProvider({ azure: { clientId, tenantId } });
    const real = await fetchAppToken(request, 'yellow', 'red');
    const [header = '', payload = '', signature = ''] = real.split('.');
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const decode = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString());

    await test.step('the real token is accepted', async () => {
      expect((await lite.$verifyJwt(real)).error).toBeUndefined();
    });

    const forged: Array<[string, string]> = [
      ['no signature, algorithm "none"', `${encode({ ...decode(header), alg: 'none' })}.${payload}.`],
      [
        'the real signature under the algorithm "none"',
        `${encode({ ...decode(header), alg: 'none' })}.${payload}.${signature}`,
      ],
      [
        'the real signature under a symmetric algorithm',
        `${encode({ ...decode(header), alg: 'HS256' })}.${payload}.${signature}`,
      ],
      [
        'a changed payload with the real signature',
        `${header}.${encode({ ...decode(payload), roles: ['admin'] })}.${signature}`,
      ],
      ['the real header and payload with no signature', `${header}.${payload}.`],
    ];
    for (const [name, token] of forged) {
      await test.step(name, async () => {
        expect((await lite.$verifyJwt(token)).error?.statusCode, `status of ${name}`).toBe(401);
      });
    }
  });
});
