import { LiteProvider, type OAuthConfig, OAuthError, OAuthProvider } from 'oauth-entra-id';
import { liveEnv } from '../src/env';
import { expect, test } from '../src/fixtures';
import { tamper } from '../src/mobile-api-client';
import { azureOf, exposedScopeOf } from '../src/registrations';

// The full OAuthProvider used directly, with no example server. Only what the flows through the example servers
// (01 to 12) do not already check: input validation, the encryption options and the B2B tokens with their cache.

const env = liveEnv();

function configOf(
  advanced?: NonNullable<OAuthConfig['advanced']>,
  azure: OAuthConfig['azure'] = azureOf('yellow'),
): OAuthConfig {
  return {
    azure,
    frontendUrl: env.frontend.url,
    serverCallbackUrl: `${env.servers.express.url}/auth/callback`,
    encryptionKey: 'e'.repeat(40),
    advanced,
  };
}

async function thrown(run: () => Promise<unknown>): Promise<OAuthError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(OAuthError);
    return error as OAuthError;
  }
  throw new Error('Expected the call to throw an OAuthError');
}

test('login and logout refuse input that is not valid', async () => {
  const provider = new OAuthProvider(configOf());

  const login: Array<[string, Parameters<OAuthProvider['getAuthUrl']>[0]]> = [
    ['an email that is not an email', { email: 'nope' }],
    ['a login prompt that does not exist', { loginPrompt: 'nope' as 'sso' }],
    ['a frontend URL that is not a URL', { frontendUrl: 'nope' }],
    ['an Azure ID that is not a GUID', { azureId: 'nope' }],
  ];
  for (const [name, params] of login) {
    await test.step(`login: ${name}`, async () => {
      await thrown(() => provider.getAuthUrl(params));
    });
  }

  const logout: Array<[string, Parameters<OAuthProvider['getLogoutUrl']>[0]]> = [
    ['a frontend URL that is not a URL', { frontendUrl: 'nope' }],
    ['an Azure ID that is not a GUID', { azureId: 'nope' }],
  ];
  for (const [name, params] of logout) {
    await test.step(`logout: ${name}`, async () => {
      await thrown(() => provider.getLogoutUrl(params));
    });
  }
});

test('a ticket can be read back with every crypto and compression setting', async () => {
  for (const cryptoType of ['node', 'web-api'] as const) {
    for (const disableCompression of [false, true]) {
      const name = `${cryptoType}, compression ${disableCompression ? 'off' : 'on'}`;
      const provider = new OAuthProvider(configOf({ cryptoType, disableCompression }));
      const { ticket } = await provider.getAuthUrl();

      const { ticketId, error } = await provider.tryDecryptTicket(ticket);
      expect(error, name).toBeUndefined();
      expect(ticketId, name).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      expect(ticket, `${name}: the ticket is encrypted`).not.toContain(ticketId ?? '');
      expect((await provider.tryDecryptTicket(tamper(ticket))).error, `${name}: a tampered ticket`).toBeDefined();
    }
  }
});

test('tryGetB2BToken refuses a missing B2B setup, unknown apps and bad params', async () => {
  const without = new OAuthProvider(configOf());
  expect((await without.tryGetB2BToken({ app: 'red' })).error?.statusCode).toBe(500);

  const provider = new OAuthProvider(
    configOf(undefined, { ...azureOf('yellow'), b2bApps: [{ appName: 'red', scope: exposedScopeOf('red') }] }),
  );
  const unknown = await provider.tryGetB2BToken({ app: 'unknown' });
  expect(unknown.error?.statusCode).toBe(400);
  expect(unknown.error?.description).toMatch(/not found/i);

  // The package leaves the status code of these two errors undefined, so only the refusal itself is checked.
  expect((await provider.tryGetB2BToken({ apps: [] })).error).toBeDefined();
  expect((await provider.tryGetB2BToken({ app: '' })).error).toBeDefined();
});

test('tryGetB2BToken gets real app tokens that the lite provider verifies, and caches them', async () => {
  const provider = new OAuthProvider(
    configOf(undefined, {
      ...azureOf('yellow'),
      b2bApps: [
        { appName: 'red', scope: exposedScopeOf('red') },
        { appName: 'blue', scope: exposedScopeOf('blue') },
      ],
    }),
  );

  await test.step('one app, verified by the lite provider of that app', async () => {
    const { result, error } = await provider.tryGetB2BToken({ app: 'red' });
    expect(error).toBeUndefined();
    expect(result?.appName).toBe('red');
    expect(result?.clientId, 'the registration that asked for the token').toBe(azureOf('yellow').clientId);

    const lite = new LiteProvider({ azure: { clientId: azureOf('red').clientId, tenantId: azureOf('red').tenantId } });
    const verified = await lite.$verifyJwt(result?.token);
    expect(verified.error).toBeUndefined();
    expect(verified.meta?.isApp).toBe(true);
    expect(result?.appId, 'the app the token was made for is the one the lite provider verified').toBe(
      verified.meta?.audience,
    );
  });

  await test.step('the token is cached', async () => {
    const first = await provider.tryGetB2BToken({ app: 'red' });
    const second = await provider.tryGetB2BToken({ app: 'red' });
    expect(second.result?.isCached).toBe(true);
    expect(second.result?.token).toBe(first.result?.token);
    expect(second.result?.expiresAt).toBeGreaterThan(Date.now() / 1000);
  });

  await test.step('several apps at once, each with its own token', async () => {
    const { results, error } = await provider.tryGetB2BToken({ apps: ['red', 'blue'] });
    expect(error).toBeUndefined();
    expect(results?.map(({ appName }) => appName).sort()).toEqual(['blue', 'red']);
    expect(new Set(results?.map(({ token }) => token)).size).toBe(2);
  });
});
