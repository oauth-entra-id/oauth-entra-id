import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PlaywrightTestConfig } from '@playwright/test';
import { colors, type LiveEnv, repoRoot, serverNames, servers } from './env';

type WebServers = NonNullable<PlaywrightTestConfig['webServer']>;

function secretKey(): string {
  return randomBytes(32).toString('hex');
}

// The example servers are configured with two Azure registrations per app and refuse to start without the second.
// The tests only use the first, so the second gets valid but inert values that never reach Microsoft.
function unusedSecondRegistration(): Record<string, string> {
  return Object.fromEntries(
    colors.flatMap((color) => {
      const prefix = `${color.toUpperCase()}2_AZURE`;
      return [
        [`${prefix}_CLIENT_ID`, randomUUID()],
        [`${prefix}_TENANT_ID`, randomUUID()],
        [`${prefix}_CUSTOM_SCOPE`, 'api://unused/e2e'],
        [`${prefix}_CLIENT_SECRET`, secretKey()],
        [`${prefix}_EXPOSED_SCOPE`, 'api://unused/.default'],
      ];
    }),
  );
}

export function webServers(env: LiveEnv): WebServers {
  const isolatedCwd = join(tmpdir(), 'oauth-entra-id-e2e', 'a', 'b');
  mkdirSync(isolatedCwd, { recursive: true });

  const serverEnv: Record<string, string> = {
    NODE_ENV: 'development',
    REACT_FRONTEND_URL: env.frontend.url,
    YELLOW_SECRET_KEY: secretKey(),
    RED_SECRET_KEY: secretKey(),
    BLUE_SECRET_KEY: secretKey(),
    ...unusedSecondRegistration(),
  };
  for (const name of serverNames) {
    serverEnv[`${servers[name].prefix}_URL`] = env.servers[name].url;
    serverEnv[`${servers[name].prefix}_PORT`] = String(env.servers[name].port);
  }

  return [
    ...serverNames.map((name) => ({
      name: servers[name].label,
      command: `node "${servers[name].entry}"`,
      cwd: isolatedCwd,
      env: serverEnv,
      url: `${env.servers[name].url}/app-info`,
      reuseExistingServer: false,
      timeout: 90_000,
    })),
    {
      name: 'React demo',
      command: `pnpm exec vite --host localhost --port ${env.frontend.port}`,
      cwd: join(repoRoot, 'examples', 'frontend-react'),
      env: {
        VITE_EXPRESS_URL: env.servers.express.url,
        VITE_NESTJS_URL: env.servers.nestjs.url,
        VITE_FASTIFY_URL: env.servers.fastify.url,
        VITE_HONOJS_URL: env.servers.honojs.url,
      },
      url: env.frontend.url,
      reuseExistingServer: false,
      timeout: 90_000,
    },
  ];
}
