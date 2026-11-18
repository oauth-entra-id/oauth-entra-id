import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PlaywrightTestConfig } from '@playwright/test';
import { type LiveEnv, mobileReturnPath, repoRoot, serverNames, servers } from './env';

type WebServers = NonNullable<PlaywrightTestConfig['webServer']>;

function secretKey(): string {
  return randomBytes(32).toString('hex');
}

export function webServers(env: LiveEnv): WebServers {
  // The servers read a `.env` relative to their working directory. A temporary one keeps a developer's own `.env`
  // (for example with a second Azure registration) out of the test run: the tests only use the first registration.
  const isolatedCwd = join(tmpdir(), 'oauth-entra-id-e2e', 'a', 'b');
  mkdirSync(isolatedCwd, { recursive: true });

  const serverEnv: Record<string, string> = {
    NODE_ENV: 'development',
    REACT_FRONTEND_URL: env.frontend.url,
    MOBILE_RETURN_PATH: mobileReturnPath,
    YELLOW_SECRET_KEY: secretKey(),
    RED_SECRET_KEY: secretKey(),
    BLUE_SECRET_KEY: secretKey(),
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
