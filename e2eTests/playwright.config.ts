import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';
import { liveEnv } from './src/env';
import { webServers } from './src/servers';

const env = liveEnv();

export default defineConfig({
  testDir: './tests',
  outputDir: join(tmpdir(), 'oauth-entra-id-e2e', 'output'),
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['./src/reporter.ts']],
  use: {
    baseURL: env.frontend.url,
    locale: 'en-US',
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    actionTimeout: 20_000,
    navigationTimeout: 60_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: webServers(env),
});
