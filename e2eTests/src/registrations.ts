import type { Color } from './env';
import { liveEnv } from './env';

const env = liveEnv();

/** The first registration of one test app, the way the example servers read it (`<COLOR>1_AZURE_*`). */
export function azureOf(color: Color) {
  const prefix = `${color.toUpperCase()}1_AZURE`;
  return {
    clientId: env.apps[color].clientId,
    tenantId: env.apps[color].tenantId,
    scopes: [process.env[`${prefix}_CUSTOM_SCOPE`] ?? ''] as [string],
    clientSecret: process.env[`${prefix}_CLIENT_SECRET`] ?? '',
  };
}

/** The scope other apps ask for when they want a token for this app. */
export function exposedScopeOf(color: Color): string {
  return process.env[`${color.toUpperCase()}1_AZURE_EXPOSED_SCOPE`] ?? '';
}
