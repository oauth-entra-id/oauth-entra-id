import { existsSync } from 'node:fs';
import { join } from 'node:path';

export const serverNames = ['express', 'nestjs', 'fastify', 'honojs'] as const;
export const colors = ['yellow', 'red', 'blue'] as const;

export type ServerName = (typeof serverNames)[number];
export type Color = (typeof colors)[number];

export const repoRoot = join(__dirname, '..', '..');

export const servers: Record<ServerName, { label: string; color: Color; prefix: string; entry: string }> = {
  express: {
    label: 'Express',
    color: 'yellow',
    prefix: 'EXPRESS',
    entry: join(repoRoot, 'examples', 'server-express', 'dist', 'index.js'),
  },
  nestjs: {
    label: 'NestJS',
    color: 'red',
    prefix: 'NESTJS',
    entry: join(repoRoot, 'examples', 'server-nestjs', 'dist', 'main.js'),
  },
  fastify: {
    label: 'Fastify',
    color: 'red',
    prefix: 'FASTIFY',
    entry: join(repoRoot, 'examples', 'server-fastify', 'dist', 'index.js'),
  },
  honojs: {
    label: 'HonoJS',
    color: 'blue',
    prefix: 'HONOJS',
    entry: join(repoRoot, 'examples', 'server-honojs', 'dist', 'index.js'),
  },
};

export interface Credentials {
  email: string;
  password: string;
}

export interface LiveEnv {
  frontend: { url: string; origin: string; port: number };
  servers: Record<ServerName, { url: string; port: number }>;
  apps: Record<Color, { clientId: string; tenantId: string }>;
  user: Credentials;
}

const envFile = join(__dirname, '..', '.env.live');
const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const localUrl = /^http:\/\/localhost:\d{2,5}$/;
const emailAddress = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const azureFields = ['CLIENT_ID', 'TENANT_ID', 'CUSTOM_SCOPE', 'CLIENT_SECRET', 'EXPOSED_SCOPE'] as const;

export function short(id: string): string {
  return `${id.slice(0, 8)}...${id.slice(-8)}`;
}

function readEnv(): LiveEnv {
  if (existsSync(envFile)) process.loadEnvFile(envFile);

  const missing: string[] = [];
  const invalid: string[] = [];
  const need = (name: string, format?: RegExp): string => {
    const value = (process.env[name] ?? '').trim();
    if (!value) missing.push(name);
    else if (format && !format.test(value)) invalid.push(name);
    return value;
  };

  const frontendUrl = need('REACT_FRONTEND_URL', localUrl);
  const serverUrls = Object.fromEntries(
    Object.values(servers).map((server) => [server.prefix, need(`${server.prefix}_URL`, localUrl)]),
  );
  const apps = {} as LiveEnv['apps'];
  for (const color of colors) {
    // The example servers name their first Azure registration `<COLOR>1_AZURE_*`; the tests only use that one.
    const prefix = `${color.toUpperCase()}1`;
    const fields = Object.fromEntries(
      azureFields.map((field) => [
        field,
        need(`${prefix}_AZURE_${field}`, field === 'CLIENT_ID' || field === 'TENANT_ID' ? guid : undefined),
      ]),
    );
    apps[color] = { clientId: fields.CLIENT_ID ?? '', tenantId: fields.TENANT_ID ?? '' };
  }
  const user = { email: need('E2E_USER_EMAIL', emailAddress), password: need('E2E_USER_PASSWORD') };

  if (missing.length > 0 || invalid.length > 0) {
    const lines = ['e2eTests/.env.live is not ready (copy .env.live.example and fill in the values).'];
    if (missing.length > 0) lines.push(`Missing: ${missing.join(', ')}`);
    if (invalid.length > 0) lines.push(`Invalid format: ${invalid.join(', ')}`);
    throw new Error(lines.join('\n'));
  }

  return {
    frontend: { url: frontendUrl, origin: new URL(frontendUrl).origin, port: Number(new URL(frontendUrl).port) },
    servers: Object.fromEntries(
      Object.entries(servers).map(([name, server]) => {
        const url = serverUrls[server.prefix] ?? '';
        return [name, { url, port: Number(new URL(url).port) }];
      }),
    ) as LiveEnv['servers'],
    apps,
    user,
  };
}

let cached: LiveEnv | undefined;

export function liveEnv(): LiveEnv {
  cached ??= readEnv();
  return cached;
}
