import { z } from 'zod/v4';
import { axiosFetch } from '~/lib/axios';
import { type Server, useServerStore } from '~/stores/server-store';

const zGetAppInfo = z.object({
  current: z.enum(['blue', 'red', 'yellow']),
  blue: z.uuid(),
  red: z.uuid(),
  yellow: z.uuid(),
});

export async function getAppInfo() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.get(`${serverUrl}/app-info`);
  const parsed = zGetAppInfo.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid app info');
  return parsed.data;
}

const zGetB2BInfo = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'nestjs', 'fastify', 'honojs']),
});

export async function getB2BInfo(appName: Server | undefined) {
  if (!appName) throw new Error('Invalid B2B service name');
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.post(`${serverUrl}/protected/get-b2b-info`, { appName });
  const parsed = zGetB2BInfo.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid on-behalf-of tokens');
  return parsed.data;
}
