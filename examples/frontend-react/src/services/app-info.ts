import { z } from 'zod';
import { axiosFetch } from '~/lib/axios';
import { zStr } from '~/lib/zod';
import { type Server, useServerStore } from '~/stores/server-store';

const zGetAppInfo = z.object({
  current: z.enum(['blue', 'red', 'yellow']),
  blue: zStr.uuid(),
  red: zStr.uuid(),
  yellow: zStr.uuid(),
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

export async function getB2BInfo(b2bServiceName: Server | undefined) {
  if (!b2bServiceName) throw new Error('Invalid B2B service name');
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.post(`${serverUrl}/protected/b2b`, { b2bServiceName });
  const parsed = zGetB2BInfo.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid on-behalf-of tokens');
  return parsed.data;
}
