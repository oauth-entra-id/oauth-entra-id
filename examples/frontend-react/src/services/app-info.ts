import { z } from 'zod';
import { axiosFetch } from '~/lib/axios';
import { zStr } from '~/lib/zod';
import { useServerStore } from '~/stores/server-store';

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
