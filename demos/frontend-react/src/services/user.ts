import axios from 'axios';
import { z } from 'zod';
import { zStr } from '~/lib/zod';
import { useServerStore } from '~/stores/serverStore';

const axiosFetch = axios.create({
  // baseURL: env.VITE_SERVER_URL, //in real usage, you will set the base URL here
  withCredentials: true,
});

async function tryCatch<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch {
    return null;
  }
}

const zGetUserData = z.object({
  user: z.object({
    uniqueId: zStr.uuid(),
    name: zStr,
    email: zStr.email(),
  }),
});
export async function getUserData() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.get(`${serverUrl}/protected/user-info`));
  const parsed = zGetUserData.safeParse(res?.data);
  if (parsed.error) return null;
  return parsed.data.user;
}

const zGetAUthUrl = z.object({
  url: zStr.url(),
});
export async function getAuthUrl({ email, loginPrompt }: { email?: string; loginPrompt?: string }) {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.post(`${serverUrl}/auth/authenticate`, { email, loginPrompt }));
  const parsed = zGetAUthUrl.safeParse(res?.data);
  if (parsed.error) return null;
  return parsed.data.url;
}

const zGetLogoutUrl = z.object({
  url: zStr.url(),
});
export async function logoutAndGetLogoutUrl() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.post(`${serverUrl}/auth/logout`));
  const parsed = zGetLogoutUrl.safeParse(res?.data);
  if (parsed.error) return null;
  return parsed.data.url;
}

const zGetAppId = z.object({
  appId: zStr.uuid(),
});
export async function getAppId() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.get(`${serverUrl}/app-id`));
  const parsed = zGetAppId.safeParse(res?.data);
  if (parsed.error) return null;
  return parsed.data.appId;
}

export async function getTokensOnBehalfOf() {
  const serverUrl = useServerStore.getState().serverUrl;
  await tryCatch(axiosFetch.post(`${serverUrl}/protected/on-behalf-of`, { name: 'main' }));
}
