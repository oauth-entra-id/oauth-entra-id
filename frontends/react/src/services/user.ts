import axios from 'axios';
import { useServerStore } from '~/stores/serverStore';

const axiosFetch = axios.create({
  // in real usage, you might want to set the baseURL to your server's URL
  // baseURL: env.VITE_SERVER_URL,
  withCredentials: true,
});

async function tryCatch<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch {
    return null;
  }
}

export async function getUserData() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.get(`${serverUrl}/protected/user-info`));
  if (!res || !res.data.user) return null;
  return res.data.user;
}

export async function getAuthUrl({ email, loginPrompt }: { email?: string; loginPrompt?: string }) {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.post(`${serverUrl}/auth/authenticate`, { loginPrompt, email }));
  if (!res || !res.data.url) return null;
  return res.data.url;
}

export async function logoutAndGetLogoutUrl() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await tryCatch(axiosFetch.post(`${serverUrl}/auth/logout`));
  if (!res || !res.data.url) return null;
  return res.data.url;
}
