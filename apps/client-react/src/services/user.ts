import { useServerStore } from '~/stores/serverStore';
import axios from 'axios';

const axiosInstance = axios.create({
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

export async function getUserData() {
  const serverUrl = useServerStore.getState().serverUrl;
  try {
    const res = await axiosInstance.get(serverUrl + '/protected/user-info');
    if (!res.data.user) throw new Error('No user data');
    return res.data.user;
  } catch {
    return null;
  }
}

export async function getAuthUrl({ email, loginPrompt }: { email?: string; loginPrompt?: string }) {
  const serverUrl = useServerStore.getState().serverUrl;
  try {
    const res = await axiosInstance.post(serverUrl + '/auth/authenticate', { loginPrompt, email });
    if (!res.data.url) throw new Error('No auth URL');
    return res.data.url;
  } catch {
    return null;
  }
}

export async function logoutAndGetLogoutUrl() {
  const serverUrl = useServerStore.getState().serverUrl;
  try {
    const res = await axiosInstance.post(serverUrl + '/auth/logout');
    return res.data.url;
  } catch {
    return null;
  }
}
