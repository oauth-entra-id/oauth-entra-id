import { useServerStore } from '~/stores/serverStore';
import axios from 'axios';

const axiosInstance = axios.create({
  // in real usage, you might want to set the baseURL to your server's URL
  // baseURL: env.VITE_SERVER_URL,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

export async function getUserData() {
  try {
    const res = await axiosInstance.get(`${useServerStore.getState().serverUrl}/protected/user-info`);
    if (!res.data.user) throw new Error('No user data');
    return res.data.user;
  } catch {
    return null;
  }
}

export async function getAuthUrl({ email, loginPrompt }: { email?: string; loginPrompt?: string }) {
  try {
    const res = await axiosInstance.post(`${useServerStore.getState().serverUrl}/auth/authenticate`, {
      loginPrompt,
      email,
    });
    if (!res.data.url) throw new Error('No auth URL');
    return res.data.url;
  } catch {
    return null;
  }
}

export async function logoutAndGetLogoutUrl() {
  try {
    const res = await axiosInstance.post(`${useServerStore.getState().serverUrl}/auth/logout`);
    return res.data.url;
  } catch {
    return null;
  }
}
