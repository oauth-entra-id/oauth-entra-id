import axios, { type InternalAxiosRequestConfig } from 'axios';
import { clearMobileSession, getBearerFor } from '~/lib/mobile-storage';
import { refreshMobileTokens } from '~/services/mobile-session';
import { isMobileActive } from '~/stores/mobile-store';
import { serversMap, useServerStore } from '~/stores/server-store';

export const axiosFetch = axios.create({
  // baseURL: env.VITE_SERVER_URL, //in real usage, you will set the base URL here
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

type MobileRequest = InternalAxiosRequestConfig & {
  /** The token this request was sent with, and whether it is the (refreshable) access token of the login service. */
  mobileToken?: { value: string; isMain: boolean };
  retriedAfterRefresh?: boolean;
};

function currentColor() {
  return serversMap[useServerStore.getState().server].color;
}

// Mobile app mode: no cookies, the server of the current colour gets the token it accepts as a Bearer token.
axiosFetch.interceptors.request.use((config: MobileRequest) => {
  if (!isMobileActive()) return config;

  config.withCredentials = false;
  const bearer = getBearerFor(currentColor());
  if (bearer && !config.headers.has('Authorization')) {
    config.headers.set('Authorization', `Bearer ${bearer.token}`);
    config.mobileToken = { value: bearer.token, isMain: bearer.isMain };
  }
  return config;
});

// Mobile app mode: when the access token is rejected the app gets new tokens once and retries the request.
axiosFetch.interceptors.response.use(undefined, async (error: unknown) => {
  if (!axios.isAxiosError(error)) throw error;

  const config = error.config as MobileRequest | undefined;
  const sentToken = config?.mobileToken;
  if (
    !config ||
    !sentToken?.isMain ||
    config.retriedAfterRefresh ||
    error.response?.status !== 401 ||
    !isMobileActive()
  ) {
    throw error;
  }
  config.retriedAfterRefresh = true;

  // Another request may already have refreshed the tokens while this one was in flight.
  const latest = getBearerFor(currentColor());
  let accessToken = latest?.isMain && latest.token !== sentToken.value ? latest.token : null;
  if (!accessToken) {
    try {
      accessToken = await refreshMobileTokens();
    } catch {
      clearMobileSession();
      throw error;
    }
  }

  config.headers.set('Authorization', `Bearer ${accessToken}`);
  return axiosFetch(config);
});
