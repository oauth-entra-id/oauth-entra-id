import axios from 'axios';
import { z } from 'zod';
import { clearTicket, getMobileTokens, getTicket, startMobileSession, updateMobileTokens } from '~/lib/mobile-storage';
import { serversMap, useServerStore } from '~/stores/server-store';

// Plain axios on purpose: these calls must not go through the Bearer/refresh interceptors of axiosFetch.
const zMobileTokensResponse = z.object({ accessToken: z.string().min(1), refreshToken: z.string() });

let exchanging: Promise<void> | null = null;

/** Exchanges the ticket saved at login for the tokens. Concurrent calls share one request, a ticket works only once. */
export function exchangeTicket(): Promise<void> {
  exchanging ??= (async () => {
    const ticket = getTicket();
    if (!ticket) throw new Error('No ticket to exchange');

    const { server, serverUrl } = useServerStore.getState();
    const res = await axios.post(`${serverUrl}/auth/mobile/token`, { ticket });
    const parsed = zMobileTokensResponse.safeParse(res.data);
    if (parsed.error) throw new Error('Invalid tokens');

    startMobileSession(parsed.data, serversMap[server].color);
    clearTicket();
  })().finally(() => {
    exchanging = null;
  });
  return exchanging;
}

let refreshing: Promise<string> | null = null;

/** Gets new tokens with the saved refresh token and returns the new access token. Concurrent calls share one request. */
export function refreshMobileTokens(): Promise<string> {
  refreshing ??= (async () => {
    const refreshToken = getMobileTokens()?.refreshToken;
    if (!refreshToken) throw new Error('No refresh token');

    const serverUrl = useServerStore.getState().serverUrl;
    const res = await axios.post(`${serverUrl}/auth/mobile/refresh`, { refreshToken });
    const parsed = zMobileTokensResponse.safeParse(res.data);
    if (parsed.error) throw new Error('Invalid tokens');

    updateMobileTokens(parsed.data);
    return parsed.data.accessToken;
  })().finally(() => {
    refreshing = null;
  });
  return refreshing;
}
