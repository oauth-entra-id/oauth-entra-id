import { z } from 'zod';
import type { Color } from '~/stores/server-store';

// Stand-ins for what a real mobile app keeps on the device: the ticket until the login is completed, and the tokens in secure storage.
const TICKET_KEY = 'mobile-ticket';
const TOKENS_KEY = 'mobile-tokens';

/** Where the server sends the system browser after a mobile login (the "deep link" back into the app). */
export const MOBILE_RETURN_PATH = '/mobile-return';

// `mainColor` is the service (server colour) the user logged in to, its access token is the one that can be refreshed.
// `services` holds the on-behalf-of tokens for other services, by service name.
const zMobileTokens = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  mainColor: z.enum(['blue', 'red', 'yellow']),
  services: z.record(z.string(), z.string()),
});

export type MobileTokens = z.infer<typeof zMobileTokens>;

export function getMobileTokens(): MobileTokens | null {
  try {
    const parsed = zMobileTokens.safeParse(JSON.parse(localStorage.getItem(TOKENS_KEY) ?? 'null'));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** A new login replaces everything that was stored. */
export function startMobileSession(tokens: { accessToken: string; refreshToken: string }, mainColor: Color) {
  localStorage.setItem(TOKENS_KEY, JSON.stringify({ ...tokens, mainColor, services: {} }));
}

/** A refresh replaces the user's tokens and keeps the rest of the session. */
export function updateMobileTokens(tokens: { accessToken: string; refreshToken: string }) {
  const current = getMobileTokens();
  if (!current) return;
  localStorage.setItem(TOKENS_KEY, JSON.stringify({ ...current, ...tokens }));
}

export function saveServiceTokens(services: Record<string, string>) {
  const tokens = getMobileTokens();
  if (!tokens) return;
  localStorage.setItem(TOKENS_KEY, JSON.stringify({ ...tokens, services: { ...tokens.services, ...services } }));
}

/** The token a server of this colour accepts: the access token for the login service, an on-behalf-of token for the others. */
export function getBearerFor(color: Color): { token: string; isMain: boolean } | null {
  const tokens = getMobileTokens();
  if (!tokens) return null;
  if (tokens.mainColor === color) return { token: tokens.accessToken, isMain: true };
  const service = tokens.services[color];
  return service ? { token: service, isMain: false } : null;
}

export function getTicket(): string | null {
  return localStorage.getItem(TICKET_KEY);
}

export function saveTicket(ticket: string) {
  localStorage.setItem(TICKET_KEY, ticket);
}

export function clearTicket() {
  localStorage.removeItem(TICKET_KEY);
}

export function clearMobileSession() {
  localStorage.removeItem(TOKENS_KEY);
  localStorage.removeItem(TICKET_KEY);
}
