import { env } from '~/env';

export interface MobileTokens {
  accessToken: string;
  refreshToken: string;
}

// In-memory store for the demo. A production server needs a shared cache (Redis/DB) so several instances can serve the ticket exchange.
const store = new Map<string, { tokens: MobileTokens; expiresAt: number }>();

export function saveMobileTokens(ticketId: string, tokens: MobileTokens): void {
  const now = Date.now();
  for (const [id, entry] of store) {
    if (entry.expiresAt <= now) store.delete(id);
  }
  store.set(ticketId, { tokens, expiresAt: now + env.MOBILE_TICKET_TTL_SEC * 1000 });
}

/** Returns the tokens saved for the ticket and forgets them, so a ticket works only once. */
export function takeMobileTokens(ticketId: string): MobileTokens | undefined {
  const entry = store.get(ticketId);
  store.delete(ticketId);
  if (!entry || entry.expiresAt <= Date.now()) return undefined;
  return entry.tokens;
}
