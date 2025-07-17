import type { LoginPrompt } from '~/types';

/** Time skew in seconds to account for clock drift between client and server */
export const TIME_SKEW = 5 * 60;

export function $transformToMsalPrompt(
  prompt: LoginPrompt,
  email: string | undefined,
): 'login' | 'select_account' | undefined {
  if (email || prompt === 'email') return 'login';
  if (prompt === 'select-account') return 'select_account';
  return undefined;
}

export async function $mapAndFilter<T, R>(items: T[], callback: (item: T) => Promise<R | null>): Promise<R[]> {
  return (
    await Promise.all(
      items.map(async (item) => {
        try {
          return await callback(item);
        } catch {
          return null;
        }
      }),
    )
  ).filter((result): result is Awaited<R> => !!result);
}
