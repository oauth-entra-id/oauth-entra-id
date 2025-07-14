import type { OAuthProvider } from '~/core';
import { $err, type HttpErrorCodes, OAuthError } from '~/error';
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

export function $coreErrors(
  err: unknown,
  method: {
    [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
  }[keyof OAuthProvider],
  defaultStatusCode: HttpErrorCodes = 500,
) {
  if (err instanceof OAuthError) {
    return $err(err.type, { error: err.message, description: err.description, status: err.statusCode });
  }

  if (err instanceof Error) {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err.message}, stack : ${err.stack}`,
      status: defaultStatusCode,
    });
  }

  if (typeof err === 'string') {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err}`,
      status: defaultStatusCode,
    });
  }

  return $err('internal', {
    error: 'Unknown error',
    description: `method: ${method}, error: ${JSON.stringify(err)}`,
    status: defaultStatusCode,
  });
}
