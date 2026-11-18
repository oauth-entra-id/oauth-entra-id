import { OAuthError, type ResultErr } from 'oauth-entra-id';

// The package leaves `statusCode` undefined on some errors, which would be answered as 200 or 500.
export function withStatus(error: ResultErr | OAuthError, fallback: 400 | 401) {
  return new OAuthError({
    message: error.message,
    description: error.description,
    statusCode: error.statusCode ?? fallback,
  });
}

export async function orClientError<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    throw error instanceof OAuthError ? withStatus(error, 400) : error;
  }
}
