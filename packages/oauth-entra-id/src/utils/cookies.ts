export const ACCESS_TOKEN_NAME = 'at' as const;
export const REFRESH_TOKEN_NAME = 'rt' as const;

export function getCookieOptions({
  clientId,
  isHttps,
  isSameSite,
  cookieTimeFrame,
  accessTokenCookieExpiry,
  refreshTokenCookieExpiry,
}: {
  clientId: string;
  isHttps: boolean;
  isSameSite: boolean;
  cookieTimeFrame: 'sec' | 'ms';
  accessTokenCookieExpiry: number;
  refreshTokenCookieExpiry: number;
}) {
  const timeFrame = cookieTimeFrame === 'sec' ? 1 : 1000;
  const baseOptions = {
    httpOnly: true,
    secure: isHttps,
    sameSite: isSameSite ? 'strict' : isHttps ? 'none' : undefined,
    path: '/',
  } as const;

  return {
    accessToken: {
      name: `${`${isHttps ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: accessTokenCookieExpiry * timeFrame },
    },
    refreshToken: {
      name: `${`${isHttps ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: refreshTokenCookieExpiry * timeFrame },
    },
    deleteOptions: { ...baseOptions, sameSite: isHttps ? 'none' : undefined, maxAge: 0 },
  } as const;
}
