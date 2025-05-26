export const ACCESS_TOKEN_NAME = 'at' as const;
export const REFRESH_TOKEN_NAME = 'rt' as const;

export function $cookieOptions({
  clientId,
  secure,
  sameSite,
  cookiesTimeUnit,
  accessTokenCookieExpiry,
  refreshTokenCookieExpiry,
}: {
  clientId: string;
  secure: boolean;
  sameSite: boolean;
  cookiesTimeUnit: 'sec' | 'ms';
  accessTokenCookieExpiry: number;
  refreshTokenCookieExpiry: number;
}) {
  const timeFrame = cookiesTimeUnit === 'sec' ? 1 : 1000;
  const baseOptions = {
    httpOnly: true,
    secure,
    sameSite: sameSite ? 'strict' : secure ? 'none' : undefined,
    path: '/',
  } as const;

  return {
    accessToken: {
      name: `${`${secure ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: accessTokenCookieExpiry * timeFrame },
    },
    refreshToken: {
      name: `${`${secure ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: refreshTokenCookieExpiry * timeFrame },
    },
    deleteOptions: { ...baseOptions, sameSite: secure ? 'none' : undefined, maxAge: 0 },
  } as const;
}
