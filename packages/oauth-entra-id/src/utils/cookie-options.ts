export const ACCESS_TOKEN_NAME = 'at' as const;
export const REFRESH_TOKEN_NAME = 'rt' as const;

export function $cookieOptions({
  clientId,
  secure,
  sameSite,
  timeUnit,
  atExp,
  rtExp,
}: { clientId: string; secure: boolean; sameSite: boolean; timeUnit: 'sec' | 'ms'; atExp: number; rtExp: number }) {
  const timeFrame = timeUnit === 'sec' ? 1 : 1000;
  const baseOptions = {
    httpOnly: true,
    secure,
    sameSite: sameSite ? 'strict' : secure ? 'none' : undefined,
    path: '/',
  } as const;

  return {
    accessToken: {
      name: `${`${secure ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: atExp * timeFrame },
    },
    refreshToken: {
      name: `${`${secure ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${clientId}`}`,
      options: { ...baseOptions, maxAge: rtExp * timeFrame },
    },
    deleteOptions: { ...baseOptions, sameSite: secure ? 'none' : undefined, maxAge: 0 },
  } as const;
}
