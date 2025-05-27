export const ACCESS_TOKEN_NAME = 'at' as const;
export const REFRESH_TOKEN_NAME = 'rt' as const;

export function $cookieOptions(params: {
  clientId: string;
  secure: boolean;
  sameSite: boolean;
  timeUnit: 'sec' | 'ms';
  atExp: number;
  rtExp: number;
}) {
  const timeFrame = params.timeUnit === 'sec' ? 1 : 1000;
  const baseOptions = {
    httpOnly: true,
    secure: params.secure,
    sameSite: params.sameSite ? 'strict' : params.secure ? 'none' : undefined,
    path: '/',
  } as const;

  return {
    accessToken: {
      name: `${`${params.secure ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${params.clientId}`}`,
      options: { ...baseOptions, maxAge: params.atExp * timeFrame },
    },
    refreshToken: {
      name: `${`${params.secure ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${params.clientId}`}`,
      options: { ...baseOptions, maxAge: params.rtExp * timeFrame },
    },
    deleteOptions: { ...baseOptions, sameSite: params.secure ? 'none' : undefined, maxAge: 0 },
  } as const;
}
