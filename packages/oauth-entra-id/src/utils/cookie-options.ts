import type { BaseCookieNames, BaseCookieOptions } from '~/types';

export const ACCESS_TOKEN_NAME = 'at' as const;
export const REFRESH_TOKEN_NAME = 'rt' as const;

export function $getCookieOptions(params: {
  secure: boolean;
  sameSite: boolean;
  timeUnit: 'sec' | 'ms';
  atExp: number;
  rtExp: number;
}): BaseCookieOptions {
  const timeFrame = params.timeUnit === 'sec' ? 1 : 1000;
  const baseOptions = {
    httpOnly: true,
    secure: params.secure,
    sameSite: params.sameSite ? 'strict' : params.secure ? 'none' : undefined,
    path: '/',
  } as const;

  return {
    accessTokenOptions: { ...baseOptions, maxAge: params.atExp * timeFrame },
    refreshTokenOptions: { ...baseOptions, maxAge: params.rtExp * timeFrame },
    deleteTokenOptions: { ...baseOptions, maxAge: 0 },
  } as const;
}

export function $getCookieNames(clientId: string, secure: boolean): BaseCookieNames {
  return {
    accessTokenName: `${`${secure ? '__Host-' : ''}${ACCESS_TOKEN_NAME}-${clientId}`}`,
    refreshTokenName: `${`${secure ? '__Host-' : ''}${REFRESH_TOKEN_NAME}-${clientId}`}`,
  } as const;
}
