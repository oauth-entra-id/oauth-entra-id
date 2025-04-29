import { queryOptions } from '@tanstack/react-query';
import { getUserData } from '~/services/user';
import type { Server } from '~/stores/server-store';

export function userDataOptions(server: Server) {
  return queryOptions({
    queryKey: ['user', server],
    queryFn: getUserData,
    refetchOnWindowFocus: false,
    retry: 1,
    staleTime: 0,
  });
}
