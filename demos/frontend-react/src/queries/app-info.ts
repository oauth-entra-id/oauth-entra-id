import { queryOptions } from '@tanstack/react-query';
import { getAppInfo } from '~/services/app-info';
import type { Server } from '~/stores/server-store';

export function appInfoOptions(server: Server) {
  return queryOptions({
    queryKey: ['app-info', server],
    queryFn: getAppInfo,
    refetchOnWindowFocus: false,
    retry: 1,
    staleTime: 0,
  });
}
