import { z } from 'zod';
import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import { Express } from '~/components/icons/Express';
import { Fastify } from '~/components/icons/Fastify';
import { HonoJS } from '~/components/icons/HonoJS';
import { NestJS } from '~/components/icons/NestJS';
import { env } from '~/env';
import type { zGetAppInfo } from '~/services/app-info';

const zServer = z.enum(['express', 'nestjs', 'fastify', 'honojs']);

export type Server = z.infer<typeof zServer>;

export const serversMap = {
  express: { value: 'express', label: 'Express', color: 'yellow', url: env.EXPRESS_SERVER, Icon: Express },
  nestjs: { value: 'nestjs', label: 'NestJS', color: 'red', url: env.NESTJS_SERVER, Icon: NestJS },
  fastify: { value: 'fastify', label: 'Fastify', color: 'red', url: env.FASTIFY_SERVER, Icon: Fastify },
  honojs: { value: 'honojs', label: 'HonoJS', color: 'blue', url: env.HONOJS_SERVER, Icon: HonoJS },
} as Record<
  Server,
  { value: Server; label: string; color: Color; url: string; Icon: React.FC<React.SVGProps<SVGSVGElement>> }
>;

export type Color = 'blue' | 'red' | 'yellow';
export type TwoStrings = { '1': string; '2'?: string };

interface ServerStore {
  server: Server;
  serverLabel: string;
  serverUrl: string;
  appInfo: {
    currentServiceIds: TwoStrings;
    currentServiceName: Color;
    other: { blue: TwoStrings; red: TwoStrings; yellow: TwoStrings };
  } | null;
  registration: keyof TwoStrings;
  setServer: (server: Server) => void;
  setRegistration: (registration: keyof TwoStrings) => void;
  setAppInfo: (appInfo: z.infer<typeof zGetAppInfo> | null) => void;
}

export const useServerStore = create<ServerStore>()(
  persist(
    (set) => ({
      server: 'honojs',
      serverLabel: serversMap.honojs.label,
      serverUrl: serversMap.honojs.url,
      appInfo: null,
      registration: '1',
      setServer: (server) =>
        set({
          server,
          serverLabel: serversMap[server].label,
          serverUrl: serversMap[server].url,
        }),
      setRegistration: (registration) => set({ registration }),
      setAppInfo: (appInfo) => {
        if (!appInfo) return set({ appInfo: null });
        const { current, blue, red, yellow } = appInfo;
        return set((state) => ({
          appInfo: {
            currentServiceIds: appInfo[current],
            currentServiceName: current,
            other: { blue, red, yellow },
          },
          // A server without a second registration cannot keep it selected.
          registration: appInfo[current]['2'] ? state.registration : '1',
        }));
      },
    }),
    {
      name: 'server',
      storage: createJSONStorage(() => localStorage),
      version: 0,
      partialize: (state) => state.server,
      merge: (persistedState, currentState) => {
        const { data: server } = zServer.safeParse(persistedState);
        if (!server) {
          localStorage.setItem('server', JSON.stringify({ state: currentState.server, version: 0 }));
          return currentState;
        }
        return {
          ...currentState,
          server,
          serverLabel: serversMap[server].label,
          serverUrl: serversMap[server].url,
          appInfo: currentState.appInfo,
        };
      },
    },
  ),
);
