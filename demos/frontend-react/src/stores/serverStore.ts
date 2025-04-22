import { z } from 'zod';
import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import { Express } from '~/components/icons/Express';
import { Fastify } from '~/components/icons/Fastify';
import { HonoJS } from '~/components/icons/HonoJS';
import { NestJS } from '~/components/icons/NestJS';
import { env } from '~/env';

const zServer = z.enum(['express', 'nestjs', 'fastify', 'honojs']);

type Server = z.infer<typeof zServer>;

export const serversMap = {
  express: { value: 'express', label: 'Express', url: env.EXPRESS_SERVER, Icon: Express },
  nestjs: { value: 'nestjs', label: 'NestJS', url: env.NESTJS_SERVER, Icon: NestJS },
  fastify: { value: 'fastify', label: 'Fastify', url: env.FASTIFY_SERVER, Icon: Fastify },
  honojs: { value: 'honojs', label: 'HonoJS', url: env.HONOJS_SERVER, Icon: HonoJS },
} as Record<Server, { value: Server; label: string; url: string; Icon: React.FC<React.SVGProps<SVGSVGElement>> }>;

type Color = 'blue' | 'red' | 'yellow';

interface ServerStore {
  server: Server;
  label: string;
  serverUrl: string;
  appRegs:
    | undefined
    | { currentAppId: string; currentColor: Color; other: { blue: string; red: string; yellow: string } }
    | null;
  setServer: (server: Server) => void;
  setAppRegs: (appId: { current: Color; blue: string; red: string; yellow: string } | null) => void;
}

export const useServerStore = create<ServerStore>()(
  persist(
    (set) => ({
      server: 'honojs',
      label: serversMap.honojs.label,
      serverUrl: serversMap.honojs.url,
      appRegs: undefined,
      setServer: (server) =>
        set({
          server,
          label: serversMap[server].label,
          serverUrl: serversMap[server].url,
        }),
      setAppRegs: (appInfo) => {
        if (!appInfo) return set({ appRegs: null });
        const { current, blue, red, yellow } = appInfo;
        return set({
          appRegs: {
            currentAppId: appInfo[current],
            currentColor: current,
            other: { blue, red, yellow },
          },
        });
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
          serverUrl: serversMap[server].url,
          label: serversMap[server].label,
          appRegs: currentState.appRegs,
        };
      },
    },
  ),
);
