import { z } from 'zod';
import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import { EXPRESS_SERVER, FASTIFY_SERVER, HONOJS_SERVER, NESTJS_SERVER } from '~/env';

const zServer = z.enum(['express', 'nestjs', 'fastify', 'honojs']);

export type Server = z.infer<typeof zServer>;

const serverMap: Record<Server, { url: string; label: string }> = {
  express: { url: EXPRESS_SERVER, label: 'Express' },
  nestjs: { url: NESTJS_SERVER, label: 'NestJS' },
  fastify: { url: FASTIFY_SERVER, label: 'Fastify' },
  honojs: { url: HONOJS_SERVER, label: 'HonoJS' },
};

interface ServerStore {
  server: Server;
  label: string;
  serverUrl: string;
  setServer: (server: Server) => void;
}

export const useServerStore = create<ServerStore>()(
  persist(
    (set) => ({
      server: 'honojs',
      label: serverMap.honojs.label,
      serverUrl: serverMap.honojs.url,
      setServer: (server) =>
        set({
          server,
          label: serverMap[server].label,
          serverUrl: serverMap[server].url,
        }),
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
          serverUrl: serverMap[server].url,
          label: serverMap[server].label,
        };
      },
    },
  ),
);
