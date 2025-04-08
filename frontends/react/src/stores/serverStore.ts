import { z } from 'zod';
import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import { Elysia } from '~/components/icons/Elysia';
import { Express } from '~/components/icons/Express';
import { Fastify } from '~/components/icons/Fastify';
import { HonoJS } from '~/components/icons/HonoJS';
import { NestJS } from '~/components/icons/NestJS';
import { env } from '~/env';

const zServer = z.enum(['express', 'nestjs', 'fastify', 'honojs', 'elysia']);

type Server = z.infer<typeof zServer>;

export const serversMap = {
  express: { value: 'express', label: 'Express', url: env.EXPRESS_SERVER, Icon: Express },
  nestjs: { value: 'nestjs', label: 'NestJS', url: env.NESTJS_SERVER, Icon: NestJS },
  fastify: { value: 'fastify', label: 'Fastify', url: env.FASTIFY_SERVER, Icon: Fastify },
  honojs: { value: 'honojs', label: 'HonoJS', url: env.HONOJS_SERVER, Icon: HonoJS },
  elysia: { value: 'elysia', label: 'Elysia', url: env.ELYSIA_SERVER, Icon: Elysia },
} as Record<Server, { value: Server; label: string; url: string; Icon: React.FC<React.SVGProps<SVGSVGElement>> }>;

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
      label: serversMap.honojs.label,
      serverUrl: serversMap.honojs.url,
      setServer: (server) =>
        set({
          server,
          label: serversMap[server].label,
          serverUrl: serversMap[server].url,
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
          serverUrl: serversMap[server].url,
          label: serversMap[server].label,
        };
      },
    },
  ),
);
