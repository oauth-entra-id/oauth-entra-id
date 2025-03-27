import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';
import { EXPRESS_SERVER, FASTIFY_SERVER, HONOJS_SERVER, NESTJS_SERVER } from '~/env';

export type Server = 'express' | 'nestjs' | 'fastify' | 'honojs';

const serverMap = {
  express: EXPRESS_SERVER,
  nestjs: NESTJS_SERVER,
  fastify: FASTIFY_SERVER,
  honojs: HONOJS_SERVER,
};

interface ServerStore {
  server: Server;
  serverUrl: string;
  setServer: (server: Server) => void;
}

export const useServerStore = create<ServerStore>()(
  persist(
    (set) => ({
      server: 'express',
      serverUrl: EXPRESS_SERVER,
      setServer: (server) =>
        set({
          server,
          serverUrl: serverMap[server],
        }),
    }),
    { name: 'server', storage: createJSONStorage(() => localStorage) },
  ),
);
