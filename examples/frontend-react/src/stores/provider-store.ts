import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

export type Provider = 'oauth' | 'lite';

interface ProviderStore {
  provider: Provider;
  setProvider: (provider: Provider) => void;
}

/** Which provider of the package the demo shows: the full OAuthProvider (login, tokens, B2B) or the LiteProvider (plain app tokens). */
export const useProviderStore = create<ProviderStore>()(
  persist(
    (set) => ({
      provider: 'oauth',
      setProvider: (provider) => set({ provider }),
    }),
    {
      name: 'provider',
      storage: createJSONStorage(() => localStorage),
      version: 0,
      partialize: (state) => ({ provider: state.provider }),
    },
  ),
);
