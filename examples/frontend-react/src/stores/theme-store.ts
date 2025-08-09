import { z } from 'zod';
import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

const zTheme = z.enum(['dark', 'light', 'system']);

type Theme = z.infer<typeof zTheme>;

interface ThemeStore {
  settings: Theme;
  theme: 'dark' | 'light';
  setTheme: (settings: Theme) => void;
}

export const useThemeStore = create<ThemeStore>()(
  persist(
    (set) => ({
      settings: 'dark',
      theme: 'dark',
      setTheme: (settings) =>
        set({
          settings,
          theme:
            settings === 'dark' || (settings === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
              ? 'dark'
              : 'light',
        }),
    }),
    {
      name: 'theme',
      storage: createJSONStorage(() => localStorage),
      version: 0,
      partialize: (state) => state.settings,
      merge: (persistedState, currentState) => {
        const { data: settings } = zTheme.safeParse(persistedState);
        if (!settings) {
          localStorage.setItem('theme', JSON.stringify({ state: currentState.settings, version: 0 }));
          return currentState;
        }
        return {
          ...currentState,
          settings,
          theme:
            settings === 'dark' || (settings === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
              ? 'dark'
              : 'light',
        };
      },
    },
  ),
);
