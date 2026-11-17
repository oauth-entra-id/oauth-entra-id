import { create } from 'zustand';
import { createJSONStorage, persist } from 'zustand/middleware';

interface MobileStore {
  enabled: boolean;
  setEnabled: (enabled: boolean) => void;
}

/** "Mobile app mode" makes this demo behave like a mobile app: ticket login, Bearer tokens kept in storage, no cookies. */
export const useMobileStore = create<MobileStore>()(
  persist(
    (set) => ({
      enabled: false,
      setEnabled: (enabled) => set({ enabled }),
    }),
    {
      name: 'mobile-mode',
      storage: createJSONStorage(() => localStorage),
      version: 0,
      partialize: (state) => ({ enabled: state.enabled }),
    },
  ),
);

export function isMobileActive(): boolean {
  return useMobileStore.getState().enabled;
}
