import { create } from 'zustand';

interface User {
  uniqueId: string;
  name: string;
  email: string;
}

interface UserStore {
  appId: undefined | string | null;
  user: undefined | User | null;
  setAppId: (appId: string | null) => void;
  setUser: (user: User | null) => void;
}

export const useUserStore = create<UserStore>((set) => ({
  appId: undefined,
  user: undefined,
  setAppId: (appId) => set({ appId }),
  setUser: (user) => set({ user }),
}));
