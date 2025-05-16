import { create } from 'zustand';

interface User {
  uniqueId: string;
  name: string;
  email: string;
  injectedData?: {
    randomNumber: number;
  };
}

interface UserStore {
  user: User | null;
  setUser: (user: User | null) => void;
}

export const useUserStore = create<UserStore>((set) => ({
  user: null,
  setUser: (user) => set({ user }),
}));
