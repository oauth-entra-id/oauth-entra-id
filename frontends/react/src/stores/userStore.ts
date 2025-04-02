import { create } from 'zustand';

interface User {
  uniqueId: string;
  name: string;
  email: string;
}

interface UserStore {
  user: undefined | User | null;
  setUser: (user: User | null) => void;
}

export const useUserStore = create<UserStore>((set) => ({
  user: undefined,
  setUser: (user: User | null) => set({ user }),
}));
