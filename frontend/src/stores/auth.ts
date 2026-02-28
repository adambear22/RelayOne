import { create } from 'zustand'

import type { User } from '../types/models'

interface AuthState {
  user: User | null
  bootstrapped: boolean
  maintenanceMode: boolean
  setUser: (user: User | null) => void
  clearAuth: () => void
  setBootstrapped: (bootstrapped: boolean) => void
  setMaintenanceMode: (enabled: boolean) => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  bootstrapped: false,
  maintenanceMode: false,
  setUser: (user) => set({ user }),
  clearAuth: () =>
    set({
      user: null,
      bootstrapped: true,
    }),
  setBootstrapped: (bootstrapped) => set({ bootstrapped }),
  setMaintenanceMode: (enabled) => set({ maintenanceMode: enabled }),
}))
