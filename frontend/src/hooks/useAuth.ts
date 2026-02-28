import { useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'

import { fetchCurrentUser, login as loginAPI, logout as logoutAPI, type LoginPayload } from '../api/auth'
import { useAuthStore } from '../stores/auth'

export function useAuthBootstrap() {
  const setUser = useAuthStore((state) => state.setUser)
  const setBootstrapped = useAuthStore((state) => state.setBootstrapped)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  const query = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: fetchCurrentUser,
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  })

  useEffect(() => {
    if (query.isSuccess) {
      setUser(query.data)
      setBootstrapped(true)
      return
    }

    if (query.isError) {
      clearAuth()
      setBootstrapped(true)
      return
    }

    if (query.fetchStatus === 'idle' && query.status === 'pending') {
      setBootstrapped(false)
    }
  }, [clearAuth, query.data, query.fetchStatus, query.isError, query.isSuccess, query.status, setBootstrapped, setUser])

  return query
}

export function useAuth() {
  const user = useAuthStore((state) => state.user)
  const bootstrapped = useAuthStore((state) => state.bootstrapped)
  const maintenanceMode = useAuthStore((state) => state.maintenanceMode)
  const setUser = useAuthStore((state) => state.setUser)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  const loginMutation = useMutation({
    mutationFn: async (payload: LoginPayload) => {
      await loginAPI(payload)
      const currentUser = await fetchCurrentUser()
      setUser(currentUser)
      return currentUser
    },
  })

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await logoutAPI()
      clearAuth()
    },
  })

  return {
    user,
    bootstrapped,
    maintenanceMode,
    isAuthenticated: Boolean(user),
    loginMutation,
    logoutMutation,
    clearAuth,
  }
}
