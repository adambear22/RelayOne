import { useMemo } from 'react'

import { useAuthStore } from '../stores/auth'

export function usePermission() {
  const user = useAuthStore((state) => state.user)

  return useMemo(() => {
    const role = user?.role
    const permissionSet = new Set(user?.permissions ?? [])

    const hasRole = (roles: string | string[]) => {
      if (!role) {
        return false
      }

      const list = Array.isArray(roles) ? roles : [roles]
      return list.some((item) => item.toLowerCase() === role.toLowerCase())
    }

    const hasPermission = (permission: string | string[]) => {
      const list = Array.isArray(permission) ? permission : [permission]
      if (permissionSet.has('*')) {
        return true
      }

      return list.every((item) => permissionSet.has(item))
    }

    return {
      role,
      permissions: Array.from(permissionSet),
      hasRole,
      hasPermission,
      isAdmin: hasRole('admin'),
    }
  }, [user?.permissions, user?.role])
}
