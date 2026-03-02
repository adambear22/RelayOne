import { create } from 'zustand'

export type NotificationKind = 'info' | 'success' | 'warning' | 'error'

export interface NotificationItem {
  id: string
  kind: NotificationKind
  title: string
  content?: string
  created_at: string
  read: boolean
}

interface NotificationState {
  items: NotificationItem[]
  addNotification: (payload: { id?: string; kind: NotificationKind; title: string; content?: string; created_at?: string }) => void
  markAsRead: (id: string) => void
  markAllAsRead: () => void
  clearAll: () => void
}

const MAX_NOTIFICATIONS = 20

export const useNotificationStore = create<NotificationState>((set) => ({
  items: [],
  addNotification: (payload) =>
    set((state) => {
      const id = payload.id?.trim() || createNotificationID()
      const createdAt = payload.created_at?.trim() || new Date().toISOString()

      const nextItem: NotificationItem = {
        id,
        kind: payload.kind,
        title: payload.title,
        content: payload.content,
        created_at: createdAt,
        read: false,
      }

      const rest = state.items.filter((item) => item.id !== id)
      return {
        items: [nextItem, ...rest].slice(0, MAX_NOTIFICATIONS),
      }
    }),
  markAsRead: (id) =>
    set((state) => ({
      items: state.items.map((item) => {
        if (item.id !== id || item.read) {
          return item
        }
        return { ...item, read: true }
      }),
    })),
  markAllAsRead: () =>
    set((state) => ({
      items: state.items.map((item) => (item.read ? item : { ...item, read: true })),
    })),
  clearAll: () => set({ items: [] }),
}))

function createNotificationID(): string {
  return `nf-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
}
