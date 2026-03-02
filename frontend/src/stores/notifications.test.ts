import { beforeEach, describe, expect, test } from 'vitest'

import { useNotificationStore } from './notifications'

describe('notification store', () => {
  beforeEach(() => {
    useNotificationStore.getState().clearAll()
  })

  test('addNotification keeps latest 20 entries', () => {
    const add = useNotificationStore.getState().addNotification

    for (let index = 0; index < 25; index += 1) {
      add({
        id: `id-${index}`,
        kind: 'info',
        title: `title-${index}`,
      })
    }

    const items = useNotificationStore.getState().items
    expect(items).toHaveLength(20)
    expect(items[0]?.id).toBe('id-24')
    expect(items[19]?.id).toBe('id-5')
  })

  test('markAsRead and markAllAsRead update read status', () => {
    const { addNotification, markAsRead, markAllAsRead } = useNotificationStore.getState()

    addNotification({ id: 'n1', kind: 'warning', title: 'one' })
    addNotification({ id: 'n2', kind: 'error', title: 'two' })

    markAsRead('n1')
    let items = useNotificationStore.getState().items
    expect(items.find((item) => item.id === 'n1')?.read).toBe(true)
    expect(items.find((item) => item.id === 'n2')?.read).toBe(false)

    markAllAsRead()
    items = useNotificationStore.getState().items
    expect(items.every((item) => item.read)).toBe(true)
  })
})
