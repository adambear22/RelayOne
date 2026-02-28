import { useEffect } from 'react'

import { useSSEStore, type SSEPayload } from '../stores/sse'

type Listener = (payload: SSEPayload) => void

export function useSSE() {
  const status = useSSEStore((state) => state.status)
  const retryAttempt = useSSEStore((state) => state.retryAttempt)
  const lastEventID = useSSEStore((state) => state.lastEventID)
  const connect = useSSEStore((state) => state.connect)
  const disconnect = useSSEStore((state) => state.disconnect)

  return {
    status,
    retryAttempt,
    lastEventID,
    connect,
    disconnect,
  }
}

export function useSSEEvent(eventType: string, listener: Listener) {
  const on = useSSEStore((state) => state.on)

  useEffect(() => {
    const unsubscribe = on(eventType, listener)
    return unsubscribe
  }, [eventType, listener, on])
}
