import { create } from 'zustand'
import { EventSourcePolyfill } from 'event-source-polyfill'

import { useAuthStore } from './auth'

export type SSEStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting'

export interface SSEPayload<T = unknown> {
  id?: string
  type: string
  data: T
}

type SSEListener = (payload: SSEPayload) => void

type SSEHandlerBundle = {
  onStatusChange?: (status: SSEStatus, retryAttempt: number) => void
  onLastEventIDChange?: (lastEventID: string | null) => void
}

const LAST_EVENT_ID_STORAGE_KEY = 'nodepass:last-event-id'
const RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 16000, 30000]
const KNOWN_EVENT_TYPES = [
  'heartbeat',
  'node.status',
  'deploy.progress',
  'rule.status',
  'traffic.update',
  'system.alert',
  'announcement',
]

export class GlobalSSEClient {
  private source: EventSource | EventSourcePolyfill | null = null
  private reconnectTimer: number | null = null
  private manuallyClosed = false
  private reconnectAttempt = 0
  private lastEventID: string | null = this.loadLastEventID()
  private listeners = new Map<string, Set<SSEListener>>()
  private handlers: SSEHandlerBundle = {}

  setHandlers(handlers: SSEHandlerBundle): void {
    this.handlers = handlers
  }

  connect(): void {
    if (this.source) {
      return
    }

    this.manuallyClosed = false
    this.transitionStatus(this.reconnectAttempt > 0 ? 'reconnecting' : 'connecting')

    const streamURL = new URL('/api/v1/events', window.location.origin)
    if (this.lastEventID) {
      streamURL.searchParams.set('last_event_id', this.lastEventID)
    }

    const source = new EventSourcePolyfill(streamURL.toString(), {
      withCredentials: true,
      headers: this.lastEventID
        ? {
            'Last-Event-ID': this.lastEventID,
          }
        : undefined,
    })
    this.source = source

    source.onopen = () => {
      this.reconnectAttempt = 0
      this.transitionStatus('connected')
    }

    source.onerror = () => {
      this.cleanupSource()
      if (!this.manuallyClosed) {
        this.scheduleReconnect()
      }
    }

    source.onmessage = (event: MessageEvent<string>) => {
      this.handleEvent('message', event)
    }

    for (const eventType of KNOWN_EVENT_TYPES) {
      source.addEventListener(eventType, (event: Event) => {
        this.handleEvent(eventType, event as MessageEvent<string>)
      })
    }
  }

  disconnect(): void {
    this.manuallyClosed = true
    this.clearReconnectTimer()
    this.cleanupSource()
    this.reconnectAttempt = 0
    this.transitionStatus('idle')
  }

  on(eventType: string, listener: SSEListener): () => void {
    const key = eventType.trim() || 'message'
    const bucket = this.listeners.get(key)
    if (bucket) {
      bucket.add(listener)
    } else {
      this.listeners.set(key, new Set([listener]))
    }

    return () => {
      this.off(key, listener)
    }
  }

  off(eventType: string, listener: SSEListener): void {
    const key = eventType.trim() || 'message'
    const bucket = this.listeners.get(key)
    if (!bucket) {
      return
    }

    bucket.delete(listener)
    if (bucket.size === 0) {
      this.listeners.delete(key)
    }
  }

  private handleEvent(eventType: string, event: MessageEvent<string>): void {
    const payload: SSEPayload = {
      id: event.lastEventId || undefined,
      type: eventType,
      data: this.parseEventData(event.data),
    }

    if (event.lastEventId) {
      this.lastEventID = event.lastEventId
      this.persistLastEventID(event.lastEventId)
      this.handlers.onLastEventIDChange?.(event.lastEventId)
    }

    this.dispatch(eventType, payload)
    this.dispatch('*', payload)
  }

  private dispatch(eventType: string, payload: SSEPayload): void {
    const listeners = this.listeners.get(eventType)
    if (!listeners || listeners.size === 0) {
      return
    }

    for (const listener of listeners) {
      listener(payload)
    }
  }

  private parseEventData(data: string): unknown {
    if (!data) {
      return null
    }

    try {
      return JSON.parse(data) as unknown
    } catch {
      return data
    }
  }

  private transitionStatus(status: SSEStatus): void {
    this.handlers.onStatusChange?.(status, this.reconnectAttempt)
  }

  private scheduleReconnect(): void {
    this.clearReconnectTimer()

    const delay = RECONNECT_BACKOFF_MS[Math.min(this.reconnectAttempt, RECONNECT_BACKOFF_MS.length - 1)]
    this.reconnectAttempt += 1
    this.transitionStatus('reconnecting')

    this.reconnectTimer = window.setTimeout(() => {
      this.connect()
    }, delay)
  }

  private cleanupSource(): void {
    if (!this.source) {
      return
    }

    this.source.close()
    this.source = null
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer === null) {
      return
    }

    window.clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }

  private persistLastEventID(value: string): void {
    try {
      window.localStorage.setItem(LAST_EVENT_ID_STORAGE_KEY, value)
    } catch {
      // ignore localStorage failures
    }
  }

  private loadLastEventID(): string | null {
    try {
      return window.localStorage.getItem(LAST_EVENT_ID_STORAGE_KEY)
    } catch {
      return null
    }
  }
}

interface SSEStore {
  status: SSEStatus
  retryAttempt: number
  lastEventID: string | null
  connect: () => void
  disconnect: () => void
  on: (eventType: string, listener: SSEListener) => () => void
  off: (eventType: string, listener: SSEListener) => void
}

const globalSSEClient = new GlobalSSEClient()

export const useSSEStore = create<SSEStore>((set) => {
  globalSSEClient.setHandlers({
    onStatusChange: (status, retryAttempt) => {
      set({ status, retryAttempt })
    },
    onLastEventIDChange: (lastEventID) => {
      set({ lastEventID })
    },
  })

  globalSSEClient.on('system.alert', (event) => {
    if (!event || typeof event.data !== 'object' || event.data === null) {
      return
    }

    const payload = event.data as { maintenance_mode?: unknown }
    if (typeof payload.maintenance_mode !== 'boolean') {
      return
    }

    useAuthStore.getState().setMaintenanceMode(payload.maintenance_mode)
  })

  return {
    status: 'idle',
    retryAttempt: 0,
    lastEventID: null,
    connect: () => {
      globalSSEClient.connect()
    },
    disconnect: () => {
      globalSSEClient.disconnect()
    },
    on: (eventType, listener) => {
      return globalSSEClient.on(eventType, listener)
    },
    off: (eventType, listener) => {
      globalSSEClient.off(eventType, listener)
    },
  }
})
