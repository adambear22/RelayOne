import { act, renderHook } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { useSSERule } from './useSSERule'
import { useSSEStore, type SSEPayload } from '../stores/sse'
import type { ForwardingRule } from '../types/models'

interface WrapperProps {
  children: ReactNode
}

describe('useSSERule', () => {
  let queryClient: QueryClient
  let capturedHandler: ((payload: SSEPayload) => void) | undefined
  let unsubscribeCalls = 0

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    })

    unsubscribeCalls = 0
    capturedHandler = undefined

    useSSEStore.setState({
      on: (eventType, listener) => {
        if (eventType === 'rule.status') {
          capturedHandler = listener
        }
        return () => {
          unsubscribeCalls += 1
        }
      },
      off: vi.fn(),
      connect: vi.fn(),
      disconnect: vi.fn(),
      status: 'idle',
      retryAttempt: 0,
      lastEventID: null,
    })
  })

  test('SSE 事件触发时 status 更新', () => {
    const ruleID = 'rule-1'
    queryClient.setQueryData<ForwardingRule[]>(['rules'], [buildRule(ruleID)])

    const wrapper = ({ children }: WrapperProps) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )

    const { result } = renderHook(() => useSSERule(ruleID), { wrapper })

    expect(result.current.status).toBe('stopped')
    expect(result.current.syncStatus).toBe('pending_sync')

    act(() => {
      capturedHandler?.({
        type: 'rule.status',
        data: {
          rule_id: ruleID,
          status: 'running',
          sync_status: 'synced',
          action: 'start',
        },
      })
    })

    expect(result.current.status).toBe('running')
    expect(result.current.syncStatus).toBe('synced')
    expect(result.current.lastAction).toBe('start')

    const cached = queryClient.getQueryData<ForwardingRule[]>(['rules'])
    expect(cached?.[0]?.status).toBe('running')
    expect(cached?.[0]?.sync_status).toBe('synced')
  })

  test('组件卸载后取消事件订阅', () => {
    const wrapper = ({ children }: WrapperProps) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )

    const { unmount } = renderHook(() => useSSERule('rule-2'), { wrapper })
    unmount()

    expect(unsubscribeCalls).toBe(1)
  })
})

function buildRule(id: string): ForwardingRule {
  return {
    id,
    name: 'rule',
    owner_id: 'owner-1',
    mode: 'single',
    ingress_node_id: 'node-1',
    ingress_port: 10000,
    target_host: '127.0.0.1',
    target_port: 443,
    status: 'stopped',
    sync_status: 'pending_sync',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }
}
