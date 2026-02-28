import { useEffect, useState } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'

import { useSSEStore, type SSEPayload } from '../stores/sse'
import type { ForwardingRule } from '../types/models'

type RuleStatus = ForwardingRule['status']
type RuleSyncStatus = ForwardingRule['sync_status']

interface RuleSnapshot {
  status: RuleStatus
  syncStatus: RuleSyncStatus
  lastAction?: string
  error?: string
}

const RULE_STATUS_VALUES = new Set<RuleStatus>(['running', 'stopped', 'paused'])
const RULE_SYNC_STATUS_VALUES = new Set<RuleSyncStatus>(['pending_sync', 'synced', 'sync_failed'])

export function useSSERule(ruleId: string) {
  const queryClient = useQueryClient()
  const on = useSSEStore((state) => state.on)

  const [snapshot, setSnapshot] = useState<RuleSnapshot>(() => {
    const cachedRule = readRuleFromCache(queryClient, ruleId)
    return {
      status: cachedRule?.status ?? 'stopped',
      syncStatus: cachedRule?.sync_status ?? 'pending_sync',
    }
  })

  useEffect(() => {
    if (!ruleId.trim()) {
      return undefined
    }

    const unsubscribe = on('rule.status', (payload) => {
      const parsed = parseRuleStatusPayload(payload)
      if (!parsed || parsed.ruleID !== ruleId) {
        return
      }

      setSnapshot((prev) => ({
        status: parsed.status ?? prev.status,
        syncStatus: parsed.syncStatus ?? prev.syncStatus,
        lastAction: parsed.action ?? prev.lastAction,
        error: parsed.error,
      }))

      queryClient.setQueryData<ForwardingRule[] | undefined>(['rules'], (current) => {
        if (!current || current.length === 0) {
          return current
        }

        let changed = false
        const next = current.map((item) => {
          if (item.id !== ruleId) {
            return item
          }
          changed = true
          return {
            ...item,
            status: parsed.status ?? item.status,
            sync_status: parsed.syncStatus ?? item.sync_status,
          }
        })
        return changed ? next : current
      })
    })

    return unsubscribe
  }, [on, queryClient, ruleId])

  return snapshot
}

function readRuleFromCache(queryClient: QueryClient, ruleId: string): ForwardingRule | undefined {
  if (!ruleId.trim()) {
    return undefined
  }

  const rules = queryClient.getQueryData<ForwardingRule[]>(['rules'])
  return rules?.find((item) => item.id === ruleId)
}

function parseRuleStatusPayload(payload: SSEPayload): {
  ruleID: string
  status?: RuleStatus
  syncStatus?: RuleSyncStatus
  action?: string
  error?: string
} | null {
  const data = asObject(payload.data)
  if (!data) {
    return null
  }

  const ruleID = normalizeString(data.rule_id)
  if (!ruleID) {
    return null
  }

  return {
    ruleID,
    status: normalizeStatus(data.status, RULE_STATUS_VALUES),
    syncStatus: normalizeStatus(data.sync_status, RULE_SYNC_STATUS_VALUES),
    action: normalizeString(data.action),
    error: normalizeString(data.error),
  }
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') {
    return null
  }
  return value as Record<string, unknown>
}

function normalizeString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }
  const normalized = value.trim()
  return normalized ? normalized : undefined
}

function normalizeStatus<T extends string>(value: unknown, allowed: Set<T>): T | undefined {
  const normalized = normalizeString(value)
  if (!normalized || !allowed.has(normalized as T)) {
    return undefined
  }
  return normalized as T
}
