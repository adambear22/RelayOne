import { useEffect, useState } from 'react'

import { useSSEStore, type SSEPayload } from '../stores/sse'

interface DeployState {
  nodeID: string
  step: string
  progress: number
  message: string
  done: boolean
  error: boolean
  lastUpdatedAt: number | null
}

export function useSSEDeploy(nodeId: string) {
  const on = useSSEStore((state) => state.on)
  const [state, setState] = useState<DeployState>(() => buildInitialState(nodeId))

  useEffect(() => {
    if (!nodeId.trim()) {
      return
    }

    const unsubscribe = on('deploy.progress', (payload) => {
      const parsed = parseDeployPayload(payload)
      if (!parsed || parsed.nodeID !== nodeId) {
        return
      }

      setState((prev) => {
        const step = parsed.step ?? prev.step
        const progress = parsed.progress ?? prev.progress
        const message = parsed.message ?? prev.message

        return {
          nodeID: parsed.nodeID,
          step,
          progress,
          message,
          done: progress >= 100,
          error: step.toLowerCase() === 'failed',
          lastUpdatedAt: Date.now(),
        }
      })
    })

    return unsubscribe
  }, [nodeId, on])

  const visible = state.nodeID === nodeId ? state : buildInitialState(nodeId)

  return {
    step: visible.step,
    progress: visible.progress,
    message: visible.message,
    done: visible.done,
    error: visible.error,
    lastUpdatedAt: visible.lastUpdatedAt,
  }
}

function buildInitialState(nodeID: string): DeployState {
  return {
    nodeID,
    step: '',
    progress: 0,
    message: '',
    done: false,
    error: false,
    lastUpdatedAt: null,
  }
}

function parseDeployPayload(payload: SSEPayload): {
  nodeID: string
  step?: string
  progress?: number
  message?: string
} | null {
  const data = asObject(payload.data)
  if (!data) {
    return null
  }

  const nodeID = normalizeString(data.node_id) ?? normalizeString(data.agent_id)
  if (!nodeID) {
    return null
  }

  return {
    nodeID,
    step: normalizeString(data.step),
    progress: normalizeProgress(data.progress),
    message: normalizeString(data.message),
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
  const output = value.trim()
  return output.length > 0 ? output : undefined
}

function normalizeProgress(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return clampProgress(value)
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) {
      return clampProgress(parsed)
    }
  }

  return undefined
}

function clampProgress(value: number): number {
  if (value < 0) {
    return 0
  }
  if (value > 100) {
    return 100
  }
  return Math.round(value)
}
