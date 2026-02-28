import { useEffect, useState } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'

import { useSSEStore, type SSEPayload } from '../stores/sse'
import type { NodeAgent } from '../types/models'

type NodeStatus = NodeAgent['status']
type DeployStatus = NodeAgent['deploy_status']

interface NodeSnapshot {
  status: NodeStatus
  deployStatus: DeployStatus
  agentVersion?: string
}

const NODE_STATUS_VALUES = new Set<NodeStatus>(['pending', 'online', 'offline'])
const DEPLOY_STATUS_VALUES = new Set<DeployStatus>(['pending', 'installing', 'success', 'failed'])

export function useSSENode(nodeId: string) {
  const queryClient = useQueryClient()
  const on = useSSEStore((state) => state.on)

  const [snapshot, setSnapshot] = useState<NodeSnapshot>(() => {
    const cachedNode = readNodeFromCache(queryClient, nodeId)
    return {
      status: cachedNode?.status ?? 'pending',
      deployStatus: cachedNode?.deploy_status ?? 'pending',
      agentVersion: cachedNode?.agent_version,
    }
  })

  useEffect(() => {
    if (!nodeId.trim()) {
      return undefined
    }

    const unsubscribe = on('node.status', (payload) => {
      const parsed = parseNodeStatusPayload(payload)
      if (!parsed || parsed.nodeID !== nodeId) {
        return
      }

      setSnapshot((prev) => ({
        status: parsed.status ?? prev.status,
        deployStatus: parsed.deployStatus ?? prev.deployStatus,
        agentVersion: parsed.agentVersion ?? prev.agentVersion,
      }))

      queryClient.setQueryData<NodeAgent[] | undefined>(['nodes'], (current) => {
        if (!current || current.length === 0) {
          return current
        }

        let changed = false
        const next = current.map((item) => {
          if (item.id !== nodeId) {
            return item
          }

          changed = true
          return {
            ...item,
            status: parsed.status ?? item.status,
            deploy_status: parsed.deployStatus ?? item.deploy_status,
            agent_version: parsed.agentVersion ?? item.agent_version,
          }
        })

        return changed ? next : current
      })
    })

    return unsubscribe
  }, [nodeId, on, queryClient])

  return {
    status: snapshot.status,
    deployStatus: snapshot.deployStatus,
    agentVersion: snapshot.agentVersion,
  }
}

function readNodeFromCache(queryClient: QueryClient, nodeId: string): NodeAgent | undefined {
  if (!nodeId.trim()) {
    return undefined
  }

  const nodes = queryClient.getQueryData<NodeAgent[]>(['nodes'])
  return nodes?.find((item) => item.id === nodeId)
}

function parseNodeStatusPayload(payload: SSEPayload): {
  nodeID: string
  status?: NodeStatus
  deployStatus?: DeployStatus
  agentVersion?: string
} | null {
  const data = asObject(payload.data)
  if (!data) {
    return null
  }

  const nodeID = normalizeString(data.agent_id) ?? normalizeString(data.node_id)
  if (!nodeID) {
    return null
  }

  const status = normalizeStatus<NodeStatus>(data.status, NODE_STATUS_VALUES)
  const deployStatus = normalizeStatus<DeployStatus>(data.deploy_status, DEPLOY_STATUS_VALUES)
  const agentVersion = normalizeString(data.agent_version)

  return {
    nodeID,
    status,
    deployStatus,
    agentVersion,
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

  const result = value.trim()
  return result ? result : undefined
}

function normalizeStatus<T extends string>(value: unknown, set: Set<T>): T | undefined {
  const normalized = normalizeString(value)
  if (!normalized || !set.has(normalized as T)) {
    return undefined
  }
  return normalized as T
}
