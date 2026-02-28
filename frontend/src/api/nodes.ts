import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { NodeAgent, NodeDeployLog, NodeTCPTestResult } from '../types/models'

export interface ListNodesParams {
  page?: number
  page_size?: number
  status?: string
  deploy_status?: string
  type?: string
  owner_id?: string
}

export interface UpdateNodePayload {
  name?: string
  type?: 'ingress' | 'egress' | 'dual'
  host?: string
  api_port?: number
  arch?: 'amd64' | 'arm64' | 'armv7'
  port_range_min?: number
  port_range_max?: number
  is_self_hosted?: boolean
  vip_level_req?: number
  traffic_ratio?: number
}

export interface NodeDeployLogsParams {
  page?: number
  page_size?: number
}

export interface NodeTCPTestPayload {
  target_host: string
  target_port: number
  timeout_sec?: number
}

export interface CreateNodePayload {
  name: string
  type: 'ingress' | 'egress' | 'dual'
  host: string
  api_port: number
  arch: 'amd64' | 'arm64' | 'armv7'
  port_range_min?: number
  port_range_max?: number
  is_self_hosted?: boolean
  vip_level_req?: number
  traffic_ratio?: number
}

export interface CreateNodeResponse extends NodeAgent {
  token?: string
  install_url?: string
}

export async function listNodes(params?: ListNodesParams) {
  return request<NodeAgent[]>({
    method: 'GET',
    url: '/nodes',
    params,
  })
}

export async function listNodesPaged(params?: ListNodesParams) {
  return requestPaginated<NodeAgent[]>({
    method: 'GET',
    url: '/nodes',
    params,
  })
}

export async function createNode(payload: CreateNodePayload) {
  return request<CreateNodeResponse>({
    method: 'POST',
    url: '/nodes',
    data: payload,
  })
}

export async function getNode(nodeId: string) {
  return request<NodeAgent>({
    method: 'GET',
    url: `/nodes/${nodeId}`,
  })
}

export async function updateNode(nodeId: string, payload: UpdateNodePayload) {
  return request<NodeAgent>({
    method: 'PUT',
    url: `/nodes/${nodeId}`,
    data: payload,
  })
}

export async function deleteNode(nodeId: string) {
  return request<{ deleted: boolean }>({
    method: 'DELETE',
    url: `/nodes/${nodeId}`,
  })
}

export async function testNodeTCP(nodeId: string, payload: NodeTCPTestPayload) {
  return request<NodeTCPTestResult>({
    method: 'POST',
    url: `/nodes/${nodeId}/tcp-test`,
    data: payload,
  })
}

export async function listNodeDeployLogs(nodeId: string, params?: NodeDeployLogsParams): Promise<PaginatedResult<NodeDeployLog[]>> {
  return requestPaginated<NodeDeployLog[]>({
    method: 'GET',
    url: `/nodes/${nodeId}/deploy-logs`,
    params,
  })
}

export function getNodeInstallScriptURL(nodeId: string, installToken: string) {
  const search = new URLSearchParams()
  search.set('installToken', installToken)
  return `/api/v1/nodes/${encodeURIComponent(nodeId)}/install.sh?${search.toString()}`
}
