import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { ForwardingRule } from '../types/models'

export interface ListRulesParams {
  page?: number
  page_size?: number
  status?: string
  mode?: string
  node_id?: string
  owner_id?: string
}

export interface CreateRulePayload {
  name: string
  mode: 'single' | 'tunnel' | 'lb' | 'hop_chain'
  ingress_node_id: string
  ingress_port?: number
  target_host: string
  target_port: number
  egress_node_id?: string
  lb_group_id?: string
  hop_chain_id?: string
  np_tls?: number
  np_mode?: 'fast' | 'safe' | 'mix'
  np_min?: number
  np_max?: number
  np_rate?: number
  np_notcp?: boolean
  np_noudp?: boolean
  np_log?: 'debug' | 'info' | 'warn' | 'error'
}

export interface UpdateRulePayload {
  name?: string
  mode?: 'single' | 'tunnel' | 'lb' | 'hop_chain'
  ingress_node_id?: string
  target_host?: string
  target_port?: number
  egress_node_id?: string
  lb_group_id?: string
  hop_chain_id?: string
  np_tls?: number
  np_mode?: 'fast' | 'safe' | 'mix'
  np_min?: number
  np_max?: number
  np_rate?: number
  np_notcp?: boolean
  np_noudp?: boolean
  np_log?: 'debug' | 'info' | 'warn' | 'error'
}

export async function listRules(params?: ListRulesParams) {
  return request<ForwardingRule[]>({
    method: 'GET',
    url: '/rules',
    params,
  })
}

export async function listRulesPaged(params?: ListRulesParams): Promise<PaginatedResult<ForwardingRule[]>> {
  return requestPaginated<ForwardingRule[]>({
    method: 'GET',
    url: '/rules',
    params,
  })
}

export async function getRule(ruleId: string) {
  return request<ForwardingRule>({
    method: 'GET',
    url: `/rules/${ruleId}`,
  })
}

export async function createRule(payload: CreateRulePayload) {
  return request<ForwardingRule>({
    method: 'POST',
    url: '/rules',
    data: payload,
  })
}

export async function updateRule(ruleId: string, payload: UpdateRulePayload) {
  return request<ForwardingRule>({
    method: 'PUT',
    url: `/rules/${ruleId}`,
    data: payload,
  })
}

export async function startRule(ruleId: string) {
  return request<{ ok: boolean }>({
    method: 'POST',
    url: `/rules/${ruleId}/start`,
  })
}

export async function stopRule(ruleId: string) {
  return request<{ ok: boolean }>({
    method: 'POST',
    url: `/rules/${ruleId}/stop`,
  })
}

export async function restartRule(ruleId: string) {
  return request<{ ok: boolean }>({
    method: 'POST',
    url: `/rules/${ruleId}/restart`,
  })
}

export async function syncRule(ruleId: string) {
  return request<{ ok: boolean }>({
    method: 'POST',
    url: `/rules/${ruleId}/sync`,
  })
}

export async function deleteRule(ruleId: string) {
  return request<{ deleted: boolean }>({
    method: 'DELETE',
    url: `/rules/${ruleId}`,
  })
}

export async function batchDeleteRules(ids: string[]) {
  return request<{ deleted: number }>({
    method: 'DELETE',
    url: '/rules/batch',
    data: { ids },
  })
}

export async function getRuleInstanceInfo(ruleId: string) {
  return request<Record<string, unknown>>({
    method: 'GET',
    url: `/rules/${ruleId}/instance`,
  })
}
