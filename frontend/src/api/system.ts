import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { SystemConfig, SystemLogEntry } from '../types/models'

export interface UpdateSystemConfigPayload {
  site_name?: string
  support_email?: string
  maintenance_mode?: boolean
  registration_enabled?: boolean
  default_traffic_quota?: number
  default_max_rules?: number
  telegram_config?: {
    bot_token?: string
    bot_username?: string
    webhook_url?: string
    webhook_secret?: string
    frontend_url?: string
    sso_base_url?: string
    default_chat_id?: number
    enabled?: boolean
  }
  external_api_keys?: Array<{
    name: string
    key?: string
    scopes?: string[]
  }>
}

export interface ListSystemLogsParams {
  page?: number
  page_size?: number
  level?: string
  keyword?: string
  from?: string
  to?: string
}

export async function getSystemConfig() {
  return request<SystemConfig>({
    method: 'GET',
    url: '/system/config',
  })
}

export async function updateSystemConfig(payload: UpdateSystemConfigPayload) {
  return request<{ updated: boolean }>({
    method: 'PUT',
    url: '/system/config',
    data: payload,
  })
}

export async function listSystemLogs(params?: ListSystemLogsParams): Promise<PaginatedResult<SystemLogEntry[]>> {
  return requestPaginated<SystemLogEntry[]>({
    method: 'GET',
    url: '/system/logs',
    params,
  })
}
