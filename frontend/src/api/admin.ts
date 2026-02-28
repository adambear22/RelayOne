import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { AuditLog, TrafficOverview } from '../types/models'

export async function getAdminOverview() {
  return request<TrafficOverview>({
    method: 'GET',
    url: '/traffic/overview',
  })
}

export interface ListAuditLogsParams {
  page?: number
  page_size?: number
  user_id?: string
  resource_type?: string
  resource_id?: string
  action?: string
  ip_address?: string
  from?: string
  to?: string
}

export async function getAuditLogs(params?: ListAuditLogsParams): Promise<PaginatedResult<AuditLog[]>> {
  return requestPaginated<AuditLog[]>({
    method: 'GET',
    url: '/audit',
    params,
  })
}
