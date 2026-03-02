import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { BenefitCode } from '../types/models'

export interface ListCodesParams {
  page?: number
  page_size?: number
  vip_level?: number
  is_used?: boolean
  is_enabled?: boolean
  keyword?: string
}

export interface ListRedeemHistoryParams {
  page?: number
  page_size?: number
}

export interface RedeemHistoryItem {
  id: string
  code: string
  vip_level: number
  duration_days: number
  used_at?: string
  expires_at?: string
  source?: string
  remark?: string
}

export interface BatchGenerateCodesPayload {
  count: number
  vip_level: number
  duration_days?: number
  expires_at?: string
  valid_days?: number
  custom_codes?: string[]
}

export interface BatchUpdateCodesStatusPayload {
  ids: string[]
  enabled: boolean
}

export interface BatchDeleteCodesPayload {
  ids: string[]
}

export async function listCodes(params?: ListCodesParams): Promise<PaginatedResult<BenefitCode[]>> {
  return requestPaginated<BenefitCode[]>({
    method: 'GET',
    url: '/codes',
    params,
  })
}

export async function listRedeemHistory(params?: ListRedeemHistoryParams): Promise<PaginatedResult<RedeemHistoryItem[]>> {
  return requestPaginated<RedeemHistoryItem[]>({
    method: 'GET',
    url: '/codes/redeem/history',
    params,
  })
}

export async function redeemCode(code: string) {
  return request<{ redeemed: boolean }>({
    method: 'POST',
    url: '/codes/redeem',
    data: { code },
  })
}

export async function batchGenerateCodes(payload: BatchGenerateCodesPayload) {
  return request<BenefitCode[]>({
    method: 'POST',
    url: '/codes/batch-generate',
    data: payload,
  })
}

export async function batchUpdateCodesStatus(payload: BatchUpdateCodesStatusPayload) {
  return request<{ updated: number; enabled: boolean }>({
    method: 'PATCH',
    url: '/codes/status',
    data: payload,
  })
}

export async function batchDeleteCodes(payload: BatchDeleteCodesPayload) {
  return request<{ deleted: number }>({
    method: 'DELETE',
    url: '/codes/batch',
    data: payload,
  })
}
