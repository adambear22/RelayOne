import { request } from './client'
import type { LBGroup } from '../types/models'

export interface ListLBGroupsParams {
  page?: number
  page_size?: number
  owner_id?: string
}

export async function listLBGroups(params?: ListLBGroupsParams) {
  return request<LBGroup[]>({
    method: 'GET',
    url: '/lb-groups',
    params,
  })
}
