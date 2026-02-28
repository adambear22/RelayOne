import { request } from './client'
import type { HopChain } from '../types/models'

export interface ListHopChainsParams {
  page?: number
  page_size?: number
  owner_id?: string
}

export async function listHopChains(params?: ListHopChainsParams) {
  return request<HopChain[]>({
    method: 'GET',
    url: '/hop-chains',
    params,
  })
}
