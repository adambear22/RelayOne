import { request } from './client'
import type { UserVIPEntitlement, VIPLevel } from '../types/models'

export interface CreateVIPLevelPayload {
  level: number
  name: string
  traffic_quota: number
  max_rules: number
  bandwidth_limit: number
  max_ingress_nodes?: number
  max_egress_nodes?: number
  accessible_node_level?: number
  traffic_ratio?: number
  custom_features?: Record<string, unknown>
}

export interface UpdateVIPLevelPayload {
  name?: string
  traffic_quota?: number
  max_rules?: number
  bandwidth_limit?: number
  max_ingress_nodes?: number
  max_egress_nodes?: number
  accessible_node_level?: number
  traffic_ratio?: number
  custom_features?: Record<string, unknown>
}

export interface UpgradeUserVIPPayload {
  level: number
  valid_days: number
}

export async function listVIPLevels() {
  return request<VIPLevel[]>({
    method: 'GET',
    url: '/vip',
  })
}

export async function getMyVIP() {
  return request<UserVIPEntitlement>({
    method: 'GET',
    url: '/vip/me',
  })
}

export async function getVIPLevel(level: number) {
  return request<VIPLevel>({
    method: 'GET',
    url: `/vip/${level}`,
  })
}

export async function createVIPLevel(payload: CreateVIPLevelPayload) {
  return request<VIPLevel>({
    method: 'POST',
    url: '/vip',
    data: payload,
  })
}

export async function updateVIPLevel(level: number, payload: UpdateVIPLevelPayload) {
  return request<VIPLevel>({
    method: 'PUT',
    url: `/vip/${level}`,
    data: payload,
  })
}

export async function deleteVIPLevel(level: number) {
  return request<{ deleted: boolean }>({
    method: 'DELETE',
    url: `/vip/${level}`,
  })
}

export async function upgradeUserVIP(userID: string, payload: UpgradeUserVIPPayload) {
  return request<{ upgraded: boolean }>({
    method: 'POST',
    url: `/vip/users/${userID}/upgrade`,
    data: payload,
  })
}
