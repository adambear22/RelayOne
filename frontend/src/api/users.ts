import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { User, UserStatus } from '../types/models'

export interface ListUsersParams {
  page?: number
  page_size?: number
  status?: UserStatus
  role?: 'admin' | 'user'
  keyword?: string
}

export interface CreateUserPayload {
  username: string
  password: string
  email?: string
  role?: 'admin' | 'user'
  status?: UserStatus
  vip_level?: number
  vip_expires_at?: string
  traffic_quota?: number
  bandwidth_limit?: number
  max_rules?: number
  permissions?: string[]
}

export interface UpdateUserPayload {
  username?: string
  email?: string
  role?: 'admin' | 'user'
  status?: UserStatus
  vip_level?: number
  vip_expires_at?: string
  traffic_quota?: number
  bandwidth_limit?: number
  max_rules?: number
  permissions?: string[]
}

export interface BindTelegramPayload {
  telegram_id?: number
  username?: string
  bind_code?: string
}

export async function listUsers(params?: ListUsersParams): Promise<PaginatedResult<User[]>> {
  return requestPaginated<User[]>({
    method: 'GET',
    url: '/users',
    params,
  })
}

export async function createUser(payload: CreateUserPayload) {
  return request<User>({
    method: 'POST',
    url: '/users',
    data: payload,
  })
}

export async function updateUser(userId: string, payload: UpdateUserPayload) {
  return request<User>({
    method: 'PUT',
    url: `/users/${userId}`,
    data: payload,
  })
}

export async function setUserStatus(userId: string, status: UserStatus) {
  return request<{ status: UserStatus }>({
    method: 'PATCH',
    url: `/users/${userId}/status`,
    data: { status },
  })
}

export async function bindUserTelegram(userId: string, payload: BindTelegramPayload) {
  return request<{ bound: boolean }>({
    method: 'POST',
    url: `/users/${userId}/telegram/bind`,
    data: payload,
  })
}

export async function unbindUserTelegram(userId: string) {
  return request<{ bound: boolean }>({
    method: 'DELETE',
    url: `/users/${userId}/telegram/bind`,
  })
}
