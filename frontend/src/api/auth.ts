import { request } from './client'
import type { User } from '../types/models'

export interface LoginPayload {
  username: string
  password: string
}

export interface ChangePasswordPayload {
  old_password: string
  new_password: string
}

export async function login(payload: LoginPayload) {
  return request<{ access_token: string; refresh_token: string }>({
    method: 'POST',
    url: '/auth/login',
    data: payload,
  })
}

export async function logout() {
  return request<{ message?: string }>({
    method: 'POST',
    url: '/auth/logout',
  })
}

export async function refreshToken() {
  return request<{ access_token: string; refresh_token: string }>({
    method: 'POST',
    url: '/auth/refresh',
  })
}

export async function changePassword(payload: ChangePasswordPayload) {
  return request<{ message?: string }>({
    method: 'POST',
    url: '/auth/password',
    data: payload,
  })
}

export async function fetchCurrentUser() {
  return request<User>({
    method: 'GET',
    url: '/users/me',
  })
}
