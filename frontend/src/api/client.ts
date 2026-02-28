import axios, { AxiosError, AxiosHeaders, type AxiosInstance, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import Cookies from 'js-cookie'

import { ApiBusinessError, type ApiEnvelope, type PaginatedResult } from '../types/api'

type RetryableConfig = AxiosRequestConfig & { _retry?: boolean }

const TOKEN_EXPIRED_CODE = 10002

export const apiClient: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  timeout: 20000,
})

const refreshClient: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  timeout: 15000,
})

let refreshPromise: Promise<void> | null = null

apiClient.interceptors.request.use((config) => {
  const token = Cookies.get('access_token') ?? Cookies.get('token')
  if (!token) {
    return config
  }

  const headers = AxiosHeaders.from(config.headers)
  headers.set('Authorization', `Bearer ${token}`)
  config.headers = headers

  return config
})

apiClient.interceptors.response.use(
  async (response) => {
    const envelope = response.data as ApiEnvelope<unknown>
    if (!isApiEnvelope(envelope)) {
      return response
    }

    if (envelope.code === 0) {
      return response
    }

    const config = response.config as RetryableConfig
    if (envelope.code === TOKEN_EXPIRED_CODE && !config._retry && !isRefreshEndpoint(config.url)) {
      config._retry = true
      await ensureRefreshToken()
      return apiClient(config)
    }

    throw new ApiBusinessError(envelope.message || 'Request failed', envelope.code, {
      httpStatus: response.status,
      requestURL: response.config.url,
      payload: response.data,
    })
  },
  async (error: AxiosError) => {
    const config = (error.config ?? {}) as RetryableConfig
    const status = error.response?.status ?? 0

    if (status === 401 && !config._retry && !isRefreshEndpoint(config.url)) {
      config._retry = true
      await ensureRefreshToken()
      return apiClient(config)
    }

    throw normalizeAxiosError(error)
  },
)

export async function request<T>(config: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.request<ApiEnvelope<T>>(config)
  if (isApiEnvelope(response.data)) {
    return response.data.data as T
  }

  return response.data as unknown as T
}

export async function requestPaginated<T>(config: AxiosRequestConfig): Promise<PaginatedResult<T>> {
  const response = await apiClient.request<ApiEnvelope<T>>(config)
  if (isApiEnvelope(response.data)) {
    return {
      items: response.data.data as T,
      pagination: response.data.pagination,
    }
  }

  return {
    items: response.data as unknown as T,
    pagination: undefined,
  }
}

export function extractPagination(response: AxiosResponse<ApiEnvelope<unknown>>) {
  if (!isApiEnvelope(response.data)) {
    return undefined
  }

  return response.data.pagination
}

async function ensureRefreshToken(): Promise<void> {
  if (!refreshPromise) {
    refreshPromise = refreshClient
      .post<ApiEnvelope<unknown>>('/auth/refresh')
      .then((response) => {
        if (!isApiEnvelope(response.data)) {
          return
        }

        if (response.data.code !== 0) {
          throw new ApiBusinessError(response.data.message || 'Refresh token failed', response.data.code, {
            httpStatus: response.status,
            requestURL: response.config.url,
            payload: response.data,
          })
        }
      })
      .finally(() => {
        refreshPromise = null
      })
  }

  return refreshPromise
}

function isRefreshEndpoint(url?: string): boolean {
  return typeof url === 'string' && url.includes('/auth/refresh')
}

function isApiEnvelope(value: unknown): value is ApiEnvelope<unknown> {
  if (!value || typeof value !== 'object') {
    return false
  }

  return typeof (value as ApiEnvelope<unknown>).code === 'number'
}

function normalizeAxiosError(error: AxiosError): Error {
  if (error instanceof ApiBusinessError) {
    return error
  }

  const envelope = error.response?.data as ApiEnvelope<unknown> | undefined
  if (envelope && typeof envelope.code === 'number') {
    return new ApiBusinessError(envelope.message || error.message, envelope.code, {
      httpStatus: error.response?.status,
      requestURL: error.config?.url,
      payload: envelope,
    })
  }

  return new Error(error.message || 'Network request failed')
}
