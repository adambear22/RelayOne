export interface Pagination {
  page: number
  page_size: number
  total: number
}

export interface ApiEnvelope<T> {
  code: number
  message: string
  data: T
  pagination?: Pagination
}

export interface PaginatedResult<T> {
  items: T
  pagination?: Pagination
}

export class ApiBusinessError extends Error {
  code: number
  httpStatus?: number
  requestURL?: string
  payload?: unknown

  constructor(message: string, code: number, options?: { httpStatus?: number; requestURL?: string; payload?: unknown }) {
    super(message)
    this.name = 'ApiBusinessError'
    this.code = code
    this.httpStatus = options?.httpStatus
    this.requestURL = options?.requestURL
    this.payload = options?.payload
  }
}
