export const DEFAULT_TLS = 1
export const DEFAULT_MODE = 'fast'
export const DEFAULT_MIN = 8
export const DEFAULT_MAX = 1024
export const DEFAULT_RATE = 0
export const DEFAULT_LOG = 'warn'

export interface NodepassParams {
  instanceType: string
  host: string
  port: number
  user?: string
  pass?: string
  tls?: number
  mode?: string
  min?: number
  max?: number
  rate?: number
  noTCP?: boolean
  noUDP?: boolean
  log?: string
}

export const PRESETS: Record<string, Partial<NodepassParams>> = {
  streaming: {
    tls: 1,
    mode: 'fast',
    min: 32,
    max: 4096,
    rate: 0,
    noTCP: false,
    noUDP: false,
    log: 'warn',
  },
  low_latency_gaming: {
    tls: 0,
    mode: 'fast',
    min: 16,
    max: 2048,
    rate: 0,
    noTCP: true,
    noUDP: false,
    log: 'warn',
  },
  secure_transfer: {
    tls: 2,
    mode: 'safe',
    min: 8,
    max: 1024,
    rate: 300,
    noTCP: false,
    noUDP: false,
    log: 'info',
  },
  ssh_tunnel: {
    tls: 1,
    mode: 'mix',
    min: 4,
    max: 128,
    rate: 0,
    noTCP: false,
    noUDP: true,
    log: 'warn',
  },
}

export function buildNodepassURL(params: NodepassParams): string {
  const scheme = normalizeString(params.instanceType) || 'tcp'
  const host = normalizeString(params.host) || '127.0.0.1'
  const port = normalizePort(params.port)
  const compiled = compileDefaults(params)
  const query = new URLSearchParams()

  if (compiled.tls !== DEFAULT_TLS) {
    query.set('tls', String(compiled.tls))
  }
  if (compiled.mode !== DEFAULT_MODE) {
    query.set('mode', compiled.mode)
  }
  if (compiled.min !== DEFAULT_MIN) {
    query.set('min', String(compiled.min))
  }
  if (compiled.max !== DEFAULT_MAX) {
    query.set('max', String(compiled.max))
  }
  if (compiled.rate !== DEFAULT_RATE) {
    query.set('rate', String(compiled.rate))
  }
  if (compiled.noTCP) {
    query.set('notcp', '1')
  }
  if (compiled.noUDP) {
    query.set('noudp', '1')
  }
  if (compiled.log !== DEFAULT_LOG) {
    query.set('log', compiled.log)
  }

  const user = normalizeString(params.user)
  const pass = params.pass ?? ''
  const auth = user || pass ? `${encodeURIComponent(user ?? '')}:${encodeURIComponent(pass)}@` : ''
  const hostPort = formatHostPort(host, port)
  const rawQuery = new URLSearchParams(
    Array.from(query.entries()).sort(([left], [right]) => left.localeCompare(right)),
  ).toString()

  return rawQuery ? `${scheme}://${auth}${hostPort}?${rawQuery}` : `${scheme}://${auth}${hostPort}`
}

function compileDefaults(params: NodepassParams) {
  return {
    tls: normalizeNumber(params.tls, DEFAULT_TLS),
    mode: normalizeString(params.mode) || DEFAULT_MODE,
    min: normalizeNumber(params.min, DEFAULT_MIN),
    max: normalizeNumber(params.max, DEFAULT_MAX),
    rate: normalizeNumber(params.rate, DEFAULT_RATE),
    noTCP: Boolean(params.noTCP),
    noUDP: Boolean(params.noUDP),
    log: normalizeString(params.log) || DEFAULT_LOG,
  }
}

function normalizeString(value: string | undefined): string {
  return value?.trim() ?? ''
}

function normalizeNumber(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return fallback
  }
  return Math.trunc(value)
}

function normalizePort(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 1
  }
  return Math.trunc(value)
}

function formatHostPort(host: string, port: number): string {
  if (host.includes(':') && !host.startsWith('[') && !host.endsWith(']')) {
    return `[${host}]:${port}`
  }
  return `${host}:${port}`
}
