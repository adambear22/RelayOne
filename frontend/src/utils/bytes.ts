const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

export function formatBytes(bytes: number, decimals = 2): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B'
  }

  const safeDecimals = Math.max(0, decimals)
  const step = 1024
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(step)), BYTE_UNITS.length - 1)
  const value = bytes / step ** unitIndex

  return `${value.toFixed(safeDecimals)} ${BYTE_UNITS[unitIndex]}`
}
