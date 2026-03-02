import type { UserStatus } from '../../types/models'

export interface PasswordStrengthResult {
  score: number
  label: string
  color: string
}

export function evaluatePasswordStrength(password: string): PasswordStrengthResult {
  const value = password.trim()
  if (!value) {
    return { score: 0, label: '请输入新密码', color: '#d9d9d9' }
  }

  let score = 0
  if (value.length >= 8) {
    score += 30
  }
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) {
    score += 20
  }
  if (/\d/.test(value)) {
    score += 25
  }
  if (/[^A-Za-z0-9]/.test(value)) {
    score += 25
  }
  if (value.length >= 14 && score < 100) {
    score += 10
  }

  const normalized = Math.min(score, 100)
  if (normalized >= 85) {
    return { score: normalized, label: '强', color: '#52c41a' }
  }
  if (normalized >= 55) {
    return { score: normalized, label: '中', color: '#faad14' }
  }
  return { score: normalized, label: '弱', color: '#ff4d4f' }
}

export function getUserStatusMeta(status: UserStatus): { text: string; color: string } {
  switch (status) {
    case 'normal':
      return { text: '正常', color: 'green' }
    case 'suspended':
      return { text: '已暂停', color: 'orange' }
    case 'banned':
      return { text: '已封禁', color: 'red' }
    case 'over_limit':
      return { text: '超额限流', color: 'volcano' }
    default:
      return { text: status, color: 'default' }
  }
}
