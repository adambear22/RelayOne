import { describe, expect, test } from 'vitest'

import { evaluatePasswordStrength, getUserStatusMeta } from './helpers'

describe('evaluatePasswordStrength', () => {
  test('空密码返回初始状态', () => {
    expect(evaluatePasswordStrength('')).toEqual({
      score: 0,
      label: '请输入新密码',
      color: '#d9d9d9',
    })
  })

  test('弱密码得分较低', () => {
    const result = evaluatePasswordStrength('abc123')
    expect(result.score).toBeLessThan(55)
    expect(result.label).toBe('弱')
  })

  test('强密码应达到高分', () => {
    const result = evaluatePasswordStrength('NodePass#2026Strong')
    expect(result.score).toBeGreaterThanOrEqual(85)
    expect(result.label).toBe('强')
  })
})

describe('getUserStatusMeta', () => {
  test('状态映射正确', () => {
    expect(getUserStatusMeta('normal')).toEqual({ text: '正常', color: 'green' })
    expect(getUserStatusMeta('banned')).toEqual({ text: '已封禁', color: 'red' })
  })
})
