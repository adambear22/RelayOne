import { request } from './client'
import type { DailyTrafficStat, MonthlyTrafficStat, RuleTrafficPoint, TrafficOverview, TrafficStat } from '../types/models'

export interface TrafficStatsParams {
  granularity?: 'hour' | 'day' | 'month'
  from?: string
  to?: string
}

export async function getTrafficStats(params?: TrafficStatsParams) {
  return request<TrafficStat[]>({
    method: 'GET',
    url: '/traffic/stats',
    params,
  })
}

export async function getTrafficDaily(days = 30) {
  return request<DailyTrafficStat[]>({
    method: 'GET',
    url: '/traffic/daily',
    params: { days },
  })
}

export async function getTrafficMonthly(months = 12) {
  return request<MonthlyTrafficStat[]>({
    method: 'GET',
    url: '/traffic/monthly',
    params: { months },
  })
}

export interface RuleTrafficStatsParams {
  from?: string
  to?: string
}

export async function getRuleTrafficStats(ruleID: string, params?: RuleTrafficStatsParams) {
  return request<RuleTrafficPoint[]>({
    method: 'GET',
    url: `/traffic/rules/${ruleID}`,
    params,
  })
}

export async function getTrafficOverview() {
  return request<TrafficOverview>({
    method: 'GET',
    url: '/traffic/overview',
  })
}

export async function resetUserTrafficQuota(userID: string) {
  return request<{ reset: boolean }>({
    method: 'POST',
    url: `/traffic/reset/${userID}`,
  })
}

export async function batchSyncTrafficQuota() {
  return request<{ synced: boolean }>({
    method: 'POST',
    url: '/traffic/sync',
  })
}
