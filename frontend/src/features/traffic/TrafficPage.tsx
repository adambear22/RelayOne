import { useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, Empty, Progress, Row, Space, Statistic, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { fetchCurrentUser } from '../../api/auth'
import { listNodes } from '../../api/nodes'
import { listRules } from '../../api/rules'
import { getRuleTrafficStats, getTrafficDaily, getTrafficMonthly, getTrafficOverview } from '../../api/traffic'
import { useSSEStore } from '../../stores/sse'
import type { ForwardingRule, NodeAgent } from '../../types/models'
import { formatBytes } from '../../utils/bytes'

interface TopRuleRow {
  rule_id: string
  rule_name: string
  node: string
  today_total: number
  month_total: number
}

export default function TrafficPage() {
  const on = useSSEStore((state) => state.on)

  const meQuery = useQuery({
    queryKey: ['users', 'me', 'traffic-page'],
    queryFn: fetchCurrentUser,
  })
  const dailyQuery = useQuery({
    queryKey: ['traffic', 'daily', 30],
    queryFn: () => getTrafficDaily(30),
  })
  const monthlyQuery = useQuery({
    queryKey: ['traffic', 'monthly', 6],
    queryFn: () => getTrafficMonthly(6),
  })

  const isAdmin = meQuery.data?.role === 'admin'

  const overviewQuery = useQuery({
    queryKey: ['traffic', 'overview'],
    queryFn: getTrafficOverview,
    enabled: isAdmin,
  })

  const allRulesQuery = useQuery({
    queryKey: ['rules', 'all-for-overview'],
    queryFn: () => listRules({ page: 1, page_size: 500 }),
    enabled: isAdmin,
  })

  const allNodesQuery = useQuery({
    queryKey: ['nodes', 'all-for-overview'],
    queryFn: () => listNodes({ page: 1, page_size: 500 }),
    enabled: isAdmin,
  })

  const topRuleIDs = useMemo(() => overviewQuery.data?.top10_rules.map((item) => item.rule_id) ?? [], [overviewQuery.data])
  const topRuleIDsKey = topRuleIDs.join(',')

  const topRuleTodayQuery = useQuery({
    queryKey: ['traffic', 'overview', 'top-rule-today', topRuleIDsKey],
    enabled: isAdmin && topRuleIDs.length > 0,
    queryFn: async () => {
      const from = dayjs().startOf('day').toISOString()
      const to = dayjs().toISOString()
      const tuples = await Promise.all(
        topRuleIDs.map(async (ruleID) => {
          const points = await getRuleTrafficStats(ruleID, { from, to })
          const total = points.reduce((sum, item) => sum + item.bytes_total, 0)
          return [ruleID, total] as const
        }),
      )

      return Object.fromEntries(tuples)
    },
  })

  useEffect(() => {
    const unsubscribe = on('traffic.update', () => {
      void meQuery.refetch()
      void dailyQuery.refetch()
      void monthlyQuery.refetch()
      if (isAdmin) {
        void overviewQuery.refetch()
        void topRuleTodayQuery.refetch()
      }
    })
    return unsubscribe
  }, [dailyQuery, isAdmin, meQuery, monthlyQuery, on, overviewQuery, topRuleTodayQuery])

  const todayTotal = useMemo(() => {
    const today = dayjs()
    const item = (dailyQuery.data ?? []).find((entry) => dayjs(entry.day).isSame(today, 'day'))
    return item?.bytes_total ?? 0
  }, [dailyQuery.data])

  const monthTotal = useMemo(() => {
    const now = dayjs()
    const item = (monthlyQuery.data ?? []).find((entry) => dayjs(entry.month).isSame(now, 'month'))
    return item?.bytes_total ?? 0
  }, [monthlyQuery.data])

  const quota = meQuery.data?.traffic_quota ?? 0
  const used = meQuery.data?.traffic_used ?? 0
  const remaining = Math.max(0, quota - used)
  const usageRate = quota > 0 ? Math.min((used / quota) * 100, 100) : 0

  const dailyChartData = useMemo(
    () =>
      (dailyQuery.data ?? []).map((item) => ({
        label: dayjs(item.day).format('MM-DD'),
        bytes: item.bytes_total,
        rawDate: dayjs(item.day).format('YYYY-MM-DD'),
      })),
    [dailyQuery.data],
  )

  const monthlyChartData = useMemo(
    () =>
      (monthlyQuery.data ?? []).map((item) => ({
        label: dayjs(item.month).format('YYYY-MM'),
        bytes: item.bytes_total,
      })),
    [monthlyQuery.data],
  )

  const topRuleRows = useMemo(() => {
    if (!overviewQuery.data) {
      return []
    }

    const rules = allRulesQuery.data ?? []
    const nodes = allNodesQuery.data ?? []
    const ruleMap = new Map<string, ForwardingRule>(rules.map((item) => [item.id, item]))
    const nodeMap = new Map<string, NodeAgent>(nodes.map((item) => [item.id, item]))
    const todayMap = topRuleTodayQuery.data ?? {}

    return overviewQuery.data.top10_rules.map<TopRuleRow>((item) => {
      const rule = ruleMap.get(item.rule_id)
      const nodeID = rule?.ingress_node_id
      const node = nodeID ? nodeMap.get(nodeID) : undefined
      const nodeLabel = node ? `${node.name} (${node.host})` : '-'

      return {
        rule_id: item.rule_id,
        rule_name: item.rule_name || item.rule_id,
        node: nodeLabel,
        today_total: todayMap[item.rule_id] ?? 0,
        month_total: item.bytes_total,
      }
    })
  }, [allNodesQuery.data, allRulesQuery.data, overviewQuery.data, topRuleTodayQuery.data])

  const topRuleColumns = useMemo<ColumnsType<TopRuleRow>>(
    () => [
      { title: '规则名称', dataIndex: 'rule_name' },
      { title: '节点', dataIndex: 'node' },
      { title: '今日流量', dataIndex: 'today_total', render: (value: number) => formatBytes(value) },
      { title: '本月流量', dataIndex: 'month_total', render: (value: number) => formatBytes(value) },
    ],
    [],
  )

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Statistic title="今日流量" value={formatBytes(todayTotal)} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Statistic title="本月流量" value={formatBytes(monthTotal)} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Statistic title="剩余配额" value={formatBytes(remaining)} />
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Typography.Text type="secondary">配额使用率</Typography.Text>
            <Progress style={{ marginTop: 12 }} percent={Number(usageRate.toFixed(2))} status={usageRate >= 100 ? 'exception' : 'active'} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="日流量折线图（30 天）">
            {dailyChartData.length === 0 ? (
              <Empty description="暂无数据" />
            ) : (
              <div style={{ height: 320 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={dailyChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="label" />
                    <YAxis tickFormatter={(value) => formatBytes(Number(value), 1)} />
                    <Tooltip
                      formatter={(value: unknown) => formatBytes(Number(value ?? 0))}
                      labelFormatter={(_, payload) => String(payload?.[0]?.payload?.rawDate ?? '')}
                    />
                    <Line type="monotone" dataKey="bytes" stroke="#1677ff" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card title="月流量柱状图（6 个月）">
            {monthlyChartData.length === 0 ? (
              <Empty description="暂无数据" />
            ) : (
              <div style={{ height: 320 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={monthlyChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="label" />
                    <YAxis tickFormatter={(value) => formatBytes(Number(value), 1)} />
                    <Tooltip formatter={(value: unknown) => formatBytes(Number(value ?? 0))} />
                    <Bar dataKey="bytes" fill="#52c41a" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>
        </Col>
      </Row>

      {isAdmin ? (
        <Card title="规则流量明细（Top 10）">
          <Table<TopRuleRow>
            rowKey="rule_id"
            loading={overviewQuery.isLoading || allRulesQuery.isLoading || allNodesQuery.isLoading || topRuleTodayQuery.isLoading}
            dataSource={topRuleRows}
            columns={topRuleColumns}
            pagination={false}
          />
        </Card>
      ) : null}
    </Space>
  )
}
