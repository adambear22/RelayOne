import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Empty, List, Progress, Row, Space, Statistic, Tag, Typography } from 'antd'
import dayjs from 'dayjs'

import { listActiveAnnouncements } from '../api/announcements'
import { fetchCurrentUser } from '../api/auth'
import { listNodes } from '../api/nodes'
import { listRules } from '../api/rules'
import { getTrafficOverview } from '../api/traffic'
import { useSSEStore } from '../stores/sse'
import { formatBytes } from '../utils/bytes'

export default function Dashboard() {
  const on = useSSEStore((state) => state.on)

  const meQuery = useQuery({
    queryKey: ['users', 'me', 'dashboard'],
    queryFn: fetchCurrentUser,
  })

  const runningRulesQuery = useQuery({
    queryKey: ['rules', 'running', 5],
    queryFn: () => listRules({ status: 'running', page: 1, page_size: 5 }),
  })

  const announcementsQuery = useQuery({
    queryKey: ['announcements', 'active'],
    queryFn: listActiveAnnouncements,
  })

  const isAdmin = meQuery.data?.role === 'admin'

  const nodeStatsQuery = useQuery({
    queryKey: ['nodes', 'dashboard-admin'],
    queryFn: () => listNodes({ page: 1, page_size: 500 }),
    enabled: isAdmin,
  })

  const overviewQuery = useQuery({
    queryKey: ['traffic', 'overview', 'dashboard-admin'],
    queryFn: getTrafficOverview,
    enabled: isAdmin,
  })

  useEffect(() => {
    const unbindAnnouncement = on('announcement', () => {
      void announcementsQuery.refetch()
    })
    const unbindTraffic = on('traffic.update', () => {
      void meQuery.refetch()
    })

    return () => {
      unbindAnnouncement()
      unbindTraffic()
    }
  }, [announcementsQuery, meQuery, on])

  const user = meQuery.data
  const quota = user?.traffic_quota ?? 0
  const used = user?.traffic_used ?? 0
  const usagePercent = quota > 0 ? Math.min((used / quota) * 100, 100) : 0

  const totalNodes = nodeStatsQuery.data?.length ?? 0
  const onlineNodes = (nodeStatsQuery.data ?? []).filter((item) => item.status === 'online').length
  const onlineRate = totalNodes > 0 ? (onlineNodes / totalNodes) * 100 : 0

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {(announcementsQuery.data ?? []).length > 0 ? (
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          {(announcementsQuery.data ?? []).map((item) => (
            <Alert key={item.id} type="info" showIcon message={item.title} description={item.content} />
          ))}
        </Space>
      ) : (
        <Alert type="success" showIcon message="当前无活跃公告" />
      )}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title="流量使用">
            <div style={{ display: 'grid', placeItems: 'center' }}>
              <Progress
                type="dashboard"
                percent={Number(usagePercent.toFixed(2))}
                status={usagePercent >= 100 ? 'exception' : 'active'}
                format={(percent) => `${percent ?? 0}%`}
              />
            </div>
            <Typography.Paragraph style={{ marginBottom: 8 }}>已用：{formatBytes(used)}</Typography.Paragraph>
            <Typography.Text type="secondary">总配额：{formatBytes(quota)}</Typography.Text>
          </Card>
        </Col>

        <Col xs={24} lg={8}>
          <Card title="VIP 状态">
            <Space direction="vertical" size={8}>
              <Typography.Text>
                当前等级：<Tag color={user?.vip_level && user.vip_level > 0 ? 'gold' : 'default'}>VIP {user?.vip_level ?? 0}</Tag>
              </Typography.Text>
              <Typography.Text>
                到期时间：{user?.vip_expires_at ? dayjs(user.vip_expires_at).format('YYYY-MM-DD HH:mm') : '未设置'}
              </Typography.Text>
              <Typography.Text type="secondary">权益：最大规则 {user?.max_rules ?? 0} 条</Typography.Text>
              <Typography.Text type="secondary">权益：流量配额 {formatBytes(user?.traffic_quota ?? 0)}</Typography.Text>
              <Typography.Text type="secondary">
                权益：带宽限制 {user?.bandwidth_limit && user.bandwidth_limit > 0 ? `${user.bandwidth_limit} bps` : '不限速'}
              </Typography.Text>
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={8}>
          <Card title="运行中规则（最多 5 条）">
            {runningRulesQuery.data && runningRulesQuery.data.length > 0 ? (
              <List
                dataSource={runningRulesQuery.data}
                renderItem={(item) => (
                  <List.Item key={item.id}>
                    <List.Item.Meta title={item.name} description={`模式：${item.mode} / 同步：${item.sync_status}`} />
                  </List.Item>
                )}
              />
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无运行中规则" />
            )}
          </Card>
        </Col>
      </Row>

      {isAdmin ? (
        <Card title="系统概览（管理员）">
          <Row gutter={[16, 16]}>
            <Col xs={24} md={8}>
              <Statistic title="节点在线率" value={Number(onlineRate.toFixed(2))} suffix="%" />
              <Typography.Text type="secondary">
                {onlineNodes} / {totalNodes} 在线
              </Typography.Text>
            </Col>
            <Col xs={24} md={8}>
              <Statistic title="系统今日流量" value={formatBytes(overviewQuery.data?.today_total ?? 0)} />
            </Col>
            <Col xs={24} md={8}>
              <Statistic title="系统本月流量" value={formatBytes(overviewQuery.data?.month_total ?? 0)} />
            </Col>
          </Row>
        </Card>
      ) : null}
    </Space>
  )
}
