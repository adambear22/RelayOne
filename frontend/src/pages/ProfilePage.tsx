import { Descriptions, Empty } from 'antd'

import PageCard from '../components/PageCard'
import { useAuth } from '../hooks/useAuth'

export default function ProfilePage() {
  const { user } = useAuth()

  return (
    <PageCard title="个人资料" subtitle="来自 /api/v1/users/me">
      {!user ? (
        <Empty description="暂无用户信息" />
      ) : (
        <Descriptions column={1} bordered>
          <Descriptions.Item label="用户名">{user.username}</Descriptions.Item>
          <Descriptions.Item label="角色">{user.role}</Descriptions.Item>
          <Descriptions.Item label="状态">{user.status}</Descriptions.Item>
          <Descriptions.Item label="VIP 等级">{user.vip_level}</Descriptions.Item>
          <Descriptions.Item label="流量使用">{user.traffic_used}</Descriptions.Item>
          <Descriptions.Item label="流量配额">{user.traffic_quota}</Descriptions.Item>
        </Descriptions>
      )}
    </PageCard>
  )
}
