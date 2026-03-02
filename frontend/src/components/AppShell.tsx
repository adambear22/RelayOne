import { Button, Layout, Menu, Space, Typography, message } from 'antd'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth'
import { useUserSSENotifications } from '../hooks/useUserSSENotifications'
import NotificationCenter from './NotificationCenter'

const { Header, Content } = Layout

const commonMenuItems = [
  { key: '/dashboard', label: <Link to="/dashboard">仪表盘</Link> },
  { key: '/nodes', label: <Link to="/nodes">节点</Link> },
  { key: '/rules', label: <Link to="/rules">规则</Link> },
  { key: '/traffic', label: <Link to="/traffic">流量</Link> },
  { key: '/vip', label: <Link to="/vip">VIP</Link> },
  { key: '/profile', label: <Link to="/profile">个人资料</Link> },
]

export default function AppShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logoutMutation } = useAuth()
  useUserSSENotifications()

  const menuItems =
    user?.role === 'admin'
      ? [...commonMenuItems, { key: '/codes', label: <Link to="/codes">权益码</Link> }, { key: '/admin', label: <Link to="/admin">管理后台</Link> }]
      : [...commonMenuItems, { key: '/redeem', label: <Link to="/redeem">权益码兑换</Link> }]

  const selectedKey = menuItems.find((item) => location.pathname.startsWith(item.key))?.key ?? '/dashboard'

  async function handleLogout() {
    try {
      await logoutMutation.mutateAsync()
      navigate('/login', { replace: true })
    } catch (error) {
      message.error(error instanceof Error ? error.message : '退出登录失败，请稍后重试')
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
        <Space size={16}>
          <Typography.Title level={4} style={{ color: '#fff', margin: 0 }}>
            NodePass 管理平台
          </Typography.Title>
          <Menu
            theme="dark"
            mode="horizontal"
            selectedKeys={[selectedKey]}
            items={menuItems}
            style={{ minWidth: 680 }}
          />
        </Space>

        <Space size={12}>
          {user?.role === 'user' ? <NotificationCenter /> : null}
          <Typography.Text style={{ color: '#fff' }}>{user?.username ?? 'Guest'}</Typography.Text>
          <Button size="small" onClick={handleLogout} loading={logoutMutation.isPending}>
            退出登录
          </Button>
        </Space>
      </Header>

      <Content style={{ padding: 24 }}>
        <Outlet />
      </Content>
    </Layout>
  )
}
