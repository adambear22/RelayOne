import { Badge, Button, Empty, List, Popover, Space, Typography } from 'antd'
import dayjs from 'dayjs'

import { useNotificationStore, type NotificationItem } from '../stores/notifications'

export default function NotificationCenter() {
  const items = useNotificationStore((state) => state.items)
  const markAsRead = useNotificationStore((state) => state.markAsRead)
  const markAllAsRead = useNotificationStore((state) => state.markAllAsRead)

  const unreadCount = items.reduce((count, item) => count + (item.read ? 0 : 1), 0)

  return (
    <Popover
      trigger="click"
      placement="bottomRight"
      content={
        <div style={{ width: 360 }}>
          <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 12 }}>
            <Typography.Text strong>通知中心</Typography.Text>
            <Button type="link" size="small" disabled={unreadCount === 0} onClick={() => markAllAsRead()}>
              全部标为已读
            </Button>
          </Space>
          {items.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无通知" style={{ margin: '20px 0' }} />
          ) : (
            <List
              dataSource={items}
              style={{ maxHeight: 420, overflowY: 'auto' }}
              renderItem={(item) => (
                <List.Item
                  key={item.id}
                  style={{
                    paddingInline: 0,
                    cursor: item.read ? 'default' : 'pointer',
                    background: item.read ? 'transparent' : '#f6ffed',
                  }}
                  onClick={() => markAsRead(item.id)}
                >
                  <List.Item.Meta
                    title={
                      <Space size={8}>
                        <Typography.Text>{iconFor(item.kind)}</Typography.Text>
                        <Typography.Text strong={!item.read}>{item.title}</Typography.Text>
                      </Space>
                    }
                    description={
                      <Space direction="vertical" size={2}>
                        {item.content ? <Typography.Text type="secondary">{item.content}</Typography.Text> : null}
                        <Typography.Text type="secondary">{relativeTime(item.created_at)}</Typography.Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          )}
        </div>
      }
    >
      <Badge count={unreadCount} size="small">
        <Button size="small">通知</Button>
      </Badge>
    </Popover>
  )
}

function iconFor(kind: NotificationItem['kind']): string {
  switch (kind) {
    case 'success':
      return '✅'
    case 'warning':
      return '⚠️'
    case 'error':
      return '🚨'
    case 'info':
    default:
      return '📣'
  }
}

function relativeTime(value: string): string {
  const createdAt = dayjs(value)
  if (!createdAt.isValid()) {
    return value
  }

  const now = dayjs()
  const diffSeconds = now.diff(createdAt, 'second')
  if (diffSeconds < 60) {
    return '刚刚'
  }
  if (diffSeconds < 3600) {
    return `${Math.floor(diffSeconds / 60)} 分钟前`
  }
  if (diffSeconds < 86400) {
    return `${Math.floor(diffSeconds / 3600)} 小时前`
  }
  if (diffSeconds < 86400 * 7) {
    return `${Math.floor(diffSeconds / 86400)} 天前`
  }
  return createdAt.format('YYYY-MM-DD HH:mm')
}
