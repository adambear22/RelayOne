import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Alert,
  Avatar,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Form,
  Input,
  Modal,
  Progress,
  Row,
  Space,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import dayjs from 'dayjs'
import { useNavigate } from 'react-router-dom'

import { changePassword, fetchCurrentUser } from '../api/auth'
import { getSystemConfig } from '../api/system'
import { bindUserTelegram, unbindUserTelegram, updateUser, type UpdateUserPayload } from '../api/users'
import PageCard from '../components/PageCard'
import { evaluatePasswordStrength, getUserStatusMeta } from '../features/profile/helpers'
import { useAuth } from '../hooks/useAuth'
import { useAuthStore } from '../stores/auth'
import { ApiBusinessError } from '../types/api'
import type { User } from '../types/models'

interface BasicProfileValues {
  username: string
  email?: string
}

interface SecurityFormValues {
  old_password: string
  new_password: string
  confirm_password: string
}

interface TelegramBindValues {
  bind_code: string
}

export default function ProfilePage() {
  const navigate = useNavigate()
  const { user, clearAuth } = useAuth()
  const setUser = useAuthStore((state) => state.setUser)

  const [basicForm] = Form.useForm<BasicProfileValues>()
  const [securityForm] = Form.useForm<SecurityFormValues>()
  const [telegramBindForm] = Form.useForm<TelegramBindValues>()
  const [closeAccountOpen, setCloseAccountOpen] = useState(false)
  const [closeAccountInput, setCloseAccountInput] = useState('')

  const newPassword = Form.useWatch('new_password', securityForm) ?? ''
  const passwordStrength = useMemo(() => evaluatePasswordStrength(newPassword), [newPassword])

  const configQuery = useQuery({
    queryKey: ['system', 'config', 'profile'],
    queryFn: getSystemConfig,
    staleTime: 5 * 60_000,
  })

  const updateProfileMutation = useMutation({
    mutationFn: ({ userID, payload }: { userID: string; payload: UpdateUserPayload }) => updateUser(userID, payload),
  })

  const changePasswordMutation = useMutation({
    mutationFn: changePassword,
  })

  const bindTelegramMutation = useMutation({
    mutationFn: ({ userID, bindCode }: { userID: string; bindCode: string }) =>
      bindUserTelegram(userID, { bind_code: bindCode }),
  })

  const unbindTelegramMutation = useMutation({
    mutationFn: (userID: string) => unbindUserTelegram(userID),
  })

  useEffect(() => {
    if (!user) {
      return
    }

    basicForm.setFieldsValue({
      username: user.username,
      email: user.email ?? '',
    })
  }, [basicForm, user])

  if (!user) {
    return (
      <PageCard title="个人中心" subtitle="管理个人资料、安全设置与 Telegram 绑定">
        <Empty description="暂无用户信息" />
      </PageCard>
    )
  }

  const statusMeta = getUserStatusMeta(user.status)
  const avatarText = (user.telegram_username ?? user.username ?? '?').slice(0, 1).toUpperCase()
  const botUsername = normalizeBotUsername(configQuery.data?.telegram_config?.bot_username)
  const botLink = botUsername ? `https://t.me/${botUsername}` : undefined
  const canConfirmClose = closeAccountInput.trim() === user.username

  const tabItems = [
    {
      key: 'basic',
      label: '基本信息',
      children: (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Row gutter={[16, 16]}>
            <Col xs={24} lg={8}>
              <Card>
                <Space direction="vertical" style={{ width: '100%', alignItems: 'center' }} size={8}>
                  <Avatar size={88} style={{ backgroundColor: user.telegram_id ? '#1677ff' : '#8c8c8c', fontSize: 32 }}>
                    {avatarText}
                  </Avatar>
                  <Typography.Text strong>{user.username}</Typography.Text>
                  <Typography.Text type="secondary">
                    {user.telegram_id ? `已绑定 @${user.telegram_username ?? 'telegram'}` : '未绑定 Telegram'}
                  </Typography.Text>
                </Space>
              </Card>
            </Col>

            <Col xs={24} lg={16}>
              <Card title="基础资料">
                <Form<BasicProfileValues> form={basicForm} layout="vertical">
                  <Form.Item name="username" label="用户名">
                    <Input readOnly />
                  </Form.Item>
                  <Form.Item name="email" label="邮箱" rules={[{ type: 'email', message: '邮箱格式不正确' }]}>
                    <Input placeholder="可选，填写后用于通知与找回" />
                  </Form.Item>
                  <Button
                    type="primary"
                    loading={updateProfileMutation.isPending}
                    onClick={async () => {
                      try {
                        const values = await basicForm.validateFields()
                        const updated = await updateProfileMutation.mutateAsync({
                          userID: user.id,
                          payload: { email: values.email?.trim() || undefined },
                        })
                        setUser(updated)
                        message.success('基本信息已保存')
                      } catch (error) {
                        if (isValidationError(error)) {
                          return
                        }
                        message.error(resolveErrorMessage(error, '保存基本信息失败，请稍后重试'))
                      }
                    }}
                  >
                    保存
                  </Button>
                </Form>
              </Card>
            </Col>
          </Row>

          <Card title="账户信息">
            <Descriptions column={2} bordered>
              <Descriptions.Item label="注册时间">{formatDateTime(user.created_at)}</Descriptions.Item>
              <Descriptions.Item label="用户 ID">{user.id}</Descriptions.Item>
              <Descriptions.Item label="VIP 等级">
                <Tag color={user.vip_level > 0 ? 'gold' : 'default'}>VIP {user.vip_level}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="账户状态">
                <Tag color={statusMeta.color}>{statusMeta.text}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Space>
      ),
    },
    {
      key: 'security',
      label: '安全设置',
      children: (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Card title="修改密码">
            <Form<SecurityFormValues> form={securityForm} layout="vertical">
              <Form.Item name="old_password" label="当前密码" rules={[{ required: true, message: '请输入当前密码' }]}>
                <Input.Password autoComplete="current-password" />
              </Form.Item>
              <Form.Item
                name="new_password"
                label="新密码"
                rules={[
                  { required: true, message: '请输入新密码' },
                  { min: 6, message: '新密码至少 6 位' },
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Progress
                percent={passwordStrength.score}
                size="small"
                showInfo={false}
                strokeColor={passwordStrength.color}
                style={{ marginBottom: 8, maxWidth: 360 }}
              />
              <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
                密码强度：{passwordStrength.label}
              </Typography.Text>
              <Form.Item
                name="confirm_password"
                label="确认新密码"
                dependencies={['new_password']}
                rules={[
                  { required: true, message: '请再次输入新密码' },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || value === getFieldValue('new_password')) {
                        return Promise.resolve()
                      }
                      return Promise.reject(new Error('两次输入的新密码不一致'))
                    },
                  }),
                ]}
              >
                <Input.Password autoComplete="new-password" />
              </Form.Item>
              <Button
                type="primary"
                loading={changePasswordMutation.isPending}
                onClick={async () => {
                  try {
                    const values = await securityForm.validateFields()
                    await changePasswordMutation.mutateAsync({
                      old_password: values.old_password,
                      new_password: values.new_password,
                    })
                    message.success('密码修改成功，请重新登录')
                    securityForm.resetFields()
                    clearAuth()
                    navigate('/login', { replace: true })
                  } catch (error) {
                    if (isValidationError(error)) {
                      return
                    }
                    message.error(resolveErrorMessage(error, '修改密码失败，请确认当前密码是否正确'))
                  }
                }}
              >
                修改密码
              </Button>
            </Form>
          </Card>

          <Card title="登录设备">
            <Alert
              type="info"
              showIcon
              message="登录设备列表与一键下线功能正在接入中，当前可通过修改密码强制所有设备重新登录。"
            />
          </Card>
        </Space>
      ),
    },
    {
      key: 'telegram',
      label: 'Telegram 绑定',
      children: user.telegram_id ? (
        <Card title="已绑定 Telegram">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions column={1} bordered>
              <Descriptions.Item label="Telegram ID">{user.telegram_id}</Descriptions.Item>
              <Descriptions.Item label="Telegram 用户名">
                {user.telegram_username ? `@${user.telegram_username}` : '未提供'}
              </Descriptions.Item>
              <Descriptions.Item label="最近同步时间">{formatDateTime(user.updated_at)}</Descriptions.Item>
            </Descriptions>

            <Button
              danger
              loading={unbindTelegramMutation.isPending}
              onClick={() => {
                Modal.confirm({
                  title: '确认解除 Telegram 绑定？',
                  content: '解除后将无法接收 Telegram 通知，且需要重新走绑定流程。',
                  okText: '确认解除',
                  okButtonProps: { danger: true },
                  cancelText: '取消',
                  onOk: async () => {
                    try {
                      await unbindTelegramMutation.mutateAsync(user.id)
                      const latest = await updateUserState(setUser)
                      message.success('Telegram 已解除绑定')
                      if (latest.telegram_id) {
                        message.warning('解除绑定状态刷新延迟，请稍后手动刷新页面')
                      }
                    } catch (error) {
                      message.error(resolveErrorMessage(error, '解除 Telegram 绑定失败，请稍后重试'))
                    }
                  },
                })
              }}
            >
              解除绑定
            </Button>
          </Space>
        </Card>
      ) : (
        <Card title="绑定 Telegram">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Alert
              type="info"
              showIcon
              message="绑定 Telegram 账号可使用 Bot 管理规则并接收告警通知。"
              description="请先在 Bot 中发送 /bind 获取一次性绑定码，再回到这里提交。"
            />

            <Space wrap>
              {botLink ? (
                <Button type="primary" href={botLink} target="_blank" rel="noreferrer">
                  开始绑定
                </Button>
              ) : (
                <Alert type="warning" showIcon message="暂未配置 Telegram Bot，请联系管理员。" />
              )}
              <Typography.Text type="secondary">Bot 命令：<Typography.Text code>/bind</Typography.Text></Typography.Text>
            </Space>

            <Form<TelegramBindValues> form={telegramBindForm} layout="vertical">
              <Form.Item
                name="bind_code"
                label="绑定码"
                normalize={(value) => (typeof value === 'string' ? value.toUpperCase() : value)}
                rules={[{ required: true, message: '请输入绑定码' }]}
              >
                <Input placeholder="输入 Bot 返回的绑定码" maxLength={32} />
              </Form.Item>
              <Button
                type="primary"
                loading={bindTelegramMutation.isPending}
                onClick={async () => {
                  try {
                    const values = await telegramBindForm.validateFields()
                    await bindTelegramMutation.mutateAsync({
                      userID: user.id,
                      bindCode: values.bind_code.trim().toUpperCase(),
                    })
                    await updateUserState(setUser)
                    telegramBindForm.resetFields()
                    message.success('Telegram 绑定成功')
                  } catch (error) {
                    if (isValidationError(error)) {
                      return
                    }
                    message.error(resolveBindErrorMessage(error))
                  }
                }}
              >
                提交绑定码
              </Button>
            </Form>
          </Space>
        </Card>
      ),
    },
  ]

  return (
    <PageCard title="个人中心" subtitle="管理个人信息、密码与 Telegram 绑定">
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Tabs defaultActiveKey="basic" items={tabItems} />

        <Card style={{ borderColor: '#ffd6d6' }}>
          <Space style={{ width: '100%', justifyContent: 'space-between' }} align="start">
            <Space direction="vertical" size={4}>
              <Typography.Text strong>账号注销</Typography.Text>
              <Typography.Text type="secondary">
                注销后规则、流量记录等数据将永久删除且无法恢复，请谨慎操作。
              </Typography.Text>
            </Space>
            <Button onClick={() => setCloseAccountOpen(true)}>申请注销账号</Button>
          </Space>
        </Card>

        <Modal
          title="确认注销账号"
          open={closeAccountOpen}
          onCancel={() => {
            setCloseAccountOpen(false)
            setCloseAccountInput('')
          }}
          onOk={() => {
            message.info('当前版本暂未开放自助注销能力，请联系管理员处理。')
            setCloseAccountOpen(false)
            setCloseAccountInput('')
          }}
          okText="确认注销"
          okButtonProps={{ danger: true, disabled: !canConfirmClose }}
          cancelText="取消"
        >
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Typography.Text>
              注销后所有数据将被永久删除，无法恢复。请输入你的用户名 <Typography.Text code>{user.username}</Typography.Text>{' '}
              以确认。
            </Typography.Text>
            <Input
              placeholder={`请输入 ${user.username} 以确认`}
              value={closeAccountInput}
              onChange={(event) => setCloseAccountInput(event.target.value)}
            />
          </Space>
        </Modal>
      </Space>
    </PageCard>
  )
}

function resolveBindErrorMessage(error: unknown): string {
  if (error instanceof ApiBusinessError) {
    if (error.httpStatus === 400) {
      return '绑定码无效或已过期，请在 Bot 中重新执行 /bind 获取。'
    }
    if (error.httpStatus === 409) {
      return '该 Telegram 账号已被其他用户绑定。'
    }
  }

  return resolveErrorMessage(error, '绑定 Telegram 失败，请稍后重试')
}

function resolveErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message
  }
  return fallback
}

function normalizeBotUsername(value?: string): string | null {
  const cleaned = value?.trim()
  if (!cleaned) {
    return null
  }

  return cleaned.startsWith('@') ? cleaned.slice(1) : cleaned
}

function formatDateTime(value?: string): string {
  if (!value) {
    return '—'
  }
  return dayjs(value).isValid() ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : value
}

function isValidationError(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'errorFields' in error)
}

async function updateUserState(setUser: (user: User | null) => void) {
  const latest = await fetchCurrentUser()
  setUser(latest)
  return latest
}
