import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import type { FormInstance } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import type { QueryClient } from '@tanstack/react-query'

import { getAdminOverview, getAuditLogs } from '../../api/admin'
import {
  createAnnouncement,
  deleteAnnouncement,
  listAnnouncements,
  toggleAnnouncement,
  updateAnnouncement,
  type SaveAnnouncementPayload,
} from '../../api/announcements'
import { batchSyncTrafficQuota, resetUserTrafficQuota } from '../../api/traffic'
import { getSystemConfig, listSystemLogs, updateSystemConfig, type UpdateSystemConfigPayload } from '../../api/system'
import {
  createUser,
  listUsers,
  setUserStatus,
  updateUser,
  type CreateUserPayload,
  type UpdateUserPayload,
} from '../../api/users'
import type { Announcement, AuditLog, SystemLogEntry, TrafficOverview, User, UserStatus } from '../../types/models'
import { formatBytes } from '../../utils/bytes'

interface UserFormValues {
  username: string
  password?: string
  email?: string
  role: 'admin' | 'user'
  status: UserStatus
  vip_level: number
  traffic_quota: number
  max_rules: number
  bandwidth_limit: number
}

interface AnnouncementFormValues {
  type: string
  title: string
  content: string
  is_enabled: boolean
  starts_at?: string
  ends_at?: string
}

interface SystemConfigFormValues {
  site_name?: string
  support_email?: string
  maintenance_mode: boolean
  registration_enabled: boolean
  default_traffic_quota: number
  default_max_rules: number
  tg_enabled: boolean
  tg_bot_username?: string
  tg_webhook_url?: string
  tg_frontend_url?: string
  tg_sso_base_url?: string
}

const defaultUserForm: UserFormValues = {
  username: '',
  password: '',
  email: '',
  role: 'user',
  status: 'normal',
  vip_level: 0,
  traffic_quota: 0,
  max_rules: 20,
  bandwidth_limit: 0,
}

const defaultAnnouncementForm: AnnouncementFormValues = {
  type: 'info',
  title: '',
  content: '',
  is_enabled: true,
  starts_at: '',
  ends_at: '',
}

export default function AdminOverview() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState('overview')

  const [userPage, setUserPage] = useState(1)
  const [userPageSize, setUserPageSize] = useState(20)
  const [announcementPage, setAnnouncementPage] = useState(1)
  const [announcementPageSize, setAnnouncementPageSize] = useState(20)
  const [auditPage, setAuditPage] = useState(1)
  const [auditPageSize, setAuditPageSize] = useState(20)
  const [logPage, setLogPage] = useState(1)
  const [logPageSize, setLogPageSize] = useState(20)
  const [logLevel, setLogLevel] = useState<string>('')

  const [userModalOpen, setUserModalOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [userForm] = Form.useForm<UserFormValues>()

  const [announcementModalOpen, setAnnouncementModalOpen] = useState(false)
  const [editingAnnouncement, setEditingAnnouncement] = useState<Announcement | null>(null)
  const [announcementForm] = Form.useForm<AnnouncementFormValues>()

  const [systemForm] = Form.useForm<SystemConfigFormValues>()

  const overviewQuery = useQuery({
    queryKey: ['admin', 'overview'],
    queryFn: getAdminOverview,
  })

  const usersQuery = useQuery({
    queryKey: ['admin', 'users', userPage, userPageSize],
    queryFn: () => listUsers({ page: userPage, page_size: userPageSize }),
    enabled: activeTab === 'users',
  })

  const announcementsQuery = useQuery({
    queryKey: ['admin', 'announcements', announcementPage, announcementPageSize],
    queryFn: () => listAnnouncements({ page: announcementPage, page_size: announcementPageSize }),
    enabled: activeTab === 'announcements',
  })

  const auditQuery = useQuery({
    queryKey: ['admin', 'audit', auditPage, auditPageSize],
    queryFn: () => getAuditLogs({ page: auditPage, page_size: auditPageSize }),
    enabled: activeTab === 'audit',
  })

  const systemConfigQuery = useQuery({
    queryKey: ['admin', 'system-config'],
    queryFn: getSystemConfig,
    enabled: activeTab === 'system',
  })

  const systemLogsQuery = useQuery({
    queryKey: ['admin', 'system-logs', logPage, logPageSize, logLevel],
    queryFn: () =>
      listSystemLogs({
        page: logPage,
        page_size: logPageSize,
        level: logLevel || undefined,
      }),
    enabled: activeTab === 'logs',
  })

  const createUserMutation = useMutation({ mutationFn: createUser })
  const updateUserMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateUserPayload }) => updateUser(id, payload),
  })
  const setUserStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: UserStatus }) => setUserStatus(id, status),
  })
  const resetUserQuotaMutation = useMutation({ mutationFn: resetUserTrafficQuota })
  const batchSyncMutation = useMutation({ mutationFn: batchSyncTrafficQuota })

  const createAnnouncementMutation = useMutation({ mutationFn: createAnnouncement })
  const updateAnnouncementMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Partial<SaveAnnouncementPayload> }) => updateAnnouncement(id, payload),
  })
  const toggleAnnouncementMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => toggleAnnouncement(id, enabled),
  })
  const deleteAnnouncementMutation = useMutation({ mutationFn: deleteAnnouncement })

  const updateSystemConfigMutation = useMutation({ mutationFn: updateSystemConfig })

  useEffect(() => {
    if (!systemConfigQuery.data) {
      return
    }

    const cfg = systemConfigQuery.data
    systemForm.setFieldsValue({
      site_name: cfg.site_name,
      support_email: cfg.support_email,
      maintenance_mode: cfg.maintenance_mode,
      registration_enabled: cfg.registration_enabled,
      default_traffic_quota: cfg.default_traffic_quota,
      default_max_rules: cfg.default_max_rules,
      tg_enabled: Boolean(cfg.telegram_config?.enabled),
      tg_bot_username: cfg.telegram_config?.bot_username,
      tg_webhook_url: cfg.telegram_config?.webhook_url,
      tg_frontend_url: cfg.telegram_config?.frontend_url,
      tg_sso_base_url: cfg.telegram_config?.sso_base_url,
    })
  }, [systemConfigQuery.data, systemForm])

  const userColumns = useMemo<ColumnsType<User>>(
    () => [
      { title: '用户名', dataIndex: 'username' },
      {
        title: '角色',
        dataIndex: 'role',
        width: 100,
        render: (value: User['role']) => <Tag color={value === 'admin' ? 'red' : 'blue'}>{value}</Tag>,
      },
      {
        title: '状态',
        dataIndex: 'status',
        width: 120,
        render: (value: UserStatus) => <Tag color={statusColor(value)}>{value}</Tag>,
      },
      {
        title: 'VIP',
        width: 80,
        render: (_, item) => `VIP ${item.vip_level}`,
      },
      {
        title: '配额',
        dataIndex: 'traffic_quota',
        render: (value: number) => formatBytes(value),
      },
      {
        title: '已用',
        dataIndex: 'traffic_used',
        render: (value: number) => formatBytes(value),
      },
      {
        title: '操作',
        width: 280,
        render: (_, item) => (
          <Space size={4}>
            <Button
              type="link"
              size="small"
              onClick={() => {
                setEditingUser(item)
                userForm.setFieldsValue({
                  username: item.username,
                  password: '',
                  email: item.email,
                  role: item.role,
                  status: item.status,
                  vip_level: item.vip_level,
                  traffic_quota: item.traffic_quota,
                  max_rules: item.max_rules,
                  bandwidth_limit: item.bandwidth_limit,
                })
                setUserModalOpen(true)
              }}
            >
              编辑
            </Button>
            <Button
              type="link"
              size="small"
              loading={setUserStatusMutation.isPending}
              onClick={async () => {
                const nextStatus: UserStatus = item.status === 'normal' ? 'suspended' : 'normal'
                await setUserStatusMutation.mutateAsync({ id: item.id, status: nextStatus })
                await queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
                message.success(`用户状态已更新为 ${nextStatus}`)
              }}
            >
              {item.status === 'normal' ? '暂停' : '恢复'}
            </Button>
            <Button
              type="link"
              size="small"
              loading={resetUserQuotaMutation.isPending}
              onClick={async () => {
                await resetUserQuotaMutation.mutateAsync(item.id)
                await queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
                message.success('用户配额已重置')
              }}
            >
              重置配额
            </Button>
          </Space>
        ),
      },
    ],
    [queryClient, resetUserQuotaMutation, setUserStatusMutation, userForm],
  )

  const announcementColumns = useMemo<ColumnsType<Announcement>>(
    () => [
      { title: '标题', dataIndex: 'title' },
      {
        title: '类型',
        dataIndex: 'type',
        width: 100,
      },
      {
        title: '启用',
        dataIndex: 'is_enabled',
        width: 90,
        render: (value: boolean, item) => (
          <Switch
            size="small"
            checked={value}
            loading={toggleAnnouncementMutation.isPending}
            onChange={async (checked) => {
              await toggleAnnouncementMutation.mutateAsync({ id: item.id, enabled: checked })
              await queryClient.invalidateQueries({ queryKey: ['admin', 'announcements'] })
              message.success('公告状态已更新')
            }}
          />
        ),
      },
      {
        title: '时间窗口',
        render: (_, item) => {
          const from = item.starts_at ? dayjs(item.starts_at).format('MM-DD HH:mm') : '-'
          const to = item.ends_at ? dayjs(item.ends_at).format('MM-DD HH:mm') : '-'
          return `${from} ~ ${to}`
        },
      },
      {
        title: '操作',
        width: 220,
        render: (_, item) => (
          <Space size={4}>
            <Button
              type="link"
              size="small"
              onClick={() => {
                setEditingAnnouncement(item)
                announcementForm.setFieldsValue({
                  type: item.type,
                  title: item.title,
                  content: item.content,
                  is_enabled: item.is_enabled,
                  starts_at: item.starts_at || '',
                  ends_at: item.ends_at || '',
                })
                setAnnouncementModalOpen(true)
              }}
            >
              编辑
            </Button>
            <Popconfirm
              title="删除公告"
              description={`确认删除公告“${item.title}”？`}
              onConfirm={async () => {
                await deleteAnnouncementMutation.mutateAsync(item.id)
                await queryClient.invalidateQueries({ queryKey: ['admin', 'announcements'] })
                message.success('公告已删除')
              }}
            >
              <Button type="link" danger size="small" loading={deleteAnnouncementMutation.isPending}>
                删除
              </Button>
            </Popconfirm>
          </Space>
        ),
      },
    ],
    [announcementForm, deleteAnnouncementMutation, queryClient, toggleAnnouncementMutation],
  )

  const auditColumns = useMemo<ColumnsType<AuditLog>>(
    () => [
      { title: 'ID', dataIndex: 'id', width: 90 },
      { title: '操作', dataIndex: 'action', width: 180 },
      { title: '资源类型', dataIndex: 'resource_type', width: 120, render: (value?: string) => value || '-' },
      { title: '资源ID', dataIndex: 'resource_id', render: (value?: string) => value || '-' },
      { title: '用户ID', dataIndex: 'user_id', render: (value?: string) => value || '-' },
      {
        title: '时间',
        dataIndex: 'created_at',
        width: 180,
        render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
      },
    ],
    [],
  )

  const systemLogColumns = useMemo<ColumnsType<SystemLogEntry>>(
    () => [
      { title: 'ID', dataIndex: 'id', width: 90 },
      {
        title: '级别',
        dataIndex: 'level',
        width: 100,
        render: (value: string) => <Tag color={logLevelColor(value)}>{value.toUpperCase()}</Tag>,
      },
      { title: '消息', dataIndex: 'message' },
      { title: '调用方', dataIndex: 'caller', width: 240, render: (value?: string) => value || '-' },
      {
        title: '时间',
        dataIndex: 'timestamp',
        width: 180,
        render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
      },
    ],
    [],
  )

  const tabs = [
    {
      key: 'overview',
      label: '系统概览',
      children: (
        <OverviewTab
          data={overviewQuery.data}
          loading={overviewQuery.isLoading}
          syncing={batchSyncMutation.isPending}
          onRefresh={() => {
            void overviewQuery.refetch()
          }}
          onSync={async () => {
            await batchSyncMutation.mutateAsync()
            message.success('配额同步任务已触发')
          }}
        />
      ),
    },
    {
      key: 'users',
      label: '用户管理',
      children: (
        <Card>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Typography.Text type="secondary">管理用户状态、配额与权限</Typography.Text>
              <Button
                type="primary"
                onClick={() => {
                  setEditingUser(null)
                  userForm.setFieldsValue(defaultUserForm)
                  setUserModalOpen(true)
                }}
              >
                新建用户
              </Button>
            </Space>

            <Table<User>
              rowKey="id"
              loading={usersQuery.isLoading || usersQuery.isFetching}
              dataSource={usersQuery.data?.items ?? []}
              columns={userColumns}
              pagination={{
                current: userPage,
                pageSize: userPageSize,
                showSizeChanger: true,
                total: Number(usersQuery.data?.pagination?.total ?? 0),
                onChange: (nextPage, nextSize) => {
                  setUserPage(nextPage)
                  setUserPageSize(nextSize)
                },
              }}
            />
          </Space>
        </Card>
      ),
    },
    {
      key: 'announcements',
      label: '公告管理',
      children: (
        <Card>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Typography.Text type="secondary">维护站内公告与活动通知</Typography.Text>
              <Button
                type="primary"
                onClick={() => {
                  setEditingAnnouncement(null)
                  announcementForm.setFieldsValue(defaultAnnouncementForm)
                  setAnnouncementModalOpen(true)
                }}
              >
                新建公告
              </Button>
            </Space>
            <Table<Announcement>
              rowKey="id"
              loading={announcementsQuery.isLoading || announcementsQuery.isFetching}
              dataSource={announcementsQuery.data?.items ?? []}
              columns={announcementColumns}
              pagination={{
                current: announcementPage,
                pageSize: announcementPageSize,
                showSizeChanger: true,
                total: Number(announcementsQuery.data?.pagination?.total ?? 0),
                onChange: (nextPage, nextSize) => {
                  setAnnouncementPage(nextPage)
                  setAnnouncementPageSize(nextSize)
                },
              }}
            />
          </Space>
        </Card>
      ),
    },
    {
      key: 'system',
      label: '系统配置',
      children: (
        <Card>
          <Form<SystemConfigFormValues>
            form={systemForm}
            layout="vertical"
            onFinish={async (values) => {
              const payload: UpdateSystemConfigPayload = {
                site_name: values.site_name?.trim() || undefined,
                support_email: values.support_email?.trim() || undefined,
                maintenance_mode: values.maintenance_mode,
                registration_enabled: values.registration_enabled,
                default_traffic_quota: values.default_traffic_quota,
                default_max_rules: values.default_max_rules,
                telegram_config: {
                  enabled: values.tg_enabled,
                  bot_username: values.tg_bot_username?.trim() || undefined,
                  webhook_url: values.tg_webhook_url?.trim() || undefined,
                  frontend_url: values.tg_frontend_url?.trim() || undefined,
                  sso_base_url: values.tg_sso_base_url?.trim() || undefined,
                },
              }

              await updateSystemConfigMutation.mutateAsync(payload)
              await queryClient.invalidateQueries({ queryKey: ['admin', 'system-config'] })
              message.success('系统配置已更新')
            }}
          >
            <Space size={12} style={{ width: '100%' }}>
              <Form.Item label="站点名称" name="site_name" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
              <Form.Item label="支持邮箱" name="support_email" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
            </Space>

            <Space size={24} style={{ marginBottom: 8 }}>
              <Form.Item label="维护模式" name="maintenance_mode" valuePropName="checked">
                <Switch />
              </Form.Item>
              <Form.Item label="允许注册" name="registration_enabled" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Space>

            <Space size={12} style={{ width: '100%' }}>
              <Form.Item label="默认流量配额" name="default_traffic_quota" style={{ flex: 1 }}>
                <InputNumber min={0} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item label="默认最大规则" name="default_max_rules" style={{ flex: 1 }}>
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
            </Space>

            <Typography.Title level={5}>Telegram 配置</Typography.Title>
            <Space size={24} style={{ marginBottom: 8 }}>
              <Form.Item label="启用 Telegram" name="tg_enabled" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Space>
            <Space size={12} style={{ width: '100%' }}>
              <Form.Item label="Bot 用户名" name="tg_bot_username" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
              <Form.Item label="Webhook URL" name="tg_webhook_url" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
            </Space>
            <Space size={12} style={{ width: '100%' }}>
              <Form.Item label="前端地址" name="tg_frontend_url" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
              <Form.Item label="SSO 地址" name="tg_sso_base_url" style={{ flex: 1 }}>
                <Input />
              </Form.Item>
            </Space>

            <Button type="primary" htmlType="submit" loading={updateSystemConfigMutation.isPending}>
              保存配置
            </Button>
          </Form>
        </Card>
      ),
    },
    {
      key: 'audit',
      label: '审计日志',
      children: (
        <Card>
          <Table<AuditLog>
            rowKey="id"
            loading={auditQuery.isLoading || auditQuery.isFetching}
            columns={auditColumns}
            dataSource={auditQuery.data?.items ?? []}
            pagination={{
              current: auditPage,
              pageSize: auditPageSize,
              showSizeChanger: true,
              total: Number(auditQuery.data?.pagination?.total ?? 0),
              onChange: (nextPage, nextSize) => {
                setAuditPage(nextPage)
                setAuditPageSize(nextSize)
              },
            }}
          />
        </Card>
      ),
    },
    {
      key: 'logs',
      label: '系统日志',
      children: (
        <Card>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space>
              <Select
                value={logLevel}
                style={{ width: 160 }}
                onChange={(value) => {
                  setLogPage(1)
                  setLogLevel(value)
                }}
                options={[
                  { label: '全部级别', value: '' },
                  { label: 'DEBUG', value: 'debug' },
                  { label: 'INFO', value: 'info' },
                  { label: 'WARN', value: 'warn' },
                  { label: 'ERROR', value: 'error' },
                ]}
              />
              <Button onClick={() => void systemLogsQuery.refetch()} loading={systemLogsQuery.isFetching}>
                刷新
              </Button>
            </Space>

            <Table<SystemLogEntry>
              rowKey="id"
              loading={systemLogsQuery.isLoading || systemLogsQuery.isFetching}
              columns={systemLogColumns}
              dataSource={systemLogsQuery.data?.items ?? []}
              pagination={{
                current: logPage,
                pageSize: logPageSize,
                showSizeChanger: true,
                total: Number(systemLogsQuery.data?.pagination?.total ?? 0),
                onChange: (nextPage, nextSize) => {
                  setLogPage(nextPage)
                  setLogPageSize(nextSize)
                },
              }}
            />
          </Space>
        </Card>
      ),
    },
  ]

  return (
    <>
      <Tabs activeKey={activeTab} items={tabs} onChange={setActiveTab} destroyInactiveTabPane />

      <Modal
        title={editingUser ? `编辑用户 - ${editingUser.username}` : '新建用户'}
        open={userModalOpen}
        onCancel={() => setUserModalOpen(false)}
        onOk={() => {
          void submitUserForm({
            form: userForm,
            editingUser,
            createMutation: createUserMutation,
            updateMutation: updateUserMutation,
            queryClient,
            onSuccess: () => {
              setUserModalOpen(false)
              setEditingUser(null)
            },
          })
        }}
        confirmLoading={createUserMutation.isPending || updateUserMutation.isPending}
        destroyOnClose
      >
        <Form<UserFormValues> form={userForm} layout="vertical" initialValues={defaultUserForm}>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="username" label="用户名" style={{ flex: 1 }} rules={[{ required: true, message: '用户名必填' }]}>
              <Input />
            </Form.Item>
            {!editingUser ? (
              <Form.Item name="password" label="初始密码" style={{ flex: 1 }} rules={[{ required: true, message: '密码必填' }]}>
                <Input.Password />
              </Form.Item>
            ) : null}
          </Space>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="email" label="邮箱" style={{ flex: 1 }}>
              <Input />
            </Form.Item>
            <Form.Item name="role" label="角色" style={{ flex: 1 }}>
              <Select
                options={[
                  { label: '普通用户', value: 'user' },
                  { label: '管理员', value: 'admin' },
                ]}
              />
            </Form.Item>
            <Form.Item name="status" label="状态" style={{ flex: 1 }}>
              <Select
                options={[
                  { label: 'normal', value: 'normal' },
                  { label: 'suspended', value: 'suspended' },
                  { label: 'banned', value: 'banned' },
                  { label: 'over_limit', value: 'over_limit' },
                ]}
              />
            </Form.Item>
          </Space>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="vip_level" label="VIP 等级" style={{ flex: 1 }}>
              <InputNumber min={0} max={20} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="traffic_quota" label="流量配额" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="max_rules" label="最大规则数" style={{ flex: 1 }}>
              <InputNumber min={1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="bandwidth_limit" label="带宽限制" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>

      <Modal
        title={editingAnnouncement ? '编辑公告' : '新建公告'}
        open={announcementModalOpen}
        onCancel={() => setAnnouncementModalOpen(false)}
        onOk={() => {
          void submitAnnouncementForm({
            form: announcementForm,
            editingAnnouncement,
            createMutation: createAnnouncementMutation,
            updateMutation: updateAnnouncementMutation,
            queryClient,
            onSuccess: () => {
              setAnnouncementModalOpen(false)
              setEditingAnnouncement(null)
            },
          })
        }}
        confirmLoading={createAnnouncementMutation.isPending || updateAnnouncementMutation.isPending}
        width={720}
        destroyOnClose
      >
        <Form<AnnouncementFormValues> form={announcementForm} layout="vertical" initialValues={defaultAnnouncementForm}>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="type" label="类型" style={{ flex: 1 }} rules={[{ required: true, message: '类型必填' }]}>
              <Select
                options={[
                  { label: 'info', value: 'info' },
                  { label: 'warning', value: 'warning' },
                  { label: 'maintenance', value: 'maintenance' },
                ]}
              />
            </Form.Item>
            <Form.Item name="is_enabled" label="启用" valuePropName="checked" style={{ width: 120 }}>
              <Switch />
            </Form.Item>
          </Space>

          <Form.Item name="title" label="标题" rules={[{ required: true, message: '标题必填' }]}> 
            <Input maxLength={200} />
          </Form.Item>
          <Form.Item name="content" label="内容" rules={[{ required: true, message: '内容必填' }]}> 
            <Input.TextArea rows={6} />
          </Form.Item>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="starts_at" label="开始时间(RFC3339)" style={{ flex: 1 }}>
              <Input placeholder="2026-03-01T00:00:00Z" />
            </Form.Item>
            <Form.Item name="ends_at" label="结束时间(RFC3339)" style={{ flex: 1 }}>
              <Input placeholder="2026-03-08T00:00:00Z" />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </>
  )
}

function OverviewTab({
  data,
  loading,
  syncing,
  onRefresh,
  onSync,
}: {
  data?: TrafficOverview
  loading: boolean
  syncing: boolean
  onRefresh: () => void
  onSync: () => Promise<void>
}) {
  return (
    <Card loading={loading}>
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Space style={{ width: '100%', justifyContent: 'space-between' }}>
          <Typography.Text type="secondary">管理员全局流量与热点对象概览</Typography.Text>
          <Space>
            <Button onClick={onRefresh}>刷新</Button>
            <Button type="primary" onClick={() => void onSync()} loading={syncing}>
              同步用户配额
            </Button>
          </Space>
        </Space>

        <Space size={32} wrap>
          <Statistic title="今日总流量" value={formatBytes(data?.today_total ?? 0)} />
          <Statistic title="本月总流量" value={formatBytes(data?.month_total ?? 0)} />
          <Statistic title="Top 用户数量" value={data?.top10_users.length ?? 0} />
          <Statistic title="Top 规则数量" value={data?.top10_rules.length ?? 0} />
        </Space>
      </Space>
    </Card>
  )
}

async function submitUserForm({
  form,
  editingUser,
  createMutation,
  updateMutation,
  queryClient,
  onSuccess,
}: {
  form: FormInstance<UserFormValues>
  editingUser: User | null
  createMutation: { mutateAsync: (payload: CreateUserPayload) => Promise<User> }
  updateMutation: { mutateAsync: (payload: { id: string; payload: UpdateUserPayload }) => Promise<User> }
  queryClient: QueryClient
  onSuccess: () => void
}) {
  const values = await form.validateFields()

  if (editingUser) {
    const payload: UpdateUserPayload = {
      username: values.username.trim(),
      email: values.email?.trim() || undefined,
      role: values.role,
      status: values.status,
      vip_level: values.vip_level,
      traffic_quota: values.traffic_quota,
      max_rules: values.max_rules,
      bandwidth_limit: values.bandwidth_limit,
    }

    await updateMutation.mutateAsync({ id: editingUser.id, payload })
    message.success('用户信息已更新')
  } else {
    const payload: CreateUserPayload = {
      username: values.username.trim(),
      password: values.password || '',
      email: values.email?.trim() || undefined,
      role: values.role,
      status: values.status,
      vip_level: values.vip_level,
      traffic_quota: values.traffic_quota,
      max_rules: values.max_rules,
      bandwidth_limit: values.bandwidth_limit,
    }

    await createMutation.mutateAsync(payload)
    message.success('用户创建成功')
  }

  await queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
  onSuccess()
}

async function submitAnnouncementForm({
  form,
  editingAnnouncement,
  createMutation,
  updateMutation,
  queryClient,
  onSuccess,
}: {
  form: FormInstance<AnnouncementFormValues>
  editingAnnouncement: Announcement | null
  createMutation: { mutateAsync: (payload: SaveAnnouncementPayload) => Promise<Announcement> }
  updateMutation: { mutateAsync: (payload: { id: string; payload: Partial<SaveAnnouncementPayload> }) => Promise<Announcement> }
  queryClient: QueryClient
  onSuccess: () => void
}) {
  const values = await form.validateFields()

  const payload: SaveAnnouncementPayload = {
    type: values.type,
    title: values.title.trim(),
    content: values.content,
    is_enabled: values.is_enabled,
    starts_at: values.starts_at?.trim() || undefined,
    ends_at: values.ends_at?.trim() || undefined,
  }

  if (editingAnnouncement) {
    await updateMutation.mutateAsync({ id: editingAnnouncement.id, payload })
    message.success('公告已更新')
  } else {
    await createMutation.mutateAsync(payload)
    message.success('公告已创建')
  }

  await queryClient.invalidateQueries({ queryKey: ['admin', 'announcements'] })
  onSuccess()
}

function statusColor(status: UserStatus) {
  switch (status) {
    case 'normal':
      return 'green'
    case 'suspended':
      return 'orange'
    case 'banned':
      return 'red'
    case 'over_limit':
      return 'purple'
    default:
      return 'default'
  }
}

function logLevelColor(level: string) {
  switch (level.toLowerCase()) {
    case 'debug':
      return 'default'
    case 'info':
      return 'blue'
    case 'warn':
      return 'orange'
    case 'error':
      return 'red'
    default:
      return 'default'
  }
}
