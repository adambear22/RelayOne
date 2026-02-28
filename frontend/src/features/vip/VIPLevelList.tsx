import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'

import {
  createVIPLevel,
  deleteVIPLevel,
  getMyVIP,
  listVIPLevels,
  updateVIPLevel,
  upgradeUserVIP,
  type CreateVIPLevelPayload,
  type UpdateVIPLevelPayload,
} from '../../api/vip'
import { usePermission } from '../../hooks/usePermission'
import type { UserVIPEntitlement, VIPLevel } from '../../types/models'
import { formatBytes } from '../../utils/bytes'

interface VIPLevelFormValues {
  level: number
  name: string
  traffic_quota: number
  max_rules: number
  bandwidth_limit: number
  max_ingress_nodes: number
  max_egress_nodes: number
  accessible_node_level: number
  traffic_ratio: number
  custom_features: string
}

interface UpgradeFormValues {
  user_id: string
  level: number
  valid_days: number
}

const defaultLevelForm: VIPLevelFormValues = {
  level: 0,
  name: '',
  traffic_quota: 0,
  max_rules: 20,
  bandwidth_limit: 0,
  max_ingress_nodes: 0,
  max_egress_nodes: 0,
  accessible_node_level: 0,
  traffic_ratio: 1,
  custom_features: '',
}

export default function VIPLevelList() {
  const { isAdmin } = usePermission()
  const queryClient = useQueryClient()
  const [editingLevel, setEditingLevel] = useState<VIPLevel | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [form] = Form.useForm<VIPLevelFormValues>()
  const [upgradeForm] = Form.useForm<UpgradeFormValues>()

  const levelsQuery = useQuery({
    queryKey: ['vip-levels'],
    queryFn: listVIPLevels,
  })

  const myVIPQuery = useQuery({
    queryKey: ['vip', 'me'],
    queryFn: getMyVIP,
  })

  const createMutation = useMutation({ mutationFn: createVIPLevel })
  const updateMutation = useMutation({
    mutationFn: ({ level, payload }: { level: number; payload: UpdateVIPLevelPayload }) => updateVIPLevel(level, payload),
  })
  const deleteMutation = useMutation({ mutationFn: deleteVIPLevel })
  const upgradeMutation = useMutation({
    mutationFn: ({ userId, level, validDays }: { userId: string; level: number; validDays: number }) =>
      upgradeUserVIP(userId, { level, valid_days: validDays }),
  })

  const columns = useMemo<ColumnsType<VIPLevel>>(
    () => [
      {
        title: '等级',
        dataIndex: 'level',
        width: 90,
        render: (value: number) => <Tag color={value > 0 ? 'gold' : 'default'}>VIP {value}</Tag>,
      },
      { title: '名称', dataIndex: 'name' },
      {
        title: '流量配额',
        dataIndex: 'traffic_quota',
        render: (value: number) => formatBytes(value),
      },
      { title: '最大规则数', dataIndex: 'max_rules' },
      {
        title: '带宽限制',
        dataIndex: 'bandwidth_limit',
        render: (value: number) => (value > 0 ? `${value} bps` : '不限速'),
      },
      {
        title: '节点权限',
        render: (_, item) => `入站 ${item.max_ingress_nodes} / 出站 ${item.max_egress_nodes}`,
      },
      {
        title: '计费倍率',
        dataIndex: 'traffic_ratio',
        render: (value?: number) => (typeof value === 'number' ? `x${value}` : '-'),
      },
      ...(isAdmin
        ? [
            {
              title: '操作',
              width: 220,
              render: (_: unknown, item: VIPLevel) => (
                <Space size={4}>
                  <Button
                    type="link"
                    size="small"
                    onClick={() => {
                      setEditingLevel(item)
                      form.setFieldsValue({
                        level: item.level,
                        name: item.name,
                        traffic_quota: item.traffic_quota,
                        max_rules: item.max_rules,
                        bandwidth_limit: item.bandwidth_limit,
                        max_ingress_nodes: item.max_ingress_nodes,
                        max_egress_nodes: item.max_egress_nodes,
                        accessible_node_level: item.accessible_node_level,
                        traffic_ratio: item.traffic_ratio,
                        custom_features: item.custom_features ? JSON.stringify(item.custom_features, null, 2) : '',
                      })
                      setEditorOpen(true)
                    }}
                  >
                    编辑
                  </Button>
                  <Popconfirm
                    title="删除 VIP 等级"
                    description={`确认删除 VIP ${item.level} 吗？`}
                    onConfirm={async () => {
                      await deleteMutation.mutateAsync(item.level)
                      await queryClient.invalidateQueries({ queryKey: ['vip-levels'] })
                      message.success('VIP 等级已删除')
                    }}
                  >
                    <Button type="link" danger size="small" loading={deleteMutation.isPending}>
                      删除
                    </Button>
                  </Popconfirm>
                </Space>
              ),
            } satisfies ColumnsType<VIPLevel>[number],
          ]
        : []),
    ],
    [deleteMutation, form, isAdmin, queryClient],
  )

  const openCreateEditor = () => {
    setEditingLevel(null)
    form.setFieldsValue(defaultLevelForm)
    setEditorOpen(true)
  }

  const submitEditor = async () => {
    const values = await form.validateFields()
    let customFeatures: Record<string, unknown> | undefined
    try {
      customFeatures = parseCustomFeatures(values.custom_features)
    } catch (error) {
      message.error(error instanceof Error ? error.message : '自定义特性 JSON 格式错误')
      return
    }

    const basePayload: CreateVIPLevelPayload = {
      level: values.level,
      name: values.name.trim(),
      traffic_quota: values.traffic_quota,
      max_rules: values.max_rules,
      bandwidth_limit: values.bandwidth_limit,
      max_ingress_nodes: values.max_ingress_nodes,
      max_egress_nodes: values.max_egress_nodes,
      accessible_node_level: values.accessible_node_level,
      traffic_ratio: values.traffic_ratio,
      custom_features: customFeatures,
    }

    if (editingLevel) {
      const updatePayload: UpdateVIPLevelPayload = {
        name: basePayload.name,
        traffic_quota: basePayload.traffic_quota,
        max_rules: basePayload.max_rules,
        bandwidth_limit: basePayload.bandwidth_limit,
        max_ingress_nodes: basePayload.max_ingress_nodes,
        max_egress_nodes: basePayload.max_egress_nodes,
        accessible_node_level: basePayload.accessible_node_level,
        traffic_ratio: basePayload.traffic_ratio,
        custom_features: basePayload.custom_features,
      }

      await updateMutation.mutateAsync({ level: editingLevel.level, payload: updatePayload })
      message.success('VIP 等级已更新')
    } else {
      await createMutation.mutateAsync(basePayload)
      message.success('VIP 等级已创建')
    }

    await queryClient.invalidateQueries({ queryKey: ['vip-levels'] })
    setEditorOpen(false)
    form.resetFields()
  }

  const myVIP = myVIPQuery.data

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <VIPEntitlementCard loading={myVIPQuery.isLoading} data={myVIP} />

      {isAdmin ? (
        <Card title="管理员操作">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Typography.Text type="secondary">管理 VIP 等级与用户升级</Typography.Text>
              <Button type="primary" onClick={openCreateEditor}>
                新增等级
              </Button>
            </Space>

            <Form<UpgradeFormValues>
              layout="inline"
              form={upgradeForm}
              initialValues={{ user_id: '', level: 1, valid_days: 30 }}
              onFinish={async (values) => {
                await upgradeMutation.mutateAsync({
                  userId: values.user_id.trim(),
                  level: values.level,
                  validDays: values.valid_days,
                })
                message.success('用户 VIP 已升级')
                upgradeForm.resetFields()
              }}
            >
              <Form.Item name="user_id" rules={[{ required: true, message: '请输入用户 ID' }]}>
                <Input placeholder="用户 ID" style={{ width: 300 }} />
              </Form.Item>
              <Form.Item name="level" rules={[{ required: true, message: '等级必填' }]}>
                <InputNumber min={0} max={20} placeholder="等级" />
              </Form.Item>
              <Form.Item name="valid_days" rules={[{ required: true, message: '有效天数必填' }]}>
                <InputNumber min={1} max={3650} placeholder="有效天数" />
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit" loading={upgradeMutation.isPending}>
                  立即升级
                </Button>
              </Form.Item>
            </Form>
          </Space>
        </Card>
      ) : null}

      <Card title="VIP 等级列表">
        <Table<VIPLevel>
          rowKey="level"
          loading={levelsQuery.isLoading || levelsQuery.isFetching}
          dataSource={levelsQuery.data ?? []}
          columns={columns}
          pagination={false}
        />
      </Card>

      <Modal
        title={editingLevel ? `编辑 VIP ${editingLevel.level}` : '新增 VIP 等级'}
        open={editorOpen}
        onCancel={() => setEditorOpen(false)}
        onOk={() => void submitEditor()}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        width={760}
        destroyOnClose
      >
        <Form<VIPLevelFormValues> form={form} layout="vertical" initialValues={defaultLevelForm}>
          <Space style={{ width: '100%' }} size={12}>
            <Form.Item
              label="等级"
              name="level"
              style={{ flex: 1 }}
              rules={[{ required: true, message: '等级必填' }]}
            >
              <InputNumber min={0} max={20} style={{ width: '100%' }} disabled={Boolean(editingLevel)} />
            </Form.Item>
            <Form.Item
              label="名称"
              name="name"
              style={{ flex: 2 }}
              rules={[{ required: true, message: '名称必填' }]}
            >
              <Input maxLength={64} />
            </Form.Item>
          </Space>

          <Space style={{ width: '100%' }} size={12}>
            <Form.Item
              label="流量配额"
              name="traffic_quota"
              style={{ flex: 1 }}
              rules={[{ required: true, message: '流量配额必填' }]}
            >
              <InputNumber min={0} step={1024 * 1024} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              label="最大规则数"
              name="max_rules"
              style={{ flex: 1 }}
              rules={[{ required: true, message: '最大规则数必填' }]}
            >
              <InputNumber min={1} max={100000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              label="带宽限制"
              name="bandwidth_limit"
              style={{ flex: 1 }}
              rules={[{ required: true, message: '带宽限制必填' }]}
            >
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Space style={{ width: '100%' }} size={12}>
            <Form.Item label="最大入口节点" name="max_ingress_nodes" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item label="最大出口节点" name="max_egress_nodes" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item label="可访问节点等级" name="accessible_node_level" style={{ flex: 1 }}>
              <InputNumber min={0} max={20} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item label="计费倍率" name="traffic_ratio" style={{ flex: 1 }}>
              <InputNumber min={0.1} max={100} step={0.1} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item
            label="自定义特性(JSON，可选)"
            name="custom_features"
            extra='例如: {"feature_x": true, "limit": 10}'
          >
            <Input.TextArea rows={4} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}

function VIPEntitlementCard({ loading, data }: { loading: boolean; data?: UserVIPEntitlement }) {
  return (
    <Card title="我的 VIP 权益" loading={loading}>
      {data ? (
        <Space size={32} wrap>
          <Statistic title="当前等级" value={`VIP ${data.vip_level}`} />
          <Statistic title="到期时间" value={data.vip_expires_at ? dayjs(data.vip_expires_at).format('YYYY-MM-DD HH:mm') : '未设置'} />
          <Statistic title="流量配额" value={formatBytes(data.traffic_quota)} />
          <Statistic title="最大规则数" value={data.max_rules} />
          <Statistic title="带宽限制" value={data.bandwidth_limit > 0 ? `${data.bandwidth_limit} bps` : '不限速'} />
        </Space>
      ) : (
        <Typography.Text type="secondary">暂无权益信息</Typography.Text>
      )}
    </Card>
  )
}

function parseCustomFeatures(raw: string): Record<string, unknown> | undefined {
  const trimmed = raw.trim()
  if (!trimmed) {
    return undefined
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('自定义特性必须是 JSON 对象')
    }
    return parsed as Record<string, unknown>
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : '自定义特性 JSON 格式错误')
  }
}
