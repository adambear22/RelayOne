import { useMemo, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Descriptions, Modal, Popconfirm, Space, Table, Typography, message } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { batchDeleteRules, deleteRule, getRuleInstanceInfo, listRules, restartRule, startRule, stopRule, syncRule } from '../../api/rules'
import { useSSERule } from '../../hooks/useSSERule'
import type { ForwardingRule } from '../../types/models'
import RuleCreateDrawer from './RuleCreateDrawer'

const MODE_LABEL: Record<ForwardingRule['mode'], string> = {
  single: '单节点',
  tunnel: '隧道',
  lb: '负载均衡',
  hop_chain: '多跳链路',
}

export default function RuleList() {
  const queryClient = useQueryClient()
  const [createDrawerOpen, setCreateDrawerOpen] = useState(false)
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([])
  const [selectedRule, setSelectedRule] = useState<ForwardingRule | null>(null)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['rules'],
    queryFn: () => listRules({ page: 1, page_size: 200 }),
  })

  const syncMutation = useMutation({ mutationFn: syncRule })
  const startMutation = useMutation({ mutationFn: startRule })
  const stopMutation = useMutation({ mutationFn: stopRule })
  const restartMutation = useMutation({ mutationFn: restartRule })
  const deleteMutation = useMutation({ mutationFn: deleteRule })
  const batchDeleteMutation = useMutation({ mutationFn: batchDeleteRules })

  const actionLoading =
    syncMutation.isPending ||
    startMutation.isPending ||
    stopMutation.isPending ||
    restartMutation.isPending ||
    deleteMutation.isPending ||
    batchDeleteMutation.isPending

  const columns = useMemo<ColumnsType<ForwardingRule>>(
    () => [
      { title: '名称', dataIndex: 'name' },
      {
        title: '模式',
        dataIndex: 'mode',
        render: (value: ForwardingRule['mode']) => MODE_LABEL[value] ?? value,
      },
      {
        title: '入口',
        render: (_, record) => `${record.ingress_node_id}:${record.ingress_port}`,
      },
      {
        title: '目标',
        render: (_, record) => `${record.target_host}:${record.target_port}`,
      },
      {
        title: '状态',
        render: (_, record) => <RuleStatusBadge rule={record} />,
      },
      {
        title: '同步状态',
        render: (_, record) => (
          <RuleSyncCell
            rule={record}
            loading={syncMutation.isPending}
            onRetry={async () => {
              await syncMutation.mutateAsync(record.id)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              message.success('已发送重同步请求')
            }}
          />
        ),
      },
      {
        title: '操作',
        render: (_, record) => (
          <RuleActions
            rule={record}
            loading={actionLoading}
            onView={() => setSelectedRule(record)}
            onStart={async () => {
              await startMutation.mutateAsync(record.id)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              message.success('启动指令已发送')
            }}
            onStop={async () => {
              await stopMutation.mutateAsync(record.id)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              message.success('停止指令已发送')
            }}
            onRestart={async () => {
              await restartMutation.mutateAsync(record.id)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              message.success('重启指令已发送')
            }}
            onDelete={async () => {
              await deleteMutation.mutateAsync(record.id)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              setSelectedRowKeys((prev) => prev.filter((item) => item !== record.id))
              if (selectedRule?.id === record.id) {
                setSelectedRule(null)
              }
              message.success('规则已删除')
            }}
          />
        ),
      },
    ],
    [
      actionLoading,
      deleteMutation,
      queryClient,
      restartMutation,
      selectedRule?.id,
      startMutation,
      stopMutation,
      syncMutation,
    ],
  )

  return (
    <>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Text type="secondary">
          {`共 ${data?.length ?? 0} 条规则${isFetching ? '（同步中）' : ''}`}
        </Typography.Text>
        <Space>
          <Button onClick={() => void refetch()} loading={isFetching}>
            刷新
          </Button>
          <Popconfirm
            title="批量删除规则"
            description={`确认删除已选中的 ${selectedRowKeys.length} 条规则？`}
            disabled={selectedRowKeys.length === 0}
            onConfirm={async () => {
              const ids = selectedRowKeys.map(String)
              if (ids.length === 0) {
                return
              }

              await batchDeleteMutation.mutateAsync(ids)
              await queryClient.invalidateQueries({ queryKey: ['rules'] })
              setSelectedRowKeys([])
              if (selectedRule && ids.includes(selectedRule.id)) {
                setSelectedRule(null)
              }
              message.success(`已删除 ${ids.length} 条规则`)
            }}
          >
            <Button danger disabled={selectedRowKeys.length === 0} loading={batchDeleteMutation.isPending}>
              批量删除
            </Button>
          </Popconfirm>
          <Button type="primary" onClick={() => setCreateDrawerOpen(true)}>
            创建规则
          </Button>
        </Space>
      </Space>

      <Table<ForwardingRule>
        rowKey="id"
        loading={isLoading}
        dataSource={data ?? []}
        columns={columns}
        pagination={{ pageSize: 10, showSizeChanger: true }}
        rowSelection={{
          selectedRowKeys,
          onChange: (keys) => setSelectedRowKeys(keys),
        }}
      />

      <RuleCreateDrawer open={createDrawerOpen} onClose={() => setCreateDrawerOpen(false)} />
      <RuleInstanceModal rule={selectedRule} onClose={() => setSelectedRule(null)} />
    </>
  )
}

function RuleStatusBadge({ rule }: { rule: ForwardingRule }) {
  const { status } = useSSERule(rule.id)
  const currentStatus = status ?? rule.status

  if (currentStatus === 'running') {
    return <Badge status="success" text="运行中" />
  }
  if (currentStatus === 'paused') {
    return <Badge status="warning" text="已暂停" />
  }
  return <Badge status="default" text="已停止" />
}

function RuleSyncCell({
  rule,
  loading,
  onRetry,
}: {
  rule: ForwardingRule
  loading: boolean
  onRetry: () => Promise<void>
}) {
  const { syncStatus } = useSSERule(rule.id)
  const currentSyncStatus = syncStatus ?? rule.sync_status

  if (currentSyncStatus === 'synced') {
    return <Badge status="success" text="已同步" />
  }

  if (currentSyncStatus === 'sync_failed') {
    return (
      <Space>
        <Badge status="error" text="同步失败" />
        <Button type="link" size="small" loading={loading} onClick={() => void onRetry()}>
          重试
        </Button>
      </Space>
    )
  }

  return <Badge status="processing" text="等待同步" />
}

function RuleActions({
  rule,
  loading,
  onView,
  onStart,
  onStop,
  onRestart,
  onDelete,
}: {
  rule: ForwardingRule
  loading: boolean
  onView: () => void
  onStart: () => Promise<void>
  onStop: () => Promise<void>
  onRestart: () => Promise<void>
  onDelete: () => Promise<void>
}) {
  const { status } = useSSERule(rule.id)
  const currentStatus = status ?? rule.status

  return (
    <Space size={4} wrap>
      <Button size="small" type="link" onClick={onView}>
        详情
      </Button>

      {currentStatus !== 'running' ? (
        <Button size="small" type="link" loading={loading} onClick={() => void onStart()}>
          启动
        </Button>
      ) : (
        <Button size="small" type="link" loading={loading} onClick={() => void onStop()}>
          停止
        </Button>
      )}

      <Button size="small" type="link" loading={loading} onClick={() => void onRestart()}>
        重启
      </Button>

      <Popconfirm title="删除规则" description={`确认删除规则“${rule.name}”？`} onConfirm={() => onDelete()}>
        <Button size="small" type="link" danger loading={loading}>
          删除
        </Button>
      </Popconfirm>
    </Space>
  )
}

function RuleInstanceModal({ rule, onClose }: { rule: ForwardingRule | null; onClose: () => void }) {
  const open = Boolean(rule)

  const instanceQuery = useQuery({
    queryKey: ['rules', rule?.id, 'instance'],
    queryFn: async () => {
      if (!rule) {
        return null
      }
      return getRuleInstanceInfo(rule.id)
    },
    enabled: open,
  })

  return (
    <Modal
      title={rule ? `规则详情 - ${rule.name}` : '规则详情'}
      open={open}
      onCancel={onClose}
      footer={[
        <Button key="refresh" onClick={() => void instanceQuery.refetch()} loading={instanceQuery.isFetching}>
          刷新
        </Button>,
        <Button key="close" type="primary" onClick={onClose}>
          关闭
        </Button>,
      ]}
      width={760}
      destroyOnClose
    >
      {rule ? (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Descriptions bordered size="small" column={2}>
            <Descriptions.Item label="规则 ID" span={2}>
              <Typography.Text copyable>{rule.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="模式">{MODE_LABEL[rule.mode] ?? rule.mode}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <RuleStatusBadge rule={rule} />
            </Descriptions.Item>
            <Descriptions.Item label="同步状态">{rule.sync_status}</Descriptions.Item>
            <Descriptions.Item label="入口">{`${rule.ingress_node_id}:${rule.ingress_port}`}</Descriptions.Item>
            <Descriptions.Item label="目标">{`${rule.target_host}:${rule.target_port}`}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{rule.created_at}</Descriptions.Item>
            <Descriptions.Item label="更新时间">{rule.updated_at}</Descriptions.Item>
          </Descriptions>

          <Typography.Title level={5} style={{ margin: 0 }}>
            实例信息
          </Typography.Title>

          <Typography.Paragraph style={{ marginBottom: 0 }}>
            <pre
              style={{
                margin: 0,
                background: '#111827',
                color: '#f9fafb',
                borderRadius: 8,
                padding: 12,
                overflowX: 'auto',
                maxHeight: 320,
              }}
            >
              {JSON.stringify(instanceQuery.data ?? rule.instance_info ?? {}, null, 2)}
            </pre>
          </Typography.Paragraph>
        </Space>
      ) : null}
    </Modal>
  )
}
