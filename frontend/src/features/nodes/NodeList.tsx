import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Badge,
  Button,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Space,
  Table,
  Typography,
  message,
} from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'

import { deleteNode, listNodeDeployLogs, listNodes, testNodeTCP } from '../../api/nodes'
import { useSSENode } from '../../hooks/useSSENode'
import type { NodeAgent, NodeDeployLog, NodeTCPTestResult } from '../../types/models'
import NodeDeployWizard from './NodeDeployWizard'

const NODE_TYPE_LABEL: Record<NodeAgent['type'], string> = {
  ingress: '入口',
  egress: '出口',
  dual: '双功能',
}

interface TCPTestFormValues {
  target_host: string
  target_port: number
  timeout_sec: number
}

export default function NodeList() {
  const queryClient = useQueryClient()
  const [wizardOpen, setWizardOpen] = useState(false)
  const [selectedNode, setSelectedNode] = useState<NodeAgent | null>(null)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => listNodes({ page: 1, page_size: 200 }),
  })

  const deleteMutation = useMutation({ mutationFn: deleteNode })

  const columns = useMemo<ColumnsType<NodeAgent>>(
    () => [
      { title: '名称', dataIndex: 'name' },
      {
        title: '类型',
        dataIndex: 'type',
        render: (value: NodeAgent['type']) => NODE_TYPE_LABEL[value] ?? value,
      },
      {
        title: '状态',
        render: (_, record) => <NodeStatusBadge node={record} />,
      },
      {
        title: '地址',
        render: (_, record) => `${record.host}:${record.api_port}`,
      },
      {
        title: '架构',
        dataIndex: 'arch',
        render: (value: string) => value || '-',
      },
      {
        title: '最后在线时间',
        dataIndex: 'last_seen_at',
        render: (value?: string) => (value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '从未在线'),
      },
      {
        title: '操作',
        render: (_, record) => (
          <Space size={2} wrap>
            <Button
              type="link"
              size="small"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(record.id)
                  message.success('节点 ID 已复制')
                } catch {
                  message.error('复制失败，请手动复制')
                }
              }}
            >
              复制 ID
            </Button>
            <Button type="link" size="small" onClick={() => setSelectedNode(record)}>
              详情
            </Button>
            <Popconfirm
              title="删除节点"
              description={`确认删除节点“${record.name}”？`}
              onConfirm={async () => {
                await deleteMutation.mutateAsync(record.id)
                await queryClient.invalidateQueries({ queryKey: ['nodes'] })
                message.success('节点已删除')
                if (selectedNode?.id === record.id) {
                  setSelectedNode(null)
                }
              }}
            >
              <Button type="link" danger size="small" loading={deleteMutation.isPending}>
                删除
              </Button>
            </Popconfirm>
          </Space>
        ),
      },
    ],
    [deleteMutation, queryClient, selectedNode?.id],
  )

  return (
    <>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Text type="secondary">
          {`共 ${data?.length ?? 0} 个节点${isFetching ? '（同步中）' : ''}`}
        </Typography.Text>
        <Space>
          <Button onClick={() => void refetch()} loading={isFetching}>
            刷新
          </Button>
          <Button type="primary" onClick={() => setWizardOpen(true)}>
            添加节点
          </Button>
        </Space>
      </Space>

      <Table<NodeAgent>
        rowKey="id"
        loading={isLoading}
        dataSource={data ?? []}
        columns={columns}
        pagination={{ pageSize: 10, showSizeChanger: true }}
      />

      <NodeDeployWizard open={wizardOpen} onClose={() => setWizardOpen(false)} />
      <NodeDetailModal node={selectedNode} onClose={() => setSelectedNode(null)} />
    </>
  )
}

function NodeStatusBadge({ node }: { node: NodeAgent }) {
  const { status, deployStatus } = useSSENode(node.id)
  const currentStatus = status ?? node.status
  const currentDeployStatus = deployStatus ?? node.deploy_status

  if (currentStatus === 'online') {
    return <Badge status="success" text="在线" />
  }

  if (currentDeployStatus === 'failed') {
    return <Badge status="error" text="部署失败" />
  }

  if (currentStatus === 'pending' || currentDeployStatus === 'pending' || currentDeployStatus === 'installing') {
    return <Badge status="processing" text="待部署" />
  }

  return <Badge status="default" text="离线" />
}

function NodeDetailModal({ node, onClose }: { node: NodeAgent | null; onClose: () => void }) {
  const [form] = Form.useForm<TCPTestFormValues>()
  const [lastResult, setLastResult] = useState<NodeTCPTestResult | null>(null)

  const open = Boolean(node)
  const logsQuery = useQuery({
    queryKey: ['nodes', node?.id, 'deploy-logs'],
    queryFn: async () => {
      if (!node) {
        return [] as NodeDeployLog[]
      }
      const response = await listNodeDeployLogs(node.id, { page: 1, page_size: 100 })
      return response.items
    },
    enabled: open,
  })

  const tcpMutation = useMutation({
    mutationFn: async (payload: TCPTestFormValues) => {
      if (!node) {
        throw new Error('节点不存在')
      }
      return testNodeTCP(node.id, payload)
    },
    onSuccess: (result) => {
      setLastResult(result)
      message.success(result.reachable ? 'TCP 探测成功' : 'TCP 探测失败')
    },
  })

  const logColumns = useMemo<ColumnsType<NodeDeployLog>>(
    () => [
      {
        title: '时间',
        dataIndex: 'created_at',
        width: 180,
        render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
      },
      { title: '步骤', dataIndex: 'step', width: 140 },
      { title: '进度', dataIndex: 'progress', width: 100, render: (value: number) => `${value}%` },
      { title: '日志', dataIndex: 'message', render: (value?: string) => value || '-' },
    ],
    [],
  )

  const status = node ? <NodeStatusBadge node={node} /> : '-'

  return (
    <Modal
      title={node ? `节点详情 - ${node.name}` : '节点详情'}
      open={open}
      onCancel={onClose}
      footer={[
        <Button key="refresh" onClick={() => void logsQuery.refetch()} loading={logsQuery.isFetching}>
          刷新日志
        </Button>,
        <Button key="close" type="primary" onClick={onClose}>
          关闭
        </Button>,
      ]}
      width={920}
      destroyOnClose
      afterClose={() => {
        setLastResult(null)
        form.resetFields()
      }}
    >
      {node ? (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Descriptions bordered size="small" column={2}>
            <Descriptions.Item label="节点 ID" span={2}>
              <Typography.Text copyable>{node.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="状态">{status}</Descriptions.Item>
            <Descriptions.Item label="部署状态">{node.deploy_status}</Descriptions.Item>
            <Descriptions.Item label="类型">{NODE_TYPE_LABEL[node.type] ?? node.type}</Descriptions.Item>
            <Descriptions.Item label="架构">{node.arch || '-'}</Descriptions.Item>
            <Descriptions.Item label="地址">{`${node.host}:${node.api_port}`}</Descriptions.Item>
            <Descriptions.Item label="Agent 版本">{node.agent_version || '-'}</Descriptions.Item>
            <Descriptions.Item label="最后在线">
              {node.last_seen_at ? dayjs(node.last_seen_at).format('YYYY-MM-DD HH:mm:ss') : '从未在线'}
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">{dayjs(node.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
          </Descriptions>

          <Typography.Title level={5} style={{ margin: 0 }}>
            TCP 连通性测试
          </Typography.Title>
          <Form<TCPTestFormValues>
            layout="inline"
            form={form}
            initialValues={{ target_host: '', target_port: 443, timeout_sec: 5 }}
            onFinish={(values) => {
              void tcpMutation.mutateAsync(values)
            }}
          >
            <Form.Item
              name="target_host"
              rules={[{ required: true, message: '请输入目标地址' }]}
              style={{ minWidth: 260 }}
            >
              <Input placeholder="目标地址，例如 1.1.1.1" />
            </Form.Item>
            <Form.Item
              name="target_port"
              rules={[{ required: true, message: '目标端口必填' }]}
            >
              <InputNumber min={1} max={65535} placeholder="端口" />
            </Form.Item>
            <Form.Item name="timeout_sec">
              <InputNumber min={1} max={60} placeholder="超时(秒)" />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" loading={tcpMutation.isPending}>
                测试
              </Button>
            </Form.Item>
          </Form>

          {lastResult ? (
            <Alert
              type={lastResult.reachable ? 'success' : 'error'}
              showIcon
              message={lastResult.reachable ? '目标可达' : '目标不可达'}
              description={lastResult.reachable ? `延迟: ${formatLatency(lastResult.latency)}` : lastResult.error || '无详细错误'}
            />
          ) : null}

          <Typography.Title level={5} style={{ margin: 0 }}>
            部署日志
          </Typography.Title>
          <Table<NodeDeployLog>
            rowKey="id"
            size="small"
            loading={logsQuery.isLoading || logsQuery.isFetching}
            columns={logColumns}
            dataSource={logsQuery.data ?? []}
            pagination={{ pageSize: 6, showSizeChanger: false }}
          />
        </Space>
      ) : null}
    </Modal>
  )
}

function formatLatency(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return '-'
  }

  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)} ms`
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(2)} us`
  }
  return `${Math.round(value)} ns`
}
