import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Form, Input, Space, Table, Typography, message } from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'
import { useNavigate } from 'react-router-dom'

import { fetchCurrentUser } from '../api/auth'
import { listRedeemHistory, redeemCode, type RedeemHistoryItem } from '../api/codes'
import PageCard from '../components/PageCard'
import { useAuthStore } from '../stores/auth'
import { ApiBusinessError } from '../types/api'
import type { User } from '../types/models'

type RedeemResult =
  | {
      status: 'success'
      code: string
      level: number
      expiresAt?: string
      addedDays?: number
    }
  | {
      status: 'error'
      code: string
      message: string
    }

interface RedeemHistoryRecord {
  id: string
  createdAt: string
  code: string
  level?: number
  expiresAt?: string
  source?: string
  remark?: string
}

export default function RedeemPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const setUser = useAuthStore((state) => state.setUser)

  const [form] = Form.useForm<{ code: string }>()
  const [result, setResult] = useState<RedeemResult | null>(null)
  const [historyPage, setHistoryPage] = useState(1)
  const [historyPageSize, setHistoryPageSize] = useState(8)

  const redeemMutation = useMutation({
    mutationFn: redeemCode,
  })

  const historyQuery = useQuery({
    queryKey: ['codes', 'redeem-history', user?.id, historyPage, historyPageSize],
    queryFn: () => listRedeemHistory({ page: historyPage, page_size: historyPageSize }),
    enabled: Boolean(user?.id),
    staleTime: 60_000,
  })

  const history = useMemo(() => mapHistory(historyQuery.data?.items), [historyQuery.data?.items])

  const columns: ColumnsType<RedeemHistoryRecord> = useMemo(
    () => [
      {
        title: '时间',
        dataIndex: 'createdAt',
        width: 180,
        render: (value: string) => formatDateTime(value),
      },
      {
        title: '权益码',
        dataIndex: 'code',
        render: (value: string) => maskCode(value),
      },
      {
        title: '获得等级',
        dataIndex: 'level',
        width: 120,
        render: (value?: number) => (typeof value === 'number' ? `VIP Lv.${value}` : '—'),
      },
      {
        title: '有效期至',
        dataIndex: 'expiresAt',
        width: 180,
        render: (value?: string) => (value ? formatDateTime(value) : '—'),
      },
      {
        title: '来源',
        dataIndex: 'source',
        width: 130,
        render: (value?: string) => value || '—',
      },
      {
        title: '备注',
        dataIndex: 'remark',
        ellipsis: true,
        render: (value?: string) => value || '—',
      },
    ],
    [],
  )

  const currentCodeValue = Form.useWatch('code', form) ?? ''

  if (!user) {
    return (
      <PageCard title="权益码兑换" subtitle="输入权益码并激活 VIP 权益">
        <Empty description="暂无用户信息" />
      </PageCard>
    )
  }

  return (
    <PageCard title="权益码兑换" subtitle="输入权益码并激活 VIP 权益">
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Card title="兑换区域">
          {result ? (
            result.status === 'success' ? (
              <Space direction="vertical" size={16} style={{ width: '100%' }}>
                <Alert
                  type="success"
                  showIcon
                  message={`🎉 兑换成功！已获得 VIP Lv.${result.level} 权益`}
                  description={
                    <Space direction="vertical" size={4}>
                      <Typography.Text>有效期至：{result.expiresAt ? formatDateTime(result.expiresAt) : '—'}</Typography.Text>
                      <Typography.Text>新增天数：{typeof result.addedDays === 'number' ? `+${result.addedDays} 天` : '—'}</Typography.Text>
                    </Space>
                  }
                />
                <Space>
                  <Button type="primary" onClick={() => navigate('/vip')}>
                    前往 VIP 中心
                  </Button>
                  <Button
                    onClick={() => {
                      setResult(null)
                      form.setFieldsValue({ code: '' })
                    }}
                  >
                    继续兑换
                  </Button>
                </Space>
              </Space>
            ) : (
              <Space direction="vertical" size={16} style={{ width: '100%' }}>
                <Alert type="error" showIcon message={result.message} />
                <Button onClick={() => setResult(null)}>重新输入</Button>
              </Space>
            )
          ) : (
            <Form<{ code: string }>
              form={form}
              layout="vertical"
              initialValues={{ code: '' }}
              onFinish={async (values) => {
                const normalizedCode = values.code.trim().toUpperCase()
                if (!normalizedCode) {
                  message.warning('请输入权益码')
                  return
                }

                try {
                  const previousUser = user
                  await redeemMutation.mutateAsync(normalizedCode)

                  const latestUser = await fetchCurrentUser()
                  setUser(latestUser)
                  await refreshRelatedQueries(queryClient)
                  setHistoryPage(1)

                  setResult({
                    status: 'success',
                    code: normalizedCode,
                    level: latestUser.vip_level,
                    expiresAt: latestUser.vip_expires_at,
                    addedDays: calcAddedDays(previousUser, latestUser),
                  })
                  message.success('🎉 兑换成功')
                } catch (error) {
                  setResult({
                    status: 'error',
                    code: normalizedCode,
                    message: resolveRedeemError(error),
                  })
                }
              }}
            >
              <Form.Item
                name="code"
                rules={[{ required: true, message: '请输入权益码' }]}
                normalize={(value) => (typeof value === 'string' ? value.toUpperCase() : value)}
              >
                <Input
                  size="large"
                  placeholder="输入权益码，如 VIP-XXXX-XXXX-XXXX"
                  autoComplete="off"
                  onPaste={(event) => {
                    event.preventDefault()
                    const pasted = event.clipboardData.getData('text').trim().toUpperCase()
                    form.setFieldsValue({ code: pasted })
                  }}
                />
              </Form.Item>
              <Button type="primary" htmlType="submit" loading={redeemMutation.isPending} disabled={!currentCodeValue.trim()}>
                兑换
              </Button>
            </Form>
          )}
        </Card>

        <Card title="已兑换记录" extra={<Typography.Text type="secondary">来自后端兑换历史接口</Typography.Text>}>
          <Table<RedeemHistoryRecord>
            rowKey="id"
            columns={columns}
            dataSource={history}
            loading={historyQuery.isLoading || historyQuery.isFetching}
            pagination={{
              current: historyPage,
              pageSize: historyPageSize,
              total: Number(historyQuery.data?.pagination?.total ?? 0),
              showSizeChanger: true,
              pageSizeOptions: [8, 16, 20, 50],
              onChange: (nextPage, nextPageSize) => {
                setHistoryPage(nextPage)
                setHistoryPageSize(nextPageSize)
              },
            }}
            locale={{ emptyText: '暂无兑换记录' }}
          />
        </Card>
      </Space>
    </PageCard>
  )
}

function resolveRedeemError(error: unknown): string {
  if (error instanceof ApiBusinessError) {
    if (error.httpStatus === 404) {
      return '权益码不存在'
    }
    if (error.httpStatus === 409) {
      return '该权益码已被使用'
    }
    if (error.httpStatus === 403) {
      return '该权益码已被禁用'
    }
    if (error.httpStatus === 422 || error.httpStatus === 410) {
      return '权益码已过期'
    }
  }

  if (error instanceof Error && error.message) {
    return error.message
  }
  return '兑换失败，请稍后重试'
}

function formatDateTime(value: string): string {
  const parsed = dayjs(value)
  return parsed.isValid() ? parsed.format('YYYY-MM-DD HH:mm:ss') : value
}

function calcAddedDays(previousUser: User, nextUser: User): number | undefined {
  const nextExpire = parseDate(nextUser.vip_expires_at)
  if (!nextExpire) {
    return undefined
  }

  const previousExpire = parseDate(previousUser.vip_expires_at) ?? dayjs()
  const diff = nextExpire.startOf('day').diff(previousExpire.startOf('day'), 'day')
  return diff > 0 ? diff : undefined
}

function parseDate(value?: string) {
  if (!value) {
    return null
  }
  const parsed = dayjs(value)
  return parsed.isValid() ? parsed : null
}

function maskCode(code: string): string {
  const parts = code.split('-').filter(Boolean)
  if (parts.length >= 3) {
    const first = parts[0]
    const last = parts[parts.length - 1]
    return `${first}-****-${last}`
  }

  if (code.length <= 8) {
    return code
  }

  return `${code.slice(0, 4)}****${code.slice(-4)}`
}

function mapHistory(items?: RedeemHistoryItem[]): RedeemHistoryRecord[] {
  if (!items || items.length === 0) {
    return []
  }

  return items.map((item) => {
    const redeemedAt = item.used_at ?? ''
    const expiresAt = item.expires_at
    return {
      id: item.id,
      createdAt: redeemedAt,
      code: item.code,
      level: item.vip_level,
      expiresAt,
      source: mapSource(item.source),
      remark: item.remark,
    }
  })
}

function mapSource(source?: string): string {
  if (!source) {
    return '权益码'
  }
  if (source === 'benefit_code') {
    return '权益码兑换'
  }
  return source
}

async function refreshRelatedQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ['auth'] }),
    queryClient.invalidateQueries({ queryKey: ['users', 'me'] }),
    queryClient.invalidateQueries({ queryKey: ['traffic'] }),
    queryClient.invalidateQueries({ queryKey: ['vip'] }),
    queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
    queryClient.invalidateQueries({ queryKey: ['codes', 'redeem-history'] }),
  ])
}
