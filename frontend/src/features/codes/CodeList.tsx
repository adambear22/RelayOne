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
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType, TableProps } from 'antd/es/table'
import type { Key } from 'react'

import {
  batchDeleteCodes,
  batchGenerateCodes,
  batchUpdateCodesStatus,
  listCodes,
  redeemCode,
  type BatchGenerateCodesPayload,
} from '../../api/codes'
import { usePermission } from '../../hooks/usePermission'
import type { BenefitCode } from '../../types/models'

interface CodeFilterValues {
  keyword?: string
  vip_level?: number
  is_used?: 'all' | 'true' | 'false'
  is_enabled?: 'all' | 'true' | 'false'
}

interface GenerateFormValues {
  count: number
  vip_level: number
  duration_days: number
  valid_days: number
  expires_at?: string
  custom_codes?: string
}

const defaultGenerateValues: GenerateFormValues = {
  count: 10,
  vip_level: 1,
  duration_days: 30,
  valid_days: 30,
  expires_at: '',
  custom_codes: '',
}

export default function CodeList() {
  const { isAdmin } = usePermission()
  const queryClient = useQueryClient()
  const [redeemForm] = Form.useForm<{ code: string }>()
  const [filterForm] = Form.useForm<CodeFilterValues>()
  const [generateForm] = Form.useForm<GenerateFormValues>()
  const [generateOpen, setGenerateOpen] = useState(false)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [filters, setFilters] = useState<CodeFilterValues>({ is_used: 'all', is_enabled: 'all' })

  const listQuery = useQuery({
    queryKey: ['codes', page, pageSize, filters],
    queryFn: () =>
      listCodes({
        page,
        page_size: pageSize,
        keyword: filters.keyword?.trim() || undefined,
        vip_level: filters.vip_level,
        is_used: normalizeBooleanFilter(filters.is_used),
        is_enabled: normalizeBooleanFilter(filters.is_enabled),
      }),
    enabled: isAdmin,
  })

  const redeemMutation = useMutation({ mutationFn: redeemCode })
  const generateMutation = useMutation({ mutationFn: batchGenerateCodes })
  const updateStatusMutation = useMutation({ mutationFn: batchUpdateCodesStatus })
  const deleteBatchMutation = useMutation({ mutationFn: batchDeleteCodes })

  const columns = useMemo<ColumnsType<BenefitCode>>(
    () => [
      {
        title: '权益码',
        dataIndex: 'code',
        render: (value: string) => <Typography.Text copyable>{value}</Typography.Text>,
      },
      {
        title: 'VIP 等级',
        dataIndex: 'vip_level',
        width: 100,
        render: (value: number) => <Tag color="gold">VIP {value}</Tag>,
      },
      {
        title: '有效天数',
        dataIndex: 'valid_days',
        width: 110,
      },
      {
        title: '礼包时长',
        dataIndex: 'duration_days',
        width: 110,
        render: (value: number) => `${value} 天`,
      },
      {
        title: '状态',
        width: 180,
        render: (_, item) => (
          <Space size={4}>
            <Tag color={item.is_enabled ? 'green' : 'default'}>{item.is_enabled ? '启用' : '禁用'}</Tag>
            <Tag color={item.is_used ? 'blue' : 'default'}>{item.is_used ? '已使用' : '未使用'}</Tag>
          </Space>
        ),
      },
      {
        title: '过期时间',
        dataIndex: 'expires_at',
        render: (value?: string) => (value ? dayjs(value).format('YYYY-MM-DD HH:mm:ss') : '不过期'),
      },
      {
        title: '创建时间',
        dataIndex: 'created_at',
        render: (value: string) => dayjs(value).format('YYYY-MM-DD HH:mm:ss'),
      },
    ],
    [],
  )

  const rowSelection: TableProps<BenefitCode>['rowSelection'] = {
    selectedRowKeys,
    onChange: (keys: Key[]) => setSelectedRowKeys(keys as string[]),
  }

  const runBatchStatusUpdate = async (enabled: boolean) => {
    if (selectedRowKeys.length === 0) {
      message.warning('请先选择权益码')
      return
    }

    await updateStatusMutation.mutateAsync({ ids: selectedRowKeys, enabled })
    await queryClient.invalidateQueries({ queryKey: ['codes'] })
    message.success(`已${enabled ? '启用' : '禁用'} ${selectedRowKeys.length} 条权益码`)
  }

  const runBatchDelete = async () => {
    if (selectedRowKeys.length === 0) {
      message.warning('请先选择权益码')
      return
    }

    await deleteBatchMutation.mutateAsync({ ids: selectedRowKeys })
    await queryClient.invalidateQueries({ queryKey: ['codes'] })
    setSelectedRowKeys([])
    message.success('批量删除成功')
  }

  const submitGenerate = async () => {
    const values = await generateForm.validateFields()
    const payload: BatchGenerateCodesPayload = {
      count: values.count,
      vip_level: values.vip_level,
      duration_days: values.duration_days,
      valid_days: values.valid_days,
      expires_at: values.expires_at?.trim() || undefined,
      custom_codes: splitCustomCodes(values.custom_codes),
    }

    await generateMutation.mutateAsync(payload)
    await queryClient.invalidateQueries({ queryKey: ['codes'] })
    message.success('权益码批量生成成功')
    setGenerateOpen(false)
    generateForm.resetFields()
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="兑换权益码">
        <Form<{ code: string }>
          layout="inline"
          form={redeemForm}
          onFinish={async (values) => {
            await redeemMutation.mutateAsync(values.code.trim())
            message.success('权益码兑换成功')
            redeemForm.resetFields()
            await queryClient.invalidateQueries({ queryKey: ['vip', 'me'] })
          }}
        >
          <Form.Item name="code" style={{ minWidth: 320 }} rules={[{ required: true, message: '请输入权益码' }]}> 
            <Input placeholder="输入权益码并兑换" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={redeemMutation.isPending}>
              立即兑换
            </Button>
          </Form.Item>
        </Form>
      </Card>

      {isAdmin ? (
        <Card title="权益码管理">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Form<CodeFilterValues>
              layout="inline"
              form={filterForm}
              initialValues={{ is_used: 'all', is_enabled: 'all' }}
              onFinish={(values) => {
                setPage(1)
                setFilters(values)
              }}
            >
              <Form.Item name="keyword">
                <Input allowClear placeholder="搜索 code 关键字" style={{ width: 240 }} />
              </Form.Item>
              <Form.Item name="vip_level">
                <InputNumber min={0} max={20} placeholder="VIP 等级" />
              </Form.Item>
              <Form.Item name="is_used">
                <Select
                  style={{ width: 140 }}
                  options={[
                    { label: '使用状态: 全部', value: 'all' },
                    { label: '已使用', value: 'true' },
                    { label: '未使用', value: 'false' },
                  ]}
                />
              </Form.Item>
              <Form.Item name="is_enabled">
                <Select
                  style={{ width: 140 }}
                  options={[
                    { label: '启用状态: 全部', value: 'all' },
                    { label: '已启用', value: 'true' },
                    { label: '已禁用', value: 'false' },
                  ]}
                />
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit">
                  筛选
                </Button>
              </Form.Item>
              <Form.Item>
                <Button
                  onClick={() => {
                    filterForm.resetFields()
                    setFilters({ is_used: 'all', is_enabled: 'all' })
                    setPage(1)
                  }}
                >
                  重置
                </Button>
              </Form.Item>
            </Form>

            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Typography.Text type="secondary">已选 {selectedRowKeys.length} 条</Typography.Text>
              <Space>
                <Button type="primary" onClick={() => setGenerateOpen(true)}>
                  批量生成
                </Button>
                <Button
                  onClick={() => void runBatchStatusUpdate(true)}
                  loading={updateStatusMutation.isPending && selectedRowKeys.length > 0}
                  disabled={selectedRowKeys.length === 0}
                >
                  批量启用
                </Button>
                <Button
                  onClick={() => void runBatchStatusUpdate(false)}
                  loading={updateStatusMutation.isPending && selectedRowKeys.length > 0}
                  disabled={selectedRowKeys.length === 0}
                >
                  批量禁用
                </Button>
                <Popconfirm
                  title="批量删除权益码"
                  description={`确认删除选中的 ${selectedRowKeys.length} 条权益码？`}
                  onConfirm={() => runBatchDelete()}
                  disabled={selectedRowKeys.length === 0}
                >
                  <Button danger disabled={selectedRowKeys.length === 0} loading={deleteBatchMutation.isPending}>
                    批量删除
                  </Button>
                </Popconfirm>
              </Space>
            </Space>

            <Table<BenefitCode>
              rowKey="id"
              loading={listQuery.isLoading || listQuery.isFetching}
              dataSource={listQuery.data?.items ?? []}
              columns={columns}
              rowSelection={rowSelection}
              pagination={{
                current: page,
                pageSize,
                showSizeChanger: true,
                total: Number(listQuery.data?.pagination?.total ?? 0),
                onChange: (nextPage, nextSize) => {
                  setPage(nextPage)
                  setPageSize(nextSize)
                },
              }}
            />
          </Space>
        </Card>
      ) : null}

      <Modal
        title="批量生成权益码"
        open={generateOpen}
        onCancel={() => setGenerateOpen(false)}
        onOk={() => void submitGenerate()}
        confirmLoading={generateMutation.isPending}
        destroyOnClose
      >
        <Form<GenerateFormValues> form={generateForm} layout="vertical" initialValues={defaultGenerateValues}>
          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="count" label="数量" style={{ flex: 1 }} rules={[{ required: true, message: '请输入数量' }]}> 
              <InputNumber min={1} max={1000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="vip_level" label="VIP 等级" style={{ flex: 1 }} rules={[{ required: true, message: '请输入 VIP 等级' }]}> 
              <InputNumber min={0} max={20} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Space size={12} style={{ width: '100%' }}>
            <Form.Item name="duration_days" label="升级时长(天)" style={{ flex: 1 }}>
              <InputNumber min={0} max={3650} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="valid_days" label="兑换有效期(天)" style={{ flex: 1 }}>
              <InputNumber min={1} max={3650} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item name="expires_at" label="固定过期时间(可选，RFC3339)">
            <Input placeholder="例如 2026-12-31T23:59:59Z" />
          </Form.Item>
          <Form.Item name="custom_codes" label="自定义 code（可选，一行一个）">
            <Input.TextArea rows={4} placeholder={'CODE_A\nCODE_B\nCODE_C'} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}

function normalizeBooleanFilter(value: 'all' | 'true' | 'false' | undefined): boolean | undefined {
  if (!value || value === 'all') {
    return undefined
  }
  return value === 'true'
}

function splitCustomCodes(raw: string | undefined): string[] | undefined {
  if (!raw) {
    return undefined
  }

  const values = raw
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)

  return values.length > 0 ? values : undefined
}
