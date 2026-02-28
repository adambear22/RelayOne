import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { zodResolver } from '@hookform/resolvers/zod'
import { Alert, Button, Collapse, Drawer, Form, Input, InputNumber, Radio, Segmented, Select, Space, Tooltip, Typography, Modal, message } from 'antd'
import { Controller, useForm, useWatch } from 'react-hook-form'
import { Link } from 'react-router-dom'
import { z } from 'zod'

import { listHopChains } from '../../api/hop-chains'
import { listLBGroups } from '../../api/lb-groups'
import { listNodes } from '../../api/nodes'
import { createRule, startRule, type CreateRulePayload } from '../../api/rules'
import type { NodeAgent } from '../../types/models'
import { PRESETS, buildNodepassURL } from '../../utils/nodepass_url'

type TransportMode = 'fast' | 'safe' | 'mix'
type LogLevel = 'debug' | 'info' | 'warn' | 'error'
type Protocol = 'tcp' | 'udp'
type PresetKey = 'none' | 'streaming' | 'low_latency_gaming' | 'secure_transfer' | 'ssh_tunnel'

interface RuleCreateDrawerProps {
  open: boolean
  onClose: () => void
}

const MAX_PORT = 65535

const formSchema = z
  .object({
    name: z.string().trim().min(2, '规则名称至少 2 个字符').max(128, '规则名称不能超过 128 个字符'),
    mode: z.enum(['single', 'tunnel', 'lb', 'hop_chain']),
    ingress_node_id: z.string().trim().min(1, '请选择入口节点'),
    ingress_port: z.number().int().min(0, '0 代表自动分配').max(MAX_PORT, `端口不能大于 ${MAX_PORT}`),
    target_host: z.string().trim().optional(),
    target_port: z.number().int().min(1, '端口最小为 1').max(MAX_PORT, `端口不能大于 ${MAX_PORT}`).optional(),
    egress_node_id: z.string().trim().optional(),
    lb_group_id: z.string().trim().optional(),
    hop_chain_id: z.string().trim().optional(),
    tls: z.number().int().min(0).max(2),
    transport_mode: z.enum(['fast', 'safe', 'mix']),
    protocols: z.array(z.enum(['tcp', 'udp'])),
    min: z.number().int().min(1).max(MAX_PORT),
    max: z.number().int().min(1).max(MAX_PORT),
    rate: z.number().int().min(0).max(1_000_000),
    log: z.enum(['debug', 'info', 'warn', 'error']),
    preset: z.enum(['none', 'streaming', 'low_latency_gaming', 'secure_transfer', 'ssh_tunnel']),
  })
  .superRefine((value, ctx) => {
    if (value.min > value.max) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['max'],
        message: '最大连接池必须大于等于最小连接池',
      })
    }

    if (!value.protocols.includes('tcp') && !value.protocols.includes('udp')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['protocols'],
        message: 'TCP 和 UDP 不能同时关闭',
      })
    }

    if (value.mode === 'single' || value.mode === 'tunnel') {
      if (!value.target_host?.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['target_host'],
          message: '请输入目标地址',
        })
      }
      if (!value.target_port) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['target_port'],
          message: '请输入目标端口',
        })
      }
    }

    if (value.mode === 'tunnel' && !value.egress_node_id?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['egress_node_id'],
        message: '隧道模式必须选择出口节点',
      })
    }

    if (value.mode === 'lb' && !value.lb_group_id?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['lb_group_id'],
        message: '负载均衡模式必须选择 LB 组',
      })
    }

    if (value.mode === 'hop_chain' && !value.hop_chain_id?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['hop_chain_id'],
        message: '多跳链路模式必须选择链路',
      })
    }
  })

type RuleFormValues = z.infer<typeof formSchema>

const defaultValues: RuleFormValues = {
  name: '',
  mode: 'single',
  ingress_node_id: '',
  ingress_port: 0,
  target_host: '',
  target_port: 443,
  egress_node_id: '',
  lb_group_id: '',
  hop_chain_id: '',
  tls: 1,
  transport_mode: 'fast',
  protocols: ['tcp', 'udp'],
  min: 8,
  max: 1024,
  rate: 0,
  log: 'warn',
  preset: 'none',
}

const PRESET_LABELS: Record<PresetKey, string> = {
  none: '不使用预设',
  streaming: '视频流媒体',
  low_latency_gaming: '低延迟游戏',
  secure_transfer: '安全传输',
  ssh_tunnel: 'SSH 隧道',
}

export default function RuleCreateDrawer({ open, onClose }: RuleCreateDrawerProps) {
  const queryClient = useQueryClient()
  const [modal, contextHolder] = Modal.useModal()

  const {
    control,
    reset,
    handleSubmit,
    setValue,
    formState: { errors, isValid },
  } = useForm<RuleFormValues>({
    resolver: zodResolver(formSchema),
    defaultValues,
    mode: 'onChange',
  })

  const mode = useWatch({ control, name: 'mode' })
  const protocols = useWatch({ control, name: 'protocols' }) ?? defaultValues.protocols
  const values = useWatch({ control }) ?? defaultValues
  const currentMode: RuleFormValues['mode'] = mode ?? 'single'

  const createMutation = useMutation({
    mutationFn: createRule,
    onSuccess: async (createdRule) => {
      await queryClient.invalidateQueries({ queryKey: ['rules'] })
      message.success('规则创建成功')

      onClose()
      reset(defaultValues)

      modal.confirm({
        title: '规则创建完成',
        content: '是否立即启动该规则？',
        okText: '立即启动',
        cancelText: '稍后',
        onOk: async () => {
          await startRule(createdRule.id)
          await queryClient.invalidateQueries({ queryKey: ['rules'] })
          message.success('已发送启动指令')
        },
      })
    },
  })

  const { data: nodes = [] } = useQuery({
    queryKey: ['nodes', 'rule-create'],
    queryFn: () => listNodes({ page: 1, page_size: 200, status: 'online' }),
  })

  const { data: lbGroups = [] } = useQuery({
    queryKey: ['lb-groups', 'selector'],
    queryFn: () => listLBGroups({ page: 1, page_size: 200 }),
    enabled: currentMode === 'lb',
  })

  const { data: hopChains = [] } = useQuery({
    queryKey: ['hop-chains', 'selector'],
    queryFn: () => listHopChains({ page: 1, page_size: 200 }),
    enabled: currentMode === 'hop_chain',
  })

  const ingressNodeOptions = useMemo(() => buildNodeOptions(nodes, ['ingress', 'dual']), [nodes])
  const egressNodeOptions = useMemo(() => buildNodeOptions(nodes, ['egress', 'dual']), [nodes])

  const previewURL = useMemo(() => {
    const previewProtocols = values.protocols ?? defaultValues.protocols
    const previewHost =
      values.target_host?.trim() ||
      (currentMode === 'lb' ? 'lb.dispatch.local' : currentMode === 'hop_chain' ? 'hop.dispatch.local' : '127.0.0.1')

    const previewPort = values.target_port && values.target_port > 0 ? values.target_port : 443
    const noTCP = !previewProtocols.includes('tcp')
    const noUDP = !previewProtocols.includes('udp')

    return buildNodepassURL({
      instanceType: values.mode ?? currentMode,
      host: previewHost,
      port: previewPort,
      tls: values.tls,
      mode: values.transport_mode,
      min: values.min,
      max: values.max,
      rate: values.rate,
      noTCP,
      noUDP,
      log: values.log,
    })
  }, [
    currentMode,
    values.log,
    values.max,
    values.min,
    values.mode,
    values.protocols,
    values.rate,
    values.target_host,
    values.target_port,
    values.tls,
    values.transport_mode,
  ])

  const canSubmit = isValid && (protocols.includes('tcp') || protocols.includes('udp'))

  const handlePresetChange = (preset: PresetKey) => {
    setValue('preset', preset, { shouldValidate: true })
    if (preset === 'none') {
      return
    }

    const presetValue = PRESETS[preset]
    if (!presetValue) {
      return
    }

    if (typeof presetValue.tls === 'number') {
      setValue('tls', presetValue.tls, { shouldValidate: true })
    }
    if (typeof presetValue.mode === 'string') {
      setValue('transport_mode', presetValue.mode as TransportMode, { shouldValidate: true })
    }
    if (typeof presetValue.min === 'number') {
      setValue('min', presetValue.min, { shouldValidate: true })
    }
    if (typeof presetValue.max === 'number') {
      setValue('max', presetValue.max, { shouldValidate: true })
    }
    if (typeof presetValue.rate === 'number') {
      setValue('rate', presetValue.rate, { shouldValidate: true })
    }
    if (typeof presetValue.log === 'string') {
      setValue('log', presetValue.log as LogLevel, { shouldValidate: true })
    }

    const nextProtocols: Protocol[] = []
    if (!presetValue.noTCP) {
      nextProtocols.push('tcp')
    }
    if (!presetValue.noUDP) {
      nextProtocols.push('udp')
    }
    setValue('protocols', nextProtocols, { shouldValidate: true })
  }

  const onSubmit = handleSubmit(async (formValue) => {
    const payload: CreateRulePayload = {
      name: formValue.name.trim(),
      mode: formValue.mode,
      ingress_node_id: formValue.ingress_node_id,
      ingress_port: formValue.ingress_port,
      target_host:
        formValue.mode === 'lb' || formValue.mode === 'hop_chain'
          ? formValue.target_host?.trim() || '127.0.0.1'
          : formValue.target_host?.trim() || '127.0.0.1',
      target_port:
        formValue.mode === 'lb' || formValue.mode === 'hop_chain'
          ? formValue.target_port && formValue.target_port > 0
            ? formValue.target_port
            : 1
          : formValue.target_port || 1,
      egress_node_id: formValue.mode === 'tunnel' ? optionalString(formValue.egress_node_id) : undefined,
      lb_group_id: formValue.mode === 'lb' ? optionalString(formValue.lb_group_id) : undefined,
      hop_chain_id: formValue.mode === 'hop_chain' ? optionalString(formValue.hop_chain_id) : undefined,
      np_tls: formValue.tls,
      np_mode: formValue.transport_mode,
      np_min: formValue.min,
      np_max: formValue.max,
      np_rate: formValue.rate,
      np_notcp: !formValue.protocols.includes('tcp'),
      np_noudp: !formValue.protocols.includes('udp'),
      np_log: formValue.log,
    }

    await createMutation.mutateAsync(payload)
  })

  return (
    <Drawer
      open={open}
      width={640}
      title="创建规则"
      onClose={() => {
        onClose()
        reset(defaultValues)
      }}
      destroyOnClose
      extra={
        <Button onClick={() => void onSubmit()} type="primary" loading={createMutation.isPending} disabled={!canSubmit}>
          创建规则
        </Button>
      }
    >
      {contextHolder}

      <Form layout="vertical" onFinish={onSubmit}>
        {createMutation.error instanceof Error ? (
          <Alert type="error" showIcon style={{ marginBottom: 16 }} message={createMutation.error.message} />
        ) : null}

        <Typography.Title level={5}>基础参数</Typography.Title>

        <Controller
          name="name"
          control={control}
          render={({ field }) => (
            <Form.Item label="规则名称" validateStatus={errors.name ? 'error' : ''} help={errors.name?.message}>
              <Input {...field} placeholder="例如：香港入口-视频线路" />
            </Form.Item>
          )}
        />

        <Controller
          name="mode"
          control={control}
          render={({ field }) => (
            <Form.Item label="规则模式" validateStatus={errors.mode ? 'error' : ''} help={errors.mode?.message}>
              <Segmented
                value={field.value}
                onChange={(value) => field.onChange(value)}
                block
                options={[
                  { label: '单节点', value: 'single' },
                  { label: '隧道', value: 'tunnel' },
                  { label: '负载均衡', value: 'lb' },
                  { label: '多跳链路', value: 'hop_chain' },
                ]}
              />
            </Form.Item>
          )}
        />

        <Space size={12} style={{ width: '100%', display: 'flex' }}>
          <Controller
            name="ingress_node_id"
            control={control}
            render={({ field }) => (
              <Form.Item
                label="入口节点"
                style={{ flex: 1 }}
                validateStatus={errors.ingress_node_id ? 'error' : ''}
                help={errors.ingress_node_id?.message}
              >
                <Select
                  value={field.value || undefined}
                  onChange={(value) => field.onChange(value)}
                  placeholder="请选择在线入口节点"
                  options={ingressNodeOptions}
                />
              </Form.Item>
            )}
          />

          <Controller
            name="ingress_port"
            control={control}
            render={({ field }) => (
              <Form.Item
                label="入口端口"
                style={{ width: 200 }}
                extra="0 表示自动分配"
                validateStatus={errors.ingress_port ? 'error' : ''}
                help={errors.ingress_port?.message}
              >
                <InputNumber
                  value={field.value}
                  min={0}
                  max={MAX_PORT}
                  style={{ width: '100%' }}
                  onChange={(value) => field.onChange(value ?? 0)}
                />
              </Form.Item>
            )}
          />
        </Space>

        {(currentMode === 'single' || currentMode === 'tunnel') && (
          <Space size={12} style={{ width: '100%', display: 'flex' }}>
            <Controller
              name="target_host"
              control={control}
              render={({ field }) => (
                <Form.Item
                  label="目标地址"
                  style={{ flex: 1 }}
                  validateStatus={errors.target_host ? 'error' : ''}
                  help={errors.target_host?.message}
                >
                  <Input {...field} placeholder="目标服务地址，例如 10.0.0.5" />
                </Form.Item>
              )}
            />

            <Controller
              name="target_port"
              control={control}
              render={({ field }) => (
                <Form.Item
                  label="目标端口"
                  style={{ width: 200 }}
                  validateStatus={errors.target_port ? 'error' : ''}
                  help={errors.target_port?.message}
                >
                  <InputNumber
                    value={field.value}
                    min={1}
                    max={MAX_PORT}
                    style={{ width: '100%' }}
                    onChange={(value) => field.onChange(value ?? undefined)}
                  />
                </Form.Item>
              )}
            />
          </Space>
        )}

        {currentMode === 'tunnel' && (
          <Controller
            name="egress_node_id"
            control={control}
            render={({ field }) => (
              <Form.Item
                label="出口节点"
                validateStatus={errors.egress_node_id ? 'error' : ''}
                help={errors.egress_node_id?.message}
              >
                <Select
                  value={field.value || undefined}
                  onChange={(value) => field.onChange(value)}
                  placeholder="请选择出口节点"
                  options={egressNodeOptions}
                />
              </Form.Item>
            )}
          />
        )}

        {currentMode === 'lb' && (
          <Controller
            name="lb_group_id"
            control={control}
            render={({ field }) => (
              <Form.Item
                label={
                  <Space>
                    <span>负载均衡组</span>
                    <Link to="/admin">管理 LB 组</Link>
                  </Space>
                }
                validateStatus={errors.lb_group_id ? 'error' : ''}
                help={errors.lb_group_id?.message}
              >
                <Select
                  value={field.value || undefined}
                  onChange={(value) => field.onChange(value)}
                  placeholder="请选择 LB 组"
                  options={lbGroups.map((group) => ({ value: group.id, label: group.name }))}
                />
              </Form.Item>
            )}
          />
        )}

        {currentMode === 'hop_chain' && (
          <Controller
            name="hop_chain_id"
            control={control}
            render={({ field }) => (
              <Form.Item
                label={
                  <Space>
                    <span>多跳链路</span>
                    <Link to="/admin">管理链路</Link>
                  </Space>
                }
                validateStatus={errors.hop_chain_id ? 'error' : ''}
                help={errors.hop_chain_id?.message}
              >
                <Select
                  value={field.value || undefined}
                  onChange={(value) => field.onChange(value)}
                  placeholder="请选择多跳链路"
                  options={hopChains.map((chain) => ({ value: chain.id, label: chain.name }))}
                />
              </Form.Item>
            )}
          />
        )}

        <Collapse
          style={{ marginBottom: 16 }}
          items={[
            {
              key: 'advanced',
              label: '高级选项',
              children: (
                <>
                  <Controller
                    name="tls"
                    control={control}
                    render={({ field }) => (
                      <Form.Item label="TLS 模式">
                        <Radio.Group
                          value={field.value}
                          onChange={(event) => field.onChange(event.target.value)}
                          options={[
                            { label: '关闭', value: 0 },
                            { label: '自签名', value: 1 },
                            { label: '自定义证书', value: 2 },
                          ]}
                        />
                      </Form.Item>
                    )}
                  />

                  <Controller
                    name="transport_mode"
                    control={control}
                    render={({ field }) => (
                      <Form.Item label="传输模式">
                        <Radio.Group
                          value={field.value}
                          onChange={(event) => field.onChange(event.target.value)}
                          options={[
                            {
                              label: (
                                <Tooltip title="更低开销，适合大吞吐场景">
                                  <span>快速</span>
                                </Tooltip>
                              ),
                              value: 'fast',
                            },
                            {
                              label: (
                                <Tooltip title="更稳健，适合弱网或高丢包场景">
                                  <span>安全</span>
                                </Tooltip>
                              ),
                              value: 'safe',
                            },
                            {
                              label: (
                                <Tooltip title="综合平衡，默认推荐">
                                  <span>混合</span>
                                </Tooltip>
                              ),
                              value: 'mix',
                            },
                          ]}
                        />
                      </Form.Item>
                    )}
                  />

                  <Controller
                    name="protocols"
                    control={control}
                    render={({ field }) => (
                      <Form.Item
                        label="协议支持"
                        validateStatus={errors.protocols ? 'error' : ''}
                        help={errors.protocols?.message}
                      >
                        <Select
                          mode="multiple"
                          value={field.value}
                          onChange={(next) => field.onChange(next as Protocol[])}
                          options={[
                            { label: 'TCP', value: 'tcp' },
                            { label: 'UDP', value: 'udp' },
                          ]}
                          maxTagCount={2}
                        />
                      </Form.Item>
                    )}
                  />
                </>
              ),
            },
          ]}
        />

        <Collapse
          items={[
            {
              key: 'expert',
              label: '专家参数',
              children: (
                <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                  <Alert type="warning" showIcon message="修改前请确认了解参数含义。" />

                  <Controller
                    name="preset"
                    control={control}
                    render={({ field }) => (
                      <Form.Item label="最佳实践预设">
                        <Select
                          value={field.value}
                          onChange={(value) => {
                            field.onChange(value)
                            handlePresetChange(value as PresetKey)
                          }}
                          options={Object.keys(PRESET_LABELS).map((key) => ({
                            value: key,
                            label: PRESET_LABELS[key as PresetKey],
                          }))}
                        />
                      </Form.Item>
                    )}
                  />

                  <Space size={12} style={{ width: '100%', display: 'flex' }}>
                    <Controller
                      name="min"
                      control={control}
                      render={({ field }) => (
                        <Form.Item
                          label="最小连接池"
                          style={{ flex: 1 }}
                          validateStatus={errors.min ? 'error' : ''}
                          help={errors.min?.message}
                        >
                          <InputNumber
                            value={field.value}
                            min={1}
                            max={MAX_PORT}
                            style={{ width: '100%' }}
                            onChange={(value) => field.onChange(value ?? 1)}
                          />
                        </Form.Item>
                      )}
                    />

                    <Controller
                      name="max"
                      control={control}
                      render={({ field }) => (
                        <Form.Item
                          label="最大连接池"
                          style={{ flex: 1 }}
                          validateStatus={errors.max ? 'error' : ''}
                          help={errors.max?.message}
                        >
                          <InputNumber
                            value={field.value}
                            min={1}
                            max={MAX_PORT}
                            style={{ width: '100%' }}
                            onChange={(value) => field.onChange(value ?? 1)}
                          />
                        </Form.Item>
                      )}
                    />
                  </Space>

                  <Space size={12} style={{ width: '100%', display: 'flex' }}>
                    <Controller
                      name="rate"
                      control={control}
                      render={({ field }) => (
                        <Form.Item
                          label="速率限制"
                          style={{ flex: 1 }}
                          extra="0 = 不限制，单位：连接/秒"
                          validateStatus={errors.rate ? 'error' : ''}
                          help={errors.rate?.message}
                        >
                          <InputNumber
                            value={field.value}
                            min={0}
                            max={1_000_000}
                            style={{ width: '100%' }}
                            onChange={(value) => field.onChange(value ?? 0)}
                          />
                        </Form.Item>
                      )}
                    />

                    <Controller
                      name="log"
                      control={control}
                      render={({ field }) => (
                        <Form.Item label="日志级别" style={{ flex: 1 }}>
                          <Select
                            value={field.value}
                            onChange={(value) => field.onChange(value)}
                            options={[
                              { label: 'debug', value: 'debug' },
                              { label: 'info', value: 'info' },
                              { label: 'warn', value: 'warn' },
                              { label: 'error', value: 'error' },
                            ]}
                          />
                        </Form.Item>
                      )}
                    />
                  </Space>

                  <div>
                    <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 8 }}>
                      <Typography.Text strong>NodePass URL 预览</Typography.Text>
                      <Button
                        size="small"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(previewURL)
                            message.success('预览 URL 已复制')
                          } catch {
                            message.error('复制失败，请手动复制')
                          }
                        }}
                      >
                        复制
                      </Button>
                    </Space>
                    <pre
                      style={{
                        margin: 0,
                        padding: 12,
                        borderRadius: 8,
                        background: '#111827',
                        color: '#f3f4f6',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {previewURL}
                    </pre>
                  </div>
                </Space>
              ),
            },
          ]}
        />

        {!protocols.includes('tcp') && !protocols.includes('udp') ? (
          <Alert
            style={{ marginTop: 16 }}
            type="error"
            showIcon
            message="TCP 和 UDP 不能同时关闭，请至少保留一个协议。"
          />
        ) : null}

        <Space style={{ marginTop: 20, width: '100%', justifyContent: 'flex-end' }}>
          <Button
            onClick={() => {
              onClose()
              reset(defaultValues)
            }}
          >
            取消
          </Button>
          <Button type="primary" htmlType="submit" loading={createMutation.isPending} disabled={!canSubmit}>
            创建规则
          </Button>
        </Space>
      </Form>
    </Drawer>
  )
}

function optionalString(value?: string): string | undefined {
  const trimmed = value?.trim()
  return trimmed ? trimmed : undefined
}

function buildNodeOptions(nodes: NodeAgent[], supportedTypes: Array<NodeAgent['type']>) {
  return nodes
    .filter((item) => item.status === 'online' && supportedTypes.includes(item.type))
    .map((item) => ({
      value: item.id,
      label: `${item.name} (${item.host}:${item.api_port})`,
    }))
}
