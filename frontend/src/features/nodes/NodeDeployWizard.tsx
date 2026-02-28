import { useCallback, useEffect, useMemo, useState } from 'react'
import { useMutation, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, InputNumber, Modal, Progress, Radio, Space, Steps, Timeline, Typography, message } from 'antd'
import { Controller, type FieldErrors, type UseFormReturn, useForm } from 'react-hook-form'

import { createNode, type CreateNodePayload, type CreateNodeResponse } from '../../api/nodes'
import { useSSEDeploy } from '../../hooks/useSSEDeploy'
import { useSSENode } from '../../hooks/useSSENode'
import type { NodeAgent } from '../../types/models'

interface NodeDeployWizardProps {
  open: boolean
  onClose: () => void
}

interface WizardFormValues {
  name: string
  type: 'ingress' | 'egress' | 'dual'
  host: string
  api_port: number
  port_range_min?: number
  port_range_max?: number
  arch: 'amd64' | 'arm64' | 'armv7'
}

const STEP_TITLES = ['节点信息', '安装命令', '部署进度']
const DEPLOY_TIMEOUT_MS = 5 * 60 * 1000
const DEFAULT_HOST = '127.0.0.1'

const defaultFormValues: WizardFormValues = {
  name: '',
  type: 'egress',
  host: '',
  api_port: 8080,
  arch: 'amd64',
}

const timelineStages: Array<{ title: string; desc: string; threshold: number }> = [
  { title: '二进制下载', desc: '下载并准备 Agent 可执行文件', threshold: 40 },
  { title: '服务安装', desc: '写入并加载 systemd 服务', threshold: 70 },
  { title: '服务启动', desc: '启动 Agent 服务并等待上报', threshold: 90 },
  { title: 'Hub 连接', desc: 'Agent 建立 WebSocket 连接', threshold: 100 },
]

export default function NodeDeployWizard({ open, onClose }: NodeDeployWizardProps) {
  const queryClient = useQueryClient()
  const form = useForm<WizardFormValues>({
    defaultValues: defaultFormValues,
    mode: 'onBlur',
  })

  const createNodeMutation = useMutation({
    mutationFn: createNode,
  })

  const [currentStep, setCurrentStep] = useState(0)
  const [createdNode, setCreatedNode] = useState<CreateNodeResponse | null>(null)
  const [installCommand, setInstallCommand] = useState('')

  const handleClose = useCallback(() => {
    setCurrentStep(0)
    setCreatedNode(null)
    setInstallCommand('')
    createNodeMutation.reset()
    form.reset(defaultFormValues)
    onClose()
  }, [createNodeMutation, form, onClose])

  const handleCreateNode = form.handleSubmit(async (values) => {
    if (values.port_range_min && values.port_range_max && values.port_range_min > values.port_range_max) {
      form.setError('port_range_max', { type: 'validate', message: '端口范围结束值不能小于起始值' })
      return
    }

    const payload: CreateNodePayload = {
      name: values.name.trim(),
      type: values.type,
      host: values.host.trim() || DEFAULT_HOST,
      api_port: values.api_port,
      arch: values.arch,
      port_range_min: values.port_range_min,
      port_range_max: values.port_range_max,
      is_self_hosted: true,
      vip_level_req: 0,
      traffic_ratio: 1,
    }

    const node = await createNodeMutation.mutateAsync(payload)
    upsertNodeInCache(queryClient, node)
    setCreatedNode(node)
    setInstallCommand(buildInstallCommand(node))
    setCurrentStep(1)
    message.success('节点创建成功，请在目标服务器执行安装命令')
  })

  return (
    <Modal
      title="添加节点"
      open={open}
      onCancel={handleClose}
      footer={null}
      destroyOnClose
      width={760}
    >
      <Steps
        current={currentStep}
        items={STEP_TITLES.map((title) => ({ title }))}
        style={{ marginBottom: 24 }}
      />

      {currentStep === 0 ? (
        <BasicInfoStep
          form={form}
          submitting={createNodeMutation.isPending}
          serverError={createNodeMutation.error instanceof Error ? createNodeMutation.error.message : undefined}
          onSubmit={handleCreateNode}
        />
      ) : null}

      {currentStep === 1 && createdNode ? (
        <InstallCommandStep
          installCommand={installCommand}
          expiresAt={createdNode.install_script_expires_at}
          onBack={() => setCurrentStep(0)}
          onCopy={async () => {
            try {
              await navigator.clipboard.writeText(installCommand)
              message.success('安装命令已复制到剪贴板')
            } catch {
              message.error('复制失败，请手动复制')
            }
          }}
          onNext={() => setCurrentStep(2)}
        />
      ) : null}

      {currentStep === 2 && createdNode ? (
        <DeployProgressStep
          nodeID={createdNode.id}
          timeoutMs={DEPLOY_TIMEOUT_MS}
          onRetry={() => setCurrentStep(1)}
          onViewNode={handleClose}
        />
      ) : null}
    </Modal>
  )
}

interface BasicInfoStepProps {
  form: UseFormReturn<WizardFormValues>
  submitting: boolean
  serverError?: string
  onSubmit: () => Promise<void>
}

function BasicInfoStep({ form, submitting, serverError, onSubmit }: BasicInfoStepProps) {
  const {
    control,
    formState: { errors },
  } = form

  return (
    <Form layout="vertical" onFinish={onSubmit}>
      {serverError ? <Alert type="error" showIcon style={{ marginBottom: 16 }} message={serverError} /> : null}

      <Controller
        name="name"
        control={control}
        rules={{ required: '请输入节点名称' }}
        render={({ field }) => (
          <Form.Item label="节点名称" validateStatus={fieldErrorStatus(errors, 'name')} help={errors.name?.message}>
            <Input {...field} placeholder="例如：上海-出口-01" maxLength={128} />
          </Form.Item>
        )}
      />

      <Controller
        name="type"
        control={control}
        rules={{ required: '请选择节点类型' }}
        render={({ field }) => (
          <Form.Item label="节点类型" validateStatus={fieldErrorStatus(errors, 'type')} help={errors.type?.message}>
            <Radio.Group
              value={field.value}
              onChange={(event) => {
                field.onChange(event.target.value)
              }}
              optionType="button"
              buttonStyle="solid"
              options={[
                { label: '入口', value: 'ingress' },
                { label: '出口', value: 'egress' },
                { label: '双功能', value: 'dual' },
              ]}
            />
          </Form.Item>
        )}
      />

      <Controller
        name="host"
        control={control}
        render={({ field }) => (
          <Form.Item
            label="服务器地址（可选）"
            extra="用于可达性测试。留空时默认使用 127.0.0.1。"
            validateStatus={fieldErrorStatus(errors, 'host')}
            help={errors.host?.message}
          >
            <Input {...field} placeholder="例如：1.2.3.4 或 node.example.com" maxLength={255} />
          </Form.Item>
        )}
      />

      <Space size={16} style={{ display: 'flex' }}>
        <Controller
          name="api_port"
          control={control}
          rules={{
            required: '请输入 API 端口',
            min: { value: 1, message: '端口最小为 1' },
            max: { value: 65535, message: '端口最大为 65535' },
          }}
          render={({ field }) => (
            <Form.Item
              label="API 端口"
              style={{ flex: 1 }}
              validateStatus={fieldErrorStatus(errors, 'api_port')}
              help={errors.api_port?.message}
            >
              <InputNumber
                value={field.value}
                min={1}
                max={65535}
                style={{ width: '100%' }}
                onChange={(value) => field.onChange(value ?? undefined)}
              />
            </Form.Item>
          )}
        />

        <Controller
          name="arch"
          control={control}
          rules={{ required: '请选择目标架构' }}
          render={({ field }) => (
            <Form.Item
              label="目标架构"
              style={{ flex: 1 }}
              validateStatus={fieldErrorStatus(errors, 'arch')}
              help={errors.arch?.message}
            >
              <Radio.Group
                value={field.value}
                onChange={(event) => {
                  field.onChange(event.target.value)
                }}
                options={[
                  { label: 'amd64', value: 'amd64' },
                  { label: 'arm64', value: 'arm64' },
                  { label: 'armv7', value: 'armv7' },
                ]}
              />
            </Form.Item>
          )}
        />
      </Space>

      <Space size={16} style={{ display: 'flex' }}>
        <Controller
          name="port_range_min"
          control={control}
          rules={{
            min: { value: 1, message: '端口最小为 1' },
            max: { value: 65535, message: '端口最大为 65535' },
          }}
          render={({ field }) => (
            <Form.Item
              label="端口范围起始"
              style={{ flex: 1 }}
              validateStatus={fieldErrorStatus(errors, 'port_range_min')}
              help={errors.port_range_min?.message}
            >
              <InputNumber
                value={field.value}
                min={1}
                max={65535}
                style={{ width: '100%' }}
                placeholder="可选"
                onChange={(value) => field.onChange(value ?? undefined)}
              />
            </Form.Item>
          )}
        />

        <Controller
          name="port_range_max"
          control={control}
          rules={{
            min: { value: 1, message: '端口最小为 1' },
            max: { value: 65535, message: '端口最大为 65535' },
          }}
          render={({ field }) => (
            <Form.Item
              label="端口范围结束"
              style={{ flex: 1 }}
              validateStatus={fieldErrorStatus(errors, 'port_range_max')}
              help={errors.port_range_max?.message}
            >
              <InputNumber
                value={field.value}
                min={1}
                max={65535}
                style={{ width: '100%' }}
                placeholder="可选"
                onChange={(value) => field.onChange(value ?? undefined)}
              />
            </Form.Item>
          )}
        />
      </Space>

      <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
        <Button type="primary" htmlType="submit" loading={submitting}>
          下一步：生成安装命令
        </Button>
      </Space>
    </Form>
  )
}

interface InstallCommandStepProps {
  installCommand: string
  expiresAt?: string
  onBack: () => void
  onCopy: () => Promise<void>
  onNext: () => void
}

function InstallCommandStep({ installCommand, expiresAt, onBack, onCopy, onNext }: InstallCommandStepProps) {
  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Alert
        type="warning"
        showIcon
        message="此命令含一次性 Token，1 小时内有效，请勿分享。"
        description={expiresAt ? `过期时间：${formatDateTime(expiresAt)}` : undefined}
      />

      <Typography.Text type="secondary">在目标服务器执行以下命令：</Typography.Text>
      <pre
        style={{
          margin: 0,
          padding: 16,
          borderRadius: 8,
          background: '#111827',
          color: '#f3f4f6',
          overflowX: 'auto',
        }}
      >
        {installCommand}
      </pre>

      <Space style={{ width: '100%', justifyContent: 'space-between' }}>
        <Button onClick={onBack}>返回修改</Button>
        <Space>
          <Button onClick={onCopy}>复制命令</Button>
          <Button type="primary" onClick={onNext}>
            我已执行，等待连接
          </Button>
        </Space>
      </Space>
    </Space>
  )
}

interface DeployProgressStepProps {
  nodeID: string
  timeoutMs: number
  onRetry: () => void
  onViewNode: () => void
}

function DeployProgressStep({ nodeID, timeoutMs, onRetry, onViewNode }: DeployProgressStepProps) {
  const deploy = useSSEDeploy(nodeID)
  const nodeRuntime = useSSENode(nodeID)
  const [timedOutMarker, setTimedOutMarker] = useState<string | null>(null)
  const marker = `${deploy.step}:${deploy.progress}:${deploy.lastUpdatedAt ?? 0}`
  const timedOut = !deploy.done && !deploy.error && timedOutMarker === marker

  const timeline = useMemo(
    () => buildTimelineItems(deploy.progress, deploy.error, deploy.step),
    [deploy.error, deploy.progress, deploy.step],
  )
  const progressStatus: 'active' | 'exception' | 'success' =
    timedOut || deploy.error ? 'exception' : deploy.done ? 'success' : 'active'

  useEffect(() => {
    if (deploy.done || deploy.error) {
      return
    }

    const currentMarker = marker
    const timer = window.setTimeout(() => {
      setTimedOutMarker(currentMarker)
    }, timeoutMs)

    return () => {
      window.clearTimeout(timer)
    }
  }, [deploy.done, deploy.error, marker, timeoutMs])

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Timeline items={timeline} />
      <Progress percent={deploy.progress} status={progressStatus} />

      {deploy.message ? <Typography.Text type={deploy.error ? 'danger' : 'secondary'}>{deploy.message}</Typography.Text> : null}

      {timedOut ? (
        <Alert
          type="error"
          showIcon
          message="5 分钟内无部署进展，请检查服务器日志后重试。"
          action={
            <Button size="small" onClick={onRetry}>
              重试
            </Button>
          }
        />
      ) : null}

      {deploy.error && !timedOut ? (
        <Alert
          type="error"
          showIcon
          message="部署失败"
          description={deploy.message || '请检查安装日志并重试。'}
          action={
            <Button size="small" onClick={onRetry}>
              重试
            </Button>
          }
        />
      ) : null}

      {deploy.done ? (
        <Alert
          type="success"
          showIcon
          message="部署成功！"
          description={`节点状态：${renderNodeStatusLabel(nodeRuntime.status, nodeRuntime.deployStatus)}`}
          action={
            <Button type="primary" size="small" onClick={onViewNode}>
              查看节点详情
            </Button>
          }
        />
      ) : null}
    </Space>
  )
}

function fieldErrorStatus(errors: FieldErrors<WizardFormValues>, field: keyof WizardFormValues): '' | 'error' {
  return errors[field] ? 'error' : ''
}

function buildInstallCommand(node: CreateNodeResponse): string {
  const installURL = resolveInstallURL(node)
  return `curl -fsSL "${installURL}" | bash`
}

function resolveInstallURL(node: CreateNodeResponse): string {
  if (node.install_url && node.install_url.trim()) {
    return node.install_url.trim()
  }

  const base = `${window.location.origin}/api/v1/nodes/${encodeURIComponent(node.id)}/install.sh`
  if (!node.token) {
    return base
  }

  return `${base}?installToken=${encodeURIComponent(node.token)}`
}

function upsertNodeInCache(queryClient: QueryClient, node: NodeAgent) {
  queryClient.setQueryData<NodeAgent[] | undefined>(['nodes'], (current) => {
    if (!current || current.length === 0) {
      return [node]
    }

    const index = current.findIndex((item) => item.id === node.id)
    if (index < 0) {
      return [node, ...current]
    }

    const next = current.slice()
    next[index] = { ...next[index], ...node }
    return next
  })
}

function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

function buildTimelineItems(progress: number, hasError: boolean, currentStep: string) {
  const activeIndex = timelineStages.findIndex((stage) => progress < stage.threshold)
  const processIndex = activeIndex === -1 ? timelineStages.length - 1 : activeIndex
  const errorIndex = inferErrorIndex(currentStep, processIndex)

  return timelineStages.map((stage, index) => {
    const status = (() => {
      if (hasError) {
        if (index < errorIndex) {
          return { color: 'green', text: '已完成' }
        }
        if (index === errorIndex) {
          return { color: 'red', text: '失败' }
        }
        return { color: 'gray', text: '等待中' }
      }

      if (progress >= stage.threshold) {
        return { color: 'green', text: '已完成' }
      }
      if (index === processIndex) {
        return { color: 'blue', text: '进行中' }
      }
      return { color: 'gray', text: '等待中' }
    })()

    return {
      color: status.color,
      children: (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{stage.title}</Typography.Text>
          <Typography.Text type="secondary">{stage.desc}</Typography.Text>
          <Typography.Text type="secondary">{status.text}</Typography.Text>
        </Space>
      ),
    }
  })
}

function inferErrorIndex(step: string, fallback: number): number {
  const normalized = step.trim().toLowerCase()
  if (normalized === 'download_binary' || normalized === 'binary_ready' || normalized === 'prepare') {
    return 0
  }
  if (normalized === 'write_service' || normalized === 'service_written') {
    return 1
  }
  if (normalized === 'start_service' || normalized === 'wait_connected') {
    return 2
  }
  if (normalized === 'connected') {
    return 3
  }
  return fallback
}

function renderNodeStatusLabel(status: NodeAgent['status'], deployStatus: NodeAgent['deploy_status']): string {
  if (status === 'online') {
    return '在线'
  }
  if (deployStatus === 'pending' || deployStatus === 'installing' || status === 'pending') {
    return '待部署'
  }
  if (deployStatus === 'failed') {
    return '部署失败'
  }
  return '离线'
}
