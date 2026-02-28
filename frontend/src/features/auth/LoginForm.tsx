import { Alert, Button, Form, Input } from 'antd'
import { Controller, useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'

const loginSchema = z.object({
  username: z.string().min(3, '用户名至少 3 个字符'),
  password: z.string().min(6, '密码至少 6 个字符'),
})

export type LoginFormValues = z.infer<typeof loginSchema>

interface LoginFormProps {
  submitting: boolean
  errorMessage?: string
  onSubmit: (values: LoginFormValues) => Promise<void>
}

export default function LoginForm({ submitting, errorMessage, onSubmit }: LoginFormProps) {
  const {
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  })

  return (
    <Form layout="vertical" onFinish={handleSubmit(onSubmit)}>
      {errorMessage ? <Alert type="error" showIcon message={errorMessage} style={{ marginBottom: 16 }} /> : null}

      <Form.Item label="用户名" validateStatus={errors.username ? 'error' : ''} help={errors.username?.message}>
        <Controller
          name="username"
          control={control}
          render={({ field }) => <Input {...field} autoComplete="username" placeholder="请输入用户名" />}
        />
      </Form.Item>

      <Form.Item label="密码" validateStatus={errors.password ? 'error' : ''} help={errors.password?.message}>
        <Controller
          name="password"
          control={control}
          render={({ field }) => <Input.Password {...field} autoComplete="current-password" placeholder="请输入密码" />}
        />
      </Form.Item>

      <Button type="primary" htmlType="submit" loading={submitting} block>
        登录
      </Button>
    </Form>
  )
}
