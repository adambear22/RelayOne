import { Card, Col, Row, Typography } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useEffect, useMemo } from 'react'

import LoginForm from '../features/auth/LoginForm'
import { useAuth } from '../hooks/useAuth'

export default function LoginPage() {
  const navigate = useNavigate()
  const { loginMutation, isAuthenticated } = useAuth()

  const errorMessage = useMemo(() => {
    if (!loginMutation.error) {
      return undefined
    }
    return loginMutation.error.message
  }, [loginMutation.error])

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate])

  return (
    <Row justify="center" align="middle" style={{ minHeight: '100vh', padding: 24 }}>
      <Col xs={24} sm={18} md={12} lg={8}>
        <Card>
          <Typography.Title level={3} style={{ textAlign: 'center' }}>
            NodePass Hub 登录
          </Typography.Title>
          <LoginForm
            submitting={loginMutation.isPending}
            errorMessage={errorMessage}
            onSubmit={async (values) => {
              await loginMutation.mutateAsync(values)
              navigate('/dashboard', { replace: true })
            }}
          />
        </Card>
      </Col>
    </Row>
  )
}
