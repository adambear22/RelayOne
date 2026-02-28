import { Result, Spin } from 'antd'
import { useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'

export default function TelegramCallbackPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  useEffect(() => {
    const redirect = searchParams.get('redirect') || '/dashboard'
    const timer = window.setTimeout(() => {
      navigate(redirect, { replace: true })
    }, 1200)

    return () => {
      window.clearTimeout(timer)
    }
  }, [navigate, searchParams])

  return (
    <Result
      status="success"
      title="Telegram 登录处理中"
      subTitle={
        <span>
          正在完成登录，请稍候...
          <Spin size="small" style={{ marginLeft: 8 }} />
        </span>
      }
    />
  )
}
