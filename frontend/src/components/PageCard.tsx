import { Card, Typography } from 'antd'
import type { PropsWithChildren } from 'react'

interface PageCardProps {
  title: string
  subtitle?: string
}

export default function PageCard({ title, subtitle, children }: PropsWithChildren<PageCardProps>) {
  return (
    <Card title={title}>
      {subtitle ? <Typography.Paragraph type="secondary">{subtitle}</Typography.Paragraph> : null}
      {children}
    </Card>
  )
}
