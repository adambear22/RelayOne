import PageCard from '../components/PageCard'
import Dashboard from './Dashboard'

export default function DashboardPage() {
  return (
    <PageCard title="仪表盘" subtitle="聚合流量、VIP、规则与公告信息">
      <Dashboard />
    </PageCard>
  )
}
