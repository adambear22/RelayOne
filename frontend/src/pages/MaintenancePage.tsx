import { Result } from 'antd'

export default function MaintenancePage() {
  return (
    <Result
      status="warning"
      title="系统维护中"
      subTitle="平台正在维护，管理员可继续访问，普通用户请稍后重试。"
    />
  )
}
