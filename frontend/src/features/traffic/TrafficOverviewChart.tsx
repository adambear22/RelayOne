import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Empty, Skeleton } from 'antd'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import dayjs from 'dayjs'

import { getTrafficStats } from '../../api/traffic'

export default function TrafficOverviewChart() {
  const { data, isLoading } = useQuery({
    queryKey: ['traffic', 'hour'],
    queryFn: () => getTrafficStats({ granularity: 'hour' }),
  })

  const chartData = useMemo(() => {
    return (data ?? []).map((item) => ({
      time: dayjs(item.time).format('MM-DD HH:mm'),
      bytes: item.bytes_total,
    }))
  }, [data])

  return (
    <Card title="最近流量趋势">
      {isLoading ? (
        <Skeleton active />
      ) : chartData.length === 0 ? (
        <Empty description="暂无流量数据" />
      ) : (
        <div style={{ height: 320 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" minTickGap={24} />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="bytes" stroke="#1677ff" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}
