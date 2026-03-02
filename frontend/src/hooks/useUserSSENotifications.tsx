import { useEffect, useRef, type MutableRefObject } from 'react'
import { Button, notification } from 'antd'
import { useNavigate, type NavigateFunction } from 'react-router-dom'

import { fetchCurrentUser } from '../api/auth'
import { useAuthStore } from '../stores/auth'
import { useNotificationStore, type NotificationKind } from '../stores/notifications'
import { useSSEStore, type SSEPayload } from '../stores/sse'
import type { User } from '../types/models'

const OVER_LIMIT_NOTIFICATION_KEY = 'user-traffic-over-limit'

export function useUserSSENotifications() {
  const navigate = useNavigate()
  const user = useAuthStore((state) => state.user)
  const setUser = useAuthStore((state) => state.setUser)
  const on = useSSEStore((state) => state.on)
  const addNotification = useNotificationStore((state) => state.addNotification)
  const refreshingRef = useRef(false)

  useEffect(() => {
    if (!user?.id || user.role !== 'user') {
      return undefined
    }

    const userID = user.id

    const unbindTrafficUpdate = on('traffic.update', (payload) => {
      void handleTrafficUpdate(payload, userID, navigate, setUser, addNotification, refreshingRef)
    })

    const unbindQuotaExceeded = on('traffic.quota_exceeded', (payload) => {
      void handleQuotaExceeded(payload, userID, navigate, setUser, addNotification, refreshingRef)
    })

    const unbindRuleStatus = on('rule.status', (payload) => {
      handleRuleStatus(payload, userID, addNotification)
    })

    const unbindRuleStatusChanged = on('rule.status_changed', (payload) => {
      handleRuleStatus(payload, userID, addNotification)
    })

    const unbindVIPChanged = on('user.vip_changed', (payload) => {
      handleVIPChanged(payload, userID, addNotification)
    })

    const unbindAnnouncement = on('announcement', (payload) => {
      handleAnnouncement(payload, addNotification)
    })

    const unbindAnnouncementCreated = on('announcement.created', (payload) => {
      handleAnnouncement(payload, addNotification)
    })

    return () => {
      unbindTrafficUpdate()
      unbindQuotaExceeded()
      unbindRuleStatus()
      unbindRuleStatusChanged()
      unbindVIPChanged()
      unbindAnnouncement()
      unbindAnnouncementCreated()
      notification.destroy(OVER_LIMIT_NOTIFICATION_KEY)
    }
  }, [addNotification, navigate, on, setUser, user?.id, user?.role])
}

async function handleTrafficUpdate(
  payload: SSEPayload,
  currentUserID: string,
  navigate: NavigateFunction,
  setUser: (user: User | null) => void,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
  refreshingRef: MutableRefObject<boolean>,
) {
  const data = asObject(payload.data)
  if (!data) {
    return
  }

  const eventUserID = asString(data.user_id) ?? currentUserID
  if (eventUserID !== currentUserID) {
    return
  }

  const status = asString(data.status)
  if (status === 'redeemed') {
    const level = asNumber(data.vip_level)
    const title = typeof level === 'number' ? `🎉 恭喜！已升级至 VIP Lv.${level}` : '权益码兑换成功'
    const content = typeof level === 'number' ? `VIP 等级已更新为 Lv.${level}` : '权益已生效，可前往 VIP 中心查看详情。'
    notification.success({ message: title, description: content, placement: 'topRight' })
    addCenterNotification(addNotification, payload, 'success', title, content, extractTimestamp(data))
  }

  if (status === 'vip_expired') {
    const title = 'VIP 已到期'
    const content = '你的 VIP 权益已到期，部分规则可能已暂停。'
    notification.warning({ message: title, description: content, placement: 'topRight' })
    addCenterNotification(addNotification, payload, 'warning', title, content, extractTimestamp(data))
  }

  if (status === 'quota_exceeded') {
    openOverLimitToast(navigate)
    addCenterNotification(addNotification, payload, 'error', '流量超限', '所有规则已暂停，请尽快升级 VIP。', extractTimestamp(data))
  }

  if (status === 'redeemed' || status === 'vip_expired' || status === 'quota_exceeded') {
    await refreshCurrentUser(setUser, refreshingRef, navigate, addNotification)
  }
}

async function handleQuotaExceeded(
  payload: SSEPayload,
  currentUserID: string,
  navigate: NavigateFunction,
  setUser: (user: User | null) => void,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
  refreshingRef: MutableRefObject<boolean>,
) {
  const data = asObject(payload.data)
  if (!data) {
    return
  }

  const userID = asString(data.user_id)
  if (userID && userID !== currentUserID) {
    return
  }

  openOverLimitToast(navigate)
  addCenterNotification(
    addNotification,
    payload,
    'error',
    '流量已超限！所有规则已暂停。',
    '点击升级 VIP 可恢复规则运行。',
    extractTimestamp(data),
  )
  await refreshCurrentUser(setUser, refreshingRef, navigate, addNotification)
}

function handleRuleStatus(
  payload: SSEPayload,
  currentUserID: string,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
) {
  const data = asObject(payload.data)
  if (!data) {
    return
  }

  const ownerID = asString(data.owner_id) ?? asString(data.user_id)
  if (ownerID && ownerID !== currentUserID) {
    return
  }

  const status = asString(data.status)
  const ruleID = asString(data.rule_id) ?? '未知规则'
  const timestamp = extractTimestamp(data)

  if (status === 'paused') {
    const title = '规则已被系统暂停'
    const content = `规则 ${ruleID} 当前状态为 paused，请检查流量配额或手动重启。`
    notification.warning({
      key: `rule-paused-${ruleID}`,
      message: title,
      description: content,
      placement: 'topRight',
    })
    addCenterNotification(addNotification, payload, 'warning', title, content, timestamp)
  }

  if (status === 'failed' || status === 'sync_failed') {
    const title = '规则同步失败'
    const content = `规则 ${ruleID} 状态异常，请检查节点连通性与实例配置。`
    notification.error({
      key: `rule-failed-${ruleID}`,
      message: title,
      description: content,
      placement: 'topRight',
    })
    addCenterNotification(addNotification, payload, 'error', title, content, timestamp)
  }
}

function handleVIPChanged(
  payload: SSEPayload,
  currentUserID: string,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
) {
  const data = asObject(payload.data)
  if (!data) {
    return
  }

  const userID = asString(data.user_id)
  if (userID && userID !== currentUserID) {
    return
  }

  const level = asNumber(data.level) ?? asNumber(data.vip_level)
  if (typeof level !== 'number') {
    return
  }

  const title = `🎉 恭喜！已升级至 VIP Lv.${level}`
  const content = '新权益已生效，可前往 VIP 中心查看。'
  notification.success({ message: title, description: content, placement: 'topRight', duration: 8 })
  addCenterNotification(addNotification, payload, 'success', title, content, extractTimestamp(data))
}

function handleAnnouncement(
  payload: SSEPayload,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
) {
  const data = asObject(payload.data)
  if (!data) {
    return
  }

  const action = asString(data.action)
  const title = asString(data.title)
  const timestamp = extractTimestamp(data)

  if (title && (!action || action === 'create' || action === 'update')) {
    const messageTitle = `📢 新公告：${title}`
    notification.info({
      key: payload.id ? `announcement-${payload.id}` : undefined,
      message: messageTitle,
      placement: 'topRight',
    })
    addCenterNotification(addNotification, payload, 'info', messageTitle, asString(data.content), timestamp)
    return
  }

  if (action === 'delete') {
    const messageTitle = '公告已更新'
    const messageContent = '一条公告已下线。'
    notification.info({ message: messageTitle, description: messageContent, placement: 'topRight' })
    addCenterNotification(addNotification, payload, 'info', messageTitle, messageContent, timestamp)
  }
}

function openOverLimitToast(navigate: NavigateFunction) {
  notification.error({
    key: OVER_LIMIT_NOTIFICATION_KEY,
    duration: 0,
    message: '流量已超限！所有规则已暂停。',
    description: (
      <Button
        type="link"
        onClick={() => {
          notification.destroy(OVER_LIMIT_NOTIFICATION_KEY)
          navigate('/vip')
        }}
        style={{ paddingLeft: 0 }}
      >
        升级 VIP
      </Button>
    ),
    placement: 'topRight',
  })
}

async function refreshCurrentUser(
  setUser: (user: User | null) => void,
  refreshingRef: MutableRefObject<boolean>,
  navigate: NavigateFunction,
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
) {
  if (refreshingRef.current) {
    return
  }
  refreshingRef.current = true

  try {
    const latest = await fetchCurrentUser()
    setUser(latest)
    if (latest.status === 'over_limit') {
      openOverLimitToast(navigate)
      addNotification({
        id: 'quota-over-limit-latest',
        kind: 'error',
        title: '账户处于超限状态',
        content: '已自动暂停规则，请前往 VIP 页面升级。',
        created_at: new Date().toISOString(),
      })
    } else {
      notification.destroy(OVER_LIMIT_NOTIFICATION_KEY)
    }
  } catch {
    return
  } finally {
    refreshingRef.current = false
  }
}

function addCenterNotification(
  addNotification: ReturnType<typeof useNotificationStore.getState>['addNotification'],
  payload: SSEPayload,
  kind: NotificationKind,
  title: string,
  content?: string,
  createdAt?: string,
) {
  addNotification({
    id: payload.id ? `sse-${payload.id}` : undefined,
    kind,
    title,
    content,
    created_at: createdAt ?? new Date().toISOString(),
  })
}

function extractTimestamp(data: Record<string, unknown>): string | undefined {
  return asString(data.ts) ?? asString(data.timestamp) ?? asString(data.created_at) ?? asString(data.published_at)
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') {
    return null
  }
  return value as Record<string, unknown>
}

function asString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined
  }
  const normalized = value.trim()
  return normalized || undefined
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value
  }
  if (typeof value === 'string') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) {
      return parsed
    }
  }
  return undefined
}
