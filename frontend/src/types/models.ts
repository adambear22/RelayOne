export type UserRole = 'admin' | 'user'
export type UserStatus = 'normal' | 'suspended' | 'banned' | 'over_limit'

export interface User {
  id: string
  username: string
  email?: string
  role: UserRole
  status: UserStatus
  telegram_id?: number
  telegram_username?: string
  vip_level: number
  vip_expires_at?: string
  traffic_quota: number
  traffic_used: number
  bandwidth_limit: number
  max_rules: number
  permissions?: string[]
  created_at: string
  updated_at: string
}

export interface NodeAgent {
  id: string
  name: string
  type: 'ingress' | 'egress' | 'dual'
  owner_id?: string
  is_self_hosted: boolean
  host: string
  api_port: number
  status: 'pending' | 'online' | 'offline'
  deploy_status: 'pending' | 'installing' | 'success' | 'failed'
  deploy_error?: string
  vip_level_req: number
  traffic_ratio: number
  port_range_min?: number
  port_range_max?: number
  arch: string
  agent_version?: string
  sys_info?: Record<string, unknown>
  last_seen_at?: string
  install_script_expires_at?: string
  created_at: string
}

export interface NodeDeployLog {
  id: number
  node_id: string
  step: string
  progress: number
  message?: string
  created_at: string
}

export interface NodeTCPTestResult {
  reachable: boolean
  latency: number
  error?: string
}

export interface ForwardingRule {
  id: string
  name: string
  owner_id: string
  mode: 'single' | 'tunnel' | 'lb' | 'hop_chain'
  ingress_node_id: string
  ingress_port: number
  egress_node_id?: string
  lb_group_id?: string
  hop_chain_id?: string
  target_host: string
  target_port: number
  status: 'stopped' | 'running' | 'paused'
  sync_status: 'pending_sync' | 'synced' | 'sync_failed'
  instance_info?: Record<string, unknown>
  np_params?: {
    np_tls?: number
    np_mode?: string
    np_min?: number
    np_max?: number
    np_rate?: number
    np_notcp?: boolean
    np_noudp?: boolean
    np_log?: string
  }
  created_at: string
  updated_at: string
}

export interface LBGroup {
  id: string
  name: string
  owner_id?: string
  strategy: string
  health_check_interval: number
  created_at: string
}

export interface LBGroupMember {
  id: string
  group_id: string
  node_id: string
  weight: number
  is_active: boolean
  created_at: string
}

export interface HopChain {
  id: string
  name: string
  owner_id?: string
  description?: string
  created_at: string
}

export interface HopChainNode {
  id: string
  chain_id: string
  hop_order: number
  node_id: string
  np_params_override?: Record<string, unknown>
}

export interface TrafficStat {
  time: string
  bytes_in: number
  bytes_out: number
  bytes_total: number
}

export interface DailyTrafficStat {
  day: string
  bytes_total: number
}

export interface MonthlyTrafficStat {
  month: string
  bytes_total: number
}

export interface RuleTrafficPoint {
  hour: string
  bytes_total: number
}

export interface TrafficOverview {
  today_total: number
  month_total: number
  top10_users: Array<{
    user_id: string
    username: string
    traffic_used: number
    traffic_quota: number
  }>
  top10_rules: Array<{
    rule_id: string
    rule_name: string
    owner_id: string
    bytes_total: number
  }>
}

export interface VIPLevel {
  level: number
  name: string
  traffic_quota: number
  max_rules: number
  bandwidth_limit: number
  max_ingress_nodes: number
  max_egress_nodes: number
  accessible_node_level: number
  traffic_ratio: number
  custom_features?: Record<string, unknown>
  created_at?: string
}

export interface UserVIPEntitlement {
  user_id: string
  vip_level: number
  vip_expires_at?: string
  traffic_quota: number
  max_rules: number
  bandwidth_limit: number
  level_info?: VIPLevel
}

export interface BenefitCode {
  id: string
  code: string
  vip_level: number
  duration_days: number
  expires_at?: string
  valid_days: number
  is_used: boolean
  is_enabled: boolean
  used_by?: string
  used_at?: string
  created_by: string
  created_at: string
}

export interface Announcement {
  id: string
  type: string
  title: string
  content: string
  is_enabled: boolean
  starts_at?: string
  ends_at?: string
  created_by: string
  created_at: string
}

export interface AuditLog {
  id: number
  user_id?: string
  action: string
  resource_type?: string
  resource_id?: string
  old_value?: Record<string, unknown>
  new_value?: Record<string, unknown>
  ip_address?: string
  user_agent?: string
  created_at: string
}

export interface TelegramConfig {
  bot_token?: string
  bot_username?: string
  webhook_url?: string
  webhook_secret?: string
  frontend_url?: string
  sso_base_url?: string
  default_chat_id?: number
  enabled?: boolean
}

export interface ExternalAPIKey {
  name: string
  key?: string
  scopes?: string[]
}

export interface SystemConfig {
  id: number
  site_name?: string
  support_email?: string
  maintenance_mode: boolean
  registration_enabled: boolean
  default_traffic_quota: number
  default_max_rules: number
  telegram_config: TelegramConfig
  external_api_keys?: ExternalAPIKey[]
  updated_at: string
}

export interface SystemLogEntry {
  id: number
  timestamp: string
  level: string
  logger_name?: string
  message: string
  caller?: string
  stack?: string
  fields?: Record<string, unknown>
}
