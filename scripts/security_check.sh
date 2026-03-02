#!/usr/bin/env bash
# shellcheck shell=bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wizard_ui.sh"

PASS=0
WARN=0
FAIL=0

DEPLOY_DIR="${DEPLOY_DIR:-/opt/nodepass}"
ENV_FILE="${DEPLOY_DIR}/.env"
DEPLOY_CONF_FILE="${DEPLOY_DIR}/deploy.conf"
CHECK_DOMAIN="${DOMAIN:-}"
HUB_CONTAINER=""
POSTGRES_CONTAINER=""

run_cmd() {
  eval "$1" >/dev/null 2>&1
}

check() {
  local name="$1"
  local cmd="$2"
  local fix_hint="$3"

  if run_cmd "${cmd}"; then
    success "${name}"
    PASS=$((PASS + 1))
  else
    error "${name}"
    hint "修复建议：${fix_hint}"
    FAIL=$((FAIL + 1))
  fi
}

warn_check() {
  local name="$1"
  local cmd="$2"
  local hint_msg="$3"

  if run_cmd "${cmd}"; then
    success "${name}"
    PASS=$((PASS + 1))
  else
    warn "${name}"
    hint "建议：${hint_msg}"
    WARN=$((WARN + 1))
  fi
}

file_mode() {
  local path="$1"

  if [[ ! -e "${path}" ]]; then
    return 1
  fi

  if stat -c %a "${path}" >/dev/null 2>&1; then
    stat -c %a "${path}"
    return 0
  fi

  if stat -f %Lp "${path}" >/dev/null 2>&1; then
    stat -f %Lp "${path}"
    return 0
  fi

  return 1
}

detect_domain() {
  if [[ -n "${CHECK_DOMAIN}" ]]; then
    return
  fi

  if [[ -f "${ENV_FILE}" ]]; then
    CHECK_DOMAIN="$(grep -E '^DOMAIN=' "${ENV_FILE}" | head -1 | cut -d '=' -f2- | tr -d '[:space:]' || true)"
  fi

  if [[ -z "${CHECK_DOMAIN}" ]]; then
    CHECK_DOMAIN="localhost"
    warn "未检测到 DOMAIN，使用 localhost 进行检查"
  fi
}

detect_containers() {
  if ! command -v docker >/dev/null 2>&1; then
    return
  fi

  HUB_CONTAINER="$(docker ps --format '{{.Names}}' | grep -m1 -E 'nodepass.*hub' || true)"
  POSTGRES_CONTAINER="$(docker ps --format '{{.Names}}' | grep -m1 -E 'nodepass.*postgres' || true)"

  if [[ -n "${HUB_CONTAINER}" ]]; then
    info "Hub 容器：${HUB_CONTAINER}"
  fi
  if [[ -n "${POSTGRES_CONTAINER}" ]]; then
    info "PostgreSQL 容器：${POSTGRES_CONTAINER}"
  fi
}

show_banner
section "NodePass 生产安全检查"

if [[ "${EUID}" -ne 0 ]]; then
  warn "当前非 root，部分检查可能受限（建议 sudo 执行）"
fi

detect_domain
detect_containers
info "检查域名：${CHECK_DOMAIN}"

section "系统安全"

warn_check "系统包索引最近 30 天更新过" \
  "[[ ! -f /var/lib/apt/periodic/update-success-stamp ]] || find /var/lib/apt/periodic/update-success-stamp -mtime -30 | grep -q ." \
  "apt update && apt upgrade -y"

check "防火墙已启用" \
  "ufw status 2>/dev/null | grep -qi '^Status: active' || systemctl is-active firewalld >/dev/null || (command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)')" \
  "启用 ufw/firewalld，并仅放行 22/80/443"

check "SSH root 登录已禁用" \
  "grep -REq '^[[:space:]]*PermitRootLogin[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" \
  "设置 PermitRootLogin no 并重载 sshd"

warn_check "SSH 密码认证已禁用（仅密钥登录）" \
  "grep -REq '^[[:space:]]*PasswordAuthentication[[:space:]]+no([[:space:]]|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null" \
  "配置 PasswordAuthentication no"

check "fail2ban 已安装并运行" \
  "systemctl is-active fail2ban >/dev/null" \
  "安装并启用 fail2ban：apt install -y fail2ban && systemctl enable --now fail2ban"

check "时间同步服务已运行" \
  "systemctl is-active systemd-timesyncd >/dev/null || systemctl is-active chronyd >/dev/null || systemctl is-active ntpd >/dev/null" \
  "启用 systemd-timesyncd 或 chronyd"

section "Docker 安全"

check "Docker 服务可用" \
  "docker info >/dev/null 2>&1" \
  "安装并启动 Docker 服务"

check "Hub 容器非 root 用户运行" \
  "[[ -n '${HUB_CONTAINER}' ]] && [[ -n \"\$(docker inspect '${HUB_CONTAINER}' --format='{{.Config.User}}' 2>/dev/null)\" ]]" \
  "在镜像中使用 USER nonroot，并重新部署 hub"

check "PostgreSQL 端口未暴露到公网" \
  "( [[ -n '${POSTGRES_CONTAINER}' ]] && ! docker port '${POSTGRES_CONTAINER}' 5432/tcp 2>/dev/null | grep -qE '0\\.0\\.0\\.0:|:::' ) || ( [[ -f '${DEPLOY_DIR}/docker-compose.yml' ]] && ! grep -Eq '^[[:space:]]*-[[:space:]]*\"?5432:5432' '${DEPLOY_DIR}/docker-compose.yml' )" \
  "移除 postgres 的 ports 暴露，保持仅内网访问"

check "Docker socket 未挂载到 Hub 容器" \
  "( [[ -n '${HUB_CONTAINER}' ]] && ! docker inspect '${HUB_CONTAINER}' --format='{{json .Mounts}}' 2>/dev/null | grep -q docker.sock ) || ( [[ -f '${DEPLOY_DIR}/docker-compose.yml' ]] && ! grep -q docker.sock '${DEPLOY_DIR}/docker-compose.yml' )" \
  "移除 docker.sock 挂载"

warn_check "Docker 内容信任已启用" \
  "[[ '${DOCKER_CONTENT_TRUST:-0}' == '1' ]]" \
  "export DOCKER_CONTENT_TRUST=1"

section "应用安全"

check "HTTPS 正常访问" \
  "curl -kfsS --max-time 10 'https://${CHECK_DOMAIN}/api/v1/health' >/dev/null" \
  "检查 Caddy/Nginx 配置和 TLS 证书"

check "HTTP 跳转到 HTTPS" \
  "[[ \"\$(curl -sS -o /dev/null -w '%{redirect_url}' 'http://${CHECK_DOMAIN}')\" == https://* ]]" \
  "在反向代理中添加 HTTP -> HTTPS 跳转"

check "HSTS 头已设置" \
  "curl -kIs 'https://${CHECK_DOMAIN}' | grep -qi '^strict-transport-security:'" \
  "在反向代理配置中添加 Strict-Transport-Security"

check "X-Frame-Options 头已设置" \
  "curl -kIs 'https://${CHECK_DOMAIN}' | grep -qi '^x-frame-options:'" \
  "在反向代理配置中添加 X-Frame-Options DENY"

check ".env 文件权限为 600" \
  "[[ \"\$(file_mode '${ENV_FILE}' 2>/dev/null)\" == '600' ]]" \
  "chmod 600 '${ENV_FILE}'"

check "deploy.conf 文件权限为 600" \
  "[[ \"\$(file_mode '${DEPLOY_CONF_FILE}' 2>/dev/null)\" == '600' ]]" \
  "chmod 600 '${DEPLOY_CONF_FILE}'"

check "internal_token 文件权限为 600" \
  "[[ \"\$(file_mode '${DEPLOY_DIR}/secrets/internal_token.txt' 2>/dev/null)\" == '600' ]]" \
  "chmod 600 '${DEPLOY_DIR}/secrets/internal_token.txt'"

warn_check "secrets 目录权限为 700" \
  "[[ \"\$(file_mode '${DEPLOY_DIR}/secrets' 2>/dev/null)\" == '700' ]]" \
  "chmod 700 '${DEPLOY_DIR}/secrets'"

divider

echo -e "\n${BOLD}检查结果：${NC}"
echo -e "  ${LGREEN}✓ 通过：${PASS}${NC}"
echo -e "  ${YELLOW}⚠ 警告：${WARN}${NC}"
echo -e "  ${LRED}✗ 失败：${FAIL}${NC}"

if [[ ${FAIL} -gt 0 ]]; then
  warn "存在 ${FAIL} 个安全问题，建议修复后再上线"
  exit 1
fi

success "安全检查通过"
