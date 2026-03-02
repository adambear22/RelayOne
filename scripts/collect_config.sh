#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wizard_ui.sh"

TOTAL_STEPS=6
CONF_FILE="deploy.conf"
EXPLICIT_CONFIG=0

usage() {
  cat <<'EOF'
Usage:
  bash collect_config.sh [deploy.conf]
  bash collect_config.sh --config deploy.conf

Options:
  --config <file>   Config file path. If file exists, reuse it and skip prompts.
  -h, --help        Show this help.
EOF
}

validate_admin_password() {
  [[ "$1" =~ ^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{12,}$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
        error "--config 需要文件路径"
        exit 1
      fi
      CONF_FILE="${2:-}"
      EXPLICIT_CONFIG=1
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ "${CONF_FILE}" != "deploy.conf" || "${EXPLICIT_CONFIG}" -eq 1 ]]; then
        error "未知参数: $1"
        usage
        exit 1
      fi
      CONF_FILE="$1"
      shift
      ;;
  esac
done

if [[ -z "${CONF_FILE}" ]]; then
  error "--config 需要文件路径"
  exit 1
fi

if [[ "${EXPLICIT_CONFIG}" -eq 1 && -f "${CONF_FILE}" ]]; then
  success "检测到已存在配置文件: ${CONF_FILE}，跳过交互采集"
  exit 0
fi

if [[ -f "${CONF_FILE}" ]]; then
  warn "发现已有配置文件 ${CONF_FILE}，将基于已有值继续（回车保留现有值）"
  # shellcheck source=/dev/null
  source "${CONF_FILE}"
fi

show_banner

step 1 "域名和基础配置"
while true; do
  ask_input "请输入部署域名（如 nodepass.example.com）" "${DOMAIN:-}" DOMAIN
  if validate_domain "${DOMAIN}"; then
    break
  fi
  error "域名格式无效，请重新输入"
done

ask_input "站点名称" "${SITE_NAME:-NodePass}" SITE_NAME
while true; do
  ask_input "管理员邮箱（可为空）" "${ADMIN_EMAIL:-}" ADMIN_EMAIL
  if [[ -z "${ADMIN_EMAIL}" ]] || validate_email "${ADMIN_EMAIL}"; then
    break
  fi
  error "邮箱格式无效，请重新输入"
done

step 2 "TLS 证书配置"
echo "TLS 获取方式："
echo "  1) Let's Encrypt 自动申请（生产推荐）"
echo "  2) 已有证书文件（手动配置路径）"
echo "  3) 跳过 TLS（仅用于内网测试）"
while true; do
  ask_input "请选择 [1/2/3]" "${TLS_MODE:-1}" TLS_MODE
  if [[ "${TLS_MODE}" =~ ^[123]$ ]]; then
    break
  fi
  error "请输入 1 / 2 / 3"
done

ACME_EMAIL="${ACME_EMAIL:-}"
TLS_CERT_PATH="${TLS_CERT_PATH:-}"
TLS_KEY_PATH="${TLS_KEY_PATH:-}"
if [[ "${TLS_MODE}" == "1" ]]; then
  ask_input "证书申请邮箱" "${ACME_EMAIL:-${ADMIN_EMAIL:-}}" ACME_EMAIL
elif [[ "${TLS_MODE}" == "2" ]]; then
  ask_input "证书文件路径（.crt/.pem）" "${TLS_CERT_PATH:-}" TLS_CERT_PATH
  ask_input "私钥文件路径（.key/.pem）" "${TLS_KEY_PATH:-}" TLS_KEY_PATH
fi

step 3 "数据库配置"
if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
  POSTGRES_PASSWORD="$(gen_secret 32)"
  info "已自动生成数据库密码"
fi
ask_input "数据库名称" "${POSTGRES_DB:-nodepass}" POSTGRES_DB
ask_input "数据库用户名" "${POSTGRES_USER:-nodepass}" POSTGRES_USER
ask_password "数据库密码（回车保留已生成值）" POSTGRES_PASSWORD_INPUT
if [[ -n "${POSTGRES_PASSWORD_INPUT}" ]]; then
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD_INPUT}"
fi

step 4 "管理员账户"
ask_input "管理员用户名" "${ADMIN_USERNAME:-admin}" ADMIN_USERNAME
while true; do
  ask_password "管理员密码（至少 12 位，含大小写字母和数字）" ADMIN_PASSWORD
  if validate_admin_password "${ADMIN_PASSWORD}"; then
    break
  fi
  error "密码强度不足，请使用至少 12 位并包含大小写字母和数字"
done

step 5 "JWT 与系统密钥"
if [[ -z "${JWT_PRIVATE_KEY_B64:-}" || -z "${JWT_PUBLIC_KEY_B64:-}" ]]; then
  info "正在生成 RS256 密钥对..."
  tmp_private="$(mktemp)"
  tmp_public="$(mktemp)"
  openssl genrsa -out "${tmp_private}" 2048 >/dev/null 2>&1
  openssl rsa -in "${tmp_private}" -pubout -out "${tmp_public}" >/dev/null 2>&1
  JWT_PRIVATE_KEY_B64="$(base64 < "${tmp_private}" | tr -d '\n')"
  JWT_PUBLIC_KEY_B64="$(base64 < "${tmp_public}" | tr -d '\n')"
  rm -f "${tmp_private}" "${tmp_public}"
  success "JWT 密钥对已生成"
else
  info "使用已有 JWT 密钥对"
fi

if [[ -z "${INTERNAL_TOKEN:-}" ]]; then
  INTERNAL_TOKEN="$(gen_secret 64)"
fi
if [[ -z "${EXTERNAL_API_KEY:-}" ]]; then
  EXTERNAL_API_KEY="$(gen_secret 48)"
fi
if [[ -z "${AGENT_HMAC_SECRET:-}" ]]; then
  AGENT_HMAC_SECRET="$(gen_secret 64)"
fi

step 6 "Telegram Bot（可选）"
ask_yn "是否配置 Telegram Bot？" ENABLE_TELEGRAM "${ENABLE_TELEGRAM_DEFAULT:-n}"
if [[ "${ENABLE_TELEGRAM}" == "true" ]]; then
  hint "前往 @BotFather 创建 Bot 并获取 Token"
  ask_input "Bot Token（格式：123456:ABC-DEF...）" "${TELEGRAM_BOT_TOKEN:-}" TELEGRAM_BOT_TOKEN
  ask_input "Bot 用户名（不含@）" "${TELEGRAM_BOT_USERNAME:-}" TELEGRAM_BOT_USERNAME
fi

ask_input "Hub 镜像地址" "${HUB_IMAGE:-ghcr.io/adambear22/nodepass-hub}" HUB_IMAGE
ask_input "Frontend 镜像地址" "${FRONTEND_IMAGE:-ghcr.io/adambear22/nodepass-frontend}" FRONTEND_IMAGE
ask_input "Agent 镜像地址" "${AGENT_IMAGE:-ghcr.io/adambear22/nodepass-agent}" AGENT_IMAGE
ask_input "Hub 版本标签" "${HUB_VERSION:-latest}" HUB_VERSION
ask_input "Frontend 版本标签" "${FRONTEND_VERSION:-${HUB_VERSION}}" FRONTEND_VERSION
ask_input "Agent 版本标签" "${AGENT_VERSION:-${HUB_VERSION}}" AGENT_VERSION

print_summary \
  "域名" "${DOMAIN}" \
  "TLS 模式" "${TLS_MODE}" \
  "数据库" "${POSTGRES_USER}@localhost/${POSTGRES_DB}" \
  "管理员" "${ADMIN_USERNAME}" \
  "Telegram Bot" "${ENABLE_TELEGRAM}" \
  "配置文件" "${CONF_FILE}"

escape_squote() {
  printf '%s' "$1" | sed "s/'/'\"'\"'/g"
}

write_conf_value() {
  local key="$1"
  local value="${2:-}"
  printf "%s='%s'\n" "${key}" "$(escape_squote "${value}")"
}

tmp_file="$(mktemp "${CONF_FILE}.tmp.XXXXXX")"
{
  echo "# NodePass Deploy Config — generated $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "# DO NOT commit this file to Git"
  write_conf_value "DOMAIN" "${DOMAIN}"
  write_conf_value "SITE_NAME" "${SITE_NAME}"
  write_conf_value "ADMIN_EMAIL" "${ADMIN_EMAIL}"
  write_conf_value "TLS_MODE" "${TLS_MODE}"
  write_conf_value "ACME_EMAIL" "${ACME_EMAIL:-}"
  write_conf_value "TLS_CERT_PATH" "${TLS_CERT_PATH:-}"
  write_conf_value "TLS_KEY_PATH" "${TLS_KEY_PATH:-}"
  write_conf_value "POSTGRES_DB" "${POSTGRES_DB}"
  write_conf_value "POSTGRES_USER" "${POSTGRES_USER}"
  write_conf_value "POSTGRES_PASSWORD" "${POSTGRES_PASSWORD}"
  write_conf_value "ADMIN_USERNAME" "${ADMIN_USERNAME}"
  write_conf_value "ADMIN_PASSWORD" "${ADMIN_PASSWORD}"
  write_conf_value "JWT_PRIVATE_KEY_B64" "${JWT_PRIVATE_KEY_B64}"
  write_conf_value "JWT_PUBLIC_KEY_B64" "${JWT_PUBLIC_KEY_B64}"
  write_conf_value "INTERNAL_TOKEN" "${INTERNAL_TOKEN}"
  write_conf_value "EXTERNAL_API_KEY" "${EXTERNAL_API_KEY}"
  write_conf_value "AGENT_HMAC_SECRET" "${AGENT_HMAC_SECRET}"
  write_conf_value "ENABLE_TELEGRAM" "${ENABLE_TELEGRAM}"
  write_conf_value "TELEGRAM_BOT_TOKEN" "${TELEGRAM_BOT_TOKEN:-}"
  write_conf_value "TELEGRAM_BOT_USERNAME" "${TELEGRAM_BOT_USERNAME:-}"
  write_conf_value "HUB_IMAGE" "${HUB_IMAGE}"
  write_conf_value "FRONTEND_IMAGE" "${FRONTEND_IMAGE}"
  write_conf_value "AGENT_IMAGE" "${AGENT_IMAGE}"
  write_conf_value "HUB_VERSION" "${HUB_VERSION}"
  write_conf_value "FRONTEND_VERSION" "${FRONTEND_VERSION}"
  write_conf_value "AGENT_VERSION" "${AGENT_VERSION}"
} > "${tmp_file}"

chmod 600 "${tmp_file}"
mv "${tmp_file}" "${CONF_FILE}"
success "配置已写入 ${CONF_FILE}"
