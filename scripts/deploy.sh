#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/wizard_ui.sh"

TOTAL_STEPS=8
CONFIG_FILE="deploy.conf"
DEPLOY_DIR="/opt/nodepass"
SECRET_RUNTIME_UID="${SECRET_RUNTIME_UID:-65532}"
SECRET_RUNTIME_GID="${SECRET_RUNTIME_GID:-65532}"
SECRET_OWNER_WARNED=0
DEPLOY_INFO_FILE=""

usage() {
  cat <<'USAGE'
Usage:
  bash deploy.sh [--config deploy.conf]

Options:
  --config <file>   Config file path (default: deploy.conf)
  -h, --help        Show this help.
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
          error "--config 需要文件路径"
          exit 1
        fi
        CONFIG_FILE="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        error "未知参数: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [[ "${CONFIG_FILE}" != /* ]]; then
    CONFIG_FILE="$(pwd)/${CONFIG_FILE}"
  fi

  DEPLOY_INFO_FILE="${DEPLOY_DIR}/deploy-info.txt"
}

require_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi

  if command -v sudo >/dev/null 2>&1; then
    warn "需要 root 权限，正在尝试使用 sudo 重新执行..."
    exec sudo bash "$0" "$@"
  fi

  error "请使用 root 或 sudo 运行部署脚本"
  exit 1
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1; then
    success "Docker 已安装: $(docker --version 2>/dev/null || echo 'available')"
    return 0
  fi

  warn "Docker 未安装，正在自动安装..."
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID:-}" in
      ubuntu|debian|centos|rhel|rocky|almalinux)
        ;;
      *)
        error "当前系统 ${ID:-unknown} 暂不支持自动安装 Docker，请先手动安装"
        exit 1
        ;;
    esac
  fi

  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  success "Docker 安装完成"
}

ensure_compose_v2() {
  if docker compose version >/dev/null 2>&1; then
    success "Docker Compose 已就绪: $(docker compose version --short 2>/dev/null || echo 'v2')"
    return 0
  fi

  warn "未检测到 Docker Compose v2，尝试自动安装 docker-compose-plugin..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get install -y docker-compose-plugin >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y docker-compose-plugin >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y docker-compose-plugin >/dev/null
  fi

  if ! docker compose version >/dev/null 2>&1; then
    error "需要 Docker Compose v2（docker compose），请手动安装后重试"
    exit 1
  fi

  success "Docker Compose 安装完成"
}

check_requirements() {
  local missing=0

  for cmd in curl openssl; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      error "缺少依赖：${cmd}"
      missing=$((missing + 1))
    else
      success "${cmd} $("${cmd}" --version 2>&1 | head -1)"
    fi
  done

  if [[ ${missing} -gt 0 ]]; then
    error "请先安装以上缺少的依赖"
    exit 1
  fi

  install_docker_if_needed
  ensure_compose_v2

  if ! command -v base64 >/dev/null 2>&1; then
    error "缺少依赖：base64"
    missing=$((missing + 1))
  fi

  local free_gb
  free_gb="$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')"
  if [[ -n "${free_gb}" && "${free_gb}" -lt 10 ]]; then
    warn "磁盘剩余空间 ${free_gb}GB，建议至少 10GB"
  else
    success "磁盘剩余空间检查通过"
  fi

  if [[ ${missing} -gt 0 ]]; then
    error "请先安装以上缺少的依赖"
    exit 1
  fi
}

load_config() {
  info "准备部署配置：${CONFIG_FILE}"
  bash "${SCRIPT_DIR}/collect_config.sh" --config "${CONFIG_FILE}"

  if [[ ! -f "${CONFIG_FILE}" ]]; then
    error "未找到配置文件：${CONFIG_FILE}"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "${CONFIG_FILE}"

  : "${DOMAIN:?缺少 DOMAIN}"
  : "${POSTGRES_DB:?缺少 POSTGRES_DB}"
  : "${POSTGRES_USER:?缺少 POSTGRES_USER}"
  : "${POSTGRES_PASSWORD:?缺少 POSTGRES_PASSWORD}"
  : "${ADMIN_USERNAME:?缺少 ADMIN_USERNAME}"
  : "${ADMIN_PASSWORD:?缺少 ADMIN_PASSWORD}"
  : "${JWT_PRIVATE_KEY_B64:?缺少 JWT_PRIVATE_KEY_B64}"
  : "${JWT_PUBLIC_KEY_B64:?缺少 JWT_PUBLIC_KEY_B64}"
  : "${INTERNAL_TOKEN:?缺少 INTERNAL_TOKEN}"
  : "${AGENT_HMAC_SECRET:?缺少 AGENT_HMAC_SECRET}"
  : "${EXTERNAL_API_KEY:?缺少 EXTERNAL_API_KEY}"

  ENABLE_TELEGRAM="${ENABLE_TELEGRAM:-false}"
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
}

prepare_deploy_dir() {
  mkdir -p "${DEPLOY_DIR}"/{secrets,backups,downloads,certs}
  chmod 700 "${DEPLOY_DIR}/secrets"

  install -m 644 "${REPO_ROOT}/deploy/docker-compose.yml" "${DEPLOY_DIR}/docker-compose.yml"
  install -m 644 "${REPO_ROOT}/deploy/Caddyfile" "${DEPLOY_DIR}/Caddyfile.template"
  success "部署目录准备完成：${DEPLOY_DIR}"
}

write_caddyfile() {
  local caddy_file="${DEPLOY_DIR}/Caddyfile"
  local host="${DOMAIN}"

  case "${TLS_MODE:-1}" in
    1)
      if [[ -n "${ACME_EMAIL:-}" ]]; then
        cat > "${caddy_file}" <<EOF_INNER
{
  email ${ACME_EMAIL}
}

${host} {
  handle_path /downloads/* {
    root * /srv/downloads
    file_server
  }

  handle /api/v1/events {
    reverse_proxy hub:8080 {
      flush_interval -1
      header_up Cache-Control no-cache
    }
  }

  handle /api/* {
    reverse_proxy hub:8080 {
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
    }
  }

  handle /ws/* {
    reverse_proxy hub:8080 {
      transport http {
        dial_timeout 5s
        response_header_timeout 0
      }
    }
  }

  handle /grafana* {
    reverse_proxy nodepass-grafana:3000
  }

  handle_path /prometheus* {
    reverse_proxy nodepass-prometheus:9090
  }

  handle_path /alertmanager* {
    reverse_proxy nodepass-alertmanager:9093
  }

  handle {
    reverse_proxy frontend:8080
  }

  encode gzip zstd

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }
}
EOF_INNER
      else
        cat > "${caddy_file}" <<EOF_INNER
${host} {
  handle_path /downloads/* {
    root * /srv/downloads
    file_server
  }

  handle /api/v1/events {
    reverse_proxy hub:8080 {
      flush_interval -1
      header_up Cache-Control no-cache
    }
  }

  handle /api/* {
    reverse_proxy hub:8080 {
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
    }
  }

  handle /ws/* {
    reverse_proxy hub:8080 {
      transport http {
        dial_timeout 5s
        response_header_timeout 0
      }
    }
  }

  handle /grafana* {
    reverse_proxy nodepass-grafana:3000
  }

  handle_path /prometheus* {
    reverse_proxy nodepass-prometheus:9090
  }

  handle_path /alertmanager* {
    reverse_proxy nodepass-alertmanager:9093
  }

  handle {
    reverse_proxy frontend:8080
  }

  encode gzip zstd

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }
}
EOF_INNER
      fi
      ;;
    2)
      cat > "${caddy_file}" <<EOF_INNER
${host} {
  tls /certs/tls.crt /certs/tls.key

  handle_path /downloads/* {
    root * /srv/downloads
    file_server
  }

  handle /api/v1/events {
    reverse_proxy hub:8080 {
      flush_interval -1
      header_up Cache-Control no-cache
    }
  }

  handle /api/* {
    reverse_proxy hub:8080 {
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
    }
  }

  handle /ws/* {
    reverse_proxy hub:8080 {
      transport http {
        dial_timeout 5s
        response_header_timeout 0
      }
    }
  }

  handle /grafana* {
    reverse_proxy nodepass-grafana:3000
  }

  handle_path /prometheus* {
    reverse_proxy nodepass-prometheus:9090
  }

  handle_path /alertmanager* {
    reverse_proxy nodepass-alertmanager:9093
  }

  handle {
    reverse_proxy frontend:8080
  }

  encode gzip zstd

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }
}
EOF_INNER
      ;;
    3)
      cat > "${caddy_file}" <<EOF_INNER
http://${host} {
  handle_path /downloads/* {
    root * /srv/downloads
    file_server
  }

  handle /api/v1/events {
    reverse_proxy hub:8080 {
      flush_interval -1
      header_up Cache-Control no-cache
    }
  }

  handle /api/* {
    reverse_proxy hub:8080 {
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
    }
  }

  handle /ws/* {
    reverse_proxy hub:8080 {
      transport http {
        dial_timeout 5s
        response_header_timeout 0
      }
    }
  }

  handle /grafana* {
    reverse_proxy nodepass-grafana:3000
  }

  handle_path /prometheus* {
    reverse_proxy nodepass-prometheus:9090
  }

  handle_path /alertmanager* {
    reverse_proxy nodepass-alertmanager:9093
  }

  handle {
    reverse_proxy frontend:8080
  }

  encode gzip zstd

  header {
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }
}
EOF_INNER
      ;;
    *)
      error "不支持的 TLS 模式：${TLS_MODE}"
      exit 1
      ;;
  esac

  success "已生成 Caddy 配置"
}

setup_tls_assets() {
  rm -f "${DEPLOY_DIR}/docker-compose.override.yml"

  case "${TLS_MODE:-1}" in
    1)
      info "TLS 模式：Let's Encrypt 自动申请（由 Caddy 在启动后自动处理）"
      ;;
    2)
      if [[ -z "${TLS_CERT_PATH:-}" || -z "${TLS_KEY_PATH:-}" ]]; then
        error "TLS_MODE=2 需要配置 TLS_CERT_PATH 和 TLS_KEY_PATH"
        exit 1
      fi
      if [[ ! -f "${TLS_CERT_PATH}" || ! -f "${TLS_KEY_PATH}" ]]; then
        error "证书文件不存在，请检查 TLS_CERT_PATH / TLS_KEY_PATH"
        exit 1
      fi

      install -m 600 "${TLS_CERT_PATH}" "${DEPLOY_DIR}/certs/tls.crt"
      install -m 600 "${TLS_KEY_PATH}" "${DEPLOY_DIR}/certs/tls.key"

      cat > "${DEPLOY_DIR}/docker-compose.override.yml" <<'EOF_INNER'
services:
  caddy:
    volumes:
      - ./certs:/certs:ro
EOF_INNER
      success "已写入自定义证书并生成 Compose 覆盖配置"
      ;;
    3)
      warn "TLS 已禁用，仅适用于内网测试环境"
      ;;
    *)
      error "不支持的 TLS 模式：${TLS_MODE}"
      exit 1
      ;;
  esac
}

write_env_file() {
  local env_file="${DEPLOY_DIR}/.env"
  local tmp_file
  tmp_file="$(mktemp)"

  cat > "${tmp_file}" <<EOF_INNER
# NodePass runtime environment — generated by scripts/deploy.sh
HUB_IMAGE=${HUB_IMAGE:-ghcr.io/adambear22/nodepass-hub}
HUB_VERSION=${HUB_VERSION:-latest}
FRONTEND_IMAGE=${FRONTEND_IMAGE:-ghcr.io/adambear22/nodepass-frontend}
FRONTEND_VERSION=${FRONTEND_VERSION:-latest}
AGENT_IMAGE=${AGENT_IMAGE:-ghcr.io/adambear22/nodepass-agent}
AGENT_VERSION=${AGENT_VERSION:-latest}

DOMAIN=${DOMAIN}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
LOG_LEVEL=info
EOF_INNER

  chmod 600 "${tmp_file}"
  mv "${tmp_file}" "${env_file}"
}

decode_b64_to_file() {
  local value="$1"
  local out_file="$2"

  if printf '%s' "${value}" | base64 --decode > "${out_file}" 2>/dev/null; then
    return 0
  fi

  if printf '%s' "${value}" | base64 -d > "${out_file}" 2>/dev/null; then
    return 0
  fi

  error "解码 base64 失败：${out_file}"
  exit 1
}

write_secret_file() {
  local file_path="$1"
  local content="$2"
  printf '%s' "${content}" > "${file_path}"
  harden_secret_file "${file_path}"
}

harden_secret_file() {
  local file_path="$1"
  chmod 600 "${file_path}"
  if ! chown "${SECRET_RUNTIME_UID}:${SECRET_RUNTIME_GID}" "${file_path}" >/dev/null 2>&1; then
    if [[ "${SECRET_OWNER_WARNED}" -eq 0 ]]; then
      warn "无法设置 secret 所有者为 ${SECRET_RUNTIME_UID}:${SECRET_RUNTIME_GID}，非 root 容器可能无法读取"
      SECRET_OWNER_WARNED=1
    fi
  fi
}

write_runtime_files() {
  write_env_file
  install -m 600 "${CONFIG_FILE}" "${DEPLOY_DIR}/deploy.conf"

  decode_b64_to_file "${JWT_PRIVATE_KEY_B64}" "${DEPLOY_DIR}/secrets/jwt_private.pem"
  decode_b64_to_file "${JWT_PUBLIC_KEY_B64}" "${DEPLOY_DIR}/secrets/jwt_public.pem"

  harden_secret_file "${DEPLOY_DIR}/secrets/jwt_private.pem"
  harden_secret_file "${DEPLOY_DIR}/secrets/jwt_public.pem"
  write_secret_file "${DEPLOY_DIR}/secrets/internal_token.txt" "${INTERNAL_TOKEN}"
  write_secret_file "${DEPLOY_DIR}/secrets/agent_hmac_secret.txt" "${AGENT_HMAC_SECRET}"
  write_secret_file "${DEPLOY_DIR}/secrets/external_api_key.txt" "${EXTERNAL_API_KEY}"

  if [[ "${ENABLE_TELEGRAM}" == "true" ]]; then
    write_secret_file "${DEPLOY_DIR}/secrets/telegram_bot_token.txt" "${TELEGRAM_BOT_TOKEN}"
  else
    write_secret_file "${DEPLOY_DIR}/secrets/telegram_bot_token.txt" ""
  fi

  success "环境变量和密钥文件已生成"
}

compose() {
  (cd "${DEPLOY_DIR}" && docker compose "$@")
}

start_services() {
  info "拉取镜像..."
  compose pull

  info "启动 PostgreSQL..."
  compose up -d postgres
  wait_postgres_ready

  info "执行数据库迁移..."
  compose run --rm migrate

  info "启动全部服务..."
  compose up -d --remove-orphans
}

wait_postgres_ready() {
  local max_wait=120
  local elapsed=0
  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if compose exec -T postgres pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
      success "postgres 已健康"
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done

  error "postgres 健康检查超时"
  compose logs --tail=40 postgres || true
  return 1
}

wait_hub_ready() {
  local max_wait=120
  local elapsed=0
  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if compose exec -T hub /nodepass-hub healthcheck >/dev/null 2>&1; then
      success "hub 已健康"
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done

  error "hub 健康检查超时"
  compose logs --tail=60 hub || true
  return 1
}

create_admin() {
  compose exec -T hub /nodepass-hub create-admin \
    --username "${ADMIN_USERNAME}" \
    --password "${ADMIN_PASSWORD}" \
    --email "${ADMIN_EMAIL:-}"
}

verify_endpoint() {
  local scheme="https"
  if [[ "${TLS_MODE:-1}" == "3" ]]; then
    scheme="http"
  fi

  if curl -kfsS "${scheme}://${DOMAIN}/api/v1/health/ready" >/dev/null 2>&1; then
    success "外部访问验证通过：${scheme}://${DOMAIN}"
    return 0
  fi

  warn "外部访问验证失败（可能是 DNS/证书尚未生效），请稍后手动检查"
  return 0
}

print_access_info() {
  local scheme="https"
  if [[ "${TLS_MODE:-1}" == "3" ]]; then
    scheme="http"
  fi

  section "访问信息"
  echo -e "  ${BOLD}站点地址：${NC} ${scheme}://${DOMAIN}"
  echo -e "  ${BOLD}管理端：${NC} ${scheme}://${DOMAIN}/admin"
  echo -e "  ${BOLD}API 文档：${NC} ${scheme}://${DOMAIN}/api/docs"
  echo -e "  ${BOLD}管理员账号：${NC} ${ADMIN_USERNAME}"
  echo -e "  ${BOLD}部署目录：${NC} ${DEPLOY_DIR}"
  echo -e "  ${BOLD}部署信息文件：${NC} ${DEPLOY_INFO_FILE}"
  divider
}

write_deploy_info() {
  local scheme now
  scheme="https"
  if [[ "${TLS_MODE:-1}" == "3" ]]; then
    scheme="http"
  fi
  now="$(date '+%Y-%m-%d %H:%M:%S %Z')"

  cat > "${DEPLOY_INFO_FILE}" <<EOF
NodePass Deployment Info
Generated: ${now}

Site URL: ${scheme}://${DOMAIN}
Admin URL: ${scheme}://${DOMAIN}/admin
API Docs: ${scheme}://${DOMAIN}/api/docs
Admin User: ${ADMIN_USERNAME}
Deploy Dir: ${DEPLOY_DIR}
Compose File: ${DEPLOY_DIR}/docker-compose.yml
Env File: ${DEPLOY_DIR}/.env

Common Commands:
- cd ${DEPLOY_DIR} && docker compose ps
- cd ${DEPLOY_DIR} && docker compose logs -f
- bash ${DEPLOY_DIR}/upgrade.sh
EOF

  chmod 600 "${DEPLOY_INFO_FILE}"
  success "部署信息已写入：${DEPLOY_INFO_FILE}"
}

main() {
  parse_args "$@"
  require_root "$@"

  show_banner

  step 1 "系统环境检查"
  check_requirements

  step 2 "收集部署配置"
  load_config

  step 3 "创建部署目录结构"
  prepare_deploy_dir

  step 4 "生成反向代理配置"
  write_caddyfile

  step 5 "TLS 证书配置"
  setup_tls_assets

  step 6 "生成环境变量并启动服务"
  write_runtime_files
  start_services

  step 7 "等待服务健康启动"
  wait_postgres_ready
  wait_hub_ready

  step 8 "创建管理员账户并验证部署"
  create_admin
  verify_endpoint

  write_deploy_info
  success "部署完成！"
  print_access_info
  warn "请妥善保存配置文件：${CONFIG_FILE}"
}

main "$@"
