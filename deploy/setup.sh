#!/bin/bash
# NodePass 管理平台 — 一键部署脚本
# 支持：Ubuntu 20.04+, Debian 11+
# 幂等执行：可重复运行，已存在的配置不会被覆盖

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_step()  { echo -e "\n${BLUE}${BOLD}[STEP]${NC} $1"; }
log_ok()    { echo -e "${GREEN}✓${NC} $1"; }
log_warn()  { echo -e "${YELLOW}⚠${NC}  $1"; }
log_error() { echo -e "${RED}✗${NC}  $1" >&2; }
log_info()  { echo -e "  $1"; }

read_tty_line() {
  local prompt="$1"
  local value

  if [[ -r /dev/tty ]]; then
    read -r -p "${prompt}" value < /dev/tty
    echo "${value}"
    return
  fi

  log_error "当前环境不可交互（无法读取 /dev/tty）"
  exit 1
}

read_tty_secret() {
  local prompt="$1"
  local value

  if [[ -r /dev/tty ]]; then
    read -r -s -p "${prompt}" value < /dev/tty
    echo "" > /dev/tty
    echo "${value}"
    return
  fi

  log_error "当前环境不可交互（无法读取 /dev/tty）"
  exit 1
}

REPO_URL="${REPO_URL:-https://raw.githubusercontent.com/adambear22/RelayOne/main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodepass}"
COMPOSE_VERSION="${COMPOSE_VERSION:-v2.27.0}"
REPO_URL="${REPO_URL%/}"

SCRIPT_ARGS=("$@")
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"
ENV_FILE="${INSTALL_DIR}/.env"
SECRETS_DIR="${INSTALL_DIR}/secrets"

OS_NAME=""
OS_VERSION=""
ARCH=""
DOMAIN=""
ADMIN_USER="admin"
TG_TOKEN=""
SETUP_INTERRUPTED=0
SERVICES_STARTED=0
POSTGRES_STARTED=0
ENV_WAS_CREATED=0

cleanup() {
  if [[ "${SETUP_INTERRUPTED}" -eq 1 ]]; then
    log_warn "收到中断信号，正在清理临时资源..."
    if [[ -f "${COMPOSE_FILE}" && -f "${ENV_FILE}" ]]; then
      docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" rm -fsv migrate >/dev/null 2>&1 || true
      if [[ "${SERVICES_STARTED}" -eq 0 && "${POSTGRES_STARTED}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" stop postgres >/dev/null 2>&1 || true
      fi
    fi
  fi
}

on_interrupt() {
  SETUP_INTERRUPTED=1
  log_warn "部署被中断"
  exit 130
}

trap on_interrupt INT TERM
trap cleanup EXIT

compose() {
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
}

check_os() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    log_error "仅支持 Linux 系统"
    exit 1
  fi

  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_NAME="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
  else
    OS_NAME="unknown"
    OS_VERSION="unknown"
  fi

  case "${OS_NAME}" in
    ubuntu|debian|centos|rhel|amzn)
      log_ok "检测到已测试发行版: ${OS_NAME} ${OS_VERSION}"
      ;;
    *)
      log_warn "当前系统 ${OS_NAME} ${OS_VERSION} 未经完整测试，可能存在兼容性问题"
      ;;
  esac
}

check_arch() {
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|aarch64|armv7l)
      log_ok "系统架构支持: ${ARCH}"
      ;;
    *)
      log_error "不支持的 CPU 架构: ${ARCH}（仅支持 x86_64 / aarch64 / armv7l）"
      exit 1
      ;;
  esac
}

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1 && [[ -f "$0" ]]; then
      exec sudo bash "$0" "${SCRIPT_ARGS[@]}"
    fi
    log_error "需要 root 权限执行，请使用 sudo 运行"
    exit 1
  fi
  log_ok "权限检查通过（root）"
}

check_ports() {
  local blocked=0
  local port
  for port in 80 443; do
    if command -v lsof >/dev/null 2>&1; then
      if lsof -Pi ":${port}" -sTCP:LISTEN >/dev/null 2>&1; then
        log_warn "端口 ${port} 已被占用："
        lsof -Pi ":${port}" -sTCP:LISTEN || true
        blocked=1
      fi
    elif command -v ss >/dev/null 2>&1; then
      if ss -lntp "( sport = :${port} )" | grep -q ":${port}"; then
        log_warn "端口 ${port} 已被占用："
        ss -lntp "( sport = :${port} )" || true
        blocked=1
      fi
    else
      log_warn "未找到 lsof/ss，无法自动检测端口占用"
    fi
  done

  if [[ "${blocked}" -eq 1 ]]; then
    log_error "请释放 80/443 端口后重试"
    exit 1
  fi

  log_ok "端口检查通过（80/443 可用）"
}

check_network() {
  if [[ "${SKIP_NETWORK_CHECK:-0}" == "1" ]]; then
    log_warn "已跳过网络检查（SKIP_NETWORK_CHECK=1）"
    return
  fi

  local ok=0
  local endpoint
  for endpoint in "https://ghcr.io/v2/" "https://raw.githubusercontent.com/"; do
    if curl -sfI --connect-timeout 10 "${endpoint}" >/dev/null 2>&1; then
      ok=1
      break
    fi
    if curl -4sfI --connect-timeout 10 "${endpoint}" >/dev/null 2>&1; then
      ok=1
      break
    fi
  done

  if [[ "${ok}" -eq 1 ]]; then
    log_ok "网络检查通过（可访问 GitHub/GHCR）"
    return
  fi

  log_error "无法访问 ghcr.io/raw.githubusercontent.com，请检查防火墙、DNS 或网络出口策略"
  if command -v getent >/dev/null 2>&1; then
    log_info "DNS 解析（ghcr.io）："
    getent hosts ghcr.io | head -n 3 || true
  fi
  log_info "可尝试：先设置代理后重试，或临时 SKIP_NETWORK_CHECK=1 跳过检查"
  exit 1
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log_ok "Docker 已安装: $(docker --version)"
  else
    log_info "安装 Docker..."
    curl -fsSL https://get.docker.com | sh
    log_ok "Docker 安装完成"
  fi

  systemctl enable --now docker
  log_ok "Docker 服务已启用"

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    usermod -aG docker "${SUDO_USER}" || true
  fi
}

install_compose() {
  if docker compose version >/dev/null 2>&1; then
    log_ok "Docker Compose 已安装: $(docker compose version --short 2>/dev/null || echo available)"
    return
  fi

  local compose_arch
  case "${ARCH}" in
    x86_64) compose_arch="x86_64" ;;
    aarch64) compose_arch="aarch64" ;;
    armv7l) compose_arch="armv7" ;;
    *)
      log_error "无法匹配 Docker Compose 架构: ${ARCH}"
      exit 1
      ;;
  esac

  log_info "安装 Docker Compose 插件..."
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  log_ok "Docker Compose 安装完成"
}

setup_deploy_dir() {
  mkdir -p "${INSTALL_DIR}"/{secrets,backups,logs,downloads}
  chmod 700 "${INSTALL_DIR}/secrets"
  log_ok "部署目录已准备: ${INSTALL_DIR}"
}

download_file_if_modified() {
  local remote_url="$1"
  local target_path="$2"
  local tmp_file
  local http_code

  tmp_file="$(mktemp)"

  if [[ -f "${target_path}" ]]; then
    http_code="$(curl -sSL --connect-timeout 15 --retry 3 --retry-delay 2 -z "${target_path}" -o "${tmp_file}" -w '%{http_code}' "${remote_url}")"
    if [[ "${http_code}" == "304" ]]; then
      rm -f "${tmp_file}"
      log_ok "文件已是最新: $(basename "${target_path}")"
      return
    fi
  else
    http_code="$(curl -sSL --connect-timeout 15 --retry 3 --retry-delay 2 -o "${tmp_file}" -w '%{http_code}' "${remote_url}")"
  fi

  if [[ "${http_code}" != "200" ]]; then
    rm -f "${tmp_file}"
    log_error "下载失败（HTTP ${http_code}）: ${remote_url}"
    exit 1
  fi

  mv "${tmp_file}" "${target_path}"
  log_ok "已更新: $(basename "${target_path}")"
}

download_files() {
  download_file_if_modified "${REPO_URL}/deploy/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml"
  download_file_if_modified "${REPO_URL}/deploy/Caddyfile" "${INSTALL_DIR}/Caddyfile"
  download_file_if_modified "${REPO_URL}/deploy/upgrade.sh" "${INSTALL_DIR}/upgrade.sh"
  download_file_if_modified "${REPO_URL}/deploy/update.sh" "${INSTALL_DIR}/update.sh"
  chmod +x "${INSTALL_DIR}/upgrade.sh"
  chmod +x "${INSTALL_DIR}/update.sh"

  download_file_if_modified "${REPO_URL}/deploy/.env.example" "${INSTALL_DIR}/.env.example"

  if [[ ! -s "${ENV_FILE}" ]]; then
    local tmp_env
    tmp_env="$(mktemp)"
    cp "${INSTALL_DIR}/.env.example" "${tmp_env}"
    chmod 600 "${tmp_env}"
    mv "${tmp_env}" "${ENV_FILE}"
    ENV_WAS_CREATED=1
    log_ok "已初始化 .env"
  else
    log_ok ".env 已存在，跳过初始化"
  fi

  ensure_env_image_vars
}

set_env_var() {
  local key="$1"
  local value="$2"
  local tmp_file

  tmp_file="$(mktemp)"

  if [[ -f "${ENV_FILE}" ]]; then
    awk -v key="${key}" -v value="${value}" '
      BEGIN { found=0 }
      $0 ~ "^"key"=" {
        print key"="value
        found=1
        next
      }
      { print }
      END {
        if (!found) {
          print key"="value
        }
      }
    ' "${ENV_FILE}" > "${tmp_file}"
  else
    printf '%s=%s\n' "${key}" "${value}" > "${tmp_file}"
  fi

  chmod 600 "${tmp_file}"
  mv "${tmp_file}" "${ENV_FILE}"
}

get_env_var() {
  local key="$1"
  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  grep -E "^${key}=" "${ENV_FILE}" | tail -1 | cut -d '=' -f2-
}

detect_repo_slug() {
  local slug=""
  if [[ "${REPO_URL}" =~ raw\.githubusercontent\.com/([^/]+/[^/]+)/ ]]; then
    slug="${BASH_REMATCH[1]}"
  fi
  echo "${slug}"
}

ensure_env_image_vars() {
  local repo_slug owner changed
  local hub_image frontend_image agent_image
  repo_slug="$(detect_repo_slug)"
  owner="${repo_slug%%/*}"
  changed=0

  if [[ -z "${owner}" || "${owner}" == "${repo_slug}" ]]; then
    return
  fi

  hub_image="$(get_env_var HUB_IMAGE)"
  frontend_image="$(get_env_var FRONTEND_IMAGE)"
  agent_image="$(get_env_var AGENT_IMAGE)"

  if [[ -z "${hub_image}" || "${hub_image}" == *"<ORG>"* ]]; then
    set_env_var "HUB_IMAGE" "ghcr.io/${owner}/nodepass-hub"
    changed=1
  fi
  if [[ -z "${frontend_image}" || "${frontend_image}" == *"<ORG>"* ]]; then
    set_env_var "FRONTEND_IMAGE" "ghcr.io/${owner}/nodepass-frontend"
    changed=1
  fi
  if [[ -z "${agent_image}" || "${agent_image}" == *"<ORG>"* ]]; then
    set_env_var "AGENT_IMAGE" "ghcr.io/${owner}/nodepass-agent"
    changed=1
  fi

  if [[ "${changed}" -eq 1 ]]; then
    log_ok ".env 镜像地址已自动修正为 ghcr.io/${owner}/nodepass-*"
  fi
}

validate_domain() {
  local candidate="$1"
  if [[ -z "${candidate}" ]]; then
    return 1
  fi

  if [[ "${candidate}" == "localhost" ]]; then
    return 0
  fi

  if is_ipv4 "${candidate}"; then
    return 0
  fi

  [[ "${candidate}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$ ]]
}

is_ipv4() {
  local candidate="$1"
  local octet
  if [[ ! "${candidate}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 1
  fi

  IFS='.' read -r -a octets <<< "${candidate}"
  if [[ "${#octets[@]}" -ne 4 ]]; then
    return 1
  fi

  for octet in "${octets[@]}"; do
    if (( octet < 0 || octet > 255 )); then
      return 1
    fi
  done

  return 0
}

is_public_fqdn() {
  local candidate="$1"
  [[ "${candidate}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

check_domain_dns() {
  local domain_name="$1"

  if [[ "${domain_name}" == "localhost" ]] || is_ipv4 "${domain_name}"; then
    log_warn "检测到本地/内网地址（${domain_name}），将跳过 DNS 校验。生产环境建议使用公网域名。"
    return
  fi

  if ! is_public_fqdn "${domain_name}"; then
    log_warn "当前输入不是标准公网域名（${domain_name}），将跳过 DNS 校验。"
    return
  fi

  if ! command -v dig >/dev/null 2>&1; then
    log_warn "未检测到 dig，跳过 DNS 校验"
    return
  fi

  local resolved_ip server_ip
  resolved_ip="$(dig +short "${domain_name}" | head -1 || true)"
  if [[ -z "${resolved_ip}" ]]; then
    log_warn "无法解析域名 ${domain_name}，请确认 DNS 配置"
    return
  fi

  server_ip="$(curl -4 -sf --max-time 5 https://api.ipify.org || true)"
  if [[ -z "${server_ip}" ]]; then
    server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi

  if [[ -n "${server_ip}" && "${resolved_ip}" != "${server_ip}" ]]; then
    log_warn "域名解析 IP (${resolved_ip}) 与当前服务器 IP (${server_ip}) 不一致"
    local confirm
    confirm="$(read_tty_line "是否继续部署？[y/N]: ")"
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
      log_error "部署已取消"
      exit 1
    fi
  else
    log_ok "域名解析检查通过"
  fi
}

validate_telegram_token() {
  local token="$1"
  if [[ -z "${token}" ]]; then
    return
  fi

  if ! command -v jq >/dev/null 2>&1; then
    log_warn "未安装 jq，跳过 Telegram Token 严格校验"
    return
  fi

  local ok
  ok="$(curl -sf "https://api.telegram.org/bot${token}/getMe" | jq -r '.ok' || echo "false")"
  if [[ "${ok}" != "true" ]]; then
    log_error "Telegram Bot Token 校验失败"
    exit 1
  fi
  log_ok "Telegram Bot Token 校验通过"
}

read_input_with_default() {
  local prompt="$1"
  local default_value="$2"

  if [[ -n "${default_value}" ]]; then
    local input_value
    input_value="$(read_tty_line "${prompt} [${default_value}]: ")"
    if [[ -z "${input_value}" ]]; then
      echo "${default_value}"
      return
    fi
    echo "${input_value}"
    return
  fi

  read_tty_line "${prompt}: "
}

read_secret_with_default() {
  local prompt="$1"
  local default_value="$2"

  if [[ -n "${default_value}" ]]; then
    local input_value
    input_value="$(read_tty_secret "${prompt}（留空沿用当前）: ")"
    if [[ -z "${input_value}" ]]; then
      echo "${default_value}"
      return
    fi
    echo "${input_value}"
    return
  fi

  read_tty_secret "${prompt}: "
}

configure_env() {
  ensure_env_image_vars

  local current_domain current_db_user current_db_name current_db_password
  local current_hub_version current_frontend_version current_agent_version
  local current_hub_image current_frontend_image current_agent_image
  local existing_tg_token

  current_domain="$(get_env_var DOMAIN)"
  current_db_user="$(get_env_var POSTGRES_USER)"
  current_db_name="$(get_env_var POSTGRES_DB)"
  current_db_password="$(get_env_var POSTGRES_PASSWORD)"
  current_hub_version="$(get_env_var HUB_VERSION)"
  current_frontend_version="$(get_env_var FRONTEND_VERSION)"
  current_agent_version="$(get_env_var AGENT_VERSION)"
  current_hub_image="$(get_env_var HUB_IMAGE)"
  current_frontend_image="$(get_env_var FRONTEND_IMAGE)"
  current_agent_image="$(get_env_var AGENT_IMAGE)"
  existing_tg_token=""
  if [[ -f "${SECRETS_DIR}/telegram_bot_token.txt" ]]; then
    existing_tg_token="$(cat "${SECRETS_DIR}/telegram_bot_token.txt" 2>/dev/null || true)"
  fi

  echo -e "${BOLD}── 基础配置 ────────────────────${NC}"
  while true; do
    DOMAIN="$(read_input_with_default "域名（公网域名；测试可填 localhost 或 IP）" "${current_domain}")"
    DOMAIN="${DOMAIN// /}"
    if validate_domain "${DOMAIN}"; then
      break
    fi
    log_warn "域名格式不正确，请重新输入"
  done
  if ! is_public_fqdn "${DOMAIN}"; then
    log_warn "当前输入不是公网域名，HTTPS 证书自动签发可能不可用（仅建议测试环境使用）"
  fi
  check_domain_dns "${DOMAIN}"

  local db_password
  db_password="$(read_secret_with_default "数据库密码（输入 random 自动生成）" "${current_db_password}")"
  if [[ -z "${db_password}" ]]; then
    db_password="$(openssl rand -base64 32 | tr -d '=+/')"
  elif [[ "${db_password}" == "random" ]]; then
    db_password="$(openssl rand -base64 32 | tr -d '=+/')"
  fi
  echo "  已设置数据库密码"

  local db_user db_name
  db_user="$(read_input_with_default "数据库用户名" "${current_db_user:-nodepass}")"
  db_name="$(read_input_with_default "数据库名" "${current_db_name:-nodepass_hub}")"

  echo -e "${BOLD}── Telegram Bot 配置（可选，回车跳过）────────────────────${NC}"
  TG_TOKEN="$(read_secret_with_default "Bot Token（格式：123456:ABC...，可选）" "${existing_tg_token}")"
  validate_telegram_token "${TG_TOKEN}"

  local repo_slug repo_owner latest_release default_version target_version
  repo_slug="$(detect_repo_slug)"
  repo_owner="${repo_slug%%/*}"
  if [[ -z "${repo_owner}" || "${repo_owner}" == "${repo_slug}" ]]; then
    repo_owner="adambear22"
  fi
  latest_release="latest"
  if [[ -n "${repo_slug}" && "${repo_slug}" != *"<"* ]]; then
    latest_release="$(curl -sf "https://api.github.com/repos/${repo_slug}/releases/latest" | jq -r '.tag_name' 2>/dev/null || echo "latest")"
    if [[ -z "${latest_release}" || "${latest_release}" == "null" ]]; then
      latest_release="latest"
    fi
  fi

  default_version="${current_hub_version:-${latest_release}}"
  target_version="$(read_input_with_default "部署版本" "${default_version}")"
  if [[ -z "${target_version}" ]]; then
    target_version="${latest_release}"
  fi

  local hub_image frontend_image agent_image
  hub_image="$(read_input_with_default "Hub 镜像地址" "${current_hub_image:-ghcr.io/${repo_owner}/nodepass-hub}")"
  frontend_image="$(read_input_with_default "Frontend 镜像地址" "${current_frontend_image:-ghcr.io/${repo_owner}/nodepass-frontend}")"
  agent_image="$(read_input_with_default "Agent 镜像地址" "${current_agent_image:-ghcr.io/${repo_owner}/nodepass-agent}")"

  if [[ -z "${hub_image}" || -z "${frontend_image}" || -z "${agent_image}" ]]; then
    log_error "镜像地址不能为空"
    exit 1
  fi

  set_env_var "DOMAIN" "${DOMAIN}"
  set_env_var "POSTGRES_USER" "${db_user:-nodepass}"
  set_env_var "POSTGRES_PASSWORD" "${db_password}"
  set_env_var "POSTGRES_DB" "${db_name:-nodepass_hub}"
  set_env_var "LOG_LEVEL" "info"

  set_env_var "HUB_IMAGE" "${hub_image}"
  set_env_var "FRONTEND_IMAGE" "${frontend_image}"
  set_env_var "AGENT_IMAGE" "${agent_image}"

  local frontend_version agent_version
  frontend_version="$(read_input_with_default "Frontend 版本标签" "${current_frontend_version:-${target_version}}")"
  agent_version="$(read_input_with_default "Agent 版本标签" "${current_agent_version:-${target_version}}")"
  if [[ -z "${frontend_version}" ]]; then
    frontend_version="${target_version}"
  fi
  if [[ -z "${agent_version}" ]]; then
    agent_version="${target_version}"
  fi

  set_env_var "HUB_VERSION" "${target_version}"
  set_env_var "FRONTEND_VERSION" "${frontend_version}"
  set_env_var "AGENT_VERSION" "${agent_version}"

  log_ok ".env 配置完成"
}

write_secret_atomic() {
  local target="$1"
  local mode="$2"
  local content="$3"
  local tmp

  tmp="$(mktemp)"
  printf '%s' "${content}" > "${tmp}"
  chmod "${mode}" "${tmp}"
  mv "${tmp}" "${target}"
}

generate_secrets() {
  mkdir -p "${SECRETS_DIR}"
  chmod 700 "${SECRETS_DIR}"

  if [[ ! -f "${SECRETS_DIR}/jwt_private.pem" || ! -f "${SECRETS_DIR}/jwt_public.pem" ]]; then
    local tmp_private tmp_public
    tmp_private="$(mktemp)"
    tmp_public="$(mktemp)"

    openssl genrsa 2048 > "${tmp_private}"
    openssl rsa -in "${tmp_private}" -pubout > "${tmp_public}"

    chmod 600 "${tmp_private}" "${tmp_public}"
    mv "${tmp_private}" "${SECRETS_DIR}/jwt_private.pem"
    mv "${tmp_public}" "${SECRETS_DIR}/jwt_public.pem"
    log_ok "JWT RSA 密钥对已生成（2048 bit）"
  else
    log_ok "JWT RSA 密钥对已存在，跳过生成"
  fi

  if [[ ! -f "${SECRETS_DIR}/agent_hmac_secret.txt" ]]; then
    write_secret_atomic "${SECRETS_DIR}/agent_hmac_secret.txt" 600 "$(openssl rand -hex 32)"
    log_ok "Agent HMAC 密钥已生成（256 bit）"
  else
    log_ok "Agent HMAC 密钥已存在，跳过生成"
  fi

  if [[ ! -f "${SECRETS_DIR}/external_api_key.txt" ]]; then
    write_secret_atomic "${SECRETS_DIR}/external_api_key.txt" 600 "$(openssl rand -base64 32 | tr -d '=+/')"
    log_ok "外部 API 密钥已生成"
  else
    log_ok "外部 API 密钥已存在，跳过生成"
  fi

  if [[ ! -f "${SECRETS_DIR}/internal_token.txt" ]]; then
    write_secret_atomic "${SECRETS_DIR}/internal_token.txt" 600 "$(openssl rand -hex 32)"
    log_ok "内部接口令牌已生成"
  else
    log_ok "内部接口令牌已存在，跳过生成"
  fi

  if [[ -n "${TG_TOKEN:-}" ]]; then
    write_secret_atomic "${SECRETS_DIR}/telegram_bot_token.txt" 600 "${TG_TOKEN}"
    log_ok "Telegram Bot Token 已保存"
  elif [[ ! -f "${SECRETS_DIR}/telegram_bot_token.txt" ]]; then
    write_secret_atomic "${SECRETS_DIR}/telegram_bot_token.txt" 600 ""
    log_warn "未提供 Telegram Token，已创建空 secret 文件"
  fi
}

extract_agent_binary() {
  local image_ref="$1"
  local platform="$2"
  local target_path="$3"
  local container_id tmp_binary

  tmp_binary="$(mktemp)"
  container_id="$(docker create --platform "${platform}" "${image_ref}")" || {
    rm -f "${tmp_binary}"
    return 1
  }

  if ! docker cp "${container_id}:/nodepass-agent" "${tmp_binary}" >/dev/null 2>&1; then
    docker rm "${container_id}" >/dev/null 2>&1 || true
    rm -f "${tmp_binary}"
    return 1
  fi

  docker rm "${container_id}" >/dev/null 2>&1 || true
  chmod 755 "${tmp_binary}"
  mv "${tmp_binary}" "${target_path}"
  return 0
}

prepare_agent_downloads() {
  local agent_image agent_version image_ref downloads_dir
  local target_amd64 target_arm64 target_armv7
  local any_success=0

  agent_image="$(get_env_var AGENT_IMAGE)"
  agent_version="$(get_env_var AGENT_VERSION)"
  if [[ -z "${agent_image}" || -z "${agent_version}" ]]; then
    log_error "缺少 AGENT_IMAGE 或 AGENT_VERSION，无法准备 Agent 下载文件"
    exit 1
  fi

  image_ref="${agent_image}:${agent_version}"
  downloads_dir="${INSTALL_DIR}/downloads"
  mkdir -p "${downloads_dir}"

  target_amd64="${downloads_dir}/nodepass-agent-${agent_version}-linux-amd64"
  if extract_agent_binary "${image_ref}" "linux/amd64" "${target_amd64}"; then
    any_success=1
  else
    log_warn "未能提取 amd64 Agent 二进制（${image_ref}）"
  fi

  target_arm64="${downloads_dir}/nodepass-agent-${agent_version}-linux-arm64"
  if extract_agent_binary "${image_ref}" "linux/arm64" "${target_arm64}"; then
    any_success=1
  else
    log_warn "未能提取 arm64 Agent 二进制（${image_ref}）"
  fi

  target_armv7="${downloads_dir}/nodepass-agent-${agent_version}-linux-armv7"
  if extract_agent_binary "${image_ref}" "linux/arm/v7" "${target_armv7}"; then
    any_success=1
  else
    log_warn "未能提取 armv7 Agent 二进制（${image_ref}）"
  fi

  if [[ "${any_success}" -eq 0 ]]; then
    log_error "未提取到任何 Agent 二进制，请检查镜像是否包含目标架构"
    exit 1
  fi

  log_ok "Agent 下载文件已准备: ${downloads_dir}"
}

pull_images() {
  cd "${INSTALL_DIR}"

  if [[ -n "${GHCR_TOKEN:-}" ]]; then
    local ghcr_user
    ghcr_user="${GHCR_USERNAME:-${GITHUB_ACTOR:-}}"
    if [[ -z "${ghcr_user}" ]]; then
      log_error "提供 GHCR_TOKEN 时需要同时设置 GHCR_USERNAME 或 GITHUB_ACTOR"
      exit 1
    fi
    echo "${GHCR_TOKEN}" | docker login ghcr.io -u "${ghcr_user}" --password-stdin
    log_ok "GHCR 登录成功"
  fi

  log_info "正在拉取镜像，请稍候..."
  compose pull --quiet
  prepare_agent_downloads
  log_ok "所有镜像拉取完成"
  compose images || true
}

run_migrations() {
  cd "${INSTALL_DIR}"
  log_info "启动数据库并执行迁移..."
  compose up -d postgres
  POSTGRES_STARTED=1

  local db_user db_name waited
  db_user="$(get_env_var POSTGRES_USER)"
  db_name="$(get_env_var POSTGRES_DB)"
  db_user="${db_user:-nodepass}"
  db_name="${db_name:-nodepass_hub}"

  waited=0
  while [[ "${waited}" -lt 60 ]]; do
    if compose exec -T postgres pg_isready -U "${db_user}" -d "${db_name}" >/dev/null 2>&1; then
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done

  if [[ "${waited}" -ge 60 ]]; then
    log_error "PostgreSQL 健康检查超时"
    exit 1
  fi

  compose run --rm migrate
  log_ok "数据库迁移完成"
}

start_services() {
  cd "${INSTALL_DIR}"
  compose up -d
  SERVICES_STARTED=1

  log_info "等待服务就绪..."
  local max_wait waited
  max_wait=120
  waited=0

  while [[ "${waited}" -lt "${max_wait}" ]]; do
    if curl -sf "http://localhost/api/v1/health/ready" >/dev/null 2>&1; then
      log_ok "Hub API 就绪"
      return
    fi

    sleep 3
    waited=$((waited + 3))
    if (( waited % 15 == 0 )); then
      log_info "已等待 ${waited}s..."
    fi
  done

  log_error "服务启动超时，请查看日志：docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} logs"
  exit 1
}

setup_admin() {
  echo ""
  echo -e "${BOLD}── 创建管理员账号 ────────────────────${NC}"

  ADMIN_USER="$(read_tty_line "管理员用户名（默认 admin）: ")"
  ADMIN_USER="${ADMIN_USER:-admin}"

  local admin_pass
  while true; do
    admin_pass="$(read_tty_secret "管理员密码（≥12位，含大小写字母和数字）: ")"
    if echo "${admin_pass}" | grep -qE '^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{12,}$'; then
      break
    fi
    log_warn "密码不符合要求，请重新输入"
  done

  compose exec -T hub /nodepass-hub create-admin \
    --username "${ADMIN_USER}" \
    --password "${admin_pass}" \
    --email ""

  log_ok "管理员账号 '${ADMIN_USER}' 初始化完成"
}

setup_systemd() {
  local unit_file tmp_file
  unit_file="/etc/systemd/system/nodepass.service"
  tmp_file="$(mktemp)"

  cat > "${tmp_file}" <<UNIT
[Unit]
Description=NodePass 管理平台
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d
ExecStop=docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

  mv "${tmp_file}" "${unit_file}"
  systemctl daemon-reload
  systemctl enable nodepass
  log_ok "已配置开机自动启动"
}

print_summary() {
  local agent_secret external_key
  agent_secret="$(cat "${SECRETS_DIR}/agent_hmac_secret.txt" 2>/dev/null || true)"
  external_key="$(cat "${SECRETS_DIR}/external_api_key.txt" 2>/dev/null || true)"

  DOMAIN="${DOMAIN:-$(get_env_var DOMAIN)}"

  echo ""
  echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
  echo -e "${GREEN}${BOLD}  🎉 NodePass 管理平台部署成功！${NC}"
  echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
  echo ""
  echo -e "  🌐 访问地址:     ${BOLD}https://${DOMAIN}${NC}"
  echo -e "  👤 管理员账号:   ${BOLD}${ADMIN_USER}${NC}"
  echo -e "  📁 部署目录:     ${INSTALL_DIR}"
  echo ""
  echo -e "${YELLOW}${BOLD}  ⚠️  请保存以下密钥（仅显示一次）：${NC}"
  echo -e "  Agent HMAC 密钥:   ${BOLD}${agent_secret}${NC}"
  echo -e "  外部 API 密钥:     ${BOLD}${external_key}${NC}"
  echo -e "  内部接口令牌:      ${INSTALL_DIR}/secrets/internal_token.txt"
  echo -e "  JWT 私钥:          ${INSTALL_DIR}/secrets/jwt_private.pem"
  echo ""
  echo -e "${BOLD}  常用命令：${NC}"
  echo -e "  查看日志:   docker compose -f ${COMPOSE_FILE} --env-file ${ENV_FILE} logs -f"
  echo -e "  重启服务:   systemctl restart nodepass"
  echo -e "  升级版本:   bash ${INSTALL_DIR}/upgrade.sh <version>"
  echo -e "  一键更新:   bash ${INSTALL_DIR}/update.sh --version latest"
  echo ""
}

main() {
  echo -e "${BOLD}NodePass 管理平台 — 一键部署向导${NC}"
  echo "────────────────────────────────────────"

  log_step "Step 0/9  环境预检"
  check_os
  check_arch
  check_root
  check_ports
  check_network

  log_step "Step 1/9  安装 Docker & Compose"
  install_docker
  install_compose

  log_step "Step 2/9  下载部署文件"
  setup_deploy_dir
  download_files

  log_step "Step 3/9  交互式配置"
  configure_env

  log_step "Step 4/9  生成密钥材料"
  generate_secrets

  log_step "Step 5/9  拉取 Docker 镜像"
  pull_images

  log_step "Step 6/9  数据库初始化"
  run_migrations

  log_step "Step 7/9  启动服务"
  start_services

  log_step "Step 8/9  初始化管理员账号"
  setup_admin

  log_step "Step 9/9  配置开机自启"
  setup_systemd

  print_summary
}

main "$@"

# Quality checklist:
# - ShellCheck static analysis should run in CI: shellcheck deploy/setup.sh
# - set -euo pipefail ensures external command failures abort immediately
# - Sensitive inputs use read -s without terminal echo
# - File writes use atomic temp file + mv to avoid partial writes
# - Trap handlers support Ctrl+C interruption and cleanup
# - cleanup() removes temporary migration containers created during this run
