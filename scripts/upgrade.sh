#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wizard_ui.sh"

DEPLOY_DIR="/opt/nodepass"
ENV_FILE="${DEPLOY_DIR}/.env"
TARGET_VERSION=""

usage() {
  cat <<'USAGE'
Usage:
  bash upgrade.sh [version-tag]

Examples:
  bash upgrade.sh
  bash upgrade.sh v1.2.3
USAGE
}

parse_args() {
  case "${1:-}" in
    "")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      TARGET_VERSION="$1"
      ;;
  esac
}

compose() {
  (cd "${DEPLOY_DIR}" && docker compose "$@")
}

set_env_var() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp_file

  tmp_file="$(mktemp)"
  if grep -qE "^${key}=" "${file}"; then
    awk -F= -v k="${key}" -v v="${value}" '
      BEGIN { OFS = "=" }
      $1 == k {
        $1 = k
        $2 = v
        print $1, $2
        next
      }
      { print $0 }
    ' "${file}" > "${tmp_file}"
  else
    cat "${file}" > "${tmp_file}"
    printf '%s=%s\n' "${key}" "${value}" >> "${tmp_file}"
  fi
  mv "${tmp_file}" "${file}"
}

wait_hub_healthy() {
  local max_wait=120
  local elapsed=0

  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if compose exec -T hub /nodepass-hub healthcheck >/dev/null 2>&1; then
      success "hub 健康检查通过"
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done

  error "hub 健康检查超时"
  compose logs --tail=80 hub || true
  return 1
}

rollback() {
  local backup_file="$1"

  warn "开始回滚到旧版本..."
  cp "${backup_file}" "${ENV_FILE}"
  compose pull hub frontend
  compose up -d --no-deps hub frontend
  wait_hub_healthy || true
  warn "回滚完成"
}

main() {
  parse_args "${1:-}"

  show_banner
  section "NodePass 平台升级向导"

  if [[ ! -d "${DEPLOY_DIR}" || ! -f "${ENV_FILE}" ]]; then
    error "未找到部署目录 ${DEPLOY_DIR} 或环境文件 ${ENV_FILE}"
    exit 1
  fi

  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    error "需要 Docker + Docker Compose v2"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "${ENV_FILE}"

  local current_hub_version
  current_hub_version="${HUB_VERSION:-latest}"
  info "当前版本：${current_hub_version}"

  ask_input "目标版本标签（如 v1.2.0，回车使用 latest）" "${TARGET_VERSION:-latest}" TARGET_VERSION

  local backup_file
  backup_file="$(mktemp "${DEPLOY_DIR}/.env.backup.XXXXXX")"
  cp "${ENV_FILE}" "${backup_file}"

  local old_hub old_frontend old_agent
  old_hub="${HUB_VERSION:-latest}"
  old_frontend="${FRONTEND_VERSION:-latest}"
  old_agent="${AGENT_VERSION:-latest}"

  set_env_var "HUB_VERSION" "${TARGET_VERSION}" "${ENV_FILE}"
  set_env_var "FRONTEND_VERSION" "${TARGET_VERSION}" "${ENV_FILE}"
  set_env_var "AGENT_VERSION" "${TARGET_VERSION}" "${ENV_FILE}"

  info "拉取新镜像..."
  if ! compose pull hub frontend; then
    error "拉取镜像失败"
    rollback "${backup_file}"
    rm -f "${backup_file}"
    exit 1
  fi

  info "执行数据库迁移..."
  if ! compose run --rm migrate; then
    error "数据库迁移失败"
    rollback "${backup_file}"
    rm -f "${backup_file}"
    exit 1
  fi

  info "滚动更新 hub..."
  if ! compose up -d --no-deps hub; then
    error "hub 更新失败"
    rollback "${backup_file}"
    rm -f "${backup_file}"
    exit 1
  fi

  if ! wait_hub_healthy; then
    error "新版本 hub 健康检查失败"
    rollback "${backup_file}"
    rm -f "${backup_file}"
    exit 1
  fi

  info "滚动更新 frontend..."
  if ! compose up -d --no-deps frontend; then
    error "frontend 更新失败"
    rollback "${backup_file}"
    rm -f "${backup_file}"
    exit 1
  fi

  rm -f "${backup_file}"
  success "升级完成"
  section "版本信息"
  echo -e "  ${BOLD}HUB:${NC} ${old_hub} -> ${TARGET_VERSION}"
  echo -e "  ${BOLD}FRONTEND:${NC} ${old_frontend} -> ${TARGET_VERSION}"
  echo -e "  ${BOLD}AGENT:${NC} ${old_agent} -> ${TARGET_VERSION}"
  divider
}

main "$@"
