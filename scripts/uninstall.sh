#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/wizard_ui.sh"

DEPLOY_DIR="/opt/nodepass"
ENV_FILE="${DEPLOY_DIR}/.env"

compose() {
  (cd "${DEPLOY_DIR}" && docker compose "$@")
}

main() {
  show_banner
  section "NodePass 平台卸载"

  if [[ ! -d "${DEPLOY_DIR}" ]]; then
    warn "部署目录不存在：${DEPLOY_DIR}"
    info "无需卸载"
    exit 0
  fi

  local hub_image="ghcr.io/adambear22/nodepass-hub"
  local frontend_image="ghcr.io/adambear22/nodepass-frontend"
  local agent_image="ghcr.io/adambear22/nodepass-agent"
  local hub_version="latest"
  local frontend_version="latest"
  local agent_version="latest"

  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck source=/dev/null
    source "${ENV_FILE}"
    hub_image="${HUB_IMAGE:-$hub_image}"
    frontend_image="${FRONTEND_IMAGE:-$frontend_image}"
    agent_image="${AGENT_IMAGE:-$agent_image}"
    hub_version="${HUB_VERSION:-$hub_version}"
    frontend_version="${FRONTEND_VERSION:-$frontend_version}"
    agent_version="${AGENT_VERSION:-$agent_version}"
  fi

  warn "此操作将停止并删除所有 NodePass 容器"
  ask_yn "是否同时删除数据库数据？（选 n 则保留数据卷）" DELETE_DATA n
  ask_yn "确认执行卸载？此操作不可逆" CONFIRMED n

  if [[ "${CONFIRMED}" != "true" ]]; then
    info "已取消"
    exit 0
  fi

  if [[ -f "${DEPLOY_DIR}/docker-compose.yml" ]]; then
    if [[ "${DELETE_DATA}" == "true" ]]; then
      compose down -v --remove-orphans || true
      warn "数据库数据已删除"
    else
      compose down --remove-orphans || true
      info "数据库数据已保留"
    fi
  else
    warn "未找到 docker-compose.yml，跳过容器编排卸载"
  fi

  ask_yn "是否同时删除 Docker 镜像？" DELETE_IMAGES n
  if [[ "${DELETE_IMAGES}" == "true" ]]; then
    docker image rm \
      "${hub_image}:${hub_version}" \
      "${frontend_image}:${frontend_version}" \
      "${agent_image}:${agent_version}" \
      2>/dev/null || true
    info "镜像删除已执行（不存在的镜像会自动跳过）"
  fi

  ask_yn "是否删除部署目录 ${DEPLOY_DIR}？（含配置与密钥）" DELETE_DIR n
  if [[ "${DELETE_DIR}" == "true" ]]; then
    rm -rf "${DEPLOY_DIR}"
    warn "部署目录已删除"
  fi

  success "NodePass 已卸载完成"
}

main "$@"
