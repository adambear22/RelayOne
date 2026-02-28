#!/bin/bash
set -euo pipefail

TARGET_VERSION="${1:-}"
if [[ -z "${TARGET_VERSION}" ]]; then
  echo "用法: $0 <version-tag>"
  echo "示例: $0 v1.2.3"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then
  DEPLOY_DIR="${SCRIPT_DIR}"
elif [[ -f "${SCRIPT_DIR}/deploy/docker-compose.yml" ]]; then
  DEPLOY_DIR="${SCRIPT_DIR}/deploy"
else
  echo "未找到 docker-compose.yml（期望路径：${SCRIPT_DIR}/docker-compose.yml）"
  exit 1
fi

ENV_FILE="${DEPLOY_DIR}/.env"
COMPOSE_FILE="${DEPLOY_DIR}/docker-compose.yml"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "未找到 ${ENV_FILE}，请先初始化部署环境"
  exit 1
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "未找到 ${COMPOSE_FILE}"
  exit 1
fi
COMPOSE_ARGS=(-f "${COMPOSE_FILE}")

PREV_HUB_VERSION=$(grep -E '^HUB_VERSION=' "${ENV_FILE}" | head -1 | cut -d '=' -f2- || true)
PREV_FRONTEND_VERSION=$(grep -E '^FRONTEND_VERSION=' "${ENV_FILE}" | head -1 | cut -d '=' -f2- || true)
PREV_AGENT_VERSION=$(grep -E '^AGENT_VERSION=' "${ENV_FILE}" | head -1 | cut -d '=' -f2- || true)

BACKUP_FILE="$(mktemp "${DEPLOY_DIR}/.env.backup.XXXXXX")"
cp "${ENV_FILE}" "${BACKUP_FILE}"

restore_env() {
  cp "${BACKUP_FILE}" "${ENV_FILE}"
}

cleanup() {
  rm -f "${BACKUP_FILE}"
}
trap cleanup EXIT

set_env_var() {
  local key="$1"
  local value="$2"

  if grep -qE "^${key}=" "${ENV_FILE}"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "${ENV_FILE}"
  else
    echo "${key}=${value}" >> "${ENV_FILE}"
  fi
}

echo "准备升级到版本 ${TARGET_VERSION}..."
set_env_var "HUB_VERSION" "${TARGET_VERSION}"
set_env_var "FRONTEND_VERSION" "${TARGET_VERSION}"
set_env_var "AGENT_VERSION" "${TARGET_VERSION}"

echo "拉取最新镜像..."
docker compose "${COMPOSE_ARGS[@]}" --env-file "${ENV_FILE}" pull

echo "滚动更新 hub/frontend 服务..."
docker compose "${COMPOSE_ARGS[@]}" --env-file "${ENV_FILE}" up -d --no-deps hub frontend

echo "执行 Hub 健康检查..."
if ! docker compose "${COMPOSE_ARGS[@]}" --env-file "${ENV_FILE}" exec -T hub /nodepass-hub healthcheck; then
  echo "❌ 健康检查失败，开始回滚到上一版本..."
  restore_env

  docker compose "${COMPOSE_ARGS[@]}" --env-file "${ENV_FILE}" pull
  docker compose "${COMPOSE_ARGS[@]}" --env-file "${ENV_FILE}" up -d --no-deps hub frontend

  echo "已回滚: HUB=${PREV_HUB_VERSION:-unknown}, FRONTEND=${PREV_FRONTEND_VERSION:-unknown}, AGENT=${PREV_AGENT_VERSION:-unknown}"
  exit 1
fi

echo "✅ 升级完成"
echo "当前版本: HUB=${TARGET_VERSION}, FRONTEND=${TARGET_VERSION}, AGENT=${TARGET_VERSION}"
