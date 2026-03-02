#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/nodepass}"
REPO_SLUG="${REPO_SLUG:-adambear22/RelayOne}"
REPO_REF="${REPO_REF:-main}"
TARGET_VERSION="${TARGET_VERSION:-latest}"
SKIP_UPGRADE=0
INSTALL_DIR_EXPLICIT=0
SECRET_RUNTIME_UID="${SECRET_RUNTIME_UID:-65532}"
SECRET_RUNTIME_GID="${SECRET_RUNTIME_GID:-65532}"

usage() {
  cat <<'USAGE'
Usage:
  bash update.sh [options]

Options:
  --version <tag>      Upgrade target version tag (default: latest)
  --ref <git-ref>      Git ref for raw files (default: main)
  --repo <owner/repo>  GitHub repo slug (default: adambear22/RelayOne)
  --install-dir <dir>  Install directory (default: auto-detect, fallback /opt/nodepass)
  --skip-upgrade       Only sync deploy files, skip image upgrade
  -h, --help           Show this help

Examples:
  bash update.sh
  bash update.sh --version v1.3.0
  bash update.sh --ref codex/develop --version latest
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)
        TARGET_VERSION="${2:-}"
        shift 2
        ;;
      --ref)
        REPO_REF="${2:-}"
        shift 2
        ;;
      --repo)
        REPO_SLUG="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        INSTALL_DIR_EXPLICIT=1
        shift 2
        ;;
      --skip-upgrade)
        SKIP_UPGRADE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

require_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi

  if command -v sudo >/dev/null 2>&1 && [[ -f "$0" ]]; then
    exec sudo bash "$0" "$@"
  fi

  echo "Please run as root or use: curl ... | sudo bash -s -- ..." >&2
  exit 1
}

download() {
  local remote_url="$1"
  local target_path="$2"
  local mode="$3"
  local tmp_file

  tmp_file="$(mktemp)"
  if ! curl -fsSL --connect-timeout 15 --retry 3 --retry-delay 2 "${remote_url}" -o "${tmp_file}"; then
    rm -f "${tmp_file}"
    echo "Failed to download: ${remote_url}" >&2
    exit 1
  fi

  install -m "${mode}" "${tmp_file}" "${target_path}"
  rm -f "${tmp_file}"
}

backup_file_if_exists() {
  local src="$1"
  local backup_dir="$2"

  if [[ -f "${src}" ]]; then
    cp -a "${src}" "${backup_dir}/"
  fi
}

is_nodepass_deploy_dir() {
  local dir="$1"
  local compose_file="${dir}/docker-compose.yml"

  [[ -f "${compose_file}" ]] || return 1
  grep -qE 'nodepass-hub|HUB_IMAGE' "${compose_file}"
}

find_deploy_dir() {
  local base="$1"

  if is_nodepass_deploy_dir "${base}"; then
    echo "${base}"
    return 0
  fi

  if is_nodepass_deploy_dir "${base}/deploy"; then
    echo "${base}/deploy"
    return 0
  fi

  return 1
}

detect_install_dir() {
  local cwd
  local detected
  cwd="$(pwd)"

  if [[ "${INSTALL_DIR_EXPLICIT}" -eq 1 ]]; then
    if detected="$(find_deploy_dir "${INSTALL_DIR}")"; then
      INSTALL_DIR="${detected}"
    fi
    return 0
  fi

  if detected="$(find_deploy_dir "${cwd}")"; then
    INSTALL_DIR="${detected}"
    return 0
  fi

  if detected="$(find_deploy_dir "/opt/nodepass")"; then
    INSTALL_DIR="${detected}"
    return 0
  fi

  local candidate
  for candidate in /opt/*; do
    [[ -d "${candidate}" ]] || continue
    if detected="$(find_deploy_dir "${candidate}")"; then
      INSTALL_DIR="${detected}"
      return 0
    fi
  done
}

check_required_secrets() {
  local secrets_dir="$1"
  local missing=0
  local owner_warned=0
  local file
  local required_files=(
    jwt_private.pem
    jwt_public.pem
    agent_hmac_secret.txt
    internal_token.txt
    external_api_key.txt
  )

  for file in "${required_files[@]}"; do
    if [[ ! -s "${secrets_dir}/${file}" ]]; then
      echo "Missing required secret: ${secrets_dir}/${file}" >&2
      missing=1
    fi
  done

  if [[ ! -f "${secrets_dir}/telegram_bot_token.txt" ]]; then
    : > "${secrets_dir}/telegram_bot_token.txt"
    chmod 600 "${secrets_dir}/telegram_bot_token.txt"
    echo "Created optional secret placeholder: ${secrets_dir}/telegram_bot_token.txt"
  fi

  for file in "${required_files[@]}" telegram_bot_token.txt; do
    if [[ -f "${secrets_dir}/${file}" ]]; then
      chmod 600 "${secrets_dir}/${file}" || true
      if ! chown "${SECRET_RUNTIME_UID}:${SECRET_RUNTIME_GID}" "${secrets_dir}/${file}" >/dev/null 2>&1; then
        if [[ "${owner_warned}" -eq 0 ]]; then
          echo "Warning: failed to set secret owner to ${SECRET_RUNTIME_UID}:${SECRET_RUNTIME_GID}" >&2
          owner_warned=1
        fi
      fi
    fi
  done

  if [[ "${missing}" -eq 1 ]]; then
    echo "Deployment is not fully initialized. Please run deploy/setup.sh first." >&2
    exit 1
  fi
}

get_env_var_from_file() {
  local key="$1"
  local env_file="$2"
  grep -E "^${key}=" "${env_file}" | tail -1 | cut -d '=' -f2-
}

write_app_config_from_env() {
  local deploy_dir="$1"
  local env_file="${deploy_dir}/.env"
  local config_file="${deploy_dir}/config.yaml"
  local db_user db_password db_name domain
  local tmp_file

  db_user="$(get_env_var_from_file "POSTGRES_USER" "${env_file}")"
  db_password="$(get_env_var_from_file "POSTGRES_PASSWORD" "${env_file}")"
  db_name="$(get_env_var_from_file "POSTGRES_DB" "${env_file}")"
  domain="$(get_env_var_from_file "DOMAIN" "${env_file}")"

  tmp_file="$(mktemp)"
  cat > "${tmp_file}" <<EOF
app:
  env: production
server:
  host: 0.0.0.0
  port: 8080
database:
  url: "postgres://${db_user}:${db_password}@postgres:5432/${db_name:-nodepass_hub}?sslmode=disable"
security:
  agent_hmac_secret_file: /run/secrets/agent_hmac_secret
  internal_token_file: /run/secrets/internal_token
cors:
  allow_origins:
    - https://${domain}
    - http://localhost:5173
EOF

  install -m 640 "${tmp_file}" "${config_file}"
  if ! chown "${SECRET_RUNTIME_UID}:${SECRET_RUNTIME_GID}" "${config_file}" >/dev/null 2>&1; then
    chmod 644 "${config_file}"
  fi
  rm -f "${tmp_file}"
}

main() {
  parse_args "$@"
  detect_install_dir

  if [[ -z "${TARGET_VERSION}" ]]; then
    echo "--version cannot be empty" >&2
    exit 1
  fi

  local raw_base
  raw_base="https://raw.githubusercontent.com/${REPO_SLUG}/${REPO_REF}"

  echo "Using deploy directory: ${INSTALL_DIR}"

  mkdir -p "${INSTALL_DIR}"
  if [[ ! -w "${INSTALL_DIR}" ]]; then
    require_root "$@"
  fi

  mkdir -p "${INSTALL_DIR}/backups" "${INSTALL_DIR}/secrets"

  local backup_dir
  backup_dir="${INSTALL_DIR}/backups/update-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "${backup_dir}"

  backup_file_if_exists "${INSTALL_DIR}/docker-compose.yml" "${backup_dir}"
  backup_file_if_exists "${INSTALL_DIR}/Caddyfile" "${backup_dir}"
  backup_file_if_exists "${INSTALL_DIR}/upgrade.sh" "${backup_dir}"
  backup_file_if_exists "${INSTALL_DIR}/update.sh" "${backup_dir}"
  backup_file_if_exists "${INSTALL_DIR}/.env.example" "${backup_dir}"
  backup_file_if_exists "${INSTALL_DIR}/.env" "${backup_dir}"

  echo "Syncing deploy files from ${REPO_SLUG}@${REPO_REF} ..."
  download "${raw_base}/deploy/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml" 644
  download "${raw_base}/deploy/Caddyfile" "${INSTALL_DIR}/Caddyfile" 644
  download "${raw_base}/deploy/upgrade.sh" "${INSTALL_DIR}/upgrade.sh" 755
  download "${raw_base}/deploy/update.sh" "${INSTALL_DIR}/update.sh" 755
  download "${raw_base}/deploy/.env.example" "${INSTALL_DIR}/.env.example" 644

  if [[ "${SKIP_UPGRADE}" -eq 1 ]]; then
    echo "Files synced. Upgrade skipped (--skip-upgrade)."
    echo "Backup saved to: ${backup_dir}"
    exit 0
  fi

  if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    echo "Missing ${INSTALL_DIR}/.env. This looks like a fresh server." >&2
    echo "Please run deployment setup first:" >&2
    echo "  curl -fsSL https://raw.githubusercontent.com/${REPO_SLUG}/${REPO_REF}/deploy/setup.sh | sudo bash" >&2
    exit 1
  fi

  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "Docker + Docker Compose v2 are required." >&2
    exit 1
  fi

  check_required_secrets "${INSTALL_DIR}/secrets"
  write_app_config_from_env "${INSTALL_DIR}"

  echo "Running upgrade to version: ${TARGET_VERSION}"
  bash "${INSTALL_DIR}/upgrade.sh" "${TARGET_VERSION}"
  echo "Update finished. Backup saved to: ${backup_dir}"
}

main "$@"
