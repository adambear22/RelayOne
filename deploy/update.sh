#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/nodepass}"
REPO_SLUG="${REPO_SLUG:-adambear22/RelayOne}"
REPO_REF="${REPO_REF:-main}"
TARGET_VERSION="${TARGET_VERSION:-latest}"
SKIP_UPGRADE=0

usage() {
  cat <<'USAGE'
Usage:
  bash update.sh [options]

Options:
  --version <tag>      Upgrade target version tag (default: latest)
  --ref <git-ref>      Git ref for raw files (default: main)
  --repo <owner/repo>  GitHub repo slug (default: adambear22/RelayOne)
  --install-dir <dir>  Install directory (default: /opt/nodepass)
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

main() {
  parse_args "$@"

  if [[ -z "${TARGET_VERSION}" ]]; then
    echo "--version cannot be empty" >&2
    exit 1
  fi

  local raw_base
  raw_base="https://raw.githubusercontent.com/${REPO_SLUG}/${REPO_REF}"

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

  echo "Syncing deploy files from ${REPO_SLUG}@${REPO_REF} ..."
  download "${raw_base}/deploy/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml" 644
  download "${raw_base}/deploy/Caddyfile" "${INSTALL_DIR}/Caddyfile" 644
  download "${raw_base}/deploy/upgrade.sh" "${INSTALL_DIR}/upgrade.sh" 755
  download "${raw_base}/deploy/update.sh" "${INSTALL_DIR}/update.sh" 755
  download "${raw_base}/deploy/.env.example" "${INSTALL_DIR}/.env.example" 644

  if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
    chmod 600 "${INSTALL_DIR}/.env"
    echo "Created ${INSTALL_DIR}/.env from .env.example"
  fi

  if [[ "${SKIP_UPGRADE}" -eq 1 ]]; then
    echo "Files synced. Upgrade skipped (--skip-upgrade)."
    echo "Backup saved to: ${backup_dir}"
    exit 0
  fi

  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "Docker + Docker Compose v2 are required." >&2
    exit 1
  fi

  echo "Running upgrade to version: ${TARGET_VERSION}"
  bash "${INSTALL_DIR}/upgrade.sh" "${TARGET_VERSION}"
  echo "Update finished. Backup saved to: ${backup_dir}"
}

main "$@"
