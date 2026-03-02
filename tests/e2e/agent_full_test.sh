#!/usr/bin/env bash
# Agent full E2E smoke test for clean Linux hosts.
# Required env:
#   PANEL_URL=wss://panel.example.com/ws/agent
#   DEPLOY_TOKEN=tok_xxx
# Optional env:
#   INSTALL_DIR=/opt/nodepass-agent-e2e

set -euo pipefail

PANEL_URL="${PANEL_URL:-}"
DEPLOY_TOKEN="${DEPLOY_TOKEN:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodepass-agent}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SCRIPT="${REPO_ROOT}/scripts/install.sh"

log() {
  printf '[e2e] %s\n' "$1"
}

die() {
  printf '[e2e][error] %s\n' "$1" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "please run as root"
  fi
}

require_inputs() {
  [[ -n "${PANEL_URL}" ]] || die "missing PANEL_URL"
  [[ -n "${DEPLOY_TOKEN}" ]] || die "missing DEPLOY_TOKEN"
  [[ -x "${INSTALL_SCRIPT}" ]] || die "install script not executable: ${INSTALL_SCRIPT}"
}

wait_for_credentials() {
  local config_file="$1"
  local timeout="$2"
  local elapsed=0
  local addr key

  while [[ "${elapsed}" -lt "${timeout}" ]]; do
    addr="$(grep '^DEPLOY_DEFAULT_MASTER_ADDR' "${config_file}" | awk -F= '{print $2}' | tr -d '[:space:]' || true)"
    key="$(grep '^DEPLOY_DEFAULT_MASTER_API_KEY' "${config_file}" | awk -F= '{print $2}' | tr -d '[:space:]' || true)"
    if [[ -n "${addr}" && -n "${key}" ]]; then
      printf '%s\n' "${key}"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  return 1
}

main() {
  require_root
  require_inputs

  log "running installer"
  bash "${INSTALL_SCRIPT}" -y \
    --panel "${PANEL_URL}" \
    --token "${DEPLOY_TOKEN}" \
    --install-dir "${INSTALL_DIR}"

  log "checking service status"
  systemctl is-active --quiet nodepass-agent || die "nodepass-agent service is not active"

  local config_file
  config_file="${INSTALL_DIR}/agent.conf"
  [[ -f "${config_file}" ]] || die "missing config file: ${config_file}"

  log "waiting credentials after first install"
  local first_key
  first_key="$(wait_for_credentials "${config_file}" 60)" || die "credentials not written after install"

  log "checking key logs"
  journalctl -u nodepass-agent -n 120 --no-pager | grep -E "nodepass binary ready|credentials saved to agent.conf|agent starting" >/dev/null \
    || die "expected startup logs not found"

  log "restart service to verify cached credentials path"
  systemctl restart nodepass-agent
  sleep 3
  journalctl -u nodepass-agent -n 120 --no-pager | grep -i "using cached credentials" >/dev/null \
    || die "cached credentials log not found after restart"

  log "kill nodepass child process to trigger watchdog"
  pkill -9 -f "${INSTALL_DIR}/bin/nodepass" || true
  sleep 8

  local second_key
  second_key="$(wait_for_credentials "${config_file}" 60)" || die "credentials missing after watchdog restart"
  if [[ "${first_key}" == "${second_key}" ]]; then
    die "expected credential rotation after watchdog restart, but API key did not change"
  fi

  log "E2E checks passed"
}

main "$@"
