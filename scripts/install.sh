#!/usr/bin/env bash
# NodePass Agent one-click installer (v2)
# Usage:
#   bash install.sh --panel wss://panel.example.com/ws/agent --token tok_xxx
# Headless:
#   PANEL_URL=wss://panel.example.com/ws/agent DEPLOY_TOKEN=tok_xxx bash install.sh -y

set -euo pipefail

PANEL_URL="${PANEL_URL:-}"
DEPLOY_TOKEN="${DEPLOY_TOKEN:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodepass-agent}"
MASTER_PORT="${MASTER_PORT:-9090}"
CONNECT_ADDR="${CONNECT_ADDR:-}"
PANEL_RELEASE_URL="${PANEL_RELEASE_URL:-}"
AGENT_VERSION="${AGENT_VERSION:-latest}"
AUTO_YES=0

log() {
  printf '[install] %s\n' "$1"
}

warn() {
  printf '[install][warn] %s\n' "$1" >&2
}

die() {
  printf '[install][error] %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
NodePass Agent installer

Options:
  --panel <url>          panel websocket URL (e.g. wss://panel.example.com/ws/agent)
  --token <token>        deploy token
  --install-dir <path>   install directory (default: /opt/nodepass-agent)
  --master-port <port>   nodepass master port (default: 9090)
  --connect-addr <addr>  optional connect_addr in agent.conf
  --release-url <url>    base URL for binaries (default: derived from --panel)
  --agent-version <ver>  agent binary version in release URL (default: latest)
  -y, --yes              non-interactive mode
  -h, --help             show this message

Deprecated and ignored:
  --master-addr <addr>
  --api-key <key>
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --panel)
        PANEL_URL="${2:-}"
        shift 2
        ;;
      --token)
        DEPLOY_TOKEN="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        shift 2
        ;;
      --master-port)
        MASTER_PORT="${2:-}"
        shift 2
        ;;
      --connect-addr)
        CONNECT_ADDR="${2:-}"
        shift 2
        ;;
      --release-url)
        PANEL_RELEASE_URL="${2:-}"
        shift 2
        ;;
      --agent-version)
        AGENT_VERSION="${2:-}"
        shift 2
        ;;
      --master-addr)
        warn "--master-addr is deprecated and ignored in v2"
        shift 2
        ;;
      --api-key)
        warn "--api-key is deprecated and ignored in v2"
        shift 2
        ;;
      -y|--yes)
        AUTO_YES=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

prompt_required_inputs() {
  if [[ -z "${PANEL_URL}" ]]; then
    if [[ "${AUTO_YES}" -eq 1 ]]; then
      die "missing required --panel (or PANEL_URL)"
    fi
    read -r -p "Panel URL (wss://.../ws/agent): " PANEL_URL
  fi

  if [[ -z "${DEPLOY_TOKEN}" ]]; then
    if [[ "${AUTO_YES}" -eq 1 ]]; then
      die "missing required --token (or DEPLOY_TOKEN)"
    fi
    read -r -p "Deploy token: " DEPLOY_TOKEN
  fi
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"

  case "${os}" in
    linux)
      case "${arch}" in
        x86_64|amd64) echo "linux_amd64" ;;
        aarch64|arm64) echo "linux_arm64" ;;
        armv7l|armv7|arm) echo "linux_armv7" ;;
        *) die "unsupported architecture: ${arch}" ;;
      esac
      ;;
    darwin)
      case "${arch}" in
        x86_64|amd64) echo "darwin_amd64" ;;
        arm64|aarch64) echo "darwin_arm64" ;;
        *) die "unsupported architecture: ${arch}" ;;
      esac
      ;;
    *)
      die "unsupported operating system: ${os}"
      ;;
  esac
}

derive_release_url() {
  if [[ -n "${PANEL_RELEASE_URL}" ]]; then
    echo "${PANEL_RELEASE_URL%/}"
    return
  fi

  local stripped
  stripped="${PANEL_URL}"
  stripped="${stripped#wss://}"
  stripped="${stripped#ws://}"
  stripped="${stripped#https://}"
  stripped="${stripped#http://}"
  stripped="${stripped%%/*}"

  if [[ -z "${stripped}" ]]; then
    die "failed to derive release URL from panel URL: ${PANEL_URL}"
  fi

  echo "https://${stripped}/downloads"
}

download_agent() {
  local platform release_url legacy_url legacy_dash_url versioned_url dash_platform tmp_file
  platform="$1"
  release_url="$2"
  dash_platform="${platform/_/-}"
  dash_platform="${dash_platform/_/-}"
  versioned_url="${release_url%/}/nodepass-agent-${AGENT_VERSION}-${dash_platform}"
  legacy_url="${release_url%/}/nodepass-agent-${platform}"
  legacy_dash_url="${release_url%/}/nodepass-agent-${dash_platform}"

  log "downloading agent binary"
  tmp_file="$(mktemp)"

  if curl -fsSL "${versioned_url}" -o "${tmp_file}"; then
    log "downloaded from: ${versioned_url}"
  elif curl -fsSL "${legacy_url}" -o "${tmp_file}"; then
    log "downloaded from fallback: ${legacy_url}"
  elif curl -fsSL "${legacy_dash_url}" -o "${tmp_file}"; then
    log "downloaded from fallback: ${legacy_dash_url}"
  else
    rm -f "${tmp_file}"
    die "failed to download agent binary"
  fi

  mkdir -p "${INSTALL_DIR}/bin"
  install -m 755 "${tmp_file}" "${INSTALL_DIR}/bin/nodepass-agent"
  rm -f "${tmp_file}"
}

generate_agent_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
    return
  fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    tr -d '\n' < /proc/sys/kernel/random/uuid
    return
  fi
  date +%s | sha256sum | awk '{print $1}'
}

write_base_config() {
  local agent_id config_path tmp_file
  config_path="${INSTALL_DIR}/agent.conf"
  agent_id="$(generate_agent_id)"
  tmp_file="$(mktemp)"

  cat > "${tmp_file}" <<EOF
# NodePass Agent configuration
[agent]
agent_id = ${agent_id}
panel_url = ${PANEL_URL}
deploy_token = ${DEPLOY_TOKEN}
connect_addr = ${CONNECT_ADDR}
egress_network =

[nodepass]
# Filled by agent automatically on first start.
DEPLOY_DEFAULT_MASTER_ADDR =
DEPLOY_DEFAULT_MASTER_API_KEY =
master_port = ${MASTER_PORT}
start_timeout = 30

[panel]
heartbeat_interval = 30
command_timeout = 30
EOF

  install -m 600 "${tmp_file}" "${config_path}"
  rm -f "${tmp_file}"
  log "wrote base config: ${config_path}"
}

create_systemd_service() {
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required"

  local service_file tmp_file
  service_file="/etc/systemd/system/nodepass-agent.service"
  tmp_file="$(mktemp)"

  cat > "${tmp_file}" <<EOF
[Unit]
Description=NodePass Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/nodepass-agent --config ${INSTALL_DIR}/agent.conf --workdir ${INSTALL_DIR}
Restart=on-failure
RestartSec=5s
KillMode=process
TimeoutStopSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nodepass-agent

[Install]
WantedBy=multi-user.target
EOF

  install -m 644 "${tmp_file}" "${service_file}"
  rm -f "${tmp_file}"
  log "wrote systemd service: ${service_file}"
}

wait_for_credentials() {
  local conf_file="$1"
  local timeout="$2"
  local elapsed=0
  local addr key

  printf 'Waiting for credentials'
  while [[ "${elapsed}" -lt "${timeout}" ]]; do
    addr="$(grep '^DEPLOY_DEFAULT_MASTER_ADDR' "${conf_file}" | awk -F= '{print $2}' | tr -d '[:space:]' || true)"
    key="$(grep '^DEPLOY_DEFAULT_MASTER_API_KEY' "${conf_file}" | awk -F= '{print $2}' | tr -d '[:space:]' || true)"
    if [[ -n "${addr}" && -n "${key}" ]]; then
      printf '\n  MASTER_ADDR = %s\n' "${addr}"
      printf '  API_KEY     = %.8s...\n' "${key}"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    printf '.'
  done

  printf '\n'
  die "credentials not written within ${timeout}s; check logs: journalctl -u nodepass-agent -n 50"
}

ensure_root_on_linux() {
  if [[ "$(uname -s)" == "Linux" && "${EUID}" -ne 0 ]]; then
    die "please run as root on Linux"
  fi
}

main() {
  parse_args "$@"
  prompt_required_inputs
  ensure_root_on_linux

  local platform release_url
  platform="$(detect_platform)"
  release_url="$(derive_release_url)"

  log "platform: ${platform}"
  download_agent "${platform}" "${release_url}"
  write_base_config

  if [[ "${platform}" == linux_* ]]; then
    create_systemd_service
    systemctl daemon-reload
    systemctl enable --now nodepass-agent
    wait_for_credentials "${INSTALL_DIR}/agent.conf" 60
    log "installation completed"
    log "logs: journalctl -u nodepass-agent -f"
  else
    warn "systemd setup skipped on non-linux platform (${platform})"
    log "binary installed at ${INSTALL_DIR}/bin/nodepass-agent"
    log "run manually: ${INSTALL_DIR}/bin/nodepass-agent --config ${INSTALL_DIR}/agent.conf --workdir ${INSTALL_DIR}"
  fi
}

main "$@"
