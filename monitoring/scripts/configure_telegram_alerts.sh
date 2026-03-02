#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITORING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${MONITORING_DIR}/alertmanager/alertmanager.yml"

BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
CHAT_ID="${TELEGRAM_ALERT_CHAT_ID:-}"
AUTO_RESTART="0"

usage() {
  cat <<'USAGE'
Usage:
  bash monitoring/scripts/configure_telegram_alerts.sh --bot-token <token> --chat-id <id> [--restart]

Options:
  --bot-token <token>   Telegram bot token from BotFather
  --chat-id <id>        Telegram chat ID (integer)
  --restart             Restart alertmanager container after updating config
  -h, --help            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bot-token)
      BOT_TOKEN="${2:-}"
      shift 2
      ;;
    --chat-id)
      CHAT_ID="${2:-}"
      shift 2
      ;;
    --restart)
      AUTO_RESTART="1"
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

if [[ -z "${BOT_TOKEN}" ]]; then
  echo "Missing --bot-token (or TELEGRAM_BOT_TOKEN)" >&2
  exit 1
fi

if [[ -z "${CHAT_ID}" || ! "${CHAT_ID}" =~ ^-?[0-9]+$ ]]; then
  echo "Invalid --chat-id (must be integer)" >&2
  exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "Config file not found: ${CONFIG_FILE}" >&2
  exit 1
fi

tmp_file="$(mktemp)"
awk -v token="${BOT_TOKEN}" -v chat_id="${CHAT_ID}" '
  BEGIN {
    bot_updated = 0
    chat_updated = 0
  }
  /^[[:space:]-]*bot_token:/ && bot_updated == 0 {
    prefix = $0
    sub(/bot_token:.*/, "", prefix)
    print prefix "bot_token: \"" token "\""
    bot_updated = 1
    next
  }
  /^[[:space:]-]*chat_id:/ && chat_updated == 0 {
    prefix = $0
    sub(/chat_id:.*/, "", prefix)
    print prefix "chat_id: " chat_id
    chat_updated = 1
    next
  }
  { print }
  END {
    if (bot_updated == 0 || chat_updated == 0) {
      print "Failed to update bot_token/chat_id. Check alertmanager.yml structure." > "/dev/stderr"
      exit 2
    }
  }
' "${CONFIG_FILE}" > "${tmp_file}"

mv "${tmp_file}" "${CONFIG_FILE}"

echo "Updated Telegram alert config: ${CONFIG_FILE}"

if [[ "${AUTO_RESTART}" == "1" ]]; then
  (
    cd "${MONITORING_DIR}"
    docker compose -f docker-compose.monitoring.yml restart alertmanager
  )
fi
