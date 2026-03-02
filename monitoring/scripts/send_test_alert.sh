#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
ALERT_NAME="${ALERT_NAME:-NodePassManualTest}"
SEVERITY="${SEVERITY:-warning}"
SUMMARY="${SUMMARY:-NodePass monitoring test alert}"
DESCRIPTION="${DESCRIPTION:-Triggered by monitoring/scripts/send_test_alert.sh}"
DURATION="${DURATION:-5m}"
WAIT_SECONDS="${WAIT_SECONDS:-2}"
VERIFY="1"

usage() {
  cat <<'USAGE'
Usage:
  bash monitoring/scripts/send_test_alert.sh [options]

Options:
  --alertmanager-url <url>   Alertmanager base URL (default: http://localhost:9093)
  --alert-name <name>        Alert name label (default: NodePassManualTest)
  --severity <level>         Severity label (default: warning)
  --summary <text>           Alert summary annotation
  --description <text>       Alert description annotation
  --duration <dur>           Alert duration: e.g. 2m, 10m, 1h, 1d (default: 5m)
  --wait-seconds <n>         Seconds to wait before verify check (default: 2)
  --no-verify                Skip follow-up active alert check
  -h, --help                 Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --alertmanager-url)
      ALERTMANAGER_URL="${2:-}"
      shift 2
      ;;
    --alert-name)
      ALERT_NAME="${2:-}"
      shift 2
      ;;
    --severity)
      SEVERITY="${2:-}"
      shift 2
      ;;
    --summary)
      SUMMARY="${2:-}"
      shift 2
      ;;
    --description)
      DESCRIPTION="${2:-}"
      shift 2
      ;;
    --duration)
      DURATION="${2:-}"
      shift 2
      ;;
    --wait-seconds)
      WAIT_SECONDS="${2:-}"
      shift 2
      ;;
    --no-verify)
      VERIFY="0"
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

if [[ ! "${WAIT_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "Invalid --wait-seconds (must be integer >= 0)" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

ALERTMANAGER_URL="${ALERTMANAGER_URL%/}"

payload="$(
python3 - "${ALERT_NAME}" "${SEVERITY}" "${SUMMARY}" "${DESCRIPTION}" "${DURATION}" <<'PY'
import datetime as dt
import json
import re
import sys

name, severity, summary, description, duration = sys.argv[1:6]
match = re.fullmatch(r"(\d+)([smhd])", duration)
if not match:
    raise SystemExit("Invalid --duration. Use formats like 2m, 10m, 1h, 1d.")
value = int(match.group(1))
unit = match.group(2)
seconds_by_unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}
seconds = value * seconds_by_unit[unit]

starts_at = dt.datetime.now(dt.timezone.utc)
ends_at = starts_at + dt.timedelta(seconds=seconds)

def fmt(value):
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")

payload = [
    {
        "labels": {
            "alertname": name,
            "severity": severity,
            "source": "manual",
        },
        "annotations": {
            "summary": summary,
            "description": description,
        },
        "startsAt": fmt(starts_at),
        "endsAt": fmt(ends_at),
    }
]

print(json.dumps(payload, separators=(",", ":")))
PY
)"

curl -fsS -X POST "${ALERTMANAGER_URL}/api/v2/alerts" \
  -H "Content-Type: application/json" \
  -d "${payload}" >/dev/null

echo "Sent test alert '${ALERT_NAME}' to ${ALERTMANAGER_URL}"

if [[ "${VERIFY}" == "1" ]]; then
  sleep "${WAIT_SECONDS}"
  alerts_json="$(curl -fsS "${ALERTMANAGER_URL}/api/v2/alerts")"
  if python3 - "${ALERT_NAME}" "${alerts_json}" <<'PY'
import json
import sys

target_name = sys.argv[1]
alerts = json.loads(sys.argv[2])

active = 0
for alert in alerts:
    labels = alert.get("labels") or {}
    status = alert.get("status") or {}
    if labels.get("alertname") == target_name and status.get("state") == "active":
        active += 1

if active == 0:
    raise SystemExit(1)
print(f"Active alerts matched: {active}")
PY
  then
    echo "Alertmanager accepted and exposed active test alert."
  else
    echo "Warning: no active alert named '${ALERT_NAME}' found yet." >&2
    exit 1
  fi
fi
