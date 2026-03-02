#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
AGENT_BIN="${REPO_ROOT}/nodepass-agent/bin/nodepass-agent"

if [[ ! -x "${AGENT_BIN}" ]]; then
  echo "[smoke] agent binary not found, building..."
  (cd "${REPO_ROOT}" && make build-agent)
fi

echo "[smoke] running agent-hub smoke harness"
(cd "${REPO_ROOT}" && go run ./tests/e2e/harness/agent_smoke)
