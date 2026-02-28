#!/bin/bash
set -euo pipefail

COMPOSE_FILE="docker/compose.dev.yml"

cat <<'MSG'
⚠️  此脚本仅用于开发环境初始化，生产环境请通过 setup.sh 设置
MSG

docker compose -f "${COMPOSE_FILE}" exec -T postgres psql -U nodepass -d nodepass_hub <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO users (
  username,
  password_hash,
  role,
  status,
  traffic_quota,
  traffic_used,
  bandwidth_limit,
  max_rules
)
VALUES (
  'admin',
  crypt('Admin@123456', gen_salt('bf', 12)),
  'admin',
  'normal',
  1099511627776,
  0,
  0,
  100
)
ON CONFLICT (username) DO UPDATE
SET
  role = EXCLUDED.role,
  status = EXCLUDED.status,
  updated_at = NOW();
SQL

echo "✓ 开发环境管理员已初始化"
echo "  用户名: admin"
echo "  密码:   Admin@123456"
