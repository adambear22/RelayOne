#!/bin/bash
set -euo pipefail
mkdir -p scripts/dev-keys
openssl genrsa -out scripts/dev-keys/jwt_private.pem 2048
openssl rsa -in scripts/dev-keys/jwt_private.pem -pubout -out scripts/dev-keys/jwt_public.pem
echo "✓ 开发用 JWT RSA 密钥对已生成到 scripts/dev-keys/"
echo "  ⚠️  这些密钥仅用于本地开发，已在 .gitignore 中排除"
