# 部署指南

## 部署要求

- 服务器：2 核 CPU、4 GB RAM、20 GB 磁盘
- 系统：Ubuntu 22.04 LTS（推荐）
- 软件：Docker 24+、Docker Compose v2
- 网络：域名已解析到服务器公网 IP，80/443 端口已放通

## 快速部署

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/<ORG>/nodepass-hub/main/deploy/setup.sh)"
```

## 手动部署

1. 克隆仓库并进入目录：
   ```bash
   git clone https://github.com/<ORG>/nodepass-hub.git
   cd nodepass-hub
   ```
2. 准备配置文件：
   ```bash
   cp deploy/.env.example deploy/.env
   # 编辑 deploy/.env
   ```
3. 生成和准备密钥（放到 `deploy/secrets/`）：
   - `jwt_private.pem`
   - `jwt_public.pem`
   - `agent_hmac_secret.txt`
   - `telegram_bot_token.txt`
   - `external_api_key.txt`
4. 启动服务：
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
   ```
5. 检查运行状态：
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps
   ```

## 常用运维命令

- 查看日志：
  ```bash
  docker compose -f deploy/docker-compose.yml --env-file deploy/.env logs -f
  ```
- 重启服务：
  ```bash
  docker compose -f deploy/docker-compose.yml --env-file deploy/.env restart hub frontend caddy
  ```
- 备份数据库（立即执行一次）：
  ```bash
  docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T postgres \
    pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "deploy/backups/manual-$(date +%F-%H%M%S).sql"
  ```
- 升级版本：
  ```bash
  bash deploy/upgrade.sh v1.2.3
  ```

## 回滚

1. 编辑 `deploy/.env`，将 `HUB_VERSION` 和 `FRONTEND_VERSION` 改为旧版本 tag。
2. 执行：
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --no-deps hub frontend
   ```
