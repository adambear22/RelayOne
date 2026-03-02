# NodePass Monitoring Stack

## Files

- `docker-compose.monitoring.yml`: Prometheus + Grafana + Alertmanager stack
- `prometheus/prometheus.yml`: scrape and alerting pipeline
- `prometheus/alerts.yml`: NodePass alert rules
- `alertmanager/alertmanager.yml`: Telegram receiver config
- `scripts/configure_telegram_alerts.sh`: write Telegram bot token + chat id
- `scripts/send_test_alert.sh`: push a manual test alert into Alertmanager

## Start

Run in this directory:

```bash
docker compose -f docker-compose.monitoring.yml up -d
```

For local development with `docker/compose.dev.yml`:

```bash
NODEPASS_DOCKER_NETWORK=docker_default \
NODEPASS_INTERNAL_TOKEN_FILE=./secrets/internal_token.txt \
docker compose -f docker-compose.monitoring.yml up -d
```

By default monitoring ports bind to localhost (`127.0.0.1`). To expose ports:

```bash
MONITORING_BIND_HOST=0.0.0.0
```

## Access

- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`
- Grafana: `http://localhost:3000`

If proxied by Caddy:

- `https://<your-domain>/grafana`
- `https://<your-domain>/prometheus`
- `https://<your-domain>/alertmanager`

## Prerequisites

1. NodePass core stack is running.
2. Internal token secret exists (production default: `/opt/nodepass/secrets/internal_token.txt`).
3. Docker network exists (production default: `nodepass_internal`).
4. For Grafana subpath:
   - `GRAFANA_ROOT_URL=https://<your-domain>/grafana`
   - `GRAFANA_SERVE_FROM_SUB_PATH=true`

## Configure Telegram alerts

```bash
bash monitoring/scripts/configure_telegram_alerts.sh \
  --bot-token "<bot-token-from-botfather>" \
  --chat-id "<telegram-chat-id>" \
  --restart
```

Environment variable mode also works:

```bash
TELEGRAM_BOT_TOKEN="<token>" \
TELEGRAM_ALERT_CHAT_ID="<chat-id>" \
bash monitoring/scripts/configure_telegram_alerts.sh --restart
```

If `bot_token` / `chat_id` are placeholders, Alertmanager will retry and log `telegram: Not Found (404)`.

## Trigger a test alert

Send a manual test alert through Alertmanager:

```bash
bash monitoring/scripts/send_test_alert.sh \
  --alert-name NodePassPipelineTest \
  --duration 3m
```

The script posts to `/api/v2/alerts` and verifies the alert becomes active.

Check delivery logs:

```bash
docker logs --tail 50 nodepass-alertmanager
```

Optional quick checks:

```bash
curl -s "http://localhost:9090/api/v1/query?query=up%7Bjob%3D%22nodepass-hub%22%7D"
curl -s "http://localhost:9093/api/v2/alerts" | grep -q "NodePassPipelineTest" && echo ok
```

## Caddy subpath smoke checks

When Caddy is configured with `/grafana`, `/prometheus`, `/alertmanager`, verify:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18080/prometheus/-/ready
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18080/alertmanager/-/ready
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18080/grafana/login
```

Expected status: `200`.
