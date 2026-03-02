# Load Test Guide

## WebSocket 10k load test

`make loadtest-ws` runs `TestWebSocket_10kConcurrentAgents` with build tag `loadtest`.

Required environment variables:

- `NODEPASS_WS_URL` - agent WS endpoint, e.g. `ws://localhost:8080/ws/agent`
- `NODEPASS_AGENT_HMAC_SECRET` - same HMAC secret as server config

Optional:

- `LOADTEST_WS_AGENTS` - agent count (default `10000`)

Example:

```bash
NODEPASS_WS_URL=ws://localhost:8080/ws/agent \
NODEPASS_AGENT_HMAC_SECRET=change-me \
LOADTEST_WS_AGENTS=10000 \
make loadtest-ws
```

## k6 mixed API load test

`make loadtest` runs `tests/loadtest/k6_load_test.js`.

Required:

- `BASE_URL` - API base URL

Optional:

- `TOKEN` - Bearer token
- `NODE_ID` - existing node ID for rule create requests
- `K6_VUS` - virtual users (default `100`)
- `K6_DURATION` - test duration (default `5m`)

Example:

```bash
BASE_URL=http://localhost:8080 \
TOKEN=<bearer-token> \
NODE_ID=<node-id> \
K6_VUS=50 \
K6_DURATION=1m \
make loadtest
```
