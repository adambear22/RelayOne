# NodePass Agent

NodePass Agent manages local NodePass processes and keeps them synced with Hub over WebSocket.

## Build

- `make build-linux-amd64`
- `make build-linux-arm64`
- `make build-linux-386`

## Run

```bash
HUB_URL=ws://127.0.0.1:8080/ws/agent \
AGENT_ID=<node-id-uuid> \
INTERNAL_TOKEN=<agent-token> \
WORK_DIR=/opt/nodepass-agent \
go run ./cmd/agent --config /opt/nodepass-agent/agent.conf --workdir /opt/nodepass-agent
```

The agent supports both config styles:

- legacy INI (`[agent]`, `[nodepass]`, `DEPLOY_DEFAULT_MASTER_ADDR`, `DEPLOY_DEFAULT_MASTER_API_KEY`)
- JSON (`master_addr`, `api_key`, `updated_at`)

## Test

- `go test ./...`
- `go test -race ./...`

## Embedded NodePass binary

Expected files in `embed/`:

- `nodepass_linux_amd64`
- `nodepass_linux_arm64`
- `nodepass_linux_386`
- `VERSION`

Large binary artifacts are ignored by `.gitignore`. Use CI or `make download-nodepass` with `NODEPASS_RELEASE_BASE` to inject real binaries.
