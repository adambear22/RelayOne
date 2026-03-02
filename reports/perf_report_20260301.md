# Performance Report

## Run metadata

- Date: 2026-03-01
- Branch: codex/develop
- Environment: docker compose dev (`postgres` + `hub` + `frontend`)
- Host: Apple M4 (darwin/arm64)

## WebSocket load (10k agents)

- Command: `NODEPASS_WS_URL=ws://localhost:8080/ws/agent NODEPASS_AGENT_HMAC_SECRET=*** LOADTEST_WS_AGENTS=10000 go test -tags=loadtest -run TestWebSocket_10kConcurrentAgents -count=1 -v ./tests/loadtest/...`
- Result: connected `10000`, failed `0`
- Duration: `1m10.660s`

## API benchmark

- Command: `make bench`
- Measured benchmark: `BenchmarkSSE_PublishToAll_1000clients`
- Result: `12.50 ns/op`, `0 B/op`, `0 allocs/op`
- Note: API endpoint benchmarks require `NODEPASS_BENCH_*` env vars and were skipped in this run.

## k6 mixed load

- Command: `BASE_URL=http://localhost:8080 K6_VUS=50 K6_DURATION=1m TOKEN=*** make loadtest`
- Scenario: 50 VUs, 1 minute (mixed read/write/SSE)
- `http_req_duration` p95: `8.55ms`
- `http_req_failed`: `0.00%`
- Throughput: `49.70 req/s` (`3000` total requests)

## Findings

1. WS load test achieved 10k concurrent agent connections with zero connection failures.
2. Mixed API load met latency threshold (`p95 < 100ms`) and error threshold.
3. Current benchmark coverage is valid but API benchmark data is incomplete without `NODEPASS_BENCH_*` inputs.

## Next actions

1. Run full 5-minute k6 profile (`K6_VUS=100 K6_DURATION=5m`) and compare p95/p99.
2. Provide `NODEPASS_BENCH_*` env vars to execute Login/ListRules/Traffic benchmark cases.
3. Collect CPU/memory telemetry during WS load to validate resource targets formally.
