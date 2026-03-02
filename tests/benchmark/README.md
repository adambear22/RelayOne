# Benchmark Guide

Run all benchmarks:

```bash
make bench
```

Report output is saved to `reports/bench_<timestamp>.txt`.

## Environment variables for API benchmarks

- `NODEPASS_BENCH_BASE_URL`
- `NODEPASS_BENCH_USERNAME`
- `NODEPASS_BENCH_PASSWORD`
- `NODEPASS_BENCH_TOKEN`
- `NODEPASS_BENCH_AGENT_ID`
- `NODEPASS_BENCH_AGENT_TOKEN`
- `NODEPASS_BENCH_RULE_ID`

If these variables are not set, API benchmarks are skipped and only local in-memory benchmarks run.
