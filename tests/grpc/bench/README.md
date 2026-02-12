# gRPC Benchmark Harness

This benchmark suite measures unary gRPC transport behavior for HTTP/2 and
HTTP/3 using local loopback fixtures and emits machine-readable JSON reports.

## Coverage

The harness includes scenarios for:

- HTTP/2 latency/throughput across payload sizes
- HTTP/3 latency/throughput across payload sizes
- Compression tradeoff checks:
  - HTTP/2 request compression enabled
  - HTTP/3 request compression marked `unsupported`

If HTTP/3 runtime transport support is unavailable in the current environment,
HTTP/3 scenarios are marked `skipped` in the report.

## Run

```bash
scripts/grpc-bench/run.sh --build-dir build --report build/grpc-bench-report.json
```

Quick smoke profile:

```bash
scripts/grpc-bench/run.sh --build-dir build --smoke
```

## Report Format

Reports include:

- Environment metadata (host, OS, CPU count)
- Config metadata (iterations, warmup)
- Per-scenario metrics:
  - `avg_latency_ms`
  - `p50_latency_ms`
  - `p95_latency_ms`
  - `p99_latency_ms`
  - `throughput_rps`

See `tests/grpc/bench/report-template.json` for a template.
