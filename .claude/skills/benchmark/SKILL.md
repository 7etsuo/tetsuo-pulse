---
name: benchmark
description: Performance benchmarking and profiling utilities for socket operations. Use when measuring throughput, latency, or profiling hot paths.
---

You are an expert C developer specializing in performance benchmarking, profiling, and optimization for high-performance socket applications.

## Benchmarking Architecture

```
Benchmark Framework
    ├── Micro-benchmarks (single operation timing)
    ├── Throughput tests (ops/sec, bytes/sec)
    ├── Latency tests (percentiles: p50, p99, p999)
    ├── Memory profiling (allocations, cache misses)
    └── Flamegraph generation (CPU hotspots)
```

## Micro-Benchmark Pattern

```c
#include <time.h>

typedef struct BenchResult {
    uint64_t iterations;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
    double mean_ns;
    double stddev_ns;
} BenchResult_T;

// High-resolution timing
static inline uint64_t bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Run benchmark with warmup
BenchResult_T bench_run(const char *name,
                         void (*setup)(void *),
                         void (*fn)(void *),
                         void (*teardown)(void *),
                         void *ctx,
                         int iterations) {
    BenchResult_T result = {0};
    result.min_ns = UINT64_MAX;

    uint64_t *samples = malloc(iterations * sizeof(uint64_t));

    // Warmup (10% of iterations)
    for (int i = 0; i < iterations / 10; i++) {
        if (setup) setup(ctx);
        fn(ctx);
        if (teardown) teardown(ctx);
    }

    // Actual benchmark
    for (int i = 0; i < iterations; i++) {
        if (setup) setup(ctx);

        uint64_t start = bench_now_ns();
        fn(ctx);
        uint64_t elapsed = bench_now_ns() - start;

        if (teardown) teardown(ctx);

        samples[i] = elapsed;
        result.total_ns += elapsed;
        if (elapsed < result.min_ns) result.min_ns = elapsed;
        if (elapsed > result.max_ns) result.max_ns = elapsed;
    }

    result.iterations = iterations;
    result.mean_ns = (double)result.total_ns / iterations;

    // Calculate stddev
    double variance = 0;
    for (int i = 0; i < iterations; i++) {
        double diff = samples[i] - result.mean_ns;
        variance += diff * diff;
    }
    result.stddev_ns = sqrt(variance / iterations);

    free(samples);

    printf("%-30s %10.2f ns/op (±%.2f) [min=%lu, max=%lu]\n",
           name, result.mean_ns, result.stddev_ns,
           result.min_ns, result.max_ns);

    return result;
}
```

## Socket Operation Benchmarks

```c
// Benchmark: Buffer write throughput
void bench_socketbuf_write(void *ctx) {
    SocketBuf_T buf = ctx;
    static char data[4096];
    SocketBuf_write(buf, data, sizeof(data));
}

void bench_socketbuf_write_teardown(void *ctx) {
    SocketBuf_T buf = ctx;
    SocketBuf_clear(buf);
}

// Benchmark: Poll wait latency
void bench_poll_wait(void *ctx) {
    SocketPoll_T poll = ctx;
    SocketEvent_T *events;
    SocketPoll_wait(poll, &events, 0);  // Non-blocking
}

// Benchmark: Connection accept rate
typedef struct {
    Socket_T server;
    Socket_T clients[100];
    int client_count;
} AcceptBenchCtx;

void bench_accept_setup(void *ctx) {
    AcceptBenchCtx *c = ctx;
    // Pre-connect clients
    for (int i = 0; i < 100; i++) {
        c->clients[i] = Socket_new(AF_INET, SOCK_STREAM, 0);
        Socket_setnonblocking(c->clients[i], true);
        connect(Socket_fd(c->clients[i]), ...);
    }
    c->client_count = 100;
}

void bench_accept(void *ctx) {
    AcceptBenchCtx *c = ctx;
    while (c->client_count > 0) {
        Socket_T client = Socket_accept(c->server);
        if (client) {
            Socket_free(&client);
            c->client_count--;
        }
    }
}
```

## Throughput Testing

```c
typedef struct ThroughputResult {
    double bytes_per_sec;
    double ops_per_sec;
    double mbps;
    uint64_t total_bytes;
    uint64_t total_ops;
    double duration_sec;
} ThroughputResult_T;

ThroughputResult_T bench_throughput(Socket_T sender, Socket_T receiver,
                                     size_t message_size,
                                     int duration_sec) {
    ThroughputResult_T result = {0};
    char *send_buf = malloc(message_size);
    char *recv_buf = malloc(message_size);

    uint64_t start = bench_now_ns();
    uint64_t end = start + duration_sec * 1000000000ULL;

    while (bench_now_ns() < end) {
        ssize_t sent = Socket_send(sender, send_buf, message_size, 0);
        if (sent > 0) {
            result.total_bytes += sent;
            result.total_ops++;
        }

        ssize_t recvd = Socket_recv(receiver, recv_buf, message_size, MSG_DONTWAIT);
        // Don't count receives, just drain
    }

    result.duration_sec = (bench_now_ns() - start) / 1e9;
    result.bytes_per_sec = result.total_bytes / result.duration_sec;
    result.ops_per_sec = result.total_ops / result.duration_sec;
    result.mbps = result.bytes_per_sec * 8 / 1e6;

    printf("Throughput: %.2f MB/s (%.2f Mbps), %.0f ops/sec\n",
           result.bytes_per_sec / 1e6, result.mbps, result.ops_per_sec);

    free(send_buf);
    free(recv_buf);
    return result;
}
```

## Latency Percentiles

```c
typedef struct LatencyResult {
    uint64_t p50_ns;
    uint64_t p90_ns;
    uint64_t p99_ns;
    uint64_t p999_ns;
    uint64_t max_ns;
    double mean_ns;
} LatencyResult_T;

int compare_uint64(const void *a, const void *b) {
    return (*(uint64_t *)a > *(uint64_t *)b) -
           (*(uint64_t *)a < *(uint64_t *)b);
}

LatencyResult_T bench_latency(void (*fn)(void *), void *ctx, int samples) {
    LatencyResult_T result = {0};
    uint64_t *latencies = malloc(samples * sizeof(uint64_t));

    for (int i = 0; i < samples; i++) {
        uint64_t start = bench_now_ns();
        fn(ctx);
        latencies[i] = bench_now_ns() - start;
        result.mean_ns += latencies[i];
    }

    result.mean_ns /= samples;

    // Sort for percentiles
    qsort(latencies, samples, sizeof(uint64_t), compare_uint64);

    result.p50_ns = latencies[(int)(samples * 0.50)];
    result.p90_ns = latencies[(int)(samples * 0.90)];
    result.p99_ns = latencies[(int)(samples * 0.99)];
    result.p999_ns = latencies[(int)(samples * 0.999)];
    result.max_ns = latencies[samples - 1];

    printf("Latency: p50=%luμs p90=%luμs p99=%luμs p999=%luμs max=%luμs\n",
           result.p50_ns / 1000, result.p90_ns / 1000,
           result.p99_ns / 1000, result.p999_ns / 1000,
           result.max_ns / 1000);

    free(latencies);
    return result;
}
```

## Memory Profiling

```c
// Track Arena allocations
typedef struct MemoryStats {
    size_t total_allocated;
    size_t peak_allocated;
    size_t allocation_count;
    size_t free_count;
} MemoryStats_T;

// Wrapper to track allocations
void *bench_alloc(Arena_T arena, size_t size, const char *file, int line) {
    stats.total_allocated += size;
    stats.allocation_count++;
    if (stats.total_allocated > stats.peak_allocated) {
        stats.peak_allocated = stats.total_allocated;
    }
    return Arena_alloc(arena, size, file, line);
}

// Report memory usage
void bench_memory_report(const char *label) {
    printf("%s: allocated=%zu bytes, peak=%zu bytes, allocs=%zu\n",
           label, stats.total_allocated, stats.peak_allocated,
           stats.allocation_count);
}
```

## CPU Profiling with perf

```bash
# Record CPU samples
perf record -g ./bench_socketbuf

# Generate flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg

# Cache miss analysis
perf stat -e cache-misses,cache-references,cycles,instructions ./bench_socketbuf

# Branch misprediction
perf stat -e branch-misses,branches ./bench_socketbuf
```

## Benchmark Harness

```c
// Main benchmark runner
int main(int argc, char **argv) {
    Arena_T arena = Arena_new();

    printf("=== Socket Library Benchmarks ===\n\n");

    // SocketBuf benchmarks
    printf("--- SocketBuf Operations ---\n");
    SocketBuf_T buf = SocketBuf_new(arena, 65536);

    bench_run("SocketBuf_write (4KB)", NULL,
              bench_socketbuf_write, bench_socketbuf_write_teardown,
              buf, 100000);

    bench_run("SocketBuf_read (4KB)", bench_socketbuf_read_setup,
              bench_socketbuf_read, NULL,
              buf, 100000);

    // SocketPoll benchmarks
    printf("\n--- SocketPoll Operations ---\n");
    SocketPoll_T poll = SocketPoll_new(1024);

    bench_run("SocketPoll_wait (empty)", NULL,
              bench_poll_wait, NULL,
              poll, 100000);

    // Connection benchmarks
    printf("\n--- Connection Operations ---\n");
    bench_run("Socket_accept", bench_accept_setup,
              bench_accept, NULL,
              &accept_ctx, 1000);

    // Latency tests
    printf("\n--- Latency Distribution ---\n");
    bench_latency(bench_roundtrip, &roundtrip_ctx, 10000);

    // Throughput tests
    printf("\n--- Throughput ---\n");
    bench_throughput(sender, receiver, 4096, 5);

    Arena_dispose(&arena);
    return 0;
}
```

## Benchmark Best Practices

1. **Warmup**: Always warm up before measuring (CPU caches, branch predictors)
2. **Isolation**: Disable frequency scaling, pin to CPU cores
3. **Statistics**: Report mean, stddev, and percentiles
4. **Realistic data**: Use representative message sizes and patterns
5. **Multiple runs**: Run multiple times, report median of means
6. **Baseline comparison**: Always compare against a baseline

```bash
# Disable CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Pin to specific CPU
taskset -c 0 ./benchmark

# Disable ASLR for consistent addresses
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

## Continuous Benchmarking

```c
// JSON output for CI integration
void bench_output_json(const char *name, BenchResult_T *result) {
    printf("{\"name\":\"%s\",\"mean_ns\":%.2f,\"min_ns\":%lu,"
           "\"max_ns\":%lu,\"stddev\":%.2f}\n",
           name, result->mean_ns, result->min_ns,
           result->max_ns, result->stddev_ns);
}

// Compare against baseline
int bench_check_regression(BenchResult_T *current, BenchResult_T *baseline,
                            double threshold) {
    double regression = (current->mean_ns - baseline->mean_ns) / baseline->mean_ns;
    if (regression > threshold) {
        fprintf(stderr, "REGRESSION: %.2f%% slower than baseline\n",
                regression * 100);
        return 1;
    }
    return 0;
}
```

## Files Reference

| File | Purpose |
|------|---------|
| `src/test/bench_socketbuf.c` | Buffer benchmarks |
| `src/test/bench_poll.c` | Poll benchmarks |
| `src/test/bench_connection.c` | Connection benchmarks |
| `src/test/bench_throughput.c` | Throughput tests |
| `scripts/run_benchmarks.sh` | Benchmark runner |
| `scripts/compare_benchmarks.py` | Regression detection |
