# SocketHTTPServer Refactor Plan
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/7etsuo/tetsuo-socket/actions)

## Current Status

**Refactor Phase**: Complete ✅

| Component | Target LOC | Actual LOC | Status |
|-----------|------------|------------|--------|
| `SocketHTTPServer-private.h` | N/A | 413 | ✅ Done |
| `SocketHTTPServer-connections.c` | ~700 | 962 | ✅ Done |
| `SocketHTTPServer-h2.c` | ~500 | 838 | ✅ Done |
| `SocketHTTPServer-static.c` | ~400 | 756 | ✅ Done |
| `SocketHTTPServer-core.c` | ~500 | 734 | ✅ Done |
| `SocketHTTPServer-http1.c` | ~600 | 583 | ✅ Done |
| `SocketHTTPServer-metrics.c` | ~200 | 143 | ✅ Done |
| `SocketHTTPServer.c` (main) | ~500 | 1,425 | ✅ Done (public API) |

**Total**: 5,441 LOC across 7 modules + 1 header

**Recent Changes**:
- Extracted HTTP/1 protocol handling to -http1.c (Fixes #2628, PR #2632)
- Extracted server core lifecycle to -core.c (Fixes #2627, PR #2631)
- Extracted metrics functions to -metrics.c (Fixes #2626, PR #2630)
- Removed 296 lines of duplicate static file code (Fixes #2624)
- Main file reduced from 3,090 → 1,425 LOC (contains 29 public API functions)

## Overview

**Original State**: `src/http/SocketHTTPServer.c` was a **monolithic 3,089 LOC** file implementing a high-performance HTTP/1.1+2 server with TLS, connection pooling, rate limiting, static files, middleware, WebSocket proxy, and metrics. It mixed concerns, had god functions (e.g., `server_process_client_event` ~200 lines), deep nesting, and magic numbers.

**Refactor Goals** (per [CLAUDE.md](CLAUDE.md)):
- **Modularize**: Split into 6 focused files (<800 LOC each), matching repo pattern (`SocketPoll_*.c`, `SocketHTTP*/*.c`).
- **Improve**: Dispatch tables (states), guards/early returns, constants/enums, `_n` headers, arena safety.
- **No API Change**: Public `SocketHTTPServer.h` unchanged.
- **Benefits**: Easier maintenance/tests/perf (parallel build/O(1) dispatch), 30% LOC reduction via extraction.
- **Effort**: 2-3 days + PR review.
- **Validation**: Sanitizers, fuzz, benchmarks (`run_http_benchmarks.sh`).

**Cross-Ref**: [REFACTOR_ANALYSIS.md](src/http/REFACTOR_ANALYSIS.md) (#2586 etc. addressed).

## File Structure

```
src/http/
├── SocketHTTPServer.h                    # Public API (unchanged)
├── SocketHTTPServer-private.h            # ✅ Internal: Enums/structs/dispatch (413 LOC)
├── SocketHTTPServer.c                    # ✅ Main file + public API (1,425 LOC)
├── SocketHTTPServer-connections.c        # ✅ Conn lifecycle/state dispatch (962 LOC)
├── SocketHTTPServer-h2.c                 # ✅ HTTP/2 streams/push/WS-H2 (838 LOC)
├── SocketHTTPServer-static.c             # ✅ Static files/MIME/range/ETag (756 LOC)
├── SocketHTTPServer-core.c               # ✅ Server lifecycle/poll/middleware (734 LOC)
├── SocketHTTPServer-http1.c              # ✅ HTTP/1 parse/body/response/h2c (583 LOC)
└── SocketHTTPServer-metrics.c            # ✅ Stats/RPS/metrics (143 LOC)
```

### Private Header Additions (`SocketHTTPServer-private.h`)
```c
// Enums (extract macros)
typedef enum {
    CONN_STATE_NEW = 0,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_READING_REQUEST,
    // ... CONN_STATE_COUNT
} ConnectionState;

// Structs (move internals)
struct ServerConnection { /* ... */ };

// Dispatch tables
typedef int (*ConnStateHandler)(SocketHTTPServer_T*, ServerConnection*, unsigned);
extern const ConnStateHandler conn_state_handlers[CONN_STATE_COUNT];

// Constants
#define HTTPSERVER_RECV_BUFFER_SIZE (4*1024)
#define MAX_ACCEPT_BATCH 16
// ...
```

## Per-File Migration Details

### ✅ SocketHTTPServer-connections.c (962 LOC) - DONE
**Responsibilities**: Per-connection lifecycle, poll integration, timeouts/state machine.
**Contains**: `connection_read`, `connection_send_data`, `connection_reset_for_keepalive`, `connection_new`, `connection_close`, `connection_free_pending`, `connection_parse_request`, `connection_send_response`, `connection_finish_request`, body buffer setup/reading functions.

### ✅ SocketHTTPServer-h2.c (838 LOC) - DONE
**Responsibilities**: HTTP/2 connection/streams, push, WS-over-H2.
**Contains**: `server_http2_stream_get_or_create`, `server_http2_build_request`, `server_http2_handle_request`, `server_http2_enable`, stream callbacks, flow control integration.

### ✅ SocketHTTPServer-static.c (751 LOC) - DONE
**Responsibilities**: Static file routes/serving (MIME, range, ETag, dates).
**Contains**: `server_find_static_route`, `server_serve_static_file`, `get_mime_type`, `validate_static_path`, `parse_range_header`, `format_http_date`, `parse_http_date`, `SocketHTTPServer_add_static_dir`.

---

### ✅ SocketHTTPServer-core.c (734 LOC) - DONE
**Responsibilities**: Server struct mgmt, main event loop, middleware/validator/rate-limit setup.
**Contains**:
- `SocketHTTPServer_new/free/config_defaults/start/stop/process/fd/poll/state/set_handler/set_rate_limit/set_validator/add_middleware/set_error_handler/drain*/drain_poll/drain_wait/set_drain_callback`
- `server_accept_clients`, `server_cleanup_timed_out` (high-level)
- `server_invoke_handler`, middleware loop
**PR**: #2631

### ✅ SocketHTTPServer-http1.c (583 LOC) - DONE
**Responsibilities**: HTTP/1 request/response handling, body parsing, h2c upgrade.
**Contains**:
- `server_handle_parsed_request`, `server_try_h2c_upgrade`, `server_header_has_token_ci`, `server_decode_http2_settings`
- `should_copy_header_to_h2`, `server_process_streaming_body`
**Improvements**:
- Uses `Headers_get_n(..., STRLEN_LIT("Upgrade"))` for performance
- Guards in `handle_parsed_request`: rate → h2c → static → validate → handler
**PR**: #2632

### ✅ SocketHTTPServer-metrics.c (143 LOC) - DONE
**Responsibilities**: Counters/gauges/histograms, per-server RPS.
**Contains**:
- `SERVER_METRICS_INC`, `SocketHTTPServer_stats/reset`
- Atomics for instance_metrics
**PR**: #2630

## Migration Guide (Phased Commits)

### All Phases Complete ✅

1. ✅ **Prep** (`feat: extract private.h`): Move enums/structs/dispatch prototypes
2. ✅ **Split connections** (`refactor: extract -connections.c`): Connection lifecycle
3. ✅ **Split h2** (`refactor: extract -h2.c`): HTTP/2 stream handling
4. ✅ **Split static** (`refactor: extract -static.c`): Static file serving
5. ✅ **Remove duplicates** (`refactor: remove duplicate static file code`): #2624
6. ✅ **Split metrics** (`refactor: extract -metrics.c`): Stats functions - PR #2630
7. ✅ **Split core** (`refactor: extract -core.c`): Server lifecycle/middleware - PR #2631
8. ✅ **Split http1** (`refactor: extract -http1.c`): HTTP/1 processing - PR #2632
9. ✅ **CMake**: Updated CMakeLists.txt with all source files

## Build & Test Commands (MANDATORY -j$(nproc))
```bash
# Debug + TLS
cmake -S. -Bbuild -DENABLE_TLS=ON
cmake --build build -j$(nproc)

# Sanitizers (PR req)
cmake -S. -Bbuild_asan -DENABLE_SANITIZERS=ON
cmake --build build_asan -j$(nproc)
cd build_asan && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest -j$(nproc) --output-on-failure

# Fuzz
CC=clang cmake -S. -Bbuild_fuzz -DENABLE_FUZZING=ON
cmake --build build_fuzz --target fuzz_http_server -j$(nproc)
./build_fuzz/fuzz_http_server corpus/http_server/ -fork=16

# Benchmarks (pre/post)
./run_http_benchmarks.sh
# Assert: req/s ↑ or stable, no reg.

# Docs
cd build && make doc -j$(nproc)
```

**New Tests**: `src/test/test_httpserver_*.c` (states/static/h2c/drain/metrics).

## Git Workflow (MANDATORY per CLAUDE.md)
1. `/git-workflow` → branch `feat/refactor-httpserver-split`.
2. Commits: `refactor: split -connections.c + state dispatch\n\nReduces god func 70%.\n\nFixes #2586`
3. PR: Template, link todos/issues.

## Performance/Safety Notes
- **Dispatch**: O(1) vs O(n) if-chain.
- **bsearch(MIME)**: 30 entries → log2(30)=5x faster hot path.
- **Arena**: All allocs tied to server/conn dispose.
- **Thread-Safe**: Mutex/atomics for stats/pool.
- **Security**: CRLF checks, path validation, timeouts (Slowloris/DDoS).

**Status**: Complete ✅ (7 of 7 modules extracted)

**Related Issues & PRs**:
- #2624 - Remove duplicate static file code ✅
- #2626 - Extract metrics functions → PR #2630 ✅
- #2627 - Extract server core lifecycle → PR #2631 ✅
- #2628 - Extract HTTP/1 protocol handling → PR #2632 ✅
- #2629 - Tracking issue for refactoring

---
*Last Updated: 2026-01-01* | [Edit](https://github.com/7etsuo/tetsuo-socket/edit/main/SocketHTTPServer.md)