# Socket Library Release Notes

## 2025-11-06 – Reliability & Performance Enhancements

### New Timeout Facilities
- Added global and per-socket timeout structure `SocketTimeouts_T` with helper APIs:
  - `Socket_timeouts_getdefaults()` / `Socket_timeouts_setdefaults()` for system-wide configuration.
  - `Socket_timeouts_get()` / `Socket_timeouts_set()` for per-socket overrides.
- Blocking `Socket_connect()` now honours the configured connect timeout by using non-blocking connects plus `poll()`.
- Async helpers (`Socket_bind_async`, `Socket_connect_async`) propagate socket-specific DNS timeouts to the resolver.

### Async DNS Cancellation & Error Reporting
- Resolver-wide and per-request DNS timeouts via `SocketDNS_settimeout()` and `SocketDNS_request_settimeout()`.
- Cancellations and timeouts now signal completion reliably; `SocketDNS_geterror()` surfaces the final `getaddrinfo()` error code.
- Request handles stay valid long enough to retrieve error information even after cancellation or timeout, simplifying cleanup paths.

### SocketPoll & SocketPool Improvements
- Introduced default poll timeout controls:
  - `SocketPoll_setdefaulttimeout()` and `SocketPoll_getdefaulttimeout()` manage the backend wait horizon.
  - `SOCKET_POLL_TIMEOUT_USE_DEFAULT` sentinel lets callers reuse the configured default.
- Optimised event translation to minimise mutex contention by caching lookup results per event.
- Connection pool now reuses input/output buffers across sessions, reducing arena churn under high turnover while keeping buffers securely cleared (`SocketBuf_secureclear`).

### Testing & Documentation
- Integration tests cover DNS cancellation signalling and poll timeout responsiveness.
- Unit tests verify SocketPool buffer reuse semantics.
- Documentation in `.cursor/rules` has been updated to reflect the new patterns.

## 2025-11-07 – Observability Layer

### Pluggable Logging
- Added `SocketLog_setcallback()` to install custom log sinks with severity filtering.
- All `SOCKET_ERROR_*` macros now route formatted messages through the logger while preserving thread-local buffers.

### Metrics Registry
- Introduced `SocketMetrics_*` helpers for thread-safe counter tracking across Socket, SocketDNS, SocketPoll, and SocketPool.
- Snapshot API (`SocketMetrics_getsnapshot()`, `SocketMetrics_snapshot_value()`) and `SocketMetrics_reset()` enable periodic export or zeroing.
- Default instrumentation records connect successes/failures, DNS lifecycle, poll wakeups, and pool activity.

### Event Hooks
- Lightweight event dispatcher (`SocketEvent_register()` / `SocketEvent_emit_*()`) surfaces accept/connect lifecycles, DNS timeouts, and poll wakeups.
- Callbacks execute outside internal locks to keep hot paths fast.

### Tests & Samples
- Extended `test_socketerror` and `test_socket` suites to cover logging callbacks, metrics snapshots, and event dispatch/unregister flows.
- Updated build to include new core modules (`SocketLog`, `SocketMetrics`, `SocketEvents`).

## Security Hardening in SocketSYNProtect (Recent Fixes)

- **CIDR Whitelist Bypass Fix**: Invalid prefix strings (e.g., `/abc`) now rejected by `strtol` validation in `parse_cidr_notation`, preventing unintended /0 wildcards that whitelist all IPs.

## HTTP/2 Flow Control & HPACK Security Hardening

- **Flow Control Overflow Protection**: Added 64-bit checks in window updates/adjustments to cap at 2^31-1 (RFC 9113 §5.2.1). New `http2_flow_adjust_window` for safe SETTINGS_INITIAL_WINDOW_SIZE deltas (§6.5.2), rejecting negative/overflow cases with `FLOW_CONTROL_ERROR`.
- **Graceful Adjustment**: SETTINGS processing now adjusts all valid streams before erroring on failures, counting issues for GOAWAY debug data.
- **Rapid Reset Mitigation (CVE-2023-44487)**: Enhanced RST_STREAM rate limiting (100/sec window), added metric `SOCKET_CTR_HTTP2_RST_FLOOD_BLOCKED`.
- **HPACK Bomb Prevention**: Explicit expansion ratio check (default 10x) in `Decoder_decode` after each header; triggers `HPACK_ERROR_BOMB` + metric if exceeded. Huffman allocs bounded by input*ratio.
- **Metrics & Observability**: New CAT_HTTP2 counters (FLOW_OVERFLOW, FLOW_NEGATIVE, HPACK_BOMB_DETECTED, etc.) for error tracking/export.
- **Tests/Docs**: 20+ new test cases (edge errors, floods), fuzz-safe. Updated HTTP.md/SECURITY.md with sections on mitigations/best practices.

These changes prevent DoS via malformed frames/SETTINGS, align with security.md HTTP/2/HPACK guidelines. Full suite passes with sanitizers.
- **Whitelist DoS Mitigation**: Optimized `whitelist_check` to parse IP address only once per check; introduced byte-based matching (`ip_matches_cidr_bytes`, `_check_bucket_bytes`) for O(1) CIDR scans regardless of list size.
- **Arena Memory Safety**: Disabled LRU eviction in arena mode to prevent bloat from un-freeable allocations; enforced hard cap at `max_tracked_ips`.
- **Metrics Precision**: `SocketSYNProtect_stats` now reports accurate active blocked IPs using `count_active_blacklists` (excludes expired); fixed duplicate gauge decrement in cleanup.
- **Hash Collision Resistance**: Added `hash_seed` to config (auto-randomized via `SocketCrypto_random_bytes`); incorporated into `synprotect_hash_ip` mixing for per-instance variation against crafted collisions in DJB2.
- **Tests**: Enhanced `test_synprotect.c` with `test_whitelist_cidr_invalid` for validation cases; added `benchmark_synprotect.c` for perf measurement (integrated to CMake and run_benchmarks.sh).
- **Fuzzing**: Existing `fuzz_synprotect.c` covers random CIDRs/IPs; recommend corpus expansion for malformed prefixes.
- **Docs**: New `docs/SYN-PROTECT.md` with usage, mitigations, and config tuning.

