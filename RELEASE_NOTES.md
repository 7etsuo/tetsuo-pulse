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

