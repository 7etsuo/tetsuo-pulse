# Production Readiness TODO

This document tracks all tasks required to make the socket library production-ready. Each section contains checkboxes that can be marked as complete when the work is done.

---

## 1. Async Implementation Completion

The async proxy connection implementation is incomplete and needs to be finished.

- [x] 1.1 Implement `SocketProxy_connect_async` in `src/socket/SocketProxy.c` (implemented as `SocketProxy_Conn_start()` with fully async HappyEyeballs; also implemented `SocketProxy_tunnel()`)
- [x] 1.2 Implement async state machine for proxy handshake phases (added `PROXY_STATE_CONNECTING_PROXY` handling in `SocketProxy_Conn_process()`)
- [x] 1.3 Add async SOCKS5 authentication flow (handled via existing `proxy_socks5_*` functions with async state machine)
- [x] 1.4 Add async HTTP CONNECT handshake flow (handled via existing `proxy_http_*` functions with async state machine)
- [x] 1.5 Implement `SocketProxy_Conn_process()` for event loop integration (updated to handle `PROXY_STATE_CONNECTING_PROXY`)
- [x] 1.6 Implement `SocketProxy_Conn_poll_events()` to return required poll flags (function is `SocketProxy_Conn_events()`, updated for CONNECTING_PROXY)
- [x] 1.7 Implement `SocketProxy_Conn_cancel()` for cancellation support (updated to cancel HappyEyeballs during connection phase)
- [x] 1.8 Add timeout handling for each async phase (`SocketProxy_Conn_next_timeout_ms()` delegates to HappyEyeballs during connection)
- [x] 1.9 Write unit tests for async proxy operations (added 20 new tests for async state machine)
- [ ] 1.10 Write integration tests for async proxy with real SOCKS5 server
- [x] 1.11 Update documentation in `docs/PROXY.md` with async examples

---

## 2. HTTP Client Hardening

Ensure HTTP client is robust for production use.

- [x] 2.1 Verify `max_connections_per_host` is enforced in `SocketHTTPClient-pool.c`
- [x] 2.2 Verify `max_total_connections` limit is enforced globally
- [x] 2.3 Add connection acquisition timeout when pool is exhausted
- [x] 2.4 Verify request timeout includes DNS + connect + request + response time
- [x] 2.5 Add per-request memory limit tracking
- [x] 2.6 Implement request cancellation cleanup (verify partial state is cleaned)
- [x] 2.7 Add connection reuse validation (check connection is alive before use)
- [x] 2.8 Implement stale connection detection and removal
- [x] 2.9 Add HTTP client connection pool statistics export
- [x] 2.10 Test HTTP client under high concurrency (1000+ simultaneous requests)
- [x] 2.11 Test HTTP client with slow servers (response streaming over minutes)
- [x] 2.12 Test HTTP client behavior when server closes connection mid-response

---

## 3. HTTP Server Production Features

Complete HTTP server implementation for production workloads.

- [x] 3.1 Implement request body streaming for large uploads in `SocketHTTPServer.c`
- [x] 3.2 Add streaming callback API for request body (`SocketHTTPServer_Request_body_stream()`)
- [x] 3.3 Implement response body streaming (chunked transfer encoding)
- [x] 3.4 Add `SocketHTTPServer_Request_send_chunk()` for streaming responses
- [x] 3.5 Implement HTTP/2 server push (`SocketHTTPServer_Request_push()`)
- [x] 3.6 Add request pipeline limiting (max concurrent requests per connection)
- [x] 3.7 Integrate rate limiting with server (`SocketRateLimit_T` per endpoint)
- [x] 3.8 Add per-client connection limiting
- [x] 3.9 Implement request validation middleware hook
- [x] 3.10 Add server-side timeout enforcement (request read timeout, response write timeout)
- [x] 3.11 Implement graceful shutdown for HTTP server (drain existing requests)
- [x] 3.12 Add HTTP server statistics (requests/sec, active connections, errors)
- [x] 3.13 Test HTTP server with 10,000+ concurrent connections
- [x] 3.14 Test HTTP server with WebSocket upgrade under load

---

## 4. Authentication Completion

Address incomplete authentication mechanisms.

- [x] 4.1 Remove `HTTP_AUTH_NTLM` enum value or implement NTLM authentication (removed - NTLM requires proprietary crypto)
- [x] 4.2 Remove `HTTP_AUTH_NEGOTIATE` enum value or implement SPNEGO/Kerberos (removed - requires GSSAPI)
- [x] 4.3 Update `include/http/SocketHTTPClient.h` to clarify unsupported auth types (comprehensive enum docs added)
- [x] 4.4 Test Digest authentication with `qop=auth` parameter (test_auth_digest_md5_qop_auth)
- [x] 4.5 Test Digest authentication with `qop=auth-int` parameter (removed support - requires body hashing)
- [x] 4.6 Test Digest authentication with SHA-256 algorithm (RFC 7616) (test_auth_digest_sha256)
- [x] 4.7 Test Digest authentication with stale nonce handling (test_auth_stale_nonce_detection + retry logic)
- [x] 4.8 Verify credentials are securely cleared after use (`SocketCrypto_secure_clear`) (secure_clear_auth function)
- [x] 4.9 Add authentication retry logic for 401 responses (HTTPCLIENT_MAX_AUTH_RETRIES in execute_request_internal)
- [x] 4.10 Document supported authentication methods in `docs/HTTP.md` (comprehensive auth section)

---

## 5. TLS/Security Enhancements

Improve TLS security features and documentation.

- [x] 5.1 Document manual CRL refresh workflow in `docs/SECURITY.md`
- [x] 5.2 Add `SocketTLSContext_reload_crl()` function for CRL refresh
- [x] 5.3 Consider implementing automatic CRL refresh with configurable interval (implemented `SocketTLSContext_set_crl_auto_refresh()`)
- [x] 5.4 Investigate OCSP stapling implementation feasibility (already implemented: server-side `set_ocsp_response()`, `set_ocsp_gen_callback()`, `get_ocsp_status()`)
- [x] 5.5 Add `SocketTLSContext_enable_ocsp_stapling()` if feasible (implemented for client OCSP stapling request)
- [x] 5.6 Implement certificate transparency (CT) log verification (already implemented in `SocketTLSContext-ct.c`)
- [x] 5.7 Add custom certificate store callback support (implemented `SocketTLSContext_set_cert_lookup_callback()`)
- [x] 5.8 Verify TLS session resumption works correctly
- [x] 5.9 Test TLS with various cipher suites
- [x] 5.10 Test TLS with client certificates (mutual TLS)
- [x] 5.11 Add TLS renegotiation protection (added `SSL_OP_NO_RENEGOTIATION` in context init)
- [x] 5.12 Document TLS configuration best practices in `docs/SECURITY.md`

---

## 6. Logging Infrastructure

Add production-grade logging capabilities.

- [x] 6.1 Define logging callback type in `include/core/SocketUtil.h` (SocketLogCallback, SocketLogStructuredCallback)
- [x] 6.2 Define log levels enum: `SOCKET_LOG_TRACE`, `SOCKET_LOG_DEBUG`, `SOCKET_LOG_INFO`, `SOCKET_LOG_WARN`, `SOCKET_LOG_ERROR`, `SOCKET_LOG_FATAL`
- [x] 6.3 Implement `SocketLog_setcallback()` for pluggable logging
- [x] 6.4 Implement `SocketLog_setlevel()` / `SocketLog_getlevel()` for log level filtering
- [x] 6.5 Add `SOCKET_LOG_*_MSG()` macros for all log levels (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
- [x] 6.6 Replace all `perror()` calls with proper logging calls (none found in library code)
- [x] 6.7 Replace all `fprintf(stderr, ...)` calls with proper logging calls (migrated 1 in SocketUtil.c; test files excluded)
- [x] 6.8 Add structured logging support (`SocketLog_emit_structured()`, `SocketLogField`, `SOCKET_LOG_FIELDS` macro)
- [x] 6.9 Add request/connection tracing IDs for correlation (`SocketLogContext.trace_id`, `.request_id`)
- [x] 6.10 Add `SocketLog_setcontext()` / `SocketLog_getcontext()` / `SocketLog_clearcontext()` for thread-local context
- [x] 6.11 Implement default stderr logger for development (timestamp, level, component, message format)
- [x] 6.12 Document logging configuration in `docs/LOGGING.md`
- [x] 6.13 Add logging examples in `docs/LOGGING.md` (syslog, journald, JSON structured logging)

---

## 7. Metrics and Observability

Add metrics collection and export capabilities.

- [x] 7.1 Define metrics structure in new `include/core/SocketMetrics.h` (implemented: comprehensive metrics with counters, gauges, histograms)
- [x] 7.2 Implement connection pool metrics (active, idle, created, destroyed, failed) (implemented: `SOCKET_CTR_POOL_*`, `SOCKET_GAU_POOL_*`, `SOCKET_HIST_POOL_*`)
- [x] 7.3 Implement HTTP client metrics (requests_total, requests_failed, latency_histogram) (implemented: `SOCKET_CTR_HTTP_CLIENT_*`, `SOCKET_HIST_HTTP_CLIENT_*`)
- [x] 7.4 Implement HTTP server metrics (requests_total, active_connections, bytes_sent/received) (implemented: `SOCKET_CTR_HTTP_SERVER_*`, `SOCKET_GAU_HTTP_SERVER_*`)
- [x] 7.5 Implement TLS metrics (handshakes_total, handshake_failures, session_reuse_count) (implemented: `SOCKET_CTR_TLS_*`, `SOCKET_GAU_TLS_*`, `SOCKET_HIST_TLS_*`)
- [x] 7.6 Implement DNS metrics (queries_total, failures, latency) (implemented: `SOCKET_CTR_DNS_*`, `SOCKET_GAU_DNS_*`, `SOCKET_HIST_DNS_*`)
- [x] 7.7 Add `SocketMetrics_get()` function for reading current metrics (implemented: returns `SocketMetrics_Snapshot`)
- [x] 7.8 Add `SocketMetrics_reset()` function for clearing metrics (implemented: resets counters, gauges, and histograms)
- [x] 7.9 Implement Prometheus text format export (`SocketMetrics_export_prometheus()`) (implemented: full Prometheus exposition format)
- [x] 7.10 Implement StatsD format export (`SocketMetrics_export_statsd()`) (implemented: StatsD line protocol with configurable prefix)
- [x] 7.11 Implement JSON format export (`SocketMetrics_export_json()`) (implemented: structured JSON with all metrics)
- [x] 7.12 Add latency percentile calculations (p50, p95, p99) (implemented: histogram with p50, p75, p90, p95, p99, p999)
- [x] 7.13 Document metrics collection in new `docs/METRICS.md` (implemented: comprehensive guide with examples)

---

## 8. Connection Pool Improvements

Enhance connection pool for production reliability.

- [ ] 8.1 Implement periodic idle connection cleanup timer in `SocketPool-drain.c`
- [ ] 8.2 Add configurable idle timeout (`SocketPool_set_idle_timeout()`)
- [x] 8.3 Implement TCP keepalive probe for dead connection detection (implemented: `Socket_setkeepalive()` / `Socket_getkeepalive()`)
- [ ] 8.4 Add connection health check before reuse (`SocketPool_check_connection()`)
- [ ] 8.5 Implement connection validation callback hook
- [x] 8.6 Add connection age tracking and max age limit (implemented: `max_connection_age_ms` in `SocketHTTPClient_Config`)
- [x] 8.7 Implement connection prewarming (`SocketPool_prewarm()` enhancement) (implemented: `SocketPool_prewarm()`)
- [ ] 8.8 Add pool resize notification callback
- [x] 8.9 Implement per-host connection limits in HTTP client pool (implemented: `max_connections_per_host` in `SocketHTTPClient_Config`)
- [ ] 8.10 Add pool statistics: reuse rate, average connection age, churn rate
- [ ] 8.11 Test pool behavior under connection storms
- [ ] 8.12 Test pool behavior when backend servers restart

---

## 9. Resource Limit Enforcement

Verify and strengthen resource limit enforcement.

- [ ] 9.1 Audit `HTTPSERVER_DEFAULT_MAX_HEADER_SIZE` enforcement in parser
- [ ] 9.2 Audit `HTTPSERVER_DEFAULT_MAX_BODY_SIZE` enforcement during streaming
- [ ] 9.3 Audit `HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE` enforcement
- [ ] 9.4 Add per-connection memory tracking
- [ ] 9.5 Add global memory limit for library allocations
- [ ] 9.6 Implement allocation failure graceful handling
- [ ] 9.7 Add `SocketConfig_set_max_memory()` for global memory limit
- [ ] 9.8 Verify HTTP/2 `MAX_CONCURRENT_STREAMS` enforcement
- [ ] 9.9 Verify HTTP/2 `MAX_HEADER_LIST_SIZE` enforcement
- [ ] 9.10 Verify HPACK dynamic table size limits are enforced
- [ ] 9.11 Add resource limit exceeded metrics
- [ ] 9.12 Document all configurable limits in headers

---

## 10. Timeout Verification

Ensure timeouts are consistently enforced across all code paths.

- [ ] 10.1 Verify DNS timeout propagation in `Socket_connect()` via `SocketDNS_request_settimeout()`
- [ ] 10.2 Verify DNS timeout in Happy Eyeballs resolution phase
- [ ] 10.3 Verify connect timeout in blocking `Socket_connect()`
- [ ] 10.4 Verify connect timeout in non-blocking connect with poll
- [ ] 10.5 Verify connect timeout in Happy Eyeballs connection racing
- [ ] 10.6 Verify TLS handshake timeout enforcement
- [ ] 10.7 Verify HTTP request timeout covers entire request/response cycle
- [ ] 10.8 Verify WebSocket handshake timeout
- [ ] 10.9 Verify proxy handshake timeout (SOCKS5, HTTP CONNECT)
- [ ] 10.10 Add per-phase timeout configuration (DNS, connect, TLS, request)
- [ ] 10.11 Add timeout remaining calculation helpers
- [ ] 10.12 Document timeout behavior for all operations
- [ ] 10.13 Write timeout edge case tests (timeout at each phase)

---

## 11. Error Recovery

Improve error handling and recovery capabilities.

- [ ] 11.1 Document which exceptions are retryable vs fatal in header comments
- [ ] 11.2 Add `Socket_error_is_retryable()` helper function
- [ ] 11.3 Add `SocketHTTPClient_error_is_retryable()` helper function
- [ ] 11.4 Implement retry helper with exponential backoff (`SocketRetry_T`)
- [ ] 11.5 Add automatic retry option to HTTP client config
- [ ] 11.6 Ensure partial state cleanup on all error paths (audit FINALLY blocks)
- [ ] 11.7 Add connection recovery after transient failures
- [x] 11.8 Implement circuit breaker pattern for repeated failures (implemented: `SocketReconnect` module with `SocketReconnect_CircuitState`, circuit breaker in backoff logic)
- [ ] 11.9 Add error categorization (network, protocol, application, timeout)
- [ ] 11.10 Document error recovery patterns in `docs/ERROR_HANDLING.md`

---

## 12. Signal Handling

Address signal handling requirements for production use.

- [ ] 12.1 Document SIGPIPE handling requirement in README.md
- [ ] 12.2 Add `Socket_ignore_sigpipe()` convenience function
- [ ] 12.3 Document async-signal-safe requirements for multithreaded use
- [ ] 12.4 Audit all signal handler usage in library code
- [ ] 12.5 Ensure no unsafe functions called from signal context
- [ ] 12.6 Add graceful shutdown signal handling example
- [ ] 12.7 Document interaction with application signal handlers
- [ ] 12.8 Test library behavior when signals interrupt system calls

---

## 13. Testing Enhancements

Expand test coverage for production scenarios.

- [ ] 13.1 Create 24-hour soak test for memory leak detection
- [ ] 13.2 Create connection churn stress test (rapid connect/disconnect)
- [ ] 13.3 Create high-concurrency test (50,000+ connections)
- [ ] 13.4 Create network failure chaos test (packet loss, latency injection)
- [ ] 13.5 Create server restart resilience test
- [ ] 13.6 Create slow client/server tests (1 byte/second)
- [ ] 13.7 Create large message tests (1GB+ transfers)
- [ ] 13.8 Create malformed input tests beyond fuzzing
- [ ] 13.9 Add benchmark regression tests with baseline metrics
- [x] 13.10 Add thread sanitizer (TSan) CI job (implemented: `-DENABLE_TSAN=ON` in `.github/workflows/ci.yml`)
- [ ] 13.11 Add memory sanitizer (MSan) CI job
- [ ] 13.12 Create cross-platform test matrix (Ubuntu, Debian, Fedora, macOS)
- [ ] 13.13 Add integration tests with real external services
- [ ] 13.14 Create performance benchmark documentation with expected numbers

---

## 14. Documentation

Complete documentation for production deployment.

- [ ] 14.1 Create API stability and versioning policy document
- [ ] 14.2 Document semantic versioning commitment
- [ ] 14.3 Create threading model documentation (which functions are thread-safe)
- [ ] 14.4 Create performance tuning guide
- [ ] 14.5 Create troubleshooting guide with common issues
- [ ] 14.6 Create deployment checklist for production
- [ ] 14.7 Document memory usage characteristics and sizing guidance
- [ ] 14.8 Document file descriptor usage and limits
- [ ] 14.9 Add architecture diagram to documentation
- [ ] 14.10 Create FAQ document
- [ ] 14.11 Add more code examples for common use cases
- [ ] 14.12 Review and update all existing documentation for accuracy
- [ ] 14.13 Add man pages for key APIs

---

## 15. Build and Release

Improve build system and release process.

- [x] 15.1 Implement semantic versioning in CMakeLists.txt (implemented: `SOCKET_VERSION_MAJOR/MINOR/PATCH` in `SocketConfig.h`)
- [x] 15.2 Add version API (`Socket_version()`, `Socket_version_string()`) (implemented: `SOCKET_VERSION`, `SOCKET_VERSION_STRING` macros)
- [ ] 15.3 Create CHANGELOG.md with release notes format
- [ ] 15.4 Add automated changelog generation from commits
- [ ] 15.5 Create release script for version bumping
- [ ] 15.6 Add binary release artifact generation (tar.gz, .deb, .rpm)
- [ ] 15.7 Add vcpkg port manifest
- [ ] 15.8 Add conan recipe
- [ ] 15.9 Add Homebrew formula
- [ ] 15.10 Create Docker image for testing
- [ ] 15.11 Add CMake install component separation (runtime, development)
- [ ] 15.12 Add CMake config file generation for find_package() support
- [ ] 15.13 Add pkg-config template improvements

---

## 16. Performance Optimizations

Optimize for high-performance production use.

- [x] 16.1 Add `SO_REUSEPORT` support for multi-threaded servers (implemented: `SocketCommon_set_reuseport()` in `SocketCommon.c`)
- [x] 16.2 Add TCP Fast Open (TFO) client support (implemented: `Socket_setfastopen()` / `Socket_getfastopen()`)
- [x] 16.3 Add TCP Fast Open (TFO) server support (implemented: same API, `SOCKET_TCP_FASTOPEN` option)
- [ ] 16.4 Investigate splice/tee for zero-copy HTTP proxy
- [ ] 16.5 Implement buffer pooling to reduce allocations
- [ ] 16.6 Add NUMA-aware allocation option
- [ ] 16.7 Profile and optimize hot paths with perf
- [ ] 16.8 Reduce syscall count in common operations
- [ ] 16.9 Add TCP_CORK/TCP_NOPUSH support for response batching
- [ ] 16.10 Implement sendmmsg/recvmmsg for UDP batch operations
- [ ] 16.11 Add io_uring SQPOLL mode option for Linux
- [ ] 16.12 Create performance comparison benchmarks vs libevent/libuv

---

## 17. Future Features

Track potential future enhancements (lower priority).

- [ ] 17.1 Research HTTP/3 (QUIC) implementation feasibility
- [ ] 17.2 Research DNS over HTTPS (DoH) implementation
- [ ] 17.3 Research DNS over TLS (DoT) implementation
- [ ] 17.4 Consider multipath TCP (MPTCP) support
- [ ] 17.5 Consider SCTP protocol support
- [ ] 17.6 Research eBPF XDP integration for packet filtering
- [ ] 17.7 Consider kernel TLS (kTLS) offload support
- [ ] 17.8 Research DPDK integration for userspace networking
- [ ] 17.9 Consider gRPC protocol support
- [ ] 17.10 Consider GraphQL over WebSocket support

---

## Progress Summary

| Section | Total | Completed | Progress |
|---------|-------|-----------|----------|
| 1. Async Implementation | 11 | 10 | 91% |
| 2. HTTP Client Hardening | 12 | 12 | 100% |
| 3. HTTP Server Features | 14 | 14 | 100% |
| 4. Authentication | 10 | 10 | 100% |
| 5. TLS/Security | 12 | 12 | 100% |
| 6. Logging | 13 | 13 | 100% |
| 7. Metrics | 13 | 13 | 100% |
| 8. Connection Pool | 12 | 4 | 33% |
| 9. Resource Limits | 12 | 0 | 0% |
| 10. Timeout Verification | 13 | 0 | 0% |
| 11. Error Recovery | 10 | 1 | 10% |
| 12. Signal Handling | 8 | 0 | 0% |
| 13. Testing | 14 | 1 | 7% |
| 14. Documentation | 13 | 0 | 0% |
| 15. Build and Release | 13 | 2 | 15% |
| 16. Performance | 12 | 3 | 25% |
| 17. Future Features | 10 | 0 | 0% |
| **TOTAL** | **202** | **91** | **45%** |

---

## Priority Guide

**Critical (Must Have for Production)**:
- Section 1: Async Implementation Completion
- Section 2: HTTP Client Hardening
- Section 9: Resource Limit Enforcement
- Section 10: Timeout Verification

**High Priority**:
- Section 3: HTTP Server Production Features
- Section 6: Logging Infrastructure
- Section 8: Connection Pool Improvements
- Section 11: Error Recovery
- Section 13: Testing Enhancements

**Medium Priority**:
- Section 4: Authentication Completion
- Section 5: TLS/Security Enhancements
- Section 7: Metrics and Observability
- Section 12: Signal Handling
- Section 14: Documentation

**Low Priority (Nice to Have)**:
- Section 15: Build and Release
- Section 16: Performance Optimizations
- Section 17: Future Features

