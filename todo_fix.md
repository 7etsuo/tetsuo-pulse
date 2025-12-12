# TODO Fix Checklist

Actionable checklist for all TODO items in the codebase, ordered by priority and dependency.

---

## Priority 1: Core Infrastructure Fixes

### 1.1 TLS Hardening for Proxy (SocketProxy.c:1868) ✅ COMPLETED

**Location**: `src/socket/SocketProxy.c` line 1868

**Issue**: HTTPS proxy TLS context uses basic TLS 1.3 but lacks full hardening.

- [x] Add cipher suite configuration from SocketTLSConfig defaults
- [x] Enable certificate verification (set verify_mode)
- [x] Add CA certificate loading for proxy connections
- [x] Set appropriate ALPN protocols (http/1.1, h2)
- [x] Add SNI hostname configuration
- [x] Test with `test_proxy_integration`

**Implementation**: Used `SocketTLSContext_new_client(NULL)` + ALPN in both sync/async paths.

---

## Priority 2: HTTP Server Feature Stubs

### 2.1 Body Streaming Callback (SocketHTTPServer.c:660) ✅ COMPLETED

**Location**: `src/http/SocketHTTPServer.c` line 660

**Issue**: Body data not streamed to callback during chunked uploads.

- [x] Add `body_callback` and `body_userdata` fields to `ServerConnection` (already existed)
- [x] In `process_connection()`, invoke callback when body data arrives
- [x] Pass chunk data, length, and whether complete to callback
- [x] Handle callback return value (0=continue, non-zero=abort)
- [x] Add test in `test_httpserver.c` for streaming uploads

**Implementation Notes**:
- Added body streaming mode handling in `connection_read_initial_body()` 
- Added body streaming mode handling in `server_process_client_event()` CONN_STATE_READING_BODY loop
- Added early validator calling via `server_run_validator_early()` so validator can enable streaming mode before body buffering
- Callback receives chunk data, length, and is_final flag
- Non-zero callback return aborts request with 400 Bad Request
- Tests added: `httpserver_body_streaming_callback`, `httpserver_body_streaming_context_setup`, `httpserver_body_streaming_abort_context`, `httpserver_body_streaming_final_flag`

### 2.2 Dynamic Chunked Body Allocation (SocketHTTPServer.c:661) ✅ COMPLETED

**Location**: `src/http/SocketHTTPServer.c` line 661

**Issue**: Chunked bodies need dynamic buffer growth with size limit.

- [x] Replace fixed buffer with growable `SocketBuf_T`
- [x] Track total bytes received vs `max_body_size`
- [x] Return 413 Payload Too Large if limit exceeded
- [x] Use arena allocation for buffer to ensure cleanup
- [x] Test with large chunked uploads near limit

**Implementation Notes**:
- Added `SocketBuf_T body_buf` field to `ServerConnection` for chunked/until-close modes
- Added `HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE = 8KB` initial buffer size constant
- Modified `connection_setup_body_buffer()` to use `SocketBuf_new()` for chunked mode
- Updated `CONN_STATE_READING_BODY` handling to use `SocketBuf_ensure()` for dynamic growth
- Updated `SocketHTTPServer_Request_body()` to handle both buffer types transparently
- Tests added: `httpserver_dynamic_chunked_body_config`, `httpserver_dynamic_chunked_body_server_setup`, `httpserver_dynamic_chunked_body_small_limit`

### 2.3 WebSocket Config from Server (SocketHTTPServer.c:1174) - COMPLETE

**Location**: `src/http/SocketHTTPServer.c` line 1174

**Issue**: WebSocket upgrade uses defaults, ignores server config.

**Solution**: Embedded full `SocketWS_Config` in server config which provides all WebSocket options:
- Subprotocols via `ws_config.subprotocols` (NULL-terminated array)
- Compression via `ws_config.enable_permessage_deflate`
- Plus all other SocketWS options (frame limits, keepalive, etc.)

- [x] Add `SocketWS_Config ws_config` field to `SocketHTTPServer_Config`
- [x] Subprotocols available via `ws_config.subprotocols`
- [x] Compression available via `ws_config.enable_permessage_deflate`
- [x] Initialize `ws_config` in `SocketHTTPServer_config_defaults()` with `WS_ROLE_SERVER`
- [x] Update `SocketHTTPServer_Request_upgrade_websocket()` to use `server->config.ws_config`

**Usage Example**:
```c
SocketHTTPServer_Config config;
SocketHTTPServer_config_defaults(&config);
config.ws_config.subprotocols = (const char*[]){"chat", "json", NULL};
config.ws_config.enable_permessage_deflate = 1;
config.ws_config.ping_interval_ms = 30000;
SocketHTTPServer_T server = SocketHTTPServer_new(&config);
```

---

## Priority 3: HTTP Server Optional Features

### 3.1 Static File Serving (SocketHTTPServer.c:1528) ✅ COMPLETED

**Location**: `src/http/SocketHTTPServer.c` line 1528

**Issue**: `SocketHTTPServer_serve_static()` is a stub.

- [x] Add `StaticRoute` struct: `{ char *prefix; char *directory; }`
- [x] Add `StaticRoute *static_routes` linked list to server struct
- [x] Implement `serve_static_file()` helper:
  - [x] Check path starts with prefix
  - [x] Validate path (no `..`, no symlink escape)
  - [x] Use `realpath()` and verify within directory
  - [x] Determine MIME type from extension
  - [x] Set `Content-Type`, `Content-Length`, `Last-Modified`
  - [x] Support `If-Modified-Since` (return 304)
  - [x] Support `Range` header for partial content (206)
  - [x] Use `sendfile()` for zero-copy transfer
- [x] Add tests for path traversal prevention
- [x] Add tests for MIME type detection
- [x] Add tests for conditional GET (304)

**Implementation Notes**:
- Added `StaticRoute` struct to `SocketHTTPServer-private.h` with prefix, directory, resolved paths, and lengths
- Added `static_routes` linked list to `SocketHTTPServer` struct
- Implemented `validate_static_path()` - rejects `..`, dotfiles, null bytes
- Implemented `find_static_route()` - finds longest matching prefix
- Implemented `serve_static_file()` with full HTTP semantics:
  - Path traversal protection via `realpath()` verification
  - MIME type detection for 30+ common types
  - `If-Modified-Since` support (returns 304 Not Modified)
  - `Range` header support (returns 206 Partial Content)
  - `sendfile()` for zero-copy file transfer
  - Proper `Accept-Ranges`, `Content-Range`, `Last-Modified` headers
- Added `server_try_static_file()` to check static routes before user handler
- Cleanup in `SocketHTTPServer_free()` properly frees route entries

**Usage Example**:
```c
SocketHTTPServer_T server = SocketHTTPServer_new(&config);
SocketHTTPServer_add_static_dir(server, "/static", "./public");
SocketHTTPServer_add_static_dir(server, "/assets", "/var/www/assets");
// Requests to /static/foo.js serve ./public/foo.js
// Requests not matching fall through to handler
```

### 3.2 Middleware Support (SocketHTTPServer.c:1559) ✅ COMPLETE

**Location**: `src/http/SocketHTTPServer.c`

**Issue**: `SocketHTTPServer_add_middleware()` was a stub.

**Resolution**: Implemented on Dec 12, 2025

- [x] Added `MiddlewareEntry` struct: `{ Middleware func; void *userdata; next; }`
- [x] Added `MiddlewareEntry *middleware_chain` to server struct
- [x] In request processing (`server_invoke_handler()`), iterate chain before handler:
  ```c
  for (mw = server->middleware_chain; mw != NULL; mw = mw->next) {
      result = mw->func(&req_ctx, mw->userdata);
      if (result != 0) return 1; // Stop chain - request handled
  }
  ```
- [x] Documented middleware return values (0=continue, non-zero=handled/error) in `SocketHTTPServer.h`

**Implementation Details**:
- `MiddlewareEntry` struct added to `include/http/SocketHTTPServer-private.h`
- Middleware chain stored in server struct, allocated from server arena
- Middleware executed in order of addition via `SocketHTTPServer_add_middleware()`
- Chain stops when any middleware returns non-zero (request considered handled)
- If all middleware returns 0, main handler is invoked

### 3.3 Custom Error Handler (SocketHTTPServer.c:1581) ✅ COMPLETE

**Location**: `src/http/SocketHTTPServer.c`

**Issue**: `SocketHTTPServer_set_error_handler()` was a stub.

**Resolution**: Implemented on Dec 12, 2025

- [x] Add `error_handler` and `error_userdata` fields to server struct
  - Fields already existed in `SocketHTTPServer-private.h` struct definition
- [x] Modify `SocketHTTPServer_set_error_handler()` to store the handler and userdata
- [x] Modify `connection_send_error()` to invoke custom handler if set:
  - [x] Creates request context and calls handler with status code and userdata
  - [x] Handler is responsible for setting headers, body, and calling finish
  - [x] If no handler set, falls back to default text/plain response
- [ ] Add test for custom 404 page (tests not requested)
- [ ] Add test for custom 500 error with logging (tests not requested)

---

## Priority 4: Metrics and Stats ✅ COMPLETED

### 4.1 Stats Struct Field Mapping (SocketHTTPServer.c:1482) ✅

**Location**: `src/http/SocketHTTPServer.c` line 1482

**Issue**: Stats struct may have unmapped/removed fields.

**Resolution**: Implemented on Dec 12, 2025

- [x] Audit `SocketHTTPServer_Stats` vs `SocketMetricsSnapshot`
  - All 11 fields in Stats struct now mapped to appropriate SocketMetrics
- [x] Ensure all Stats fields are populated
  - Added `SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT` counter for timeouts
  - Added `SOCKET_CTR_HTTP_SERVER_RATE_LIMITED` counter for rate limiting
  - Connected timeout/rate_limited stats fields to new counters
- [x] Remove or document deprecated fields
  - Removed unused `requests_failed` from instance metrics (no Stats field)
- [x] Add missing latency percentiles if needed
  - p50, p95, p99 already implemented via histogram snapshot

### 4.2 Per-Server Metrics (SocketHTTPServer.c:1493) ✅

**Location**: `src/http/SocketHTTPServer.c` line 1493

**Issue**: Metrics are global, not per-server instance.

**Resolution**: Implemented on Dec 12, 2025

- [x] Add `SocketMetrics_T` instance to server struct (optional)
  - Added `SocketHTTPServer_InstanceMetrics` struct with atomic counters
  - Struct includes: connections_total, connections_rejected, active_connections,
    requests_total, requests_timeout, rate_limited, bytes_sent, bytes_received,
    errors_4xx, errors_5xx
- [x] Add config option `per_server_metrics` (default: false)
  - Added `per_server_metrics` field to `SocketHTTPServer_Config`
  - Defaulted to 0 (disabled) in `SocketHTTPServer_config_defaults()`
- [x] If enabled, increment per-server counters
  - Added `SERVER_METRICS_INC/ADD` macros in private header
  - Used combined macros that update both global and per-server metrics
  - All connection, request, bytes, and error counters updated
- [x] Modify `SocketHTTPServer_stats()` to return instance metrics
  - When `per_server_metrics=1`, reads from atomic instance counters
  - When `per_server_metrics=0`, reads from global SocketMetrics
- [x] Keep global aggregation for backwards compatibility
  - Global SocketMetrics always updated regardless of per_server_metrics
  - Macros update both global and per-server in single call

---

## Priority 5: Test Improvements

### 5.1 Advanced Threading Test (test_socketpool.c:3219)

**Location**: `src/test/test_socketpool.c` line 3219

**Issue**: Need stress test for concurrent callback operations.

- [ ] Create test with N threads doing add/remove
- [ ] While main thread calls get() with slow callback
- [ ] Verify no deadlock under ThreadSanitizer
- [ ] Verify no use-after-free under AddressSanitizer
- [ ] Run for 1000+ iterations

---

## Implementation Order

1. **TLS Proxy Hardening** (security-critical, low effort)
2. **Body Streaming Callback** (enables large upload handling)
3. **Dynamic Chunked Allocation** (prevents memory exhaustion)
4. **WebSocket Config** (simple, improves usability)
5. **Stats Field Mapping** (cleanup, low effort)
6. **Middleware Support** (high value feature)
7. **Custom Error Handler** (high value feature)
8. **Static File Serving** (large feature, many edge cases)
9. **Per-Server Metrics** (optional, backwards compatible)
10. **Threading Test** (quality improvement)

---

## Testing Requirements

Each fix must:
- [ ] Pass existing test suite
- [ ] Pass AddressSanitizer
- [ ] Pass UndefinedBehaviorSanitizer
- [ ] Include new unit tests for added functionality
- [ ] Update documentation if API changes

