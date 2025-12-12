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

### 3.2 Middleware Support (SocketHTTPServer.c:1559)

**Location**: `src/http/SocketHTTPServer.c` line 1559

**Issue**: `SocketHTTPServer_add_middleware()` is a stub.

- [ ] Add `MiddlewareEntry` struct: `{ Middleware func; void *userdata; next; }`
- [ ] Add `MiddlewareEntry *middleware_chain` to server struct
- [ ] In request processing, iterate chain before handler:
  ```c
  for (mw = server->middleware_chain; mw; mw = mw->next) {
      int result = mw->func(req, res, mw->userdata);
      if (result != 0) return result; // Stop chain
  }
  ```
- [ ] Document middleware return values (0=continue, non-zero=handled/error)
- [ ] Add test with logging middleware
- [ ] Add test with auth middleware that rejects requests

### 3.3 Custom Error Handler (SocketHTTPServer.c:1581)

**Location**: `src/http/SocketHTTPServer.c` line 1581

**Issue**: `SocketHTTPServer_set_error_handler()` is a stub.

- [ ] Add `error_handler` and `error_userdata` fields to server struct
- [ ] Create `server_send_error()` internal function
- [ ] In error paths, check if `error_handler` is set:
  - [ ] Call handler with status code, message, request context
  - [ ] If handler returns response, send it
  - [ ] If handler returns NULL, use default response
- [ ] Add test for custom 404 page
- [ ] Add test for custom 500 error with logging

---

## Priority 4: Metrics and Stats

### 4.1 Stats Struct Field Mapping (SocketHTTPServer.c:1482)

**Location**: `src/http/SocketHTTPServer.c` line 1482

**Issue**: Stats struct may have unmapped/removed fields.

- [ ] Audit `SocketHTTPServer_Stats` vs `SocketMetricsSnapshot`
- [ ] Ensure all Stats fields are populated
- [ ] Remove or document deprecated fields
- [ ] Add missing latency percentiles if needed

### 4.2 Per-Server Metrics (SocketHTTPServer.c:1493)

**Location**: `src/http/SocketHTTPServer.c` line 1493

**Issue**: Metrics are global, not per-server instance.

- [ ] Add `SocketMetrics_T` instance to server struct (optional)
- [ ] Add config option `per_server_metrics` (default: false)
- [ ] If enabled, increment per-server counters
- [ ] Modify `SocketHTTPServer_stats()` to return instance metrics
- [ ] Keep global aggregation for backwards compatibility

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

