# Socket Library Enhancement TODO

## Convenience Functions

### TCP/UDP One-Liners
- [x] `Socket_listen_tcp(host, port, backlog)` - Create listening server in one call
- [x] `Socket_connect_tcp(host, port, timeout_ms)` - Create connected client in one call
- [x] `SocketDgram_bind_udp(host, port)` - Create bound UDP socket in one call
- [x] `Socket_accept_timeout(socket, timeout_ms)` - Accept with explicit timeout
- [x] `Socket_connect_nonblocking(socket, ip, port)` - Non-blocking connect initiation (IP only)

### Unix Domain Socket Helpers
- [x] `Socket_listen_unix(path, backlog)` - Create Unix domain listener in one call
- [x] `Socket_connect_unix_timeout(socket, path, timeout_ms)` - Connect with timeout

---

## Socket Statistics & Metrics

### Per-Socket Statistics
- [x] Define `SocketStats_T` structure (bytes_sent, bytes_received, packets, timestamps)
- [x] `Socket_getstats(socket, stats)` - Retrieve socket statistics
- [x] `Socket_resetstats(socket)` - Reset statistics counters
- [x] Track connection establishment time (create_time_ms, connect_time_ms)
- [x] Track last send/recv timestamps (last_send_time_ms, last_recv_time_ms)
- [x] Optional: RTT estimation from TCP_INFO (Linux only, rtt_us/rtt_var_us)

### Global Metrics Enhancement
- [x] `SocketMetrics_get_socket_count()` - Currently open sockets
- [x] `SocketMetrics_get_peak_connections()` - High watermark
- [x] `SocketMetrics_reset_peaks()` - Reset peak counters

---

## Connection Pool Enhancements

### Iterator Pattern
- [x] Verify `SocketPool_foreach()` is fully implemented
- [x] Add `SocketPool_find(pool, predicate, userdata)` - Find first matching connection
- [x] Add `SocketPool_filter(pool, predicate, userdata, results, max)` - Get matching connections

### Pool Statistics
- [x] `SocketPool_get_idle_count(pool)` - Number of idle connections
- [x] `SocketPool_get_active_count(pool)` - Number of active connections
- [x] `SocketPool_get_hit_rate(pool)` - Connection reuse rate

### Pool Management
- [x] `SocketPool_shrink(pool)` - Release unused capacity
- [x] `SocketPool_set_idle_callback(pool, callback)` - Notify when connection goes idle

---

## DNS Enhancements

### Cache Control
- [x] `SocketDNS_cache_clear(dns)` - Clear entire DNS cache
- [x] `SocketDNS_cache_remove(dns, hostname)` - Remove specific entry
- [x] `SocketDNS_cache_set_ttl(dns, ttl_seconds)` - Override TTL
- [x] `SocketDNS_cache_set_max_entries(dns, max)` - Limit cache size

### Cache Statistics
- [x] Define `SocketDNS_CacheStats` structure
- [x] `SocketDNS_cache_stats(dns, stats)` - Get cache hit/miss rates
- [x] Track cache evictions

### DNS Configuration
- [x] `SocketDNS_set_nameservers(dns, servers[], count)` - Custom nameservers
- [x] `SocketDNS_set_search_domains(dns, domains[], count)` - Search path
- [x] `SocketDNS_prefer_ipv6(dns, enable)` - Address family preference

---

## Connection Health & Probing

### Health Checks
- [x] `Socket_probe(socket, timeout_ms)` - Check if connection is alive
- [x] `Socket_get_error(socket)` - Get pending socket error (SO_ERROR)
- [x] `Socket_is_readable(socket)` - Check if data available without blocking
- [x] `Socket_is_writable(socket)` - Check if write would block

### TCP Info
- [x] `Socket_get_tcp_info(socket, info)` - Retrieve TCP_INFO stats (Linux)
- [x] `Socket_get_rtt(socket)` - Get current RTT estimate
- [x] `Socket_get_cwnd(socket)` - Get congestion window size

---

## I/O Enhancements

### Timeout Variants
- [x] `Socket_sendv_timeout(socket, iov, iovcnt, timeout_ms)` - Scatter with timeout
- [x] `Socket_recvv_timeout(socket, iov, iovcnt, timeout_ms)` - Gather with timeout
- [x] `Socket_sendall_timeout(socket, buf, len, timeout_ms)` - Complete send with timeout
- [x] `Socket_recvall_timeout(socket, buf, len, timeout_ms)` - Complete recv with timeout

### Advanced I/O
- [x] `Socket_splice(socket_in, socket_out, len)` - Zero-copy transfer (Linux)
- [x] `Socket_cork(socket, enable)` - TCP_CORK control
- [x] `Socket_peek(socket, buf, len)` - Peek without consuming (MSG_PEEK wrapper)

### Socket Duplication
- [x] `Socket_dup(socket)` - Duplicate socket (shares fd via dup())
- [x] `Socket_dup2(socket, target_fd)` - Duplicate to specific fd

---

## TLS Enhancements

### Session Management
- [x] `SocketTLS_session_save(socket, buffer, len)` - Export session for resumption
- [x] `SocketTLS_session_restore(socket, buffer, len)` - Import saved session
- [x] `SocketTLS_is_session_reused(socket)` - Check if session was reused (already existed)

### Renegotiation
- [x] `SocketTLS_check_renegotiation(socket)` - Handle renegotiation requests
- [x] `SocketTLS_disable_renegotiation(socket)` - Prevent renegotiation

### Certificate Info
- [x] `SocketTLS_get_peer_cert_info(socket, info)` - Get peer certificate details
- [x] `SocketTLS_get_cert_expiry(socket)` - Get peer cert expiration time
- [x] `SocketTLS_get_cert_subject(socket, buf, len)` - Get certificate subject

### OCSP
- [x] `SocketTLSContext_enable_ocsp_stapling(ctx)` - Enable OCSP stapling (already existed)
- [x] `SocketTLS_get_ocsp_response_status(socket)` - Get stapled response status

---

## HTTP Enhancements

### HTTP Client Convenience
- [x] `SocketHTTPClient_download(client, url, filepath)` - Download to file
- [x] `SocketHTTPClient_upload(client, url, filepath)` - Upload from file
- [x] `SocketHTTPClient_json_get(client, url, response)` - GET with JSON parsing
- [x] `SocketHTTPClient_json_post(client, url, json, response)` - POST JSON

### HTTP Server
- [x] `SocketHTTPServer_add_static_dir(server, prefix, directory)` - Serve static files
- [x] `SocketHTTPServer_add_middleware(server, middleware)` - Request middleware
- [x] `SocketHTTPServer_set_error_handler(server, handler)` - Custom error pages

### HTTP/2 Specific
- [x] `SocketHTTP2_Conn_get_concurrent_streams(conn)` - Current stream count
- [x] `SocketHTTP2_Conn_set_max_concurrent(conn, max)` - Limit streams
- [x] `SocketHTTP2_Conn_ping_wait(conn, timeout_ms)` - Send PING and wait for ACK

---

## WebSocket Enhancements

### Convenience Functions
- [x] `SocketWS_connect(url, protocols)` - One-liner WebSocket client
- [x] `SocketWS_send_json(conn, json)` - Send JSON as text frame
- [x] `SocketWS_recv_json(conn, json)` - Receive and parse JSON

### Control Frames
- [x] `SocketWS_ping(conn, data, len)` - Send ping with payload (already existed)
- [x] `SocketWS_pong(conn, data, len)` - Send pong (already existed)
- [x] `SocketWS_get_ping_latency(conn)` - Get ping/pong RTT

### Compression
- [x] `SocketWS_enable_compression(conn, options)` - permessage-deflate
- [x] `SocketWS_compression_options_defaults(options)` - Initialize options

---

## Buffer Enhancements

### SocketBuf Operations
- [x] `SocketBuf_compact(buf)` - Move data to front, maximize contiguous space
- [x] `SocketBuf_ensure(buf, min_space)` - Ensure minimum write space
- [x] `SocketBuf_find(buf, needle, needle_len)` - Search in buffer
- [x] `SocketBuf_readline(buf, line, max_len)` - Read until newline

### Zero-Copy Improvements
- [x] `SocketBuf_readv(buf, iov, iovcnt)` - Scatter read from buffer
- [x] `SocketBuf_writev(buf, iov, iovcnt)` - Gather write to buffer

---

## Event System Enhancements

### SocketPoll Additions
- [x] `SocketPoll_get_backend_name(poll)` - Return "epoll"/"kqueue"/"poll"
- [x] `SocketPoll_get_registered_sockets(poll, sockets, max)` - List monitored sockets
- [x] `SocketPoll_modify_events(poll, socket, add_events, remove_events)` - Modify event mask

### Timer Enhancements
- [x] `SocketTimer_reschedule(poll, timer, new_delay_ms)` - Change timer delay
- [x] `SocketTimer_pause(poll, timer)` - Pause timer
- [x] `SocketTimer_resume(poll, timer)` - Resume paused timer

---

## Async I/O Enhancements

### Batch Operations
- [x] `SocketAsync_submit_batch(async, ops, count)` - Submit multiple operations
- [x] `SocketAsync_cancel_all(async)` - Cancel all pending operations

### io_uring Support (Linux 5.1+)
- [x] Detect io_uring availability at runtime
- [x] Implement io_uring backend for SocketAsync
- [x] `SocketAsync_set_backend(async, backend)` - Select backend

---

## Documentation Improvements

### Header Documentation
- [ ] Add return value convention section to each public header
- [ ] Add "Quick Start" example to each module header
- [ ] Document thread safety for every function
- [ ] Add architecture diagram to main header

### Guides
- [ ] Write migration guide from raw sockets
- [ ] Write performance tuning guide
- [ ] Write security hardening guide
- [ ] Add troubleshooting section for common issues

---

## API Consistency Fixes

### Return Value Standardization
- [ ] Audit all functions returning int for success/failure
- [ ] Document which functions use 0=success vs 1=success
- [ ] Consider typedef for SocketResult enum

### Const Correctness Audit
- [ ] Review all getter functions for const correctness
- [ ] Review all read-only parameters for const
- [ ] Add const to appropriate function pointers

### Error Handling
- [ ] Ensure all functions document their exceptions
- [ ] Add `Socket_GetLastErrorCode()` returning enum
- [ ] Standardize errno preservation across all functions

---

## Testing & Validation

### Test Coverage
- [x] Add fuzz tests for new functions
- [x] Add integration tests for convenience functions
- [x] Add stress tests for pool operations
- [x] Add tests for all error paths
- [x] Achieve 100% test pass rate (45/45 tests passing)

### Benchmarks
- [ ] Benchmark convenience functions vs manual calls
- [ ] Benchmark DNS cache performance
- [ ] Benchmark pool iterator vs manual iteration

---

## Platform Support

### macOS Specific
- [ ] Verify all new functions work on macOS
- [ ] Test kqueue backend with new features
- [ ] Document macOS-specific limitations

### FreeBSD Specific
- [ ] Test on FreeBSD
- [ ] Verify sendfile compatibility
- [ ] Test capsicum integration

### Windows Future Support
- [ ] Document what would need to change for Windows
- [ ] Identify POSIX-only features
- [ ] Plan Winsock adaptation layer

