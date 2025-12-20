# Module APIs Reference

This document lists all public APIs for Socket library modules, extracted from command files for reuse.

## SocketCommon Helpers

Shared socket utilities (from `include/socket/SocketCommon.h` and `src/socket/SocketCommon.c`):

- `SocketCommon_set_option_int()` - Set integer socket options
- `SocketCommon_resolve_address()` - Resolve hostname to address
- `SocketCommon_calculate_total_iov_len()` - Calculate total iovec length
- `SocketCommon_cache_endpoint()` - Cache endpoint information
- `SocketBase_T` - Shared socket state structure
- `SocketLiveCount_increment/decrement()` - Track live socket count for leak detection

## SocketIO Functions

Vectored I/O operations (from `include/socket/SocketIO.h`):

- `SocketIO_readv()` - Scatter input
- `SocketIO_writev()` - Gather output
- `SocketIO_sendmsg()` - Send with message structure
- `SocketIO_recvmsg()` - Receive with message structure

## SocketCrypto Functions

Cryptographic primitives (from `include/core/SocketCrypto.h`):

### Hash Functions:
- `SocketCrypto_sha256(data, len, hash)` - SHA-256 hash
- `SocketCrypto_sha1(data, len, hash)` - SHA-1 hash (for protocols)
- `SocketCrypto_md5(data, len, hash)` - MD5 hash (for protocols)

### HMAC:
- `SocketCrypto_hmac_sha256(key, key_len, data, data_len, mac)` - HMAC-SHA256

### Random:
- `SocketCrypto_random_bytes(buffer, len)` - Cryptographically secure random

### Encoding:
- `SocketCrypto_base64_encode(data, len, output, output_size)` - Base64 encode
- `SocketCrypto_base64_decode(data, len, output, output_size)` - Base64 decode
- `SocketCrypto_hex_encode(data, len, output, output_size)` - Hex encode
- `SocketCrypto_hex_decode(data, len, output, output_size)` - Hex decode

### Security:
- `SocketCrypto_secure_compare(a, b, len)` - Constant-time comparison (prevents timing attacks)
- `SocketCrypto_secure_clear(data, len)` - Non-optimizable memory clearing

### WebSocket:
- `SocketCrypto_websocket_key(output)` - Generate Sec-WebSocket-Key
- `SocketCrypto_websocket_accept(key, output)` - Compute Sec-WebSocket-Accept

## SocketHTTP Functions

HTTP core types and utilities (from `include/http/SocketHTTP.h`):

### Headers:
- `SocketHTTP_Headers_new(arena)` - Create header collection
- `SocketHTTP_Headers_add(headers, name, value)` - Add header (case-insensitive)
- `SocketHTTP_Headers_get(headers, name)` - Get header (case-insensitive)
- `SocketHTTP_Headers_remove(headers, name)` - Remove header
- `SocketHTTP_Headers_count(headers)` - Get header count
- `SocketHTTP_Headers_iterate(headers, callback, userdata)` - Iterate headers

### Methods and Status:
- `SocketHTTP_method_parse(method_str, len)` - Parse HTTP method
- `SocketHTTP_method_string(method)` - Get method string
- `SocketHTTP_status_reason(status_code)` - Get status reason phrase

### URI Parsing:
- `SocketHTTP_URI_parse(uri_str, flags, &uri, arena)` - Parse URI per RFC 3986
- `SocketHTTP_URI_get_port(&uri, default_port)` - Get port from URI
- `SocketHTTP_URI_percent_encode(input, output, output_size)` - Percent-encode
- `SocketHTTP_URI_percent_decode(input, output, output_size)` - Percent-decode

### Dates:
- `SocketHTTP_date_parse(date_str, flags, &time)` - Parse HTTP-date
- `SocketHTTP_date_format(time, output, output_size)` - Format HTTP-date

### Media Types:
- `SocketHTTP_media_type_parse(content_type, &media_type, arena)` - Parse Content-Type
- `SocketHTTP_parse_accept(accept_header, accept_array, max_count)` - Parse Accept header

## SocketHTTP1 Functions

HTTP/1.1 message parsing and serialization (from `include/http/SocketHTTP1.h`):

### Parser:
- `SocketHTTP1_Parser_new(type, config, arena)` - Create parser (REQUEST or RESPONSE)
- `SocketHTTP1_Parser_execute(parser, data, len, &consumed)` - Incremental parse
- `SocketHTTP1_Parser_get_request(parser)` - Get parsed request
- `SocketHTTP1_Parser_get_response(parser)` - Get parsed response
- `SocketHTTP1_Parser_body_mode(parser)` - Get body mode (NONE/LENGTH/CHUNKED/EOF)
- `SocketHTTP1_Parser_read_body(parser, input, in_len, &consumed, output, out_len, &written)` - Read body data
- `SocketHTTP1_Parser_should_keepalive(parser)` - Check if connection should be kept alive

### Serialization:
- `SocketHTTP1_serialize_request(&request, buffer, buffer_size)` - Serialize request
- `SocketHTTP1_serialize_response(&response, buffer, buffer_size)` - Serialize response

### Chunked Encoding:
- `SocketHTTP1_chunk_encode(data, len, output, output_size)` - Encode chunk
- `SocketHTTP1_chunk_final(output, output_size, trailers)` - Final chunk with trailers

### Compression (if ENABLE_HTTP_COMPRESSION):
- `SocketHTTP1_compress_gzip(data, len, &output, &output_len, arena)` - gzip compress
- `SocketHTTP1_compress_deflate(data, len, &output, &output_len, arena)` - deflate compress
- `SocketHTTP1_compress_brotli(data, len, &output, &output_len, arena)` - Brotli compress
- `SocketHTTP1_decompress_gzip(data, len, &output, &output_len, arena)` - gzip decompress
- `SocketHTTP1_decompress_deflate(data, len, &output, &output_len, arena)` - deflate decompress
- `SocketHTTP1_decompress_brotli(data, len, &output, &output_len, arena)` - Brotli decompress

## SocketHPACK Functions

HPACK header compression for HTTP/2 (from `include/http/SocketHPACK.h`):

### Encoder/Decoder:
- `SocketHPACK_Encoder_new(arena, max_table_size)` - Create encoder
- `SocketHPACK_Decoder_new(arena, config)` - Create decoder
- `SocketHPACK_encode(encoder, headers, header_count, output, output_size, &output_len)` - Encode headers
- `SocketHPACK_decode(decoder, input, input_len, headers, max_headers, &header_count)` - Decode headers

### Table Operations:
- `SocketHPACK_Encoder_set_max_size(encoder, max_size)` - Update encoder table size
- `SocketHPACK_Decoder_set_max_size(decoder, max_size)` - Update decoder table size
- `SocketHPACK_static_find(name, name_len, value, value_len)` - Lookup static table

### Integer Coding:
- `SocketHPACK_int_encode(value, prefix, output, output_size)` - Encode integer
- `SocketHPACK_int_decode(input, len, prefix, &value, &consumed)` - Decode integer

### Huffman Coding:
- `SocketHPACK_huffman_encode(data, len, output, output_size)` - Huffman encode
- `SocketHPACK_huffman_decode(data, len, output, output_size, &output_len)` - Huffman decode
- `SocketHPACK_huffman_encoded_size(data, len)` - Calculate encoded size

## SocketHTTP2 Functions

HTTP/2 protocol implementation (from `include/http/SocketHTTP2.h`):

### Connection:
- `SocketHTTP2_Conn_new(socket, config, arena)` - Create HTTP/2 connection
- `SocketHTTP2_Conn_handshake(conn)` - Perform connection preface/SETTINGS exchange
- `SocketHTTP2_Conn_process(conn, events)` - Process incoming frames
- `SocketHTTP2_Conn_flush(conn)` - Send buffered frames
- `SocketHTTP2_Conn_is_closed(conn)` - Check if connection is closed
- `SocketHTTP2_Conn_goaway(conn, error_code, debug_data, debug_len)` - Send GOAWAY
- `SocketHTTP2_Conn_free(&conn)` - Free connection

### Stream:
- `SocketHTTP2_Stream_new(conn)` - Create new stream (auto-assigns stream ID)
- `SocketHTTP2_Stream_send_headers(stream, headers, count, end_stream)` - Send HEADERS
- `SocketHTTP2_Stream_send_data(stream, data, len, end_stream)` - Send DATA
- `SocketHTTP2_Stream_send_rst(stream, error_code)` - Send RST_STREAM
- `SocketHTTP2_Stream_state(stream)` - Get stream state
- `SocketHTTP2_Stream_id(stream)` - Get stream ID

### Settings:
- `SocketHTTP2_Conn_settings(conn, settings, count)` - Send SETTINGS frame
- `SocketHTTP2_Conn_get_setting(conn, setting_id)` - Get current setting value

### Flow Control:
- `SocketHTTP2_Conn_window_update(conn, increment)` - Update connection window
- `SocketHTTP2_Stream_window_update(stream, increment)` - Update stream window
- `SocketHTTP2_Conn_get_send_window(conn)` - Get connection send window
- `SocketHTTP2_Stream_get_send_window(stream)` - Get stream send window

### Callbacks:
- `SocketHTTP2_Conn_set_stream_callback(conn, callback, userdata)` - Stream event callback
- `SocketHTTP2_Conn_set_conn_callback(conn, callback, userdata)` - Connection event callback

### h2c Upgrade:
- `SocketHTTP2_Conn_upgrade_client(socket, settings_payload, arena)` - Upgrade client to h2c
- `SocketHTTP2_Conn_upgrade_server(socket, settings_payload, len, arena)` - Upgrade server to h2c

### Frame Utilities:
- `SocketHTTP2_frame_header_parse(data, &header)` - Parse frame header
- `SocketHTTP2_frame_header_serialize(&header, output)` - Serialize frame header
- `SocketHTTP2_config_defaults(&config, role)` - Initialize config with defaults

## SocketWS Functions

WebSocket protocol (RFC 6455) implementation (from `include/http/SocketWS.h`):

### Configuration:
- `SocketWS_config_defaults(&config)` - Initialize config with defaults

### Lifecycle:
- `SocketWS_client_new(socket, host, path, config)` - Create client WebSocket
- `SocketWS_server_accept(socket, request, config)` - Accept server WebSocket upgrade
- `SocketWS_server_reject(socket, status_code, reason)` - Reject upgrade with HTTP status
- `SocketWS_is_upgrade(request)` - Check if HTTP request is WebSocket upgrade
- `SocketWS_handshake(ws)` - Perform/continue handshake
- `SocketWS_free(&ws)` - Free WebSocket

### Messaging:
- `SocketWS_send_text(ws, data, len)` - Send text message
- `SocketWS_send_binary(ws, data, len)` - Send binary message
- `SocketWS_recv_message(ws, &message)` - Receive complete message (with auto-reassembly)
- `SocketWS_recv_available(ws)` - Check if data available

### Control Frames:
- `SocketWS_ping(ws, payload, len)` - Send PING
- `SocketWS_pong(ws, payload, len)` - Send PONG
- `SocketWS_close(ws, code, reason)` - Initiate close handshake

### State and Status:
- `SocketWS_state(ws)` - Get connection state (CONNECTING/OPEN/CLOSING/CLOSED)
- `SocketWS_socket(ws)` - Get underlying TCP socket
- `SocketWS_close_code(ws)` - Get close code
- `SocketWS_close_reason(ws)` - Get close reason string
- `SocketWS_last_error(ws)` - Get last error code
- `SocketWS_error_string(ws)` - Get error description

### Event Loop Integration:
- `SocketWS_pollfd(ws)` - Get file descriptor for polling
- `SocketWS_poll_events(ws)` - Get events to poll for
- `SocketWS_process(ws, events)` - Process events

### Keepalive:
- `SocketWS_enable_auto_ping(ws, interval_ms)` - Enable automatic PING
- `SocketWS_disable_auto_ping(ws)` - Disable automatic PING

### Extensions:
- `SocketWS_selected_subprotocol(ws)` - Get negotiated subprotocol
- `SocketWS_compression_enabled(ws)` - Check if permessage-deflate is active

## SocketProxy Functions

Proxy tunneling (HTTP CONNECT, SOCKS4/5) (from `include/http/SocketProxy.h`):

### Configuration:
- `SocketProxy_config_defaults(&proxy)` - Initialize config with defaults
- `SocketProxy_parse_url(url, &proxy, arena)` - Parse proxy URL (e.g., `socks5://user:pass@host:port`)

### Synchronous Connection:
- `SocketProxy_connect(&proxy, target_host, target_port)` - Connect through proxy (sync)
- `SocketProxy_connect_tls(&proxy, tls_ctx, target_host, target_port)` - Connect with TLS to target

### Asynchronous Connection:
- `SocketProxy_connect_async(socket, &proxy, target_host, target_port, arena)` - Start async connection
- `SocketProxy_Conn_process(conn, events)` - Process async connection events
- `SocketProxy_Conn_poll_events(conn)` - Get events to poll for
- `SocketProxy_Conn_state(conn)` - Get current state
- `SocketProxy_Conn_result(conn)` - Get result code
- `SocketProxy_Conn_socket(conn)` - Get tunneled socket (transfers ownership)
- `SocketProxy_Conn_free(&conn)` - Free async connection context

### Utilities:
- `SocketProxy_result_string(result)` - Get error description

## SocketTLS Functions

TLS/SSL secure connections (from `include/tls/SocketTLS.h`):

### Enable/Disable:
- `SocketTLS_enable(socket, tls_ctx)` - Enable TLS on socket
- `SocketTLS_disable(socket)` - Best-effort TLS disable (for STARTTLS reversal)
- `SocketTLS_is_enabled(socket)` - Check if TLS is enabled

### Handshake:
- `SocketTLS_set_hostname(socket, hostname)` - Set SNI hostname
- `SocketTLS_handshake(socket)` - Non-blocking handshake step
- `SocketTLS_handshake_auto(socket)` - Blocking handshake (complete)
- `SocketTLS_handshake_state(socket)` - Get handshake state

### I/O:
- `SocketTLS_send(socket, data, len)` - Send TLS data
- `SocketTLS_recv(socket, buffer, len)` - Receive TLS data
- `SocketTLS_pending(socket)` - Check buffered TLS data

### Shutdown:
- `SocketTLS_shutdown(socket)` - Strict TLS shutdown (raises on failure)
- `SocketTLS_shutdown_send(socket)` - Send close_notify (half-close)

### Session Management:
- `SocketTLS_session_save(socket, buffer, &len)` - Save session for resumption
- `SocketTLS_session_restore(socket, buffer, len)` - Restore saved session

### Certificate Info:
- `SocketTLS_get_peer_cert(socket)` - Get peer certificate
- `SocketTLS_get_peer_cert_chain(socket, &count)` - Get certificate chain
- `SocketTLS_verify_peer_cert(socket)` - Verify peer certificate

### ALPN:
- `SocketTLS_get_alpn(socket)` - Get negotiated ALPN protocol

### kTLS (Kernel TLS Offload):
- `SocketTLS_ktls_available()` - Check if kTLS is supported
- `SocketTLS_enable_ktls(socket)` - Request kTLS offload
- `SocketTLS_is_ktls_tx_active(socket)` - Check if TX offload is active
- `SocketTLS_is_ktls_rx_active(socket)` - Check if RX offload is active
- `SocketTLS_sendfile(socket, file_fd, offset, count)` - Zero-copy sendfile with kTLS

### Key Update (TLS 1.3):
- `SocketTLS_request_key_update(socket, update_peer)` - Request key rotation

### Renegotiation (TLS 1.2):
- `SocketTLS_check_renegotiation(socket)` - Check for renegotiation attempt
- `SocketTLS_disable_renegotiation(socket)` - Disable renegotiation (recommended)

### OCSP:
- `SocketTLS_get_ocsp_status(socket)` - Get OCSP stapling status

## SocketTLSContext Functions

TLS context configuration (from `include/tls/SocketTLSContext.h`):

### Core Context:
- `SocketTLSContext_new_client(ca_path)` - Create client context
- `SocketTLSContext_new_server(cert_path, key_path, ca_path)` - Create server context
- `SocketTLSContext_free(&ctx)` - Free context

### Certificates:
- `SocketTLSContext_load_cert(ctx, cert_path)` - Load certificate
- `SocketTLSContext_load_key(ctx, key_path)` - Load private key
- `SocketTLSContext_load_chain(ctx, chain_path)` - Load certificate chain
- `SocketTLSContext_add_certificate(ctx, cert_path, key_path, sni_hostname)` - Add SNI cert
- `SocketTLSContext_set_cert_lookup_callback(ctx, callback, userdata)` - Custom cert lookup (for HSM/database)

### CA and Verification:
- `SocketTLSContext_load_ca(ctx, ca_path)` - Load CA certificates
- `SocketTLSContext_set_verify_mode(ctx, mode)` - Set verification mode
- `SocketTLSContext_set_verify_depth(ctx, depth)` - Set max chain depth
- `SocketTLSContext_set_verify_callback(ctx, callback, userdata)` - Custom verification

### CRL:
- `SocketTLSContext_load_crl(ctx, crl_path)` - Load CRL
- `SocketTLSContext_set_crl_auto_refresh(ctx, enabled, interval_sec)` - Auto-refresh CRL

### OCSP:
- `SocketTLSContext_set_ocsp_response(ctx, response, len)` - Set OCSP stapling response (server)
- `SocketTLSContext_set_ocsp_must_staple(ctx, enabled)` - Require OCSP stapling (client)

### Certificate Transparency:
- `SocketTLSContext_enable_ct(ctx, enabled)` - Enable CT verification

### ALPN:
- `SocketTLSContext_set_alpn_protos(ctx, protos, count)` - Set ALPN protocols
- `SocketTLSContext_set_alpn_callback(ctx, callback, userdata)` - Server ALPN selection callback

### Session Cache:
- `SocketTLSContext_enable_session_cache(ctx, max_sessions, timeout_sec)` - Enable session cache
- `SocketTLSContext_create_sharded_cache(ctx, shard_count)` - Sharded cache for performance
- `SocketTLSContext_set_session_id_context(ctx, id, len)` - Set session ID context (multi-tenant)

### Session Tickets:
- `SocketTLSContext_enable_session_tickets(ctx, key, key_len)` - Enable session tickets
- `SocketTLSContext_rotate_session_ticket_key(ctx, new_key, key_len)` - Rotate ticket key

### Certificate Pinning:
- `SocketTLSContext_add_pin(ctx, pin_hash)` - Add certificate pin (binary SHA256)
- `SocketTLSContext_add_pin_hex(ctx, pin_hex)` - Add pin from hex string
- `SocketTLSContext_add_pin_from_cert(ctx, cert_path)` - Add pin from certificate file
- `SocketTLSContext_set_pin_enforcement(ctx, strict)` - Set pin enforcement mode

## SocketDTLS Functions

DTLS for UDP (from `include/tls/SocketDTLS.h`):

### Context:
- `SocketDTLSContext_new_client(ca_path)` - Create DTLS client context
- `SocketDTLSContext_new_server(cert_path, key_path, ca_path)` - Create DTLS server context
- `SocketDTLSContext_set_mtu(ctx, mtu)` - Set MTU for fragmentation
- `SocketDTLSContext_set_timeout(ctx, timeout_ms)` - Set handshake timeout
- `SocketDTLSContext_enable_cookie_exchange(ctx)` - Enable DoS protection (server)
- `SocketDTLSContext_rotate_cookie_secret(ctx)` - Rotate cookie secret

### Enable/Handshake:
- `SocketDTLS_enable(socket, ctx)` - Enable DTLS on datagram socket
- `SocketDTLS_set_peer(socket, host, port)` - Set peer address (client)
- `SocketDTLS_set_hostname(socket, hostname)` - Set SNI hostname
- `SocketDTLS_listen(socket)` - Server listen for handshake (handles cookie exchange)
- `SocketDTLS_handshake(socket)` - Non-blocking handshake step
- `SocketDTLS_handshake_loop(socket, timeout_ms)` - Blocking handshake

### I/O:
- `SocketDTLS_send(socket, data, len)` - Send DTLS datagram
- `SocketDTLS_recv(socket, buffer, len)` - Receive DTLS datagram

## SocketUTF8 Functions

UTF-8 validation (from `include/core/SocketUTF8.h`):

### One-Shot Validation:
- `SocketUTF8_validate(data, len)` - Validate UTF-8 buffer (returns UTF8_VALID/UTF8_INVALID/UTF8_INCOMPLETE)

### Incremental Validation:
- `SocketUTF8_init(&state)` - Initialize validation state
- `SocketUTF8_update(&state, data, len)` - Update state with data chunk
- `SocketUTF8_finish(&state)` - Finalize validation (check for incomplete sequences)

## SocketUtil Functions

Logging, metrics, and events (from `include/core/SocketUtil.h`):

### Logging:
- `SocketLog_emit(level, message)` - Emit log message
- `SocketLog_emitf(level, format, ...)` - Emit formatted log message
- `SocketLog_set_callback(callback, userdata)` - Set custom log callback
- `SocketLog_set_level(level)` - Set minimum log level

### Metrics:
- `SocketMetrics_increment(metric_id)` - Increment metric counter
- `SocketMetrics_set(metric_id, value)` - Set metric value
- `SocketMetrics_snapshot(&metrics)` - Get current metrics snapshot
- `SocketMetrics_set_callback(callback, userdata)` - Set custom metrics callback

### Events:
- `SocketEvents_emit(event_type, event_data)` - Emit event
- `SocketEvents_set_callback(callback, userdata)` - Set custom event callback

### Hash Utilities:
- `socket_util_hash_fd(fd, table_size)` - Hash file descriptor (golden ratio)
- `socket_util_hash_ptr(ptr, table_size)` - Hash pointer
- `socket_util_hash_uint(value, table_size)` - Hash unsigned integer
- `socket_util_hash_djb2(str, table_size)` - Hash null-terminated string (DJB2)
- `socket_util_hash_djb2_len(str, len, table_size)` - Hash string with length
- `socket_util_hash_djb2_ci(str, table_size)` - Case-insensitive hash (HTTP headers)
- `socket_util_hash_djb2_ci_len(str, len, table_size)` - Length-aware + case-insensitive
- `socket_util_round_up_pow2(size)` - Round up to next power of 2

## SocketRateLimit Functions

Token bucket rate limiting (from `include/core/SocketRateLimit.h`):

- `SocketRateLimit_new(tokens_per_sec, bucket_size)` - Create rate limiter
- `SocketRateLimit_try_acquire(limiter, tokens)` - Try to acquire tokens (non-blocking)
- `SocketRateLimit_wait_time_ms(limiter, tokens)` - Calculate wait time for tokens
- `SocketRateLimit_free(&limiter)` - Free rate limiter

## SocketIPTracker Functions

Per-IP connection tracking (from `include/core/SocketIPTracker.h`):

- `SocketIPTracker_new(max_per_ip)` - Create IP tracker
- `SocketIPTracker_track(tracker, ip_address)` - Track IP (returns 1 if allowed, 0 if limit exceeded)
- `SocketIPTracker_release(tracker, ip_address)` - Release IP slot
- `SocketIPTracker_free(&tracker)` - Free tracker

## SocketTimer Functions

Timer subsystem (from `include/poll/SocketTimer.h`):

- `SocketTimer_new()` - Create timer subsystem
- `SocketTimer_add(timer, delay_ms, callback, userdata)` - Add one-shot timer
- `SocketTimer_add_repeating(timer, interval_ms, callback, userdata)` - Add repeating timer
- `SocketTimer_cancel(timer, timer_handle)` - Cancel timer
- `SocketTimer_remaining(timer, timer_handle)` - Get remaining time
- `SocketTimer_next_expiry(timer)` - Get time until next timer
- `SocketTimer_process(timer)` - Process expired timers
- `SocketTimer_free(&timer)` - Free timer subsystem

## SocketReconnect Functions

Auto-reconnection with backoff (from `include/socket/SocketReconnect.h`):

- `SocketReconnect_new(policy, arena)` - Create reconnect manager
- `SocketReconnect_connect(reconnect, host, port)` - Initial connection
- `SocketReconnect_tick(reconnect)` - Process reconnection logic
- `SocketReconnect_pollfd(reconnect)` - Get file descriptor for polling
- `SocketReconnect_state(reconnect)` - Get current state
- `SocketReconnect_socket(reconnect)` - Get connected socket (if any)
- `SocketReconnect_free(&reconnect)` - Free reconnect manager

## SocketHappyEyeballs Functions

Dual-stack connection racing (RFC 8305) (from `include/socket/SocketHappyEyeballs.h`):

### Synchronous:
- `SocketHappyEyeballs_connect(host, port, timeout_ms)` - Simple dual-stack connect

### Asynchronous:
- `SocketHappyEyeballs_start(host, port, config, arena)` - Start async connection
- `SocketHappyEyeballs_process(he, events)` - Process connection attempts
- `SocketHappyEyeballs_poll_events(he)` - Get events to poll for
- `SocketHappyEyeballs_state(he)` - Get current state
- `SocketHappyEyeballs_result(he)` - Get winning socket (transfers ownership)
- `SocketHappyEyeballs_free(&he)` - Free Happy Eyeballs context

## SocketPool Functions

Connection pool management (from `include/pool/SocketPool.h`):

### Core:
- `SocketPool_new(arena, max_connections, buffer_size)` - Create pool
- `SocketPool_add(pool, socket)` - Add connection to pool
- `SocketPool_remove(pool, socket)` - Remove connection from pool
- `SocketPool_get_by_fd(pool, fd)` - Lookup connection by file descriptor
- `SocketPool_count(pool)` - Get active connection count
- `SocketPool_free(&pool)` - Free pool

### Drain (Graceful Shutdown):
- `SocketPool_drain(pool, timeout_ms)` - Initiate graceful drain
- `SocketPool_drain_poll(pool)` - Check drain progress (returns active count)
- `SocketPool_drain_wait(pool, timeout_ms)` - Blocking drain
- `SocketPool_drain_force(pool)` - Force close all connections
- `SocketPool_drain_remaining_ms(pool)` - Get remaining drain timeout
- `SocketPool_set_drain_callback(pool, callback, userdata)` - Set drain completion callback

### Health:
- `SocketPool_health(pool)` - Get pool health status (HEALTHY/DRAINING/UNHEALTHY)

### Statistics:
- `SocketPool_stats(pool, &stats)` - Get pool statistics

## SocketDNS Functions

Asynchronous DNS resolution (from `include/dns/SocketDNS.h`):

- `SocketDNS_init(worker_count)` - Initialize DNS resolver with worker threads
- `SocketDNS_request(hostname, port, callback, userdata)` - Async DNS lookup
- `SocketDNS_request_settimeout(request, timeout_ms)` - Set request timeout
- `SocketDNS_cancel(request)` - Cancel pending request
- `SocketDNS_pollfd()` - Get file descriptor for poll integration
- `SocketDNS_process()` - Process completed requests (invoke callbacks)
- `SocketDNS_settimeout(timeout_ms)` - Set default timeout
- `SocketDNS_setmaxpending(max_pending)` - Set maximum pending requests
- `SocketDNS_shutdown()` - Shutdown DNS resolver

## SocketPoll Functions

Event polling abstraction (from `include/poll/SocketPoll.h`):

- `SocketPoll_new()` - Create event poll instance
- `SocketPoll_add(poll, socket, events, userdata)` - Add socket to poll
- `SocketPoll_mod(poll, socket, events)` - Modify socket events
- `SocketPoll_del(poll, socket)` - Remove socket from poll
- `SocketPoll_wait(poll, &events, timeout_ms)` - Wait for events
- `SocketPoll_setdefaulttimeout(poll, timeout_ms)` - Set default timeout
- `SocketPoll_free(&poll)` - Free poll instance

## SocketSYNProtect Functions

SYN flood protection (from `include/socket/SocketSYNProtect.h`):

- `SocketSYNProtect_new(config, arena)` - Create SYN protection
- `SocketSYNProtect_check(syn_protect, ip_address)` - Check if connection allowed (returns action)
- `SocketSYNProtect_record_success(syn_protect, ip_address)` - Record successful connection
- `SocketSYNProtect_record_failure(syn_protect, ip_address)` - Record failed attempt
- `SocketSYNProtect_free(&syn_protect)` - Free SYN protection

## SocketHTTPClient Functions

HTTP client (from `include/http/SocketHTTPClient.h`):

### Configuration:
- `SocketHTTPClient_new(config, arena)` - Create HTTP client
- `SocketHTTPClient_config_defaults(&config)` - Initialize config

### Simple Requests:
- `SocketHTTPClient_get(client, url, &response)` - Sync GET request
- `SocketHTTPClient_post(client, url, body, body_len, &response)` - Sync POST request
- `SocketHTTPClient_put(client, url, body, body_len, &response)` - Sync PUT request
- `SocketHTTPClient_delete(client, url, &response)` - Sync DELETE request

### Advanced Requests:
- `SocketHTTPClient_request(client, &request, &response)` - Custom sync request
- `SocketHTTPClient_request_async(client, &request, callback, userdata)` - Async request

### Cookies:
- `SocketHTTPClient_set_cookie_jar(client, jar)` - Set cookie jar
- `SocketHTTPClient_get_cookie(client, domain, path, name)` - Get cookie

### Authentication:
- `SocketHTTPClient_set_auth_basic(client, username, password)` - Set Basic auth
- `SocketHTTPClient_set_auth_bearer(client, token)` - Set Bearer token

### Lifecycle:
- `SocketHTTPClient_free(&client)` - Free client

## SocketHTTPServer Functions

HTTP server (from `include/http/SocketHTTPServer.h`):

### Configuration:
- `SocketHTTPServer_new(config, arena)` - Create HTTP server
- `SocketHTTPServer_config_defaults(&config)` - Initialize config

### Request Handling:
- `SocketHTTPServer_set_handler(server, callback, userdata)` - Set request handler
- `SocketHTTPServer_run(server)` - Run server event loop
- `SocketHTTPServer_stop(server)` - Stop server gracefully

### Response Building:
- `SocketHTTPServer_send_response(request, &response)` - Send response
- `SocketHTTPServer_send_error(request, status_code, message)` - Send error response
- `SocketHTTPServer_send_file(request, file_path)` - Send file

### Lifecycle:
- `SocketHTTPServer_free(&server)` - Free server
