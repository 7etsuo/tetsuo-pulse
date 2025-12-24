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

### Safe String Utilities:
- `socket_util_safe_strncpy(dest, src, max_len)` - Safe string copy with guaranteed null-termination (use instead of strncpy)
- `socket_util_safe_copy_ip(dest, src, max_len)` - Safe IP address string copy (use with SOCKET_IP_MAX_LEN)

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

### SocketDNSResolver (Async Resolver, RFC 1035)

Async DNS resolver with query multiplexing (from `include/dns/SocketDNSResolver.h`):

#### Lifecycle:
- `SocketDNSResolver_new(arena)` - Create resolver instance
- `SocketDNSResolver_free(&resolver)` - Dispose of resolver

#### Configuration:
- `SocketDNSResolver_load_resolv_conf(resolver)` - Load nameservers from /etc/resolv.conf
- `SocketDNSResolver_add_nameserver(resolver, address, port)` - Add nameserver manually
- `SocketDNSResolver_clear_nameservers(resolver)` - Remove all nameservers
- `SocketDNSResolver_nameserver_count(resolver)` - Get nameserver count
- `SocketDNSResolver_set_timeout(resolver, timeout_ms)` - Set query timeout (default: 5000)
- `SocketDNSResolver_set_retries(resolver, max_retries)` - Set max retries (default: 3)

#### Resolution:
- `SocketDNSResolver_resolve(resolver, hostname, flags, callback, userdata)` - Start async resolution
- `SocketDNSResolver_cancel(resolver, query)` - Cancel pending query
- `SocketDNSResolver_query_hostname(query)` - Get hostname from query handle

#### Resolution Flags:
- `RESOLVER_FLAG_IPV4` - Query for A records
- `RESOLVER_FLAG_IPV6` - Query for AAAA records
- `RESOLVER_FLAG_BOTH` - Query for both A and AAAA
- `RESOLVER_FLAG_NO_CACHE` - Bypass cache
- `RESOLVER_FLAG_TCP` - Force TCP transport

#### Event Loop:
- `SocketDNSResolver_fd_v4(resolver)` - Get IPv4 socket fd for poll
- `SocketDNSResolver_fd_v6(resolver)` - Get IPv6 socket fd for poll
- `SocketDNSResolver_process(resolver, timeout_ms)` - Process pending queries
- `SocketDNSResolver_pending_count(resolver)` - Get pending query count

#### Cache:
- `SocketDNSResolver_cache_clear(resolver)` - Clear all cached entries
- `SocketDNSResolver_cache_set_ttl(resolver, ttl_seconds)` - Set cache TTL
- `SocketDNSResolver_cache_set_max(resolver, max_entries)` - Set max cache size
- `SocketDNSResolver_cache_stats(resolver, &stats)` - Get cache statistics

#### Utility:
- `SocketDNSResolver_result_free(&result)` - Free resolution result
- `SocketDNSResolver_strerror(error)` - Convert error code to string

### SocketDNSoverTLS (RFC 7858, RFC 8310)

DNS-over-TLS encrypted transport (from `include/dns/SocketDNSoverTLS.h`):

#### Lifecycle:
- `SocketDNSoverTLS_new(arena)` - Create DoT transport
- `SocketDNSoverTLS_free(&transport)` - Dispose of transport

#### Configuration:
- `SocketDNSoverTLS_configure(transport, &config)` - Configure server
- `SocketDNSoverTLS_add_server(transport, "google", mode)` - Add well-known server
- `SocketDNSoverTLS_clear_servers(transport)` - Clear servers
- `SocketDNSoverTLS_server_count(transport)` - Get server count

#### Privacy Modes (RFC 8310):
- `DOT_MODE_OPPORTUNISTIC` - Encrypt without authentication
- `DOT_MODE_STRICT` - Require certificate validation

#### Query:
- `SocketDNSoverTLS_query(transport, query, len, callback, userdata)` - Send query
- `SocketDNSoverTLS_cancel(transport, query)` - Cancel query
- `SocketDNSoverTLS_query_id(query)` - Get DNS message ID

#### Event Loop:
- `SocketDNSoverTLS_process(transport, timeout_ms)` - Process queries
- `SocketDNSoverTLS_fd(transport)` - Get socket fd for poll
- `SocketDNSoverTLS_pending_count(transport)` - Get pending count

#### Connection:
- `SocketDNSoverTLS_close_all(transport)` - Close all connections
- `SocketDNSoverTLS_is_connected(transport)` - Check connection status
- `SocketDNSoverTLS_stats(transport, &stats)` - Get statistics
- `SocketDNSoverTLS_strerror(error)` - Convert error to string

### SocketDNSoverHTTPS (RFC 8484)

DNS-over-HTTPS encrypted transport (from `include/dns/SocketDNSoverHTTPS.h`):

#### Lifecycle:
- `SocketDNSoverHTTPS_new(arena)` - Create DoH transport
- `SocketDNSoverHTTPS_free(&transport)` - Dispose of transport

#### Configuration:
- `SocketDNSoverHTTPS_configure(transport, &config)` - Configure server
- `SocketDNSoverHTTPS_add_server(transport, "cloudflare")` - Add well-known server
- `SocketDNSoverHTTPS_clear_servers(transport)` - Clear servers
- `SocketDNSoverHTTPS_server_count(transport)` - Get server count

#### HTTP Methods:
- `DOH_METHOD_POST` - POST with binary body (default, recommended)
- `DOH_METHOD_GET` - GET with base64url query parameter

#### Query:
- `SocketDNSoverHTTPS_query(transport, query, len, callback, userdata)` - Send query
- `SocketDNSoverHTTPS_cancel(transport, query)` - Cancel query
- `SocketDNSoverHTTPS_query_id(query)` - Get DNS message ID

#### Event Loop:
- `SocketDNSoverHTTPS_process(transport, timeout_ms)` - Process queries
- `SocketDNSoverHTTPS_pending_count(transport)` - Get pending count
- `SocketDNSoverHTTPS_stats(transport, &stats)` - Get statistics
- `SocketDNSoverHTTPS_strerror(error)` - Convert error to string

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

## SocketBuf Functions

Circular buffer for efficient socket I/O (from `include/socket/SocketBuf.h`):

### Creation/Disposal:
- `SocketBuf_new(arena, capacity)` - Create buffer with initial capacity
- `SocketBuf_release(&buf)` - Release buffer resources

### Writing Data:
- `SocketBuf_write(buf, data, len)` - Write data to buffer (returns bytes written)
- `SocketBuf_writef(buf, format, ...)` - Printf-style write
- `SocketBuf_writeptr(buf, &len)` - Get write pointer for direct writes
- `SocketBuf_commit(buf, len)` - Commit bytes after direct write

### Reading Data:
- `SocketBuf_read(buf, data, len)` - Read and remove data (returns bytes read)
- `SocketBuf_peek(buf, data, len)` - Read without removing
- `SocketBuf_readptr(buf, &len)` - Get read pointer for zero-copy
- `SocketBuf_consume(buf, len)` - Remove bytes after read

### Buffer Management:
- `SocketBuf_available(buf)` - Bytes available to read
- `SocketBuf_space(buf)` - Space available for writing
- `SocketBuf_capacity(buf)` - Total capacity
- `SocketBuf_reserve(buf, min_space)` - Ensure minimum write space
- `SocketBuf_clear(buf)` - Clear buffer (fast)
- `SocketBuf_secureclear(buf)` - Clear buffer securely (for sensitive data)
- `SocketBuf_compact(buf)` - Compact buffer to reduce fragmentation

## SocketDgram Functions

UDP and datagram socket operations (from `include/socket/SocketDgram.h`):

### Creation:
- `SocketDgram_new()` - Create unbound datagram socket
- `SocketDgram_new6()` - Create IPv6 datagram socket
- `SocketDgram_bind(host, port)` - Create and bind datagram socket
- `SocketDgram_bind6(host, port)` - Create and bind IPv6 datagram socket
- `SocketDgram_unix(path)` - Create Unix domain datagram socket

### I/O:
- `SocketDgram_sendto(socket, data, len, host, port)` - Send datagram to address
- `SocketDgram_recvfrom(socket, buf, len, &from_host, &from_port)` - Receive with sender info
- `SocketDgram_send(socket, data, len)` - Send to connected peer
- `SocketDgram_recv(socket, buf, len)` - Receive from connected peer
- `SocketDgram_sendv(socket, iov, iovcnt)` - Scatter-gather send
- `SocketDgram_recvv(socket, iov, iovcnt)` - Scatter-gather receive
- `SocketDgram_sendmsg(socket, &msg, flags)` - Low-level send with message header
- `SocketDgram_recvmsg(socket, &msg, flags)` - Low-level receive with message header

### Connected Mode:
- `SocketDgram_connect(socket, host, port)` - Connect to default peer
- `SocketDgram_disconnect(socket)` - Remove connected peer
- `SocketDgram_isconnected(socket)` - Check if connected

### Multicast:
- `SocketDgram_joinmulticast(socket, group, interface)` - Join multicast group
- `SocketDgram_leavemulticast(socket, group, interface)` - Leave multicast group
- `SocketDgram_setmulticastttl(socket, ttl)` - Set multicast TTL
- `SocketDgram_setmulticastloop(socket, enable)` - Enable/disable multicast loopback

### Broadcast:
- `SocketDgram_setbroadcast(socket, enable)` - Enable/disable broadcast

### Options:
- `SocketDgram_setnonblocking(socket, nonblock)` - Set non-blocking mode
- `SocketDgram_gettimeout(socket)` - Get timeout
- `SocketDgram_settimeout(socket, timeout_ms)` - Set timeout
- `SocketDgram_setrecvbuf(socket, size)` - Set receive buffer size
- `SocketDgram_setsendbuf(socket, size)` - Set send buffer size

### Cleanup:
- `SocketDgram_close(&socket)` - Close datagram socket

## SocketAsync Functions

Asynchronous I/O with native backends (from `include/socket/SocketAsync.h`):

### Context Management:
- `SocketAsync_new(arena, max_ops)` - Create async context
- `SocketAsync_free(&async)` - Free async context
- `SocketAsync_pollfd(async)` - Get file descriptor for poll integration
- `SocketAsync_process(async)` - Process completions

### Operations:
- `SocketAsync_send(async, socket, data, len, callback, userdata)` - Async send
- `SocketAsync_recv(async, socket, buf, len, callback, userdata)` - Async receive
- `SocketAsync_sendv(async, socket, iov, iovcnt, callback, userdata)` - Async scatter send
- `SocketAsync_recvv(async, socket, iov, iovcnt, callback, userdata)` - Async gather receive
- `SocketAsync_accept(async, socket, callback, userdata)` - Async accept
- `SocketAsync_connect(async, socket, host, port, callback, userdata)` - Async connect

### Cancellation:
- `SocketAsync_cancel(async, op)` - Cancel pending operation
- `SocketAsync_cancel_all(async, socket)` - Cancel all ops on socket

### Backend Info:
- `SocketAsync_backend(async)` - Get backend name ("io_uring", "kqueue", "poll")
- `SocketAsync_capabilities(async)` - Get capability flags (ZEROCOPY, LINKED, etc.)
- `SocketAsync_is_available()` - Check if native async I/O is available

### Flags:
- `SOCKETASYNC_URGENT` - High priority operation
- `SOCKETASYNC_LINKED` - Link with next operation (io_uring)
- `SOCKETASYNC_ZEROCOPY` - Enable zero-copy if supported

### io_uring Advanced Features (Linux 5.1+, requires `-DENABLE_IO_URING=ON`):
- `SocketAsync_enable_sqpoll(async)` - Enable SQPOLL kernel thread for reduced syscalls
- `SocketAsync_register_buffers(async, bufs, count)` - Register fixed buffers for zero-copy
- `SocketAsync_unregister_buffers(async)` - Unregister fixed buffers
- `SocketAsync_submit_batch(async)` - Batch multiple submissions for efficiency
- Automatic eventfd integration with poll backends for timer processing

## SocketDNSSEC Functions

DNSSEC validation (RFC 4033, 4034, 4035) (from `include/dns/SocketDNSSEC.h`):

### Validation:
- `SocketDNSSEC_validate(response, trust_anchors, result, arena)` - Validate DNS response
- `SocketDNSSEC_validate_rrset(rrset, rrsig, dnskey, &result)` - Validate individual RRset
- `SocketDNSSEC_verify_signature(rrsig, dnskey, rrset)` - Verify RRSIG against DNSKEY

### Trust Anchors:
- `SocketDNSSEC_TrustAnchor_new(arena)` - Create trust anchor store
- `SocketDNSSEC_TrustAnchor_add_root(anchors)` - Add IANA root trust anchors
- `SocketDNSSEC_TrustAnchor_add_ds(anchors, zone, ds)` - Add DS trust anchor
- `SocketDNSSEC_TrustAnchor_add_dnskey(anchors, zone, dnskey)` - Add DNSKEY trust anchor
- `SocketDNSSEC_TrustAnchor_free(&anchors)` - Free trust anchor store

### Key Operations:
- `SocketDNSSEC_parse_dnskey(rdata, len, &dnskey, arena)` - Parse DNSKEY RDATA
- `SocketDNSSEC_parse_rrsig(rdata, len, &rrsig, arena)` - Parse RRSIG RDATA
- `SocketDNSSEC_parse_ds(rdata, len, &ds, arena)` - Parse DS RDATA
- `SocketDNSSEC_compute_keytag(dnskey)` - Compute key tag from DNSKEY
- `SocketDNSSEC_compute_ds(dnskey, digest_type, &ds, arena)` - Compute DS from DNSKEY

### NSEC/NSEC3:
- `SocketDNSSEC_parse_nsec(rdata, len, &nsec, arena)` - Parse NSEC RDATA
- `SocketDNSSEC_parse_nsec3(rdata, len, &nsec3, arena)` - Parse NSEC3 RDATA
- `SocketDNSSEC_nsec_covers(nsec, name)` - Check if NSEC covers a name
- `SocketDNSSEC_nsec3_hash(name, algorithm, iterations, salt, &hash)` - Compute NSEC3 hash

### Validation States:
- `DNSSEC_SECURE` - Validated via chain of trust from trust anchor
- `DNSSEC_INSECURE` - Provably unsigned (no DS at parent)
- `DNSSEC_BOGUS` - Validation failed (bad signature, expired, etc.)
- `DNSSEC_INDETERMINATE` - Cannot determine (network error, missing data)

### Algorithms:
- `DNSSEC_ALGO_RSASHA256` (8) - RSA/SHA-256 (recommended)
- `DNSSEC_ALGO_RSASHA512` (10) - RSA/SHA-512
- `DNSSEC_ALGO_ECDSAP256SHA256` (13) - ECDSA P-256/SHA-256
- `DNSSEC_ALGO_ECDSAP384SHA384` (14) - ECDSA P-384/SHA-384
- `DNSSEC_ALGO_ED25519` (15) - Ed25519
- `DNSSEC_ALGO_ED448` (16) - Ed448

## SocketDNSCookie Functions

DNS Cookies for spoofing protection (RFC 7873) (from `include/dns/SocketDNSCookie.h`):

### Cookie Cache:
- `SocketDNSCookie_new(arena)` - Create cookie cache
- `SocketDNSCookie_free(&cache)` - Free cookie cache
- `SocketDNSCookie_set_max_entries(cache, max)` - Set max cache entries (default: 64)
- `SocketDNSCookie_set_secret_lifetime(cache, seconds)` - Set client secret lifetime (default: 86400)

### Client Cookie Generation:
- `SocketDNSCookie_generate_client(cache, server_addr, addr_len, cookie)` - Generate client cookie
- `SocketDNSCookie_rotate_secret(cache)` - Rotate client secret (recommended every 24 hours)

### Server Cookie Handling:
- `SocketDNSCookie_cache_server(cache, server_addr, addr_len, &cookie)` - Cache server cookie
- `SocketDNSCookie_lookup(cache, server_addr, addr_len, &cookie)` - Look up cached cookies
- `SocketDNSCookie_invalidate(cache, server_addr, addr_len)` - Invalidate cached entry

### EDNS0 Integration:
- `SocketDNSCookie_encode(cookie, buf, len)` - Encode COOKIE option for EDNS0
- `SocketDNSCookie_parse(buf, len, &cookie)` - Parse COOKIE option from EDNS0
- `DNS_COOKIE_OPTION_CODE` (10) - EDNS0 option code for cookies

### Constants:
- `DNS_CLIENT_COOKIE_SIZE` (8) - Fixed client cookie size
- `DNS_SERVER_COOKIE_MIN_SIZE` (8) - Minimum server cookie size
- `DNS_SERVER_COOKIE_MAX_SIZE` (32) - Maximum server cookie size

## SocketDNSError Functions

Extended DNS Errors (RFC 8914) (from `include/dns/SocketDNSError.h`):

### Parsing:
- `SocketDNSError_parse(buf, len, &ede)` - Parse EDE option from EDNS0
- `SocketDNSError_has_ede(response)` - Check if response contains EDE option
- `SocketDNSError_get_ede(response, &ede)` - Extract EDE from parsed response

### Error Information:
- `SocketDNSError_code_string(code)` - Get human-readable error code description
- `SocketDNSError_category(code)` - Get error category (DNSSEC, Policy, Server, etc.)

### EDE Structure:
- `info_code` - 16-bit INFO-CODE value
- `extra_text` - Optional UTF-8 EXTRA-TEXT string
- `extra_text_len` - Length of extra text

### Error Codes (RFC 8914 Section 4):
- `DNS_EDE_OTHER` (0) - Other Error
- `DNS_EDE_UNSUPPORTED_DNSKEY_ALGORITHM` (1) - DNSKEY algorithm not supported
- `DNS_EDE_UNSUPPORTED_DS_DIGEST_TYPE` (2) - DS digest type not supported
- `DNS_EDE_STALE_ANSWER` (3) - Stale Answer
- `DNS_EDE_FORGED_ANSWER` (4) - Forged Answer
- `DNS_EDE_DNSSEC_INDETERMINATE` (5) - DNSSEC Indeterminate
- `DNS_EDE_DNSSEC_BOGUS` (6) - DNSSEC Bogus
- `DNS_EDE_SIGNATURE_EXPIRED` (7) - Signature Expired
- `DNS_EDE_SIGNATURE_NOT_YET_VALID` (8) - Signature Not Yet Valid
- `DNS_EDE_DNSKEY_MISSING` (9) - DNSKEY Missing
- `DNS_EDE_RRSIGS_MISSING` (10) - RRSIGs Missing
- `DNS_EDE_NO_ZONE_KEY_BIT_SET` (11) - No Zone Key Bit Set
- `DNS_EDE_NSEC_MISSING` (12) - NSEC Missing
- `DNS_EDE_CACHED_ERROR` (13) - Cached Error
- `DNS_EDE_NOT_READY` (14) - Not Ready
- `DNS_EDE_BLOCKED` (15) - Blocked
- `DNS_EDE_CENSORED` (16) - Censored
- `DNS_EDE_FILTERED` (17) - Filtered
- `DNS_EDE_PROHIBITED` (18) - Prohibited
- `DNS_EDE_STALE_NXDOMAIN_ANSWER` (19) - Stale NXDOMAIN Answer
- `DNS_EDE_NOT_AUTHORITATIVE` (20) - Not Authoritative
- `DNS_EDE_NOT_SUPPORTED` (21) - Not Supported
- `DNS_EDE_NO_REACHABLE_AUTHORITY` (22) - No Reachable Authority
- `DNS_EDE_NETWORK_ERROR` (23) - Network Error
- `DNS_EDE_INVALID_DATA` (24) - Invalid Data

## SocketDNSNegCache Functions

DNS Negative Response Cache (RFC 2308) (from `include/dns/SocketDNSNegCache.h`):

### Cache Management:
- `SocketDNSNegCache_new(arena)` - Create negative cache
- `SocketDNSNegCache_free(&cache)` - Free negative cache
- `SocketDNSNegCache_set_max_entries(cache, max)` - Set max entries (default: 1000)
- `SocketDNSNegCache_set_max_ttl(cache, seconds)` - Set max TTL (default: 3600)
- `SocketDNSNegCache_clear(cache)` - Clear all entries

### Insertion:
- `SocketDNSNegCache_insert_nxdomain(cache, qname, qclass, ttl)` - Cache NXDOMAIN (matches any type)
- `SocketDNSNegCache_insert_nodata(cache, qname, qtype, qclass, ttl)` - Cache NODATA (type-specific)
- `SocketDNSNegCache_insert_from_soa(cache, type, qname, qtype, qclass, soa)` - Insert using SOA MINIMUM TTL

### Lookup:
- `SocketDNSNegCache_lookup(cache, qname, qtype, qclass, &entry)` - Look up negative entry
- `SocketDNSNegCache_lookup_nxdomain(cache, qname, qclass)` - Check for NXDOMAIN only
- `SocketDNSNegCache_lookup_nodata(cache, qname, qtype, qclass)` - Check for NODATA only

### Statistics:
- `SocketDNSNegCache_stats(cache, &stats)` - Get cache statistics

### RFC 2308 Key Tuples:
- **NXDOMAIN**: Cached against `<QNAME, QCLASS>` - domain doesn't exist
- **NODATA**: Cached against `<QNAME, QTYPE, QCLASS>` - name exists but no records of type

### Cache Entry Types:
- `DNS_NEG_NXDOMAIN` - Name Error (RCODE 3)
- `DNS_NEG_NODATA` - Name exists but no data of requested type

### Lookup Results:
- `DNS_NEG_MISS` - No cached entry found
- `DNS_NEG_HIT_NXDOMAIN` - Cached NXDOMAIN found
- `DNS_NEG_HIT_NODATA` - Cached NODATA found

## SocketDNSDeadServer Functions

Dead Server Tracking (RFC 2308 Section 7.2) (from `include/dns/SocketDNSDeadServer.h`):

### Tracker Management:
- `SocketDNSDeadServer_new(arena)` - Create dead server tracker
- `SocketDNSDeadServer_free(&tracker)` - Free tracker
- `SocketDNSDeadServer_set_threshold(tracker, count)` - Set consecutive failure threshold (default: 2)
- `SocketDNSDeadServer_clear(tracker)` - Clear all tracked servers

### Recording Failures:
- `SocketDNSDeadServer_record_timeout(tracker, server_addr)` - Record a timeout
- `SocketDNSDeadServer_record_success(tracker, server_addr)` - Record success (clears failure count)

### Checking Status:
- `SocketDNSDeadServer_is_dead(tracker, server_addr)` - Check if server is blacklisted
- `SocketDNSDeadServer_lookup(tracker, server_addr, &entry)` - Get detailed entry info
- `SocketDNSDeadServer_get_ttl(tracker, server_addr)` - Get remaining blacklist TTL

### Statistics:
- `SocketDNSDeadServer_stats(tracker, &stats)` - Get tracker statistics
- `SocketDNSDeadServer_count(tracker)` - Get number of tracked dead servers

### Constants:
- `DNS_DEAD_SERVER_MAX_TTL` (300) - RFC 2308 §7.2: 5-minute maximum blacklist
- `DNS_DEAD_SERVER_DEFAULT_THRESHOLD` (2) - Consecutive timeouts before marking dead
- `DNS_DEAD_SERVER_MAX_TRACKED` (32) - Maximum tracked servers

### Entry Structure:
- `ttl_remaining` - Seconds until server is retried
- `consecutive_failures` - Number of consecutive failures
- `marked_dead_ms` - Timestamp when marked dead

### Difference from SERVFAIL Caching:
| Condition | Detection | Cache Scope |
|-----------|-----------|-------------|
| SERVFAIL | RCODE=2 in response | Per query + nameserver |
| Dead Server | Timeout / no response | Per nameserver (all queries) |

## SocketDNSWire EDNS0 Functions

EDNS0 support (RFC 6891) (from `include/dns/SocketDNSWire.h`):

### OPT Record Handling (§6.1.1):
- `SocketDNSWire_parse_opt(rdata, len, &opt)` - Parse OPT pseudo-record
- `SocketDNSWire_validate_opt(opt)` - Validate OPT record constraints
- `SocketDNSWire_encode_opt(opt, buf, len)` - Encode OPT record

### Option Parsing Framework (§6.1.2):
- `SocketDNSWire_opt_get_option(opt, code, &data, &len)` - Get specific option
- `SocketDNSWire_opt_iterate(opt, callback, userdata)` - Iterate all options
- `SocketDNSWire_opt_add_option(opt, code, data, len)` - Add option to OPT

### Version Negotiation (§6.1.3):
- `SocketDNSWire_opt_get_version(opt)` - Get EDNS version from OPT
- `SocketDNSWire_check_version(response)` - Check for BADVERS (RCODE=16)
- Version mismatch handling: respond with highest supported version

### UDP Payload Size (§6.2.5):
- `SocketDNSWire_opt_get_udp_size(opt)` - Get requestor's UDP payload size
- `SocketDNSWire_opt_set_udp_size(opt, size)` - Set UDP payload size
- Automatic fallback to 512 bytes on truncation or FORMERR

### Common Option Codes:
- `DNS_OPT_NSID` (3) - Name Server Identifier
- `DNS_OPT_COOKIE` (10) - DNS Cookies (RFC 7873)
- `DNS_OPT_KEEPALIVE` (11) - TCP Keepalive
- `DNS_OPT_PADDING` (12) - Padding (RFC 7830)
- `DNS_OPT_EDE` (15) - Extended DNS Errors (RFC 8914)
