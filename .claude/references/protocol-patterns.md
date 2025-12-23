# Protocol Implementation Patterns

This document contains implementation patterns for TLS, HTTP, WebSocket, and other protocols, extracted from command files for reuse.

## TLS Lifecycle Pattern

```c
/* Enable TLS on socket */
SocketTLS_enable(socket, tls_ctx);
SocketTLS_set_hostname(socket, "example.com");
SocketTLS_handshake_auto(socket);  /* Complete handshake */

/* ... use TLS I/O ... */

/* Option 1: Strict shutdown (raises on failure) */
SocketTLS_shutdown(socket);

/* Option 2: Best-effort disable (for STARTTLS reversal) */
int result = SocketTLS_disable(socket);  /* 1=clean, 0=partial, -1=not enabled */
/* Socket is now in plain mode - use Socket_send/recv */

/* Option 3: Half-close (send close_notify without waiting) */
SocketTLS_shutdown_send(socket);
```

## kTLS High-Performance Pattern

```c
/* Check if kTLS is available on this system */
if (SocketTLS_ktls_available()) {
    SocketTLS_enable_ktls(socket);  /* Request kTLS before handshake */
}

SocketTLS_enable(socket, ctx);
SocketTLS_handshake_auto(socket);

/* Verify kTLS activation */
if (SocketTLS_is_ktls_tx_active(socket)) {
    /* Use zero-copy sendfile for files */
    SocketTLS_sendfile(socket, file_fd, 0, file_size);
}
```

## Certificate Pinning Pattern

```c
SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");

/* Add pins (binary SHA256 hash, hex string, or from certificate file) */
SocketTLSContext_add_pin(ctx, pin_hash_bytes);
SocketTLSContext_add_pin_hex(ctx, "sha256//AAAA...");
SocketTLSContext_add_pin_from_cert(ctx, "backup-cert.pem");

/* Enable strict enforcement (default is warn-only) */
SocketTLSContext_set_pin_enforcement(ctx, 1);
```

## Session Resumption Pattern

```c
/* Server: Set session ID context for multi-tenant isolation */
SocketTLSContext_set_session_id_context(ctx, (unsigned char *)"myapp", 5);
SocketTLSContext_enable_session_cache(ctx, 1000, 300);

/* Server: Enable session tickets with key rotation */
SocketTLSContext_enable_session_tickets(ctx, ticket_key, 80);
/* ... periodically rotate ... */
SocketTLSContext_rotate_session_ticket_key(ctx, new_key, 80);

/* Client: Save and restore sessions */
size_t len = 0;
SocketTLS_session_save(socket, NULL, &len);  /* Query size */
unsigned char *session_data = malloc(len);
SocketTLS_session_save(socket, session_data, &len);
/* ... later ... */
SocketTLS_session_restore(socket, session_data, len);
```

## Long-Lived Connection Forward Secrecy

```c
/* TLS 1.3: Use KeyUpdate for periodic key rotation */
if (SocketTLS_request_key_update(socket, 1) > 0) {
    /* Keys rotated, peer will also rotate */
}

/* TLS 1.2: Check and limit renegotiation */
SocketTLS_disable_renegotiation(socket);  /* Recommended for security */
```

## DTLS Server Pattern

```c
/* Create server context with DoS protection */
SocketDTLSContext_T ctx = SocketDTLSContext_new_server("cert.pem", "key.pem", "ca.pem");
SocketDTLSContext_enable_cookie_exchange(ctx);  /* CRITICAL for DoS protection */
SocketDTLSContext_set_mtu(ctx, 1400);

/* Enable DTLS on UDP socket */
SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(socket, "0.0.0.0", 4433);
SocketDTLS_enable(socket, ctx);

/* Server handshake with cookie exchange */
DTLSHandshakeState state;
while ((state = SocketDTLS_listen(socket)) == DTLS_HANDSHAKE_COOKIE_EXCHANGE) {
    /* Cookie exchange in progress - handle retransmissions */
}
if (state == DTLS_HANDSHAKE_IN_PROGRESS) {
    while ((state = SocketDTLS_handshake(socket)) > DTLS_HANDSHAKE_COMPLETE) {
        /* Continue handshake */
    }
}

/* Secure I/O */
SocketDTLS_send(socket, data, len);
SocketDTLS_recv(socket, buffer, sizeof(buffer));
```

## DTLS Client Pattern

```c
SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");
SocketDTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);

SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
SocketDTLS_enable(socket, ctx);
SocketDTLS_set_peer(socket, "example.com", 4433);
SocketDTLS_set_hostname(socket, "example.com");

/* Complete handshake with timeout */
if (SocketDTLS_handshake_loop(socket, 30000) != DTLS_HANDSHAKE_COMPLETE) {
    /* Handle handshake failure */
}
```

## Cookie Secret Rotation

```c
/* Periodically rotate cookie secret (e.g., every hour) */
SocketDTLSContext_rotate_cookie_secret(ctx);
/* Previous secret still valid for grace period */
```

## Cryptographic Patterns (SocketCrypto)

```c
/* Hash computation */
unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
SocketCrypto_sha256(data, data_len, hash);

/* HMAC for message authentication */
unsigned char mac[SOCKET_CRYPTO_SHA256_SIZE];
SocketCrypto_hmac_sha256(key, key_len, data, data_len, mac);

/* Secure random generation */
unsigned char nonce[16];
if (SocketCrypto_random_bytes(nonce, sizeof(nonce)) < 0)
    handle_error();

/* Constant-time comparison (prevents timing attacks) */
if (SocketCrypto_secure_compare(computed_mac, received_mac, 32) != 0)
    reject_message();

/* Clear sensitive data (won't be optimized away) */
SocketCrypto_secure_clear(password, sizeof(password));

/* WebSocket handshake (RFC 6455) */
char accept_key[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
SocketCrypto_websocket_accept(client_key, accept_key);
```

## File Descriptor Passing Pattern (Unix Domain Sockets)

```c
/* Send single FD over Unix socket */
Socket_sendfd(unix_socket, fd_to_pass);

/* Receive single FD */
int received_fd = -1;
Socket_recvfd(unix_socket, &received_fd);
if (received_fd >= 0) {
    /* Use fd... */
    close(received_fd);  /* Caller owns, must close */
}

/* Multiple FDs */
int fds_to_send[3] = { fd1, fd2, fd3 };
Socket_sendfds(unix_socket, fds_to_send, 3);

int received_fds[10];
size_t count;
Socket_recvfds(unix_socket, received_fds, 10, &count);
for (size_t i = 0; i < count; i++)
    close(received_fds[i]);
```

## HTTP Header Patterns

```c
/* Header collection */
SocketHTTP_Headers_T headers = SocketHTTP_Headers_new(arena);
SocketHTTP_Headers_add(headers, "Content-Type", "application/json");
const char *value = SocketHTTP_Headers_get(headers, "content-type");  /* Case-insensitive */

/* Method/Status */
SocketHTTP_Method m = SocketHTTP_method_parse("POST", 4);
const char *reason = SocketHTTP_status_reason(404);  /* "Not Found" */

/* URI parsing */
SocketHTTP_URI uri;
if (SocketHTTP_URI_parse("https://example.com:8080/path?q=1", 0, &uri, arena) == URI_PARSE_OK) {
    int port = SocketHTTP_URI_get_port(&uri, 443);
}

/* Date parsing */
time_t t;
SocketHTTP_date_parse("Sun, 06 Nov 1994 08:49:37 GMT", 0, &t);
```

## Graceful Shutdown Pattern (SocketPool Drain)

```c
/* Event-loop friendly drain (non-blocking) */
SocketPool_drain(pool, 30000);  /* 30s timeout */
while (SocketPool_drain_poll(pool) > 0) {
    int64_t timeout = SocketPool_drain_remaining_ms(pool);
    SocketPoll_wait(poll, &events, timeout);
    /* Continue processing - connections close naturally */
}

/* Or blocking drain for simple cases */
int result = SocketPool_drain_wait(pool, 30000);
if (result < 0) {
    log_warn("Drain timed out, connections force-closed");
}

/* Health check for load balancers */
if (SocketPool_health(pool) != POOL_HEALTH_HEALTHY) {
    return HTTP_503_SERVICE_UNAVAILABLE;
}
```

### SocketPool State Machine:
- `POOL_STATE_RUNNING` - Normal operation, accepting connections
- `POOL_STATE_DRAINING` - Rejecting new, waiting for existing
- `POOL_STATE_STOPPED` - Fully stopped, safe to free

## HTTP/1.1 Message Parsing Pattern

```c
/* Incremental HTTP/1.1 parsing */
SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new(HTTP1_PARSE_REQUEST, NULL, arena);

while (more_data) {
    size_t consumed;
    SocketHTTP1_Result r = SocketHTTP1_Parser_execute(parser, buf, len, &consumed);
    if (r == HTTP1_OK || r == HTTP1_INCOMPLETE) {
        buf += consumed;
        len -= consumed;
    }
    if (r != HTTP1_INCOMPLETE) break;
}

/* Get parsed request */
const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request(parser);

/* Check body mode */
SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode(parser);
if (mode == HTTP1_BODY_CHUNKED) {
    /* Read chunked body */
    SocketHTTP1_Parser_read_body(parser, input, input_len, &consumed,
                                  output, output_len, &written);
}

/* Chunked encoding for responses */
ssize_t n = SocketHTTP1_chunk_encode(data, len, output, output_size);
n = SocketHTTP1_chunk_final(output, output_size, trailers);

/* Serialization */
ssize_t n = SocketHTTP1_serialize_request(&request, buffer, sizeof(buffer));
ssize_t n = SocketHTTP1_serialize_response(&response, buffer, sizeof(buffer));
```

## HPACK Header Compression Pattern

```c
/* Create encoder/decoder */
SocketHPACK_Encoder_T encoder = SocketHPACK_Encoder_new(arena, 4096);
SocketHPACK_Decoder_T decoder = SocketHPACK_Decoder_new(arena, NULL);

/* Encode headers */
SocketHPACK_Header headers[] = {
    { ":method", 7, "GET", 3, 0 },
    { ":path", 5, "/", 1, 0 },
};
unsigned char output[4096];
size_t output_len;
SocketHPACK_encode(encoder, headers, 2, output, sizeof(output), &output_len);

/* Decode headers */
SocketHPACK_Header decoded[64];
size_t decoded_count;
SocketHPACK_decode(decoder, input, input_len, decoded, 64, &decoded_count);

/* Integer coding (for custom protocols) */
size_t consumed;
uint64_t value;
SocketHPACK_int_decode(input, len, 5, &value, &consumed);  /* 5-bit prefix */

/* Huffman coding */
size_t encoded_size = SocketHPACK_huffman_encoded_size(data, len);
SocketHPACK_huffman_encode(data, len, output, output_size);
```

## Hash Utility Patterns

```c
/* Hash file descriptor */
unsigned hash = socket_util_hash_fd(fd, TABLE_SIZE);

/* Hash string (null-terminated) */
unsigned hash = socket_util_hash_djb2(name, TABLE_SIZE);

/* Hash string with explicit length (non-null-terminated) */
unsigned hash = socket_util_hash_djb2_len(name, name_len, TABLE_SIZE);

/* Case-insensitive hash (for HTTP headers) */
unsigned hash = socket_util_hash_djb2_ci(header_name, TABLE_SIZE);

/* Combined: length-aware + case-insensitive */
unsigned hash = socket_util_hash_djb2_ci_len(header_name, name_len, TABLE_SIZE);

/* Power-of-2 capacity for efficient modulo */
size_t capacity = socket_util_round_up_pow2(initial_size);
unsigned index = hash & (capacity - 1);  /* Fast modulo */
```

## HTTP/2 Protocol Pattern

```c
/* Create HTTP/2 connection */
SocketHTTP2_Config config;
SocketHTTP2_config_defaults(&config, HTTP2_ROLE_CLIENT);
SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(socket, &config, arena);

/* Perform handshake */
while (SocketHTTP2_Conn_handshake(conn) > 0) {
    SocketHTTP2_Conn_flush(conn);
    SocketHTTP2_Conn_process(conn, POLL_READ);
}

/* Create stream and send request */
SocketHTTP2_Stream_T stream = SocketHTTP2_Stream_new(conn);
SocketHPACK_Header headers[] = {
    { ":method", 7, "GET", 3, 0 },
    { ":path", 5, "/", 1, 0 },
    { ":scheme", 7, "https", 5, 0 },
    { ":authority", 10, "example.com", 11, 0 },
};
SocketHTTP2_Stream_send_headers(stream, headers, 4, 1);  /* END_STREAM */

/* Set callbacks for events */
SocketHTTP2_Conn_set_stream_callback(conn, on_stream_event, userdata);
SocketHTTP2_Conn_set_conn_callback(conn, on_conn_event, userdata);

/* Process frames in event loop */
while (!SocketHTTP2_Conn_is_closed(conn)) {
    SocketHTTP2_Conn_process(conn, events);
    SocketHTTP2_Conn_flush(conn);
}

/* Graceful shutdown */
SocketHTTP2_Conn_goaway(conn, HTTP2_NO_ERROR, NULL, 0);
SocketHTTP2_Conn_free(&conn);
```

## Proxy Tunneling Pattern

```c
/* Configure proxy */
SocketProxy_Config proxy;
SocketProxy_config_defaults(&proxy);
proxy.type = SOCKET_PROXY_SOCKS5;
proxy.host = "proxy.example.com";
proxy.port = 1080;
proxy.username = "user";
proxy.password = "pass";

/* Parse proxy URL (alternative) */
SocketProxy_parse_url("socks5://user:pass@proxy:1080", &proxy, arena);

/* Synchronous connection through proxy */
Socket_T sock = SocketProxy_connect(&proxy, "target.example.com", 443);
if (sock) {
    /* Tunnel established - can now use Socket_send/recv */
    /* Or add TLS: SocketTLS_enable(sock, tls_ctx); */
}

/* Async connection (for event loops) */
SocketProxy_Conn_T conn = SocketProxy_connect_async(socket, &proxy, host, port, arena);
while (SocketProxy_Conn_state(conn) < PROXY_STATE_CONNECTED) {
    unsigned events = SocketProxy_Conn_poll_events(conn);
    /* poll for events... */
    SocketProxy_Conn_process(conn, received_events);
}
Socket_T tunneled = SocketProxy_Conn_socket(conn);
SocketProxy_Conn_free(&conn);

/* HTTP CONNECT with custom headers */
proxy.type = SOCKET_PROXY_HTTP;
proxy.extra_headers = SocketHTTP_Headers_new(arena);
SocketHTTP_Headers_add(proxy.extra_headers, "X-Custom", "value");
```

## WebSocket Protocol Pattern

```c
/* Configure WebSocket */
SocketWS_Config config;
SocketWS_config_defaults(&config);
config.role = WS_ROLE_CLIENT;
config.max_message_size = 16 * 1024 * 1024;  /* 16MB */
config.validate_utf8 = 1;
config.ping_interval_ms = 30000;

/* Client handshake */
SocketWS_T ws = SocketWS_client_new(socket, host, path, &config);
while (SocketWS_handshake(ws) > 0) {
    /* Poll and process */
}

/* Send messages */
SocketWS_send_text(ws, "Hello, WebSocket!", 17);
SocketWS_send_binary(ws, binary_data, data_len);

/* Receive messages */
SocketWS_Message msg;
int result = SocketWS_recv_message(ws, &msg);
if (result > 0) {
    /* Process msg.data (msg.len bytes) */
    /* msg.type is WS_OPCODE_TEXT or WS_OPCODE_BINARY */
    free(msg.data);  /* Caller owns the data */
}

/* Control frames */
SocketWS_ping(ws, NULL, 0);
SocketWS_pong(ws, payload, payload_len);

/* Close gracefully */
SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye");
SocketWS_free(&ws);

/* Server: Check for upgrade request */
if (SocketWS_is_upgrade(request)) {
    config.role = WS_ROLE_SERVER;
    SocketWS_T ws = SocketWS_server_accept(socket, request, &config);
}
```

## UTF-8 Validation Pattern

```c
/* One-shot validation */
if (SocketUTF8_validate(data, len) != UTF8_VALID) {
    /* Reject invalid UTF-8 */
}

/* Incremental validation for streaming */
SocketUTF8_State state;
SocketUTF8_init(&state);
while (more_data) {
    SocketUTF8_Result r = SocketUTF8_update(&state, chunk, chunk_len);
    if (r == UTF8_INVALID) break;
}
SocketUTF8_Result final = SocketUTF8_finish(&state);
```

## DNS Resolution Pattern

```c
/* Create async resolver */
Arena_T arena = Arena_new();
SocketDNSResolver_T resolver = SocketDNSResolver_new(arena);

/* Load system nameservers or add manually */
SocketDNSResolver_load_resolv_conf(resolver);
/* Or: SocketDNSResolver_add_nameserver(resolver, "8.8.8.8", 53); */

/* Async resolution callback */
void on_resolved(SocketDNSResolver_Query_T query,
                 const SocketDNSResolver_Result *result,
                 int error, void *userdata) {
    if (error == RESOLVER_OK) {
        for (size_t i = 0; i < result->count; i++) {
            if (result->addresses[i].family == AF_INET) {
                /* Use IPv4 address */
            } else {
                /* Use IPv6 address */
            }
        }
    } else {
        fprintf(stderr, "DNS error: %s\n", SocketDNSResolver_strerror(error));
    }
}

/* Start resolution */
SocketDNSResolver_resolve(resolver, "example.com", RESOLVER_FLAG_BOTH,
                          on_resolved, userdata);

/* Event loop */
while (SocketDNSResolver_pending_count(resolver) > 0) {
    SocketDNSResolver_process(resolver, 100);
}

SocketDNSResolver_free(&resolver);
```

## DNS-over-TLS Pattern (RFC 7858)

```c
Arena_T arena = Arena_new();
SocketDNSoverTLS_T dot = SocketDNSoverTLS_new(arena);

/* Add well-known server with strict privacy */
SocketDNSoverTLS_add_server(dot, "cloudflare", DOT_MODE_STRICT);

/* Or configure manually with SPKI pinning */
SocketDNSoverTLS_Config config = {
    .server_address = "1.1.1.1",
    .port = 853,
    .server_name = "cloudflare-dns.com",
    .mode = DOT_MODE_STRICT,
    .spki_pin = NULL  /* Optional SPKI pin for out-of-band key pinning */
};
SocketDNSoverTLS_configure(dot, &config);

/* Query callback */
void on_dot_response(SocketDNSoverTLS_Query_T query,
                     const unsigned char *response, size_t len,
                     int error, void *userdata) {
    if (error == DOT_ERROR_SUCCESS) {
        /* Parse DNS response */
    }
}

/* Send query (2-byte length prefix added automatically) */
SocketDNSoverTLS_query(dot, query_buf, query_len, on_dot_response, userdata);

/* Event loop */
while (SocketDNSoverTLS_pending_count(dot) > 0) {
    SocketDNSoverTLS_process(dot, 100);
}

SocketDNSoverTLS_free(&dot);
```

## DNS-over-HTTPS Pattern (RFC 8484)

```c
Arena_T arena = Arena_new();
SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new(arena);

/* Add well-known server (uses HTTPS POST by default) */
SocketDNSoverHTTPS_add_server(doh, "google");

/* Or configure with custom options */
SocketDNSoverHTTPS_Config config = {
    .url = "https://dns.google/dns-query",
    .method = DOH_METHOD_POST,  /* Or DOH_METHOD_GET for caching */
    .prefer_http2 = 1,
    .timeout_ms = 5000
};
SocketDNSoverHTTPS_configure(doh, &config);

/* Query callback */
void on_doh_response(SocketDNSoverHTTPS_Query_T query,
                     const unsigned char *response, size_t len,
                     int error, void *userdata) {
    if (error == DOH_ERROR_SUCCESS) {
        /* Parse DNS response from application/dns-message body */
    }
}

/* Send query */
SocketDNSoverHTTPS_query(doh, query_buf, query_len, on_doh_response, userdata);

/* Event loop */
while (SocketDNSoverHTTPS_pending_count(doh) > 0) {
    SocketDNSoverHTTPS_process(doh, 100);
}

SocketDNSoverHTTPS_free(&doh);
```

## DNS Cache Configuration Pattern

```c
SocketDNSResolver_T resolver = SocketDNSResolver_new(arena);

/* Configure cache */
SocketDNSResolver_cache_set_ttl(resolver, 300);     /* 5 min TTL */
SocketDNSResolver_cache_set_max(resolver, 1000);    /* 1000 entries max */

/* Monitor cache performance */
SocketDNSResolver_CacheStats stats;
SocketDNSResolver_cache_stats(resolver, &stats);
printf("Cache hit rate: %.2f%%\n", stats.hit_rate * 100);

/* Clear cache if needed */
SocketDNSResolver_cache_clear(resolver);
```
