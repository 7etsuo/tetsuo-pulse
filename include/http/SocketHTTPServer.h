/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer.h
 * @brief High-level HTTP server supporting HTTP/1.1 and HTTP/2.
 *
 * Features:
 * - Event-driven request handling with keep-alive
 * - Protocol negotiation (ALPN for HTTP/2)
 * - WebSocket upgrade support
 * - Request/response body streaming
 * - HTTP/2 server push
 * - Rate limiting per endpoint
 * - Per-client connection limiting
 * - Request validation middleware
 * - Granular timeout enforcement
 * - Graceful shutdown (drain)
 *
 * Thread safety: Server instances are NOT thread-safe.
 * Use one server per thread or external synchronization.
 */

#ifndef SOCKETHTTPSERVER_INCLUDED
#define SOCKETHTTPSERVER_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketRateLimit.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP2.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

#include "socket/SocketWS.h"

#ifndef HTTPSERVER_DEFAULT_BACKLOG
#define HTTPSERVER_DEFAULT_BACKLOG 128
#endif

#ifndef HTTPSERVER_DEFAULT_PORT
#define HTTPSERVER_DEFAULT_PORT 8080
#endif

#ifndef HTTPSERVER_DEFAULT_BIND_ADDR
#define HTTPSERVER_DEFAULT_BIND_ADDR "0.0.0.0"
#endif

#ifndef HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE
#define HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE 0
#endif

#ifndef HTTPSERVER_CONTENT_LENGTH_BUF_SIZE
#define HTTPSERVER_CONTENT_LENGTH_BUF_SIZE 32
#endif

#ifndef HTTPSERVER_CHUNK_FINAL_BUF_SIZE
#define HTTPSERVER_CHUNK_FINAL_BUF_SIZE 64
#endif

#ifndef HTTPSERVER_CLIENT_ADDR_MAX
#define HTTPSERVER_CLIENT_ADDR_MAX 64
#endif

#ifndef HTTPSERVER_DRAIN_POLL_MS
#define HTTPSERVER_DRAIN_POLL_MS 100
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTIONS
#define HTTPSERVER_DEFAULT_MAX_CONNECTIONS 1000
#endif

#ifndef HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS 30000
#endif

#ifndef HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS 60000
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_HEADER_SIZE
#define HTTPSERVER_DEFAULT_MAX_HEADER_SIZE (64 * 1024)
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_BODY_SIZE
#define HTTPSERVER_DEFAULT_MAX_BODY_SIZE (10 * 1024 * 1024)
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN
#define HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN 1000
#endif

#ifndef HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS 30000
#endif

#ifndef HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS 60000
#endif

#ifndef HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS 10000
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTION_LIFETIME_MS
#define HTTPSERVER_DEFAULT_MAX_CONNECTION_LIFETIME_MS 300000
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT
#define HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT 100
#endif

#ifndef HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS
#define HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS 100
#endif

#ifndef HTTPSERVER_DEFAULT_STREAM_CHUNK_SIZE
#define HTTPSERVER_DEFAULT_STREAM_CHUNK_SIZE 8192
#endif

#ifndef HTTPSERVER_RPS_WINDOW_SECONDS
#define HTTPSERVER_RPS_WINDOW_SECONDS 10
#endif

#ifndef HTTPSERVER_IO_BUFFER_SIZE
#define HTTPSERVER_IO_BUFFER_SIZE 8192
#endif

#ifndef HTTPSERVER_RECV_BUFFER_SIZE
#define HTTPSERVER_RECV_BUFFER_SIZE 4096
#endif

#ifndef HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE
#define HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE 8192
#endif

#ifndef HTTPSERVER_MAX_CLIENTS_PER_ACCEPT
#define HTTPSERVER_MAX_CLIENTS_PER_ACCEPT 10
#endif

#ifndef HTTPSERVER_CHUNK_BUFFER_SIZE
#define HTTPSERVER_CHUNK_BUFFER_SIZE 16384
#endif

#ifndef HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE
#define HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE 8192
#endif

#ifndef HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS
#define HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS 64
#endif

#ifndef HTTPSERVER_LATENCY_SAMPLES
#define HTTPSERVER_LATENCY_SAMPLES 1000
#endif

extern const Except_T SocketHTTPServer_Failed;
extern const Except_T SocketHTTPServer_BindFailed;
extern const Except_T SocketHTTPServer_ProtocolError;

typedef enum
{
  HTTPSERVER_STATE_RUNNING,
  HTTPSERVER_STATE_DRAINING,
  HTTPSERVER_STATE_STOPPED
} SocketHTTPServer_State;

typedef struct
{
  int port;
  const char *bind_address;
  int backlog;

  SocketTLSContext_T tls_context;

  SocketHTTP_Version max_version;
  int enable_h2c_upgrade;

  size_t max_header_size;
  size_t max_body_size;

  int request_timeout_ms;
  int keepalive_timeout_ms;
  int request_read_timeout_ms;
  int response_write_timeout_ms;
  int tls_handshake_timeout_ms;
  int max_connection_lifetime_ms;

  size_t max_connections;
  size_t max_requests_per_connection;
  int max_connections_per_client;
  size_t max_concurrent_requests;

  SocketWS_Config ws_config;

  int per_server_metrics;
} SocketHTTPServer_Config;

typedef struct SocketHTTPServer *SocketHTTPServer_T;
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

typedef void (*SocketHTTPServer_Handler) (SocketHTTPServer_Request_T req,
                                          void *userdata);
typedef int (*SocketHTTPServer_BodyCallback) (SocketHTTPServer_Request_T req,
                                              const void *chunk,
                                              size_t len,
                                              int is_final,
                                              void *userdata);
typedef int (*SocketHTTPServer_Validator) (SocketHTTPServer_Request_T req,
                                           int *reject_status,
                                           void *userdata);
typedef void (*SocketHTTPServer_DrainCallback) (SocketHTTPServer_T server,
                                                int timed_out,
                                                void *userdata);

extern void SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config);
extern SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config);
extern void SocketHTTPServer_free (SocketHTTPServer_T *server);
extern int SocketHTTPServer_start (SocketHTTPServer_T server);
extern void SocketHTTPServer_stop (SocketHTTPServer_T server);
extern void SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                                          SocketHTTPServer_Handler handler,
                                          void *userdata);

extern int SocketHTTPServer_fd (SocketHTTPServer_T server);
extern int SocketHTTPServer_process (SocketHTTPServer_T server, int timeout_ms);
extern SocketPoll_T SocketHTTPServer_poll (SocketHTTPServer_T server);

extern SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req);
extern const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req);
extern const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req);
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_headers (SocketHTTPServer_Request_T req);
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_trailers (SocketHTTPServer_Request_T req);
extern const char *
SocketHTTPServer_Request_h2_protocol (SocketHTTPServer_Request_T req);
extern const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req);
extern size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req);
extern const char *
SocketHTTPServer_Request_client_addr (SocketHTTPServer_Request_T req);
extern SocketHTTP_Version
SocketHTTPServer_Request_version (SocketHTTPServer_Request_T req);
extern Arena_T SocketHTTPServer_Request_arena (SocketHTTPServer_Request_T req);
extern size_t
SocketHTTPServer_Request_memory_used (SocketHTTPServer_Request_T req);

extern void
SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req, int code);
extern void SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);
extern int SocketHTTPServer_Request_trailer (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);
extern void SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                                const void *data,
                                                size_t len);
extern void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str);
extern void SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req);

extern void
SocketHTTPServer_Request_body_stream (SocketHTTPServer_Request_T req,
                                      SocketHTTPServer_BodyCallback callback,
                                      void *userdata);
extern int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req);
extern int SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req);

extern int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req);
extern int SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                                const void *data,
                                                size_t len);
extern int SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req);

extern int SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                                          const char *path,
                                          SocketHTTP_Headers_T headers);
extern int SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req);

extern int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req);
extern SocketWS_T SocketHTTPServer_Request_upgrade_websocket (
    SocketHTTPServer_Request_T req,
    SocketHTTPServer_BodyCallback callback,
    void *userdata);
extern SocketHTTP2_Stream_T SocketHTTPServer_Request_accept_websocket_h2 (
    SocketHTTPServer_Request_T req,
    SocketHTTPServer_BodyCallback callback,
    void *userdata);

extern void SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                             const char *path_prefix,
                                             SocketRateLimit_T limiter);

extern void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata);

extern int SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms);
extern int SocketHTTPServer_drain_poll (SocketHTTPServer_T server);
extern int
SocketHTTPServer_drain_wait (SocketHTTPServer_T server, int timeout_ms);
extern int64_t SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server);
extern void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata);
extern SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server);

typedef struct
{
  size_t active_connections;
  size_t total_connections;
  size_t connections_rejected;

  size_t total_requests;
  size_t requests_per_second;

  size_t total_bytes_sent;
  size_t total_bytes_received;

  size_t errors_4xx;
  size_t errors_5xx;
  size_t timeouts;
  size_t rate_limited;

  int64_t avg_request_time_us;
  int64_t max_request_time_us;
  int64_t p50_request_time_us;
  int64_t p95_request_time_us;
  int64_t p99_request_time_us;
} SocketHTTPServer_Stats;

extern void SocketHTTPServer_stats (SocketHTTPServer_T server,
                                    SocketHTTPServer_Stats *stats);
extern void SocketHTTPServer_stats_reset (SocketHTTPServer_T server);

extern int SocketHTTPServer_add_static_dir (SocketHTTPServer_T server,
                                            const char *prefix,
                                            const char *directory);

typedef int (*SocketHTTPServer_Middleware) (SocketHTTPServer_Request_T req,
                                            void *userdata);
extern int
SocketHTTPServer_add_middleware (SocketHTTPServer_T server,
                                 SocketHTTPServer_Middleware middleware,
                                 void *userdata);

typedef void (*SocketHTTPServer_ErrorHandler) (SocketHTTPServer_Request_T req,
                                               int status_code,
                                               void *userdata);
extern void
SocketHTTPServer_set_error_handler (SocketHTTPServer_T server,
                                    SocketHTTPServer_ErrorHandler handler,
                                    void *userdata);

#endif /* SOCKETHTTPSERVER_INCLUDED */
