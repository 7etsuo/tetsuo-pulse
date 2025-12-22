/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer-private.h
 * @brief Private implementation details for HTTP server.
 * @internal
 *
 * Internal header for HTTP server implementation (src/http/*.c only).
 * Threading: Single-threaded event loop (non-thread-safe).
 */

#ifndef SOCKETHTTPSERVER_PRIVATE_INCLUDED
#define SOCKETHTTPSERVER_PRIVATE_INCLUDED

#include "SocketHTTPServer.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "socket/SocketBuf.h"
#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * Per-Server Instance Metrics
 * ============================================================================
 */

typedef struct SocketHTTPServer_InstanceMetrics
{
  _Atomic uint64_t connections_total;
  _Atomic uint64_t connections_rejected;
  _Atomic int64_t active_connections;
  _Atomic uint64_t requests_total;
  _Atomic uint64_t requests_timeout;
  _Atomic uint64_t rate_limited;
  _Atomic uint64_t bytes_sent;
  _Atomic uint64_t bytes_received;
  _Atomic uint64_t errors_4xx;
  _Atomic uint64_t errors_5xx;
} SocketHTTPServer_InstanceMetrics;

/* ============================================================================
 * Metrics Macros - Update both global and per-server metrics
 * ============================================================================
 */

#define SERVER_METRICS_INC(server, global_metric, instance_field)              \
  do                                                                           \
    {                                                                          \
      SocketMetrics_counter_inc (global_metric);                               \
      if ((server)->config.per_server_metrics)                                 \
        atomic_fetch_add (&(server)->instance_metrics.instance_field, 1);      \
    }                                                                          \
  while (0)

#define SERVER_METRICS_ADD(server, global_metric, instance_field, value)       \
  do                                                                           \
    {                                                                          \
      SocketMetrics_counter_add ((global_metric), (value));                    \
      if ((server)->config.per_server_metrics)                                 \
        atomic_fetch_add (&(server)->instance_metrics.instance_field, (value));\
    }                                                                          \
  while (0)

#define SERVER_GAUGE_INC(server, global_metric, instance_field)                \
  do                                                                           \
    {                                                                          \
      SocketMetrics_gauge_inc (global_metric);                                 \
      if ((server)->config.per_server_metrics)                                 \
        atomic_fetch_add (&(server)->instance_metrics.instance_field, 1);      \
    }                                                                          \
  while (0)

#define SERVER_GAUGE_DEC(server, global_metric, instance_field)                \
  do                                                                           \
    {                                                                          \
      SocketMetrics_gauge_dec (global_metric);                                 \
      if ((server)->config.per_server_metrics)                                 \
        atomic_fetch_sub (&(server)->instance_metrics.instance_field, 1);      \
    }                                                                          \
  while (0)

/* ============================================================================
 * Internal Types
 * ============================================================================
 */

/** Per-path rate limiter entry. */
typedef struct RateLimitEntry
{
  char *path_prefix;
  SocketRateLimit_T limiter;
  struct RateLimitEntry *next;
} RateLimitEntry;

/** Static file serving route. */
typedef struct StaticRoute
{
  char *prefix;
  char *directory;
  size_t prefix_len;
  char *resolved_directory;
  size_t resolved_dir_len;
  struct StaticRoute *next;
} StaticRoute;

/** Middleware chain entry. */
typedef struct MiddlewareEntry
{
  SocketHTTPServer_Middleware func;
  void *userdata;
  struct MiddlewareEntry *next;
} MiddlewareEntry;

/** Connection state machine states. */
typedef enum
{
  CONN_STATE_TLS_HANDSHAKE,
  CONN_STATE_READING_REQUEST,
  CONN_STATE_READING_BODY,
  CONN_STATE_HANDLING,
  CONN_STATE_STREAMING_RESPONSE,
  CONN_STATE_SENDING_RESPONSE,
  CONN_STATE_HTTP2,
  CONN_STATE_CLOSED
} ServerConnState;

/** Per-stream state for HTTP/2 connections. */
typedef struct ServerHTTP2Stream
{
  SocketHTTP2_Stream_T stream;
  Arena_T arena;
  struct ServerHTTP2Stream *next;

  /* Request data */
  SocketHTTP_Request *request;
  char *h2_protocol;
  SocketHTTP_Headers_T request_trailers;
  int request_complete;
  int request_end_stream;
  int handled;
  void *body;
  SocketBuf_T body_buf;
  size_t body_len;
  size_t body_capacity;
  size_t body_received;
  int body_uses_buf;

  /* Request body streaming */
  SocketHTTPServer_BodyCallback body_callback;
  void *body_callback_userdata;
  int body_streaming;
  int ws_over_h2;

  /* Response data */
  int response_status;
  SocketHTTP_Headers_T response_headers;
  SocketHTTP_Headers_T response_trailers;
  void *response_body;
  size_t response_body_len;
  size_t response_body_sent;
  int response_finished;
  int response_end_stream_sent;

  /* Response streaming */
  int response_streaming;
  int response_headers_sent;
  SocketBuf_T response_outbuf;
} ServerHTTP2Stream;

/** Active HTTP client connection state. */
typedef struct ServerConnection
{
  Socket_T socket;
  char client_addr[HTTPSERVER_CLIENT_ADDR_MAX];

  ServerConnState state;
  SocketHTTP1_Parser_T parser;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;

  /* TLS / HTTP/2 mode */
  int tls_enabled;
  int tls_handshake_done;
  int is_http2;
  SocketHTTP2_Conn_T http2_conn;
  int http2_callback_set;
  ServerHTTP2Stream *http2_streams;

  /* Request data */
  const SocketHTTP_Request *request;
  void *body;
  SocketBuf_T body_buf;
  size_t body_len;
  size_t body_capacity;
  SocketHTTP1_BodyMode body_mode;
  size_t body_received;
  int body_uses_buf;

  /* Request body streaming */
  SocketHTTPServer_BodyCallback body_callback;
  void *body_callback_userdata;
  int body_streaming;

  /* Response data */
  int response_status;
  SocketHTTP_Headers_T response_headers;
  void *response_body;
  size_t response_body_len;
  int response_finished;

  /* Response streaming */
  int response_streaming;
  int response_headers_sent;

  /* Connection metadata */
  int64_t created_at_ms;
  int64_t last_activity_ms;
  int64_t request_start_ms;
  int64_t response_start_ms;
  size_t request_count;
  size_t active_requests;

  /* Memory tracking */
  size_t memory_used;

  Arena_T arena;

  struct ServerConnection *next;
  struct ServerConnection *prev;
} ServerConnection;

/** Request context passed to handlers. */
struct SocketHTTPServer_Request
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  ServerHTTP2Stream *h2_stream;
  Arena_T arena;
  int64_t start_time_ms;
};

/** HTTP server instance. */
struct SocketHTTPServer
{
  SocketHTTPServer_Config config;

  Socket_T listen_socket;
  SocketPoll_T poll;

  /* Callbacks */
  SocketHTTPServer_Handler handler;
  void *handler_userdata;
  SocketHTTPServer_Validator validator;
  void *validator_userdata;
  SocketHTTPServer_DrainCallback drain_callback;
  void *drain_callback_userdata;
  SocketHTTPServer_ErrorHandler error_handler;
  void *error_handler_userdata;

  /* Middleware chain */
  MiddlewareEntry *middleware_chain;

  /* Connections */
  ServerConnection *connections;
  size_t connection_count;

  /* Rate limiting */
  RateLimitEntry *rate_limiters;
  SocketRateLimit_T global_rate_limiter;

  /* Static file serving */
  StaticRoute *static_routes;

  /* Per-client limiting */
  SocketIPTracker_T ip_tracker;

  /* Graceful shutdown */
  volatile int state;
  int64_t drain_start_ms;
  int drain_timeout_ms;

  /* Per-server stats tracking for RPS calculation */
  uint64_t stats_prev_requests;
  int64_t stats_prev_time_ms;
  pthread_mutex_t stats_mutex;

  /* Per-server metrics (optional, enabled via config.per_server_metrics) */
  SocketHTTPServer_InstanceMetrics instance_metrics;

  int running;
  Arena_T arena;
};

/* ============================================================================
 * Error Handling Macros
 * ============================================================================
 */

#define HTTPSERVER_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPSERVER_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)
#define RAISE_HTTPSERVER_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTPServer, e)

/* ============================================================================
 * Connection Helper Functions (implemented in SocketHTTPServer-connections.c)
 * ============================================================================
 */

void connection_send_error (SocketHTTPServer_T server,
                            ServerConnection *conn,
                            int status_code,
                            const char *reason);

int connection_send_data (SocketHTTPServer_T server,
                          ServerConnection *conn,
                          const void *data,
                          size_t len);

void connection_send_response (SocketHTTPServer_T server,
                               ServerConnection *conn);

void connection_finish_request (SocketHTTPServer_T server,
                                ServerConnection *conn);

int connection_read (SocketHTTPServer_T server, ServerConnection *conn);

int connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn);

void connection_close (SocketHTTPServer_T server, ServerConnection *conn);

/* ============================================================================
 * Early Validator Support (implemented in SocketHTTPServer.c)
 * ============================================================================
 */

int server_run_validator_early (SocketHTTPServer_T server,
                                ServerConnection *conn);

#endif /* SOCKETHTTPSERVER_PRIVATE_INCLUDED */
