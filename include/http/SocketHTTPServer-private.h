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

#define SERVER_METRICS_INC(server, global_metric, instance_field)         \
  do                                                                      \
    {                                                                     \
      SocketMetrics_counter_inc (global_metric);                          \
      if ((server)->config.per_server_metrics)                            \
        atomic_fetch_add (&(server)->instance_metrics.instance_field, 1); \
    }                                                                     \
  while (0)

#define SERVER_METRICS_ADD(server, global_metric, instance_field, value) \
  do                                                                     \
    {                                                                    \
      SocketMetrics_counter_add ((global_metric), (value));              \
      if ((server)->config.per_server_metrics)                           \
        atomic_fetch_add (&(server)->instance_metrics.instance_field,    \
                          (value));                                      \
    }                                                                    \
  while (0)

#define SERVER_GAUGE_INC(server, global_metric, instance_field)           \
  do                                                                      \
    {                                                                     \
      SocketMetrics_gauge_inc (global_metric);                            \
      if ((server)->config.per_server_metrics)                            \
        atomic_fetch_add (&(server)->instance_metrics.instance_field, 1); \
    }                                                                     \
  while (0)

#define SERVER_GAUGE_DEC(server, global_metric, instance_field)           \
  do                                                                      \
    {                                                                     \
      SocketMetrics_gauge_dec (global_metric);                            \
      if ((server)->config.per_server_metrics)                            \
        atomic_fetch_sub (&(server)->instance_metrics.instance_field, 1); \
    }                                                                     \
  while (0)

typedef struct RateLimitEntry
{
  char *path_prefix;
  size_t prefix_len;
  SocketRateLimit_T limiter;
  struct RateLimitEntry *next;
} RateLimitEntry;

typedef struct StaticRoute
{
  char *prefix;
  char *directory;
  size_t prefix_len;
  char *resolved_directory;
  size_t resolved_dir_len;
  struct StaticRoute *next;
} StaticRoute;

typedef struct MiddlewareEntry
{
  SocketHTTPServer_Middleware func;
  void *userdata;
  struct MiddlewareEntry *next;
} MiddlewareEntry;

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

typedef struct ServerHTTP2Stream
{
  SocketHTTP2_Stream_T stream;
  Arena_T arena;
  struct ServerHTTP2Stream *next;

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

  SocketHTTPServer_BodyCallback body_callback;
  void *body_callback_userdata;
  int body_streaming;
  int ws_over_h2;

  int response_status;
  SocketHTTP_Headers_T response_headers;
  SocketHTTP_Headers_T response_trailers;
  void *response_body;
  size_t response_body_len;
  size_t response_body_sent;
  int response_finished;
  int response_end_stream_sent;

  int response_streaming;
  int response_headers_sent;
  SocketBuf_T response_outbuf;
} ServerHTTP2Stream;

typedef struct ServerConnection
{
  Socket_T socket;
  char client_addr[HTTPSERVER_CLIENT_ADDR_MAX];

  ServerConnState state;
  SocketHTTP1_Parser_T parser;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;

  int tls_enabled;
  int tls_handshake_done;
  int is_http2;
  SocketHTTP2_Conn_T http2_conn;
  int http2_callback_set;
  ServerHTTP2Stream *http2_streams;

  const SocketHTTP_Request *request;
  void *body;
  SocketBuf_T body_buf;
  size_t body_len;
  size_t body_capacity;
  SocketHTTP1_BodyMode body_mode;
  size_t body_received;
  int body_uses_buf;

  SocketHTTPServer_BodyCallback body_callback;
  void *body_callback_userdata;
  int body_streaming;

  int response_status;
  SocketHTTP_Headers_T response_headers;
  void *response_body;
  size_t response_body_len;
  int response_finished;

  int response_streaming;
  int response_headers_sent;

  int64_t created_at_ms;
  int64_t last_activity_ms;
  int64_t request_start_ms;
  int64_t response_start_ms;
  size_t request_count;
  size_t active_requests;

  size_t memory_used;

  Arena_T arena;

  struct ServerConnection *next;
  struct ServerConnection *prev;

  /* Deferred deletion: connection marked for close but not yet freed.
   * This prevents use-after-free when multiple events for same connection
   * arrive in a single poll batch (common with io_uring multishot polls). */
  int pending_close;
  struct ServerConnection *next_pending;
} ServerConnection;

struct SocketHTTPServer_Request
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  ServerHTTP2Stream *h2_stream;
  Arena_T arena;
  int64_t start_time_ms;
};

struct SocketHTTPServer
{
  SocketHTTPServer_Config config;

  Socket_T listen_socket;
  SocketPoll_T poll;

  SocketHTTPServer_Handler handler;
  void *handler_userdata;
  SocketHTTPServer_Validator validator;
  void *validator_userdata;
  SocketHTTPServer_DrainCallback drain_callback;
  void *drain_callback_userdata;
  SocketHTTPServer_ErrorHandler error_handler;
  void *error_handler_userdata;

  MiddlewareEntry *middleware_chain;
  MiddlewareEntry *middleware_tail;

  ServerConnection *connections;
  size_t connection_count;

  /* Connections pending deletion (deferred until end of event loop).
   * Prevents use-after-free when same connection has multiple events. */
  ServerConnection *pending_close_list;

  RateLimitEntry *rate_limiters;
  SocketRateLimit_T global_rate_limiter;

  StaticRoute *static_routes;

  SocketIPTracker_T ip_tracker;

  volatile int state;
  int64_t drain_start_ms;
  int drain_timeout_ms;

  uint64_t stats_prev_requests;
  int64_t stats_prev_time_ms;
  pthread_mutex_t stats_mutex;

  SocketHTTPServer_InstanceMetrics instance_metrics;

  int running;
  Arena_T arena;
};

/**
 * @brief Helper macro to free a singly-linked list with custom cleanup.
 *
 * Safely traverses and frees a linked list, executing custom cleanup code for
 * each node before freeing the node itself. Avoids use-after-free by saving
 * the next pointer before cleanup.
 *
 * @param head       Pointer to the head of the list
 * @param type       Type of the list node
 * @param cleanup    Cleanup code block (can reference 'node' variable)
 *
 * Example:
 *   FREE_LIST(server->rate_limiters, RateLimitEntry, {
 *     free(node->path_prefix);
 *   });
 */
#define FREE_LIST(head, type, cleanup)   \
  do                                     \
    {                                    \
      type *node = (head);               \
      while (node != NULL)               \
        {                                \
          type *next = node->next;       \
          cleanup;                       \
          free (node);                   \
          node = next;                   \
        }                                \
    }                                    \
  while (0)

#define HTTPSERVER_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPSERVER_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)
#define RAISE_HTTPSERVER_ERROR(e) \
  SOCKET_RAISE_MODULE_ERROR (SocketHTTPServer, e)

void connection_send_error (SocketHTTPServer_T server,
                            ServerConnection *conn,
                            int status_code,
                            const char *reason);
int connection_send_data (SocketHTTPServer_T server,
                          ServerConnection *conn,
                          const void *data,
                          size_t len);
void
connection_send_response (SocketHTTPServer_T server, ServerConnection *conn);
void
connection_finish_request (SocketHTTPServer_T server, ServerConnection *conn);
int connection_read (SocketHTTPServer_T server, ServerConnection *conn);
int
connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn);
void connection_close (SocketHTTPServer_T server, ServerConnection *conn);
void connection_free_pending (SocketHTTPServer_T server);
ServerConnection *connection_new (SocketHTTPServer_T server, Socket_T socket);

/* Event loop helpers (SocketHTTPServer.c) */
int server_check_connection_timeout (SocketHTTPServer_T server,
                                     ServerConnection *conn,
                                     int64_t now);
int server_process_client_event (SocketHTTPServer_T server,
                                 ServerConnection *conn,
                                 unsigned events);

int
server_run_validator_early (SocketHTTPServer_T server, ServerConnection *conn);

/* Rate limiting (SocketHTTPServer.c) */
SocketRateLimit_T
find_rate_limiter (SocketHTTPServer_T server, const char *path);

/* Static file serving (SocketHTTPServer-static.c) */
StaticRoute *
server_find_static_route (SocketHTTPServer_T server, const char *path);
int server_serve_static_file (SocketHTTPServer_T server,
                              ServerConnection *conn,
                              StaticRoute *route,
                              const char *file_path);

/* HTTP/2 server stream handling (SocketHTTPServer-h2.c) */
typedef struct
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
} HTTP2ServerCallbackCtx;

ServerHTTP2Stream *
server_http2_stream_get_or_create (SocketHTTPServer_T server,
                                   ServerConnection *conn,
                                   SocketHTTP2_Stream_T stream);
int server_http2_build_request (SocketHTTPServer_T server,
                                ServerHTTP2Stream *s,
                                const SocketHPACK_Header *headers,
                                size_t header_count,
                                int end_stream);
void
server_http2_try_dispose_stream (ServerConnection *conn, ServerHTTP2Stream *s);
void
server_http2_send_end_stream (ServerConnection *conn, ServerHTTP2Stream *s);
void
server_http2_flush_stream_output (ServerConnection *conn, ServerHTTP2Stream *s);
void server_http2_send_nonstreaming_response (ServerConnection *conn,
                                              ServerHTTP2Stream *s);
void
server_http2_handle_request (HTTP2ServerCallbackCtx *ctx, ServerHTTP2Stream *s);
void server_http2_stream_cb (SocketHTTP2_Conn_T http2_conn,
                             SocketHTTP2_Stream_T stream,
                             int event,
                             void *userdata);
int server_http2_enable (SocketHTTPServer_T server, ServerConnection *conn);

/*
 * Response state accessors - abstract HTTP/1.1 vs HTTP/2 path selection.
 * These inline helpers eliminate dual-path conditionals in response API.
 */

static inline int *
server_response_status_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_status
                        : &req->conn->response_status;
}

static inline SocketHTTP_Headers_T *
server_response_headers_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_headers
                        : &req->conn->response_headers;
}

static inline void **
server_response_body_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_body
                        : &req->conn->response_body;
}

static inline size_t *
server_response_body_len_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_body_len
                        : &req->conn->response_body_len;
}

static inline int *
server_response_finished_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_finished
                        : &req->conn->response_finished;
}

static inline int *
server_response_streaming_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_streaming
                        : &req->conn->response_streaming;
}

static inline int *
server_response_headers_sent_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->response_headers_sent
                        : &req->conn->response_headers_sent;
}

static inline int *
server_body_streaming_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->body_streaming
                        : &req->conn->body_streaming;
}

static inline SocketHTTPServer_BodyCallback *
server_body_callback_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->body_callback
                        : &req->conn->body_callback;
}

static inline void **
server_body_callback_userdata_ptr (SocketHTTPServer_Request_T req)
{
  return req->h2_stream ? &req->h2_stream->body_callback_userdata
                        : &req->conn->body_callback_userdata;
}

#endif /* SOCKETHTTPSERVER_PRIVATE_INCLUDED */
