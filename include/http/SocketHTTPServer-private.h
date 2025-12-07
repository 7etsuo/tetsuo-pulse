/**
 * SocketHTTPServer-private.h - Internal HTTP Server Structures
 *
 * Part of the Socket Library
 *
 * PRIVATE HEADER - Do not include directly. Included by SocketHTTPServer.c and split files.
 */

#ifndef SOCKETHTTPSERVER_PRIVATE_INCLUDED
#define SOCKETHTTPSERVER_PRIVATE_INCLUDED

#include "SocketHTTPServer.h"
#include "http/SocketHTTP1.h"
#include "socket/SocketBuf.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include <pthread.h>

/* Internal types */

typedef struct RateLimitEntry
{
  char *path_prefix;
  SocketRateLimit_T limiter;
  struct RateLimitEntry *next;
} RateLimitEntry;

typedef enum
{
  CONN_STATE_READING_REQUEST,
  CONN_STATE_READING_BODY,
  CONN_STATE_HANDLING,
  CONN_STATE_STREAMING_RESPONSE,
  CONN_STATE_SENDING_RESPONSE,
  CONN_STATE_CLOSED
} ServerConnState;

typedef struct ServerConnection
{
  Socket_T socket;
  char client_addr[HTTPSERVER_CLIENT_ADDR_MAX];

  ServerConnState state;
  SocketHTTP1_Parser_T parser;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;

  /* Request data */
  const SocketHTTP_Request *request;
  void *body;
  size_t body_len;
  size_t body_capacity;
  SocketHTTP1_BodyMode body_mode;  /* Body transfer mode for processing */
  size_t body_received;

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
  size_t active_requests; /* For HTTP/2 multiplexing */

  /* Memory tracking */
  size_t memory_used; /* Total bytes allocated for this connection */

  Arena_T arena;

  struct ServerConnection *next;
  struct ServerConnection *prev;
} ServerConnection;

/* Internal request struct - opaque to users */
struct SocketHTTPServer_Request
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  Arena_T arena;
  int64_t start_time_ms;
};

/* LatencyTracker removed - use SocketMetrics histograms */

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

  /* Connections */
  ServerConnection *connections;
  size_t connection_count;

  /* Rate limiting */
  RateLimitEntry *rate_limiters;
  SocketRateLimit_T global_rate_limiter;

  /* Per-client limiting */
  SocketIPTracker_T ip_tracker;

  /* Graceful shutdown */
  volatile int state; /* SocketHTTPServer_State */
  int64_t drain_start_ms;
  int drain_timeout_ms;

  /* Statistics moved to SocketMetrics_* (counters, gauges, histograms) 
   * Query via SocketMetrics_get() or specific functions in stats API */

  /* Latency tracking moved to SocketMetrics (SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS) */

  /* No custom mutex - SocketMetrics handles thread safety internally */

  int running;
  Arena_T arena;
};

/* STATS macros removed - replace with SocketMetrics_counter_inc/gauge_inc etc. calls
 * Examples:
 *   SocketMetrics_counter_inc(SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL);
 *   SocketMetrics_gauge_inc(SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);
 *   SocketMetrics_counter_add(SOCKET_CTR_HTTP_SERVER_BYTES_SENT, bytes); 
 */

/* ============================================================================
 * Error Handling Macros
 * ============================================================================
 *
 * Centralized for consistency across split files.
 * Uses socket_error_buf (thread-local) for messages.
 */
#define HTTPSERVER_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)
#define HTTPSERVER_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

#define RAISE_HTTPSERVER_ERROR(e) SOCKET_RAISE_MODULE_ERROR (HTTPServer, e)

/* Internal helper functions - declared here for split files */

/* Connection management */
ServerConnection *connection_new (SocketHTTPServer_T server, Socket_T socket);
void connection_close (SocketHTTPServer_T server, ServerConnection *conn);
int connection_read (SocketHTTPServer_T server, ServerConnection *conn);
int connection_send_data (SocketHTTPServer_T server, ServerConnection *conn,
                          const void *data, size_t len);
void connection_reset_for_keepalive (ServerConnection *conn);
void connection_finish_request (SocketHTTPServer_T server, ServerConnection *conn);
int connection_parse_request (SocketHTTPServer_T server, ServerConnection *conn);
void connection_send_response (SocketHTTPServer_T server, ServerConnection *conn);
void connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                            int status, const char *body);

/* Latency tracking removed - use SocketMetrics histograms instead:
 *   SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS, latency);
 */


#endif /* SOCKETHTTPSERVER_PRIVATE_INCLUDED */
