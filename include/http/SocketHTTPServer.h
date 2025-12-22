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

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 *
 * All limits can be overridden at compile time with -D flags or at runtime
 * via SocketHTTPServer_Config fields.
 *
 * RESOURCE LIMITS:
 *   HTTPSERVER_DEFAULT_MAX_HEADER_SIZE  - 64KB   - Max total header size
 *   HTTPSERVER_DEFAULT_MAX_BODY_SIZE    - 10MB   - Max request body size
 *   HTTPSERVER_DEFAULT_MAX_CONNECTIONS  - 1000   - Max concurrent connections
 *   HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT - 100 - Per-IP limit
 *   HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN - 1000 - Max requests per connection
 *   HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS - 100 - HTTP/2 streams
 *
 * TIMEOUT LIMITS:
 *   HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS - 30s - Idle timeout
 *   HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS - 60s - Keep-alive timeout
 *   HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS - 30s - Full request read
 *   HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS - 60s - Full response write
 *   HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS - 10s - TLS handshake timeout
 *   HTTPSERVER_DEFAULT_MAX_CONNECTION_LIFETIME_MS - 300s - Max connection lifetime
 *
 * ENFORCEMENT:
 *   - max_header_size: Enforced by HTTP/1.1 parser (returns error)
 *   - max_body_size: Enforced before body allocation (returns 413)
 *   - max_connections: Enforced in accept loop (rejects new clients)
 *   - max_connections_per_client: Enforced via SocketIPTracker
 */

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

/**
 * Default maximum header size (64KB).
 * Enforced by HTTP/1.1 parser during parsing.
 */
#ifndef HTTPSERVER_DEFAULT_MAX_HEADER_SIZE
#define HTTPSERVER_DEFAULT_MAX_HEADER_SIZE (64 * 1024)
#endif

/**
 * Default maximum body size (10MB).
 * Returns 413 Payload Too Large when exceeded.
 */
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

/** TLS handshake timeout (ms) - prevents slowloris attacks. */
#ifndef HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS 10000
#endif

/** Max connection lifetime (ms) - defense-in-depth timeout. */
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

/**
 * Initial buffer for chunked request bodies.
 * Grows dynamically up to max_body_size.
 */
#ifndef HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE
#define HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE 8192
#endif

#ifndef HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS
#define HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS 64
#endif

#ifndef HTTPSERVER_LATENCY_SAMPLES
#define HTTPSERVER_LATENCY_SAMPLES 1000
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/** General server failures (allocation errors, internal state corruption). */
extern const Except_T SocketHTTPServer_Failed;

/** Binding to address/port failed (EADDRINUSE, etc.). */
extern const Except_T SocketHTTPServer_BindFailed;

/** HTTP protocol violations or parsing errors. */
extern const Except_T SocketHTTPServer_ProtocolError;

/* ============================================================================
 * Server State
 * ============================================================================ */

/** Server lifecycle states. */
typedef enum
{
  HTTPSERVER_STATE_RUNNING,  /**< Normal operation */
  HTTPSERVER_STATE_DRAINING, /**< Finishing existing requests */
  HTTPSERVER_STATE_STOPPED   /**< All requests complete */
} SocketHTTPServer_State;

/* ============================================================================
 * Server Configuration
 * ============================================================================ */

/**
 * HTTP server configuration.
 * Use SocketHTTPServer_config_defaults() to initialize, then customize.
 */
typedef struct
{
  /* Listener */
  int port;                 /**< Listen port (default: 8080) */
  const char *bind_address; /**< Bind address (default: "0.0.0.0") */
  int backlog;              /**< Listen backlog (default: 128) */

  /* TLS */
  SocketTLSContext_T tls_context; /**< TLS context for HTTPS (NULL = HTTP) */

  /* Protocol */
  SocketHTTP_Version max_version; /**< Max HTTP version (default: HTTP/2) */
  int enable_h2c_upgrade; /**< Enable HTTP/2 upgrade over cleartext (default: 0) */

  /* Size Limits */
  size_t max_header_size; /**< Max header size in bytes (default: 64KB) */
  size_t max_body_size;   /**< Max body size in bytes (default: 10MB) */

  /* Timeouts (ms) */
  int request_timeout_ms;       /**< Idle timeout between requests (default: 30s) */
  int keepalive_timeout_ms;     /**< Keep-alive timeout (default: 60s) */
  int request_read_timeout_ms;  /**< Time to read complete request (default: 30s) */
  int response_write_timeout_ms; /**< Time to send complete response (default: 60s) */
  int tls_handshake_timeout_ms; /**< TLS handshake timeout (default: 10s) */
  int max_connection_lifetime_ms; /**< Max connection lifetime (default: 5min) */

  /* Connection Limits */
  size_t max_connections;           /**< Max concurrent connections (default: 1000) */
  size_t max_requests_per_connection; /**< Max requests per connection (default: 1000) */
  int max_connections_per_client;   /**< Max connections per IP (default: 100) */
  size_t max_concurrent_requests;   /**< Max concurrent streams (default: 100) */

  /* WebSocket */
  SocketWS_Config ws_config; /**< WebSocket upgrade configuration */

  /* Metrics */
  int per_server_metrics; /**< Enable per-server metrics (default: 0) */
} SocketHTTPServer_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/**
 * Opaque HTTP server instance.
 * Manages connections, parsing, and response handling.
 */
typedef struct SocketHTTPServer *SocketHTTPServer_T;

/**
 * Opaque request context for handling individual HTTP requests.
 * Valid only during handler callback execution.
 */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * Request handler callback invoked for each incoming HTTP request.
 *
 * Handler responsibilities:
 * 1. Inspect request via accessors (method, path, headers, body)
 * 2. Set response status and headers
 * 3. Provide body (static or streaming)
 * 4. Finalize with finish() or end_stream()
 *
 * The request context is valid only during callback execution.
 *
 * @param req      Request context
 * @param userdata User data from set_handler()
 */
typedef void (*SocketHTTPServer_Handler) (SocketHTTPServer_Request_T req,
                                          void *userdata);

/**
 * Callback for streaming request body data incrementally.
 *
 * Enables memory-efficient handling of large uploads by processing chunks
 * as received without buffering the entire body.
 *
 * @param req       Request context
 * @param chunk     Body data chunk (valid only during callback)
 * @param len       Chunk length in bytes
 * @param is_final  Non-zero if this is the final chunk
 * @param userdata  User data from body_stream()
 * @return 0 to continue, non-zero to abort (sends 400)
 */
typedef int (*SocketHTTPServer_BodyCallback) (SocketHTTPServer_Request_T req,
                                              const void *chunk, size_t len,
                                              int is_final, void *userdata);

/**
 * Middleware validator callback for request validation/authentication.
 *
 * Executed after header parsing, before body read/handler. Can short-circuit
 * invalid requests early.
 *
 * @param req           Request context (headers available, no body)
 * @param reject_status Output: HTTP status for rejection (if returning 0)
 * @param userdata      User data from set_validator()
 * @return Non-zero to proceed to handler, 0 to reject with *reject_status
 */
typedef int (*SocketHTTPServer_Validator) (SocketHTTPServer_Request_T req,
                                           int *reject_status, void *userdata);

/**
 * Callback for graceful drain completion.
 *
 * @param server    Server entering STOPPED state
 * @param timed_out Non-zero if drain timed out (connections force-closed)
 * @param userdata  User data from set_drain_callback()
 */
typedef void (*SocketHTTPServer_DrainCallback) (SocketHTTPServer_T server,
                                                int timed_out, void *userdata);

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

/**
 * Initialize config with production-ready defaults.
 * @param config Config structure to initialize
 */
extern void SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config);

/**
 * Allocate and initialize a new HTTP server.
 *
 * Does not start listening; call start() after configuring handler.
 *
 * @param config Configuration (copied internally)
 * @return Server instance (caller owns; free with free())
 * @throws SocketHTTPServer_Failed on allocation failure
 */
extern SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config);

/**
 * Dispose of server instance and release all resources.
 *
 * Aborts ongoing requests. For clean shutdown, call drain() first.
 * Sets *server to NULL. Idempotent.
 *
 * @param server Pointer to server instance
 */
extern void SocketHTTPServer_free (SocketHTTPServer_T *server);

/**
 * Bind and start listening for connections.
 *
 * Non-blocking; use process() to handle events.
 *
 * @param server Initialized server instance
 * @return 0 on success, -1 on error
 * @throws SocketHTTPServer_BindFailed on bind/listen errors
 */
extern int SocketHTTPServer_start (SocketHTTPServer_T server);

/**
 * Stop accepting new connections; existing ones complete normally.
 * Idempotent.
 * @param server Running server instance
 */
extern void SocketHTTPServer_stop (SocketHTTPServer_T server);

/**
 * Register the request handler callback.
 *
 * @param server   Server instance
 * @param handler  Callback (NULL disables handling)
 * @param userdata Passed to handler on each request
 */
extern void SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                                          SocketHTTPServer_Handler handler,
                                          void *userdata);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================ */

/**
 * Get listening socket fd for external poll integration.
 * @param server Server instance
 * @return fd >= 0 if listening, -1 otherwise
 */
extern int SocketHTTPServer_fd (SocketHTTPServer_T server);

/**
 * Main event loop step: poll, accept, parse, handle requests.
 *
 * @param server     Running server
 * @param timeout_ms Max wait time (-1 = infinite)
 * @return Number of requests processed, -1 on fatal error
 */
extern int SocketHTTPServer_process (SocketHTTPServer_T server,
                                     int timeout_ms);

/**
 * Access internal SocketPoll_T for custom event handling.
 * Do not free the returned poll (server-owned).
 * @param server Server instance
 * @return Internal poll, or NULL if invalid
 */
extern SocketPoll_T SocketHTTPServer_poll (SocketHTTPServer_T server);

/* ============================================================================
 * Request Accessors
 * ============================================================================ */

/** Get HTTP method. */
extern SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req);

/** Get request path (decoded, no query string). */
extern const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req);

/** Get query string (raw, NULL if none). */
extern const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req);

/** Get request headers (server-owned, do not free). */
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_headers (SocketHTTPServer_Request_T req);

/** Get trailer headers (HTTP/2 only, NULL otherwise). */
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_trailers (SocketHTTPServer_Request_T req);

/** Get HTTP/2 :protocol pseudo-header (RFC 8441), NULL if not present. */
extern const char *
SocketHTTPServer_Request_h2_protocol (SocketHTTPServer_Request_T req);

/** Get buffered request body (NULL if streaming or no body). */
extern const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req);

/** Get request body length. */
extern size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req);

/** Get client IP address as string (format: "IP:port"). */
extern const char *
SocketHTTPServer_Request_client_addr (SocketHTTPServer_Request_T req);

/** Get HTTP version. */
extern SocketHTTP_Version
SocketHTTPServer_Request_version (SocketHTTPServer_Request_T req);

/** Get per-request arena for temporary allocations. */
extern Arena_T SocketHTTPServer_Request_arena (SocketHTTPServer_Request_T req);

/** Get approximate memory usage for this connection. */
extern size_t
SocketHTTPServer_Request_memory_used (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Building
 * ============================================================================ */

/**
 * Set HTTP status code for response.
 * Must be called before headers/body. Defaults to 200.
 */
extern void SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req,
                                             int code);

/** Add response header. */
extern void SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);

/**
 * Add response trailer (HTTP/2 only).
 * @return 0 on success, -1 if unsupported or pseudo-header provided
 */
extern int SocketHTTPServer_Request_trailer (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);

/** Set response body from buffer (sets Content-Length). */
extern void SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/** Set response body from null-terminated string. */
extern void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str);

/**
 * Finalize and send response.
 * Request context invalidated after this call.
 */
extern void SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Request Body Streaming
 * ============================================================================ */

/**
 * Enable streaming for request body.
 * When enabled, body() returns NULL and chunks arrive via callback.
 */
extern void
SocketHTTPServer_Request_body_stream (SocketHTTPServer_Request_T req,
                                      SocketHTTPServer_BodyCallback callback,
                                      void *userdata);

/**
 * Get expected body length from Content-Length.
 * @return Expected bytes, or -1 if chunked/unknown
 */
extern int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req);

/** Check if request uses chunked transfer encoding. */
extern int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Body Streaming
 * ============================================================================ */

/**
 * Start streaming response (chunked transfer encoding).
 * Call send_chunk() to emit body, then end_stream() to finalize.
 * @return 0 on success, -1 on failure
 */
extern int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req);

/**
 * Send a chunk of response body.
 * Requires begin_stream() first.
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * End streaming response.
 * @return 0 on success, -1 on error
 */
extern int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req);

/* ============================================================================
 * HTTP/2 Server Push
 * ============================================================================ */

/**
 * Initiate HTTP/2 server push.
 *
 * @param req     Request context (must be HTTP/2)
 * @param path    Resource path to push
 * @param headers Optional headers for pushed request
 * @return 0 on success, -1 if not HTTP/2 or push disabled
 */
extern int SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                                          const char *path,
                                          SocketHTTP_Headers_T headers);

/** Check if connection uses HTTP/2. */
extern int SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req);

/* ============================================================================
 * WebSocket Upgrade
 * ============================================================================ */

/** Check if request is a WebSocket upgrade attempt. */
extern int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req);

/**
 * Accept WebSocket upgrade.
 * Sends 101 Switching Protocols and returns WebSocket handle.
 * HTTP functions invalid after upgrade.
 * @return SocketWS_T on success, NULL on failure
 */
extern SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req);

/**
 * Accept WebSocket-over-HTTP/2 (RFC 8441 Extended CONNECT).
 *
 * @param req       HTTP/2 request with :protocol=websocket
 * @param callback  Callback for received DATA
 * @param userdata  Passed to callback
 * @return HTTP/2 stream on success, NULL on failure
 */
extern SocketHTTP2_Stream_T
SocketHTTPServer_Request_accept_websocket_h2 (SocketHTTPServer_Request_T req,
                                              SocketHTTPServer_BodyCallback callback,
                                              void *userdata);

/* ============================================================================
 * Rate Limiting
 * ============================================================================ */

/**
 * Register rate limiter for endpoints.
 *
 * Requests matching path_prefix are checked against limiter.
 * NULL prefix = global, NULL limiter = disable for prefix.
 *
 * @param server      Server instance
 * @param path_prefix Path prefix to match (case-sensitive)
 * @param limiter     Rate limiter (caller-owned; server references only)
 */
extern void SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                             const char *path_prefix,
                                             SocketRateLimit_T limiter);

/* ============================================================================
 * Request Validation Middleware
 * ============================================================================ */

/**
 * Install middleware validator for incoming requests.
 * Runs after header parsing, before body read/handler.
 *
 * @param server    Server instance
 * @param validator Callback (NULL disables)
 * @param userdata  Passed to validator
 */
extern void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata);

/* ============================================================================
 * Graceful Shutdown
 * ============================================================================ */

/**
 * Initiate graceful shutdown.
 *
 * Stops accepting new connections, waits for in-flight requests.
 *
 * @param server     Server instance
 * @param timeout_ms Max wait time (-1=infinite, 0=immediate force)
 * @return 0 if started, -1 if already stopped/draining
 */
extern int SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms);

/**
 * Non-blocking drain progress check.
 * @return >0 connections remaining, 0 fully drained, -1 timed out
 */
extern int SocketHTTPServer_drain_poll (SocketHTTPServer_T server);

/**
 * Block until drain completes.
 * @param timeout_ms Additional wait time (-1=use drain timeout)
 * @return 0 if drained gracefully, -1 if timed out
 */
extern int SocketHTTPServer_drain_wait (SocketHTTPServer_T server,
                                        int timeout_ms);

/** Get milliseconds remaining before drain timeout. */
extern int64_t SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server);

/**
 * Register drain completion callback.
 *
 * @param server   Server instance
 * @param callback Completion handler (NULL disables)
 * @param userdata Passed to callback
 */
extern void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata);

/** Get current server state. */
extern SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server);

/* ============================================================================
 * Server Statistics
 * ============================================================================ */

/** Server statistics for monitoring. */
typedef struct
{
  /* Connection stats */
  size_t active_connections;   /**< Current active connections */
  size_t total_connections;    /**< Cumulative connections accepted */
  size_t connections_rejected; /**< Connections rejected (limits) */

  /* Request stats */
  size_t total_requests;      /**< Total requests processed */
  size_t requests_per_second; /**< Recent RPS */

  /* Byte counters */
  size_t total_bytes_sent;     /**< Total response bytes */
  size_t total_bytes_received; /**< Total request bytes */

  /* Error stats */
  size_t errors_4xx;   /**< 4xx client errors */
  size_t errors_5xx;   /**< 5xx server errors */
  size_t timeouts;     /**< Timeout closures */
  size_t rate_limited; /**< Rate-limited requests (429) */

  /* Latency stats (microseconds) */
  int64_t avg_request_time_us; /**< Mean request time */
  int64_t max_request_time_us; /**< Maximum request time */
  int64_t p50_request_time_us; /**< 50th percentile */
  int64_t p95_request_time_us; /**< 95th percentile */
  int64_t p99_request_time_us; /**< 99th percentile */
} SocketHTTPServer_Stats;

/** Get server statistics snapshot. */
extern void SocketHTTPServer_stats (SocketHTTPServer_T server,
                                    SocketHTTPServer_Stats *stats);

/** Reset cumulative statistics counters. */
extern void SocketHTTPServer_stats_reset (SocketHTTPServer_T server);

/* ============================================================================
 * Static File Serving
 * ============================================================================ */

/**
 * Add static file serving for a directory.
 *
 * Serves files from directory for requests matching prefix.
 * Supports conditional requests and range requests.
 * Path traversal attacks prevented.
 *
 * @param server    Server instance
 * @param prefix    URL prefix (e.g., "/static")
 * @param directory Filesystem directory
 * @return 0 on success, -1 if directory not accessible
 */
extern int SocketHTTPServer_add_static_dir (SocketHTTPServer_T server,
                                            const char *prefix,
                                            const char *directory);

/* ============================================================================
 * Middleware
 * ============================================================================ */

/**
 * Middleware callback.
 *
 * @param req      Request context
 * @param userdata Middleware-specific data
 * @return 0 to continue, non-zero to stop (request handled)
 */
typedef int (*SocketHTTPServer_Middleware) (SocketHTTPServer_Request_T req,
                                            void *userdata);

/**
 * Add request middleware.
 *
 * Middleware executes in order before the main handler.
 *
 * @param server     Server instance
 * @param middleware Callback
 * @param userdata   Passed to callback
 * @return 0 on success, -1 if too many middleware
 */
extern int SocketHTTPServer_add_middleware (SocketHTTPServer_T server,
                                            SocketHTTPServer_Middleware middleware,
                                            void *userdata);

/**
 * Error handler callback for custom error pages.
 *
 * @param req         Request context (status already set)
 * @param status_code HTTP status (400-599)
 * @param userdata    Handler-specific data
 */
typedef void (*SocketHTTPServer_ErrorHandler) (SocketHTTPServer_Request_T req,
                                               int status_code, void *userdata);

/**
 * Set custom error page handler.
 *
 * @param server  Server instance
 * @param handler Error handler (NULL resets to default)
 * @param userdata Passed to handler
 */
extern void SocketHTTPServer_set_error_handler (SocketHTTPServer_T server,
                                                SocketHTTPServer_ErrorHandler handler,
                                                void *userdata);

#endif /* SOCKETHTTPSERVER_INCLUDED */
