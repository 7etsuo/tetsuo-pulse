/**
 * SocketHTTPServer.h - HTTP Server API
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * High-level HTTP server supporting HTTP/1.1 and HTTP/2:
 * - Event-driven request handling
 * - Connection management with keep-alive
 * - Protocol negotiation (ALPN for HTTP/2)
 * - WebSocket upgrade support
 * - Request body streaming for large uploads
 * - Response body streaming (chunked transfer encoding)
 * - HTTP/2 server push support
 * - Rate limiting per endpoint
 * - Per-client connection limiting
 * - Request validation middleware
 * - Granular timeout enforcement
 * - Graceful shutdown (drain)
 *
 * Dependencies (leveraged, not duplicated):
 * - SocketHTTP for headers, URI, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing
 * - SocketHTTP2 for HTTP/2 protocol
 * - SocketPoll for event loop integration
 * - SocketRateLimit for rate limiting
 * - SocketIPTracker for per-client limits
 *
 * Thread safety: Server instances are NOT thread-safe.
 * Use one server per thread or external synchronization.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - pthread for mutex synchronization
 * - OpenSSL for TLS (optional, via SOCKET_HAS_TLS)
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
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/* Forward declarations for optional TLS */
#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/* Forward declaration for WebSocket */
typedef struct SocketWS *SocketWS_T;

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 *
 * CONFIGURABLE LIMITS SUMMARY
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
 *
 * ENFORCEMENT:
 *   - max_header_size: Enforced by HTTP/1.1 parser (returns error)
 *   - max_body_size: Enforced before body allocation (returns 413)
 *   - max_connections: Enforced in accept loop (rejects new clients)
 *   - max_connections_per_client: Enforced via SocketIPTracker
 *
 * METRICS:
 *   - SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED incremented on body limit violation
 *   - SOCKET_CTR_LIMIT_HEADER_SIZE_EXCEEDED incremented on header limit violation
 */

/** Default listen backlog */
#ifndef HTTPSERVER_DEFAULT_BACKLOG
#define HTTPSERVER_DEFAULT_BACKLOG 128
#endif

/** Default maximum connections */
#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTIONS
#define HTTPSERVER_DEFAULT_MAX_CONNECTIONS 1000
#endif

/** Default request timeout (ms) - idle timeout between requests */
#ifndef HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS 30000
#endif

/** Default keep-alive timeout (ms) */
#ifndef HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS 60000
#endif

/**
 * Default maximum header size
 * ENFORCEMENT: Passed to HTTP/1.1 parser config, enforced during parsing.
 */
#ifndef HTTPSERVER_DEFAULT_MAX_HEADER_SIZE
#define HTTPSERVER_DEFAULT_MAX_HEADER_SIZE (64 * 1024)
#endif

/**
 * Default maximum body size
 * ENFORCEMENT: Checked before body allocation. Returns 413 Payload Too Large.
 */
#ifndef HTTPSERVER_DEFAULT_MAX_BODY_SIZE
#define HTTPSERVER_DEFAULT_MAX_BODY_SIZE (10 * 1024 * 1024)
#endif

/** Default maximum requests per connection */
#ifndef HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN
#define HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN 1000
#endif

/** Default request read timeout (ms) - time to read full request */
#ifndef HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS 30000
#endif

/** Default response write timeout (ms) - time to send full response */
#ifndef HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS 60000
#endif

/** Default max connections per client IP */
#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT
#define HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT 100
#endif

/** Default max concurrent requests per connection (HTTP/2 multiplexing) */
#ifndef HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS
#define HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS 100
#endif

/** Default streaming chunk size for response */
#ifndef HTTPSERVER_DEFAULT_STREAM_CHUNK_SIZE
#define HTTPSERVER_DEFAULT_STREAM_CHUNK_SIZE 8192
#endif

/** Requests per second window (seconds) for RPS calculation */
#ifndef HTTPSERVER_RPS_WINDOW_SECONDS
#define HTTPSERVER_RPS_WINDOW_SECONDS 10
#endif

/** I/O buffer size per connection (bytes) */
#ifndef HTTPSERVER_IO_BUFFER_SIZE
#define HTTPSERVER_IO_BUFFER_SIZE 8192
#endif

/** Max clients to accept per event loop iteration */
#ifndef HTTPSERVER_MAX_CLIENTS_PER_ACCEPT
#define HTTPSERVER_MAX_CLIENTS_PER_ACCEPT 10
#endif

/** Chunk buffer size for streaming responses (bytes) */
#ifndef HTTPSERVER_CHUNK_BUFFER_SIZE
#define HTTPSERVER_CHUNK_BUFFER_SIZE 16384
#endif

/** Max rate limit endpoints */
#ifndef HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS
#define HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS 64
#endif

/** Number of latency samples to track */
#ifndef HTTPSERVER_LATENCY_SAMPLES
#define HTTPSERVER_LATENCY_SAMPLES 1000
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/** General server failure */
extern const Except_T SocketHTTPServer_Failed;

/** Bind failure */
extern const Except_T SocketHTTPServer_BindFailed;

/** Protocol error */
extern const Except_T SocketHTTPServer_ProtocolError;

/* ============================================================================
 * Server State
 * ============================================================================ */

/**
 * Server lifecycle state for graceful shutdown
 */
typedef enum
{
  HTTPSERVER_STATE_RUNNING,  /**< Normal operation */
  HTTPSERVER_STATE_DRAINING, /**< Draining - finishing existing requests */
  HTTPSERVER_STATE_STOPPED   /**< Stopped - all requests complete */
} SocketHTTPServer_State;

/* ============================================================================
 * Server Configuration
 * ============================================================================ */

/**
 * HTTP server configuration
 */
typedef struct
{
  /* Listener */
  int port;                 /**< Listen port */
  const char *bind_address; /**< Bind address (NULL = all interfaces) */
  int backlog;              /**< Listen backlog */

  /* TLS */
  SocketTLSContext_T tls_context; /**< TLS context (NULL = HTTP only) */

  /* Protocol */
  SocketHTTP_Version max_version; /**< Max HTTP version (default: HTTP/2) */
  int enable_h2c_upgrade;         /**< Allow HTTP/2 upgrade (default: 0) */

  /* Size Limits */
  size_t max_header_size;
  size_t max_body_size;

  /* Timeout Configuration */
  int request_timeout_ms;        /**< Idle timeout between requests */
  int keepalive_timeout_ms;      /**< Keep-alive timeout */
  int request_read_timeout_ms;   /**< Max time to read complete request */
  int response_write_timeout_ms; /**< Max time to send complete response */

  /* Connection Limits */
  size_t max_connections;             /**< Total max connections */
  size_t max_requests_per_connection; /**< Max requests per connection */
  int max_connections_per_client;     /**< Max connections per client IP */
  size_t max_concurrent_requests;     /**< Max concurrent requests (HTTP/2) */
} SocketHTTPServer_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/** HTTP server instance */
typedef struct SocketHTTPServer *SocketHTTPServer_T;

/** Server request context */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * Request handler callback
 *
 * Called for each incoming HTTP request. The handler should:
 * 1. Read request details using accessor functions
 * 2. Set response status and headers
 * 3. Send response body
 * 4. Call finish() when done
 *
 * The request context is valid only during the callback.
 */
typedef void (*SocketHTTPServer_Handler) (SocketHTTPServer_Request_T req,
                                          void *userdata);

/**
 * Request body streaming callback
 *
 * Called incrementally as request body data arrives. Enables processing
 * large uploads without buffering the entire body in memory.
 *
 * @req: Request context
 * @chunk: Body data chunk
 * @len: Chunk length
 * @is_final: 1 if this is the last chunk, 0 otherwise
 * @userdata: User data from SocketHTTPServer_Request_body_stream()
 *
 * Returns: 0 to continue receiving, non-zero to abort and close connection
 */
typedef int (*SocketHTTPServer_BodyCallback) (SocketHTTPServer_Request_T req,
                                              const void *chunk, size_t len,
                                              int is_final, void *userdata);

/**
 * Request validation callback (middleware)
 *
 * Called before the request handler to validate/authenticate requests.
 * Can reject requests before they reach the handler.
 *
 * @req: Request context
 * @reject_status: Output - HTTP status code if rejecting (e.g., 401, 403)
 * @userdata: User data from SocketHTTPServer_set_validator()
 *
 * Returns: Non-zero to allow request (call handler), 0 to reject
 */
typedef int (*SocketHTTPServer_Validator) (SocketHTTPServer_Request_T req,
                                           int *reject_status, void *userdata);

/**
 * Drain completion callback
 *
 * Called when graceful shutdown completes or times out.
 *
 * @server: Server instance
 * @timed_out: 1 if drain timed out (forced shutdown), 0 if graceful
 * @userdata: User data from SocketHTTPServer_set_drain_callback()
 */
typedef void (*SocketHTTPServer_DrainCallback) (SocketHTTPServer_T server,
                                                int timed_out, void *userdata);

/* ============================================================================
 * Server Lifecycle
 * ============================================================================ */

/**
 * SocketHTTPServer_config_defaults - Initialize config with defaults
 * @config: Configuration structure
 *
 * Thread-safe: Yes
 */
extern void SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config);

/**
 * SocketHTTPServer_new - Create HTTP server
 * @config: Configuration
 *
 * Returns: New server instance
 * Raises: SocketHTTPServer_Failed on error
 * Thread-safe: Yes
 */
extern SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config);

/**
 * SocketHTTPServer_free - Free server and resources
 * @server: Pointer to server (set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHTTPServer_free (SocketHTTPServer_T *server);

/**
 * SocketHTTPServer_start - Start listening
 * @server: Server instance
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTPServer_start (SocketHTTPServer_T server);

/**
 * SocketHTTPServer_stop - Stop server
 * @server: Server instance
 *
 * Stops accepting new connections. Existing connections continue.
 * Thread-safe: No
 */
extern void SocketHTTPServer_stop (SocketHTTPServer_T server);

/**
 * SocketHTTPServer_set_handler - Set request handler
 * @server: Server instance
 * @handler: Handler callback
 * @userdata: User data passed to handler
 *
 * Thread-safe: No
 */
extern void SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                                          SocketHTTPServer_Handler handler,
                                          void *userdata);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================ */

/**
 * SocketHTTPServer_fd - Get server socket for poll
 * @server: Server instance
 *
 * Returns: File descriptor for listening socket
 * Thread-safe: Yes
 */
extern int SocketHTTPServer_fd (SocketHTTPServer_T server);

/**
 * SocketHTTPServer_process - Process events
 * @server: Server instance
 * @timeout_ms: Poll timeout in milliseconds
 *
 * Accepts new connections, reads requests, and invokes handlers.
 *
 * Returns: Number of requests processed
 * Thread-safe: No
 */
extern int SocketHTTPServer_process (SocketHTTPServer_T server, int timeout_ms);

/**
 * SocketHTTPServer_poll - Get poll instance
 * @server: Server instance
 *
 * Returns: Internal SocketPoll_T for advanced integration
 * Thread-safe: Yes
 */
extern SocketPoll_T SocketHTTPServer_poll (SocketHTTPServer_T server);

/* ============================================================================
 * Request Accessors
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_method - Get request method
 */
extern SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_path - Get request path
 */
extern const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_query - Get query string
 */
extern const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_headers - Get request headers
 */
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_headers (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_body - Get request body
 */
extern const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_body_len - Get request body length
 */
extern size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_client_addr - Get client address
 */
extern const char *
SocketHTTPServer_Request_client_addr (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_version - Get HTTP version
 */
extern SocketHTTP_Version
SocketHTTPServer_Request_version (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_arena - Get request arena
 */
extern Arena_T SocketHTTPServer_Request_arena (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_memory_used - Get connection memory usage
 * @req: Request context
 *
 * Returns: Total bytes allocated for this connection (including buffers, body)
 * Thread-safe: No
 */
extern size_t
SocketHTTPServer_Request_memory_used (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Building
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_status - Set response status
 * @req: Request context
 * @code: HTTP status code
 */
extern void SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req,
                                             int code);

/**
 * SocketHTTPServer_Request_header - Add response header
 * @req: Request context
 * @name: Header name
 * @value: Header value
 */
extern void SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);

/**
 * SocketHTTPServer_Request_body_data - Set response body
 * @req: Request context
 * @data: Body data
 * @len: Body length
 */
extern void SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * SocketHTTPServer_Request_body_string - Set response body from string
 * @req: Request context
 * @str: Null-terminated string
 */
extern void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str);

/**
 * SocketHTTPServer_Request_finish - Finish and send response
 * @req: Request context
 *
 * Must be called to complete the response.
 */
extern void SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Request Body Streaming
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_body_stream - Enable streaming body callback
 * @req: Request context
 * @callback: Callback invoked for each body chunk
 * @userdata: User data passed to callback
 *
 * Enables streaming mode for receiving request body. When enabled:
 * - Body chunks are delivered via callback as they arrive
 * - Body is NOT buffered in memory
 * - SocketHTTPServer_Request_body() returns NULL
 *
 * Call this before calling finish() to receive body data.
 * Thread-safe: No
 */
extern void SocketHTTPServer_Request_body_stream (
    SocketHTTPServer_Request_T req, SocketHTTPServer_BodyCallback callback,
    void *userdata);

/**
 * SocketHTTPServer_Request_body_expected - Get expected body length
 * @req: Request context
 *
 * Returns: Content-Length if known, -1 if chunked/unknown
 * Thread-safe: No
 */
extern int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_is_chunked - Check if request uses chunked encoding
 * @req: Request context
 *
 * Returns: 1 if chunked transfer encoding, 0 otherwise
 * Thread-safe: No
 */
extern int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Body Streaming
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_begin_stream - Begin streaming response
 * @req: Request context
 *
 * Begins a chunked transfer-encoding response. After calling:
 * - Response headers are sent with Transfer-Encoding: chunked
 * - Use send_chunk() to send body data
 * - Use end_stream() to complete the response
 * - Do NOT call body_data(), body_string(), or finish()
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_send_chunk - Send response chunk
 * @req: Request context
 * @data: Chunk data
 * @len: Chunk length
 *
 * Sends a chunk of the response body. Can be called multiple times.
 * begin_stream() must be called first.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * SocketHTTPServer_Request_end_stream - End streaming response
 * @req: Request context
 *
 * Sends the final zero-length chunk and completes the response.
 * After calling, the request context is complete.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req);

/* ============================================================================
 * HTTP/2 Server Push
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_push - Push a resource (HTTP/2 only)
 * @req: Request context
 * @path: Path of resource to push
 * @headers: Headers for pushed request (can be NULL)
 *
 * Initiates HTTP/2 server push for a resource. Only works for HTTP/2
 * connections. For HTTP/1.1 connections, returns -1.
 *
 * Returns: 0 on success, -1 on error or not supported
 * Thread-safe: No
 */
extern int SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                                          const char *path,
                                          SocketHTTP_Headers_T headers);

/**
 * SocketHTTPServer_Request_is_http2 - Check if connection is HTTP/2
 * @req: Request context
 *
 * Returns: 1 if HTTP/2, 0 if HTTP/1.x
 * Thread-safe: No
 */
extern int SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req);

/* ============================================================================
 * WebSocket Upgrade
 * ============================================================================ */

/**
 * SocketHTTPServer_Request_is_websocket - Check WebSocket upgrade
 * @req: Request context
 *
 * Returns: 1 if WebSocket upgrade requested, 0 otherwise
 */
extern int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req);

/**
 * SocketHTTPServer_Request_upgrade_websocket - Upgrade to WebSocket
 * @req: Request context
 *
 * Returns: WebSocket instance (Phase 9), or NULL on error
 * Thread-safe: No
 *
 * Sends 101 Switching Protocols and returns WebSocket handle.
 * The request context is invalid after this call.
 */
extern SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Rate Limiting
 * ============================================================================ */

/**
 * SocketHTTPServer_set_rate_limit - Set rate limiter for endpoint
 * @server: Server instance
 * @path_prefix: Path prefix to limit (NULL for global default)
 * @limiter: Rate limiter instance
 *
 * Registers a rate limiter for requests matching path_prefix.
 * When rate limit exceeded, server returns 429 Too Many Requests.
 * NULL limiter removes rate limiting for the path.
 *
 * Thread-safe: No
 */
extern void SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                             const char *path_prefix,
                                             SocketRateLimit_T limiter);

/* ============================================================================
 * Request Validation Middleware
 * ============================================================================ */

/**
 * SocketHTTPServer_set_validator - Set request validation callback
 * @server: Server instance
 * @validator: Validation callback (NULL to disable)
 * @userdata: User data passed to callback
 *
 * Sets a middleware callback that runs before each request handler.
 * Can be used for authentication, authorization, input validation.
 *
 * Thread-safe: No
 */
extern void SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                            SocketHTTPServer_Validator validator,
                                            void *userdata);

/* ============================================================================
 * Graceful Shutdown
 * ============================================================================ */

/**
 * SocketHTTPServer_drain - Begin graceful shutdown
 * @server: Server instance
 * @timeout_ms: Maximum time to wait for requests to complete (-1 = infinite)
 *
 * Begins draining the server:
 * - Stops accepting new connections
 * - Existing connections continue processing
 * - After timeout, force-closes remaining connections
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms);

/**
 * SocketHTTPServer_drain_poll - Poll drain progress
 * @server: Server instance
 *
 * Check drain status. Call repeatedly until returns 0 or negative.
 *
 * Returns: >0 remaining connections, 0 drain complete, -1 timed out (forced)
 * Thread-safe: No
 */
extern int SocketHTTPServer_drain_poll (SocketHTTPServer_T server);

/**
 * SocketHTTPServer_drain_wait - Blocking wait for drain
 * @server: Server instance
 * @timeout_ms: Maximum time to wait (-1 = use drain timeout)
 *
 * Blocks until drain completes or timeout. Convenience wrapper around
 * drain + drain_poll loop.
 *
 * Returns: 0 on graceful completion, -1 on timeout (forced)
 * Thread-safe: No
 */
extern int SocketHTTPServer_drain_wait (SocketHTTPServer_T server,
                                        int timeout_ms);

/**
 * SocketHTTPServer_drain_remaining_ms - Get time until forced shutdown
 * @server: Server instance
 *
 * Returns: Milliseconds until drain timeout, 0 if not draining, -1 if infinite
 * Thread-safe: Yes (atomic read)
 */
extern int64_t SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server);

/**
 * SocketHTTPServer_set_drain_callback - Set drain completion callback
 * @server: Server instance
 * @callback: Callback (NULL to disable)
 * @userdata: User data passed to callback
 *
 * Thread-safe: No
 */
extern void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata);

/**
 * SocketHTTPServer_state - Get server lifecycle state
 * @server: Server instance
 *
 * Returns: Current state (RUNNING, DRAINING, or STOPPED)
 * Thread-safe: Yes (atomic read)
 */
extern SocketHTTPServer_State SocketHTTPServer_state (SocketHTTPServer_T server);

/* ============================================================================
 * Server Statistics
 * ============================================================================ */

/**
 * Server statistics (enhanced for production monitoring)
 */
typedef struct
{
  /* Connection stats */
  size_t active_connections;       /**< Current active connections */
  size_t total_connections;        /**< Total connections accepted */
  size_t connections_rejected;     /**< Connections rejected (limits) */

  /* Request stats */
  size_t total_requests;           /**< Total requests processed */
  size_t requests_per_second;      /**< RPS over sliding window */

  /* Byte counters */
  size_t total_bytes_sent;         /**< Total bytes sent */
  size_t total_bytes_received;     /**< Total bytes received */

  /* Error stats */
  size_t errors_4xx;               /**< 4xx client errors */
  size_t errors_5xx;               /**< 5xx server errors */
  size_t timeouts;                 /**< Connections closed by timeout */
  size_t rate_limited;             /**< Requests rate limited (429) */

  /* Latency stats (microseconds) */
  int64_t avg_request_time_us;     /**< Average request latency */
  int64_t max_request_time_us;     /**< Maximum request latency */
  int64_t p50_request_time_us;     /**< 50th percentile latency */
  int64_t p95_request_time_us;     /**< 95th percentile latency */
  int64_t p99_request_time_us;     /**< 99th percentile latency */
} SocketHTTPServer_Stats;

/**
 * SocketHTTPServer_stats - Get server statistics
 * @server: Server instance
 * @stats: Output statistics
 *
 * Thread-safe: No
 */
extern void SocketHTTPServer_stats (SocketHTTPServer_T server,
                                    SocketHTTPServer_Stats *stats);

/**
 * SocketHTTPServer_stats_reset - Reset statistics counters
 * @server: Server instance
 *
 * Resets all counters to zero. Active connections is not reset.
 * Thread-safe: No
 */
extern void SocketHTTPServer_stats_reset (SocketHTTPServer_T server);

#endif /* SOCKETHTTPSERVER_INCLUDED */

