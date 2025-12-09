/**
 * @file SocketHTTPServer-private.h
 * @brief Private implementation details for HTTP server connection and state management.
 * @ingroup http
 * @internal
 *
 * Internal header exposing structures and helpers for HTTP server implementation.
 * **Not part of public API** - intended for use only within C implementation files (src/http/ *.c).
 * For public interface, include SocketHTTPServer.h.
 *
 * Key internals documented here:
 * - @ref ServerConnection active connection state and buffers
 * - @ref ServerConnState processing pipeline states
 * - Rate limiting integration (@ref RateLimitEntry)
 * - Error macros (@ref http_error_macros)
 * - Connection lifecycle helpers (connection_new(), etc.)
 *
 * Supports HTTP/1.1 parsing via SocketHTTP1, HTTP/2 via SocketHTTP2,
 * event-driven I/O with SocketPoll, and security features from utilities modules.
 * Includes graceful drain/shutdown, per-IP limits, and DoS protections.
 *
 * Threading model: Single-threaded event loop (non-thread-safe).
 *
 * @see @ref http "HTTP Module" group for public APIs.
 * @see SocketHTTPServer.h public header and functions.
 * @see SocketHTTP-private.h shared HTTP internals.
 * @see @ref connection_mgmt "Connection Management" for pooling integration.
 * @see @ref utilities "Utilities" for rate limiting and metrics.
 * @see docs/HTTP-REFACTOR.md for design rationale (if exists).
 */

#ifndef SOCKETHTTPSERVER_PRIVATE_INCLUDED
#define SOCKETHTTPSERVER_PRIVATE_INCLUDED

#include "SocketHTTPServer.h"
#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "http/SocketHTTP1.h"
#include "socket/SocketBuf.h"
#include <pthread.h>

/* Internal types */

/**
 * @brief Linked list entry for per-path rate limiters.
 * @ingroup http
 * @internal
 *
 * Allows configuring different rate limits for different URL path prefixes.
 * For example, API endpoints can have stricter limits than static files.
 * 
 * @see SocketRateLimit_T for the underlying token bucket limiter.
 * @see SocketHTTPServer_set_rate_limiter() for adding limiters.
 */
typedef struct RateLimitEntry
{
  char *path_prefix;
  SocketRateLimit_T limiter;
  struct RateLimitEntry *next;
} RateLimitEntry;

/**
 * @brief Internal states tracking the processing pipeline of a server connection.
 * @ingroup http
 * @internal
 *
 * State machine transitions:
 * - CONN_STATE_READING_REQUEST → CONN_STATE_READING_BODY (if content-length/chunked) → CONN_STATE_HANDLING
 * - CONN_STATE_HANDLING → CONN_STATE_STREAMING_RESPONSE (if streaming response) → CONN_STATE_SENDING_RESPONSE
 * - CONN_STATE_SENDING_RESPONSE → CONN_STATE_CLOSED or back to CONN_STATE_READING_REQUEST (keep-alive)
 * 
 * Used for timeout enforcement, logging, and resource cleanup.
 * @see ServerConnection::state
 * @see SocketHTTPServer_Config for timeout configurations per state.
 */
typedef enum
{
  CONN_STATE_READING_REQUEST,
  CONN_STATE_READING_BODY,
  CONN_STATE_HANDLING,
  CONN_STATE_STREAMING_RESPONSE,
  CONN_STATE_SENDING_RESPONSE,
  CONN_STATE_CLOSED
} ServerConnState;

/**
 * @brief Core internal structure representing an active HTTP client connection.
 * @ingroup http
 * @internal
 *
 * Encapsulates all state for one client connection:
 * - Socket handle and client address
 * - Parsing and buffering (HTTP/1.1 parser, in/out buffers)
 * - Request data (parsed request, body handling/streaming)
 * - Response data (status, headers, body streaming)
 * - Timing (creation, activity, request/response start times)
 * - Metrics (request count, active streams for HTTP/2)
 * - Resource tracking (memory used, arena)
 * - Linked list pointers for server-wide connection management
 *
 * State transitions managed via ::state field.
 * Memory managed via ::arena; cleared on connection close.
 * Thread-unsafe; accessed only from server event loop thread.
 *
 * @see connection_new() for allocation.
 * @see connection_close() for cleanup.
 * @see SocketHTTPServer::connections for list integration.
 * @see SocketHTTP_Request for parsed request details.
 * @see SocketHTTP1_Parser_T for HTTP/1.1 parsing state.
 */
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
  SocketHTTP1_BodyMode body_mode; /* Body transfer mode for processing */
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

/**
 * @brief Internal implementation details of the SocketHTTPServer_Request opaque type.
 * @ingroup http
 * @internal
 *
 * This structure is passed to user-defined request handlers (@ref SocketHTTPServer_Handler).
 * It provides:
 * - Reference to owning server for configuration and stats access
 * - Underlying connection for low-level operations (internal use)
 * - Per-request Arena_T for temporary allocations (freed after handler completes)
 * - Start timestamp for latency calculations
 *
 * Users MUST NOT access fields directly. Use public accessors like:
 * - SocketHTTPServer_request_server()
 * - SocketHTTPServer_request_arena()
 * - SocketHTTPServer_request_time()
 *
 * @see SocketHTTPServer_Request in SocketHTTPServer.h for public opaque declaration.
 * @see SocketHTTPServer_Handler for usage in callbacks.
 * @see Arena_T for memory management details.
 */
struct SocketHTTPServer_Request
{
  SocketHTTPServer_T server;
  ServerConnection *conn;
  Arena_T arena;
  int64_t start_time_ms;
};

/**
 * @brief Internal implementation of the SocketHTTPServer opaque type.
 * @ingroup http
 * @internal
 *
 * Central structure managing the entire HTTP server instance:
 * - Configuration (::config)
 * - Listening socket and event poll (::listen_socket, ::poll)
 * - User callbacks for handling, validation, draining (::handler, ::validator, ::drain_callback)
 * - Connection list and counts (::connections, ::connection_count)
 * - Rate limiting configuration (::rate_limiters, ::global_rate_limiter)
 * - IP-based connection limiting (::ip_tracker)
 * - Graceful shutdown state (::state, ::drain_start_ms, ::drain_timeout_ms)
 * - Legacy stats fields (being phased out in favor of SocketMetrics)
 * - Server arena for allocations
 *
 * Thread-unsafe by design; intended for single-threaded use with SocketPoll.
 * All access serialized by the event loop.
 *
 * @note Statistics and latency tracking migrated to @ref SocketMetrics for centralized, thread-safe metrics.
 *       Legacy fields (::stats_prev_requests, etc.) retained for compatibility but deprecated.
 * @note No embedded TLS; use SocketTLS integration via public API.
 *
 * @see SocketHTTPServer_new() for creation and initialization.
 * @see SocketHTTPServer_free() for cleanup and resource release.
 * @see SocketPoll_T for event loop integration details.
 * @see SocketIPTracker_T for client limiting implementation.
 * @see SocketRateLimit_T for rate limiting details.
 */
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

  /* Per-server stats tracking for RPS calculation (thread-safe via
   * single-thread poll assumption) */
  uint64_t stats_prev_requests;
  int64_t stats_prev_time_ms;
  pthread_mutex_t stats_mutex; /* Protect RPS calc if multi-threaded */

  /* Statistics moved to SocketMetrics_* (counters, gauges, histograms)
   * Query via SocketMetrics_get() or specific functions in stats API */

  /* Latency tracking moved to SocketMetrics
   * (SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS) */

  /* No custom mutex - SocketMetrics handles thread safety internally */

  int running;
  Arena_T arena;
};

/**
 * @brief Migration guide for deprecated HTTP server statistics macros.
 * @ingroup http
 * @internal
 * @deprecated
 *
 * The STATS_* macros previously used for server metrics have been removed.
 * Migrate to SocketMetrics API for improved thread-safety and observability:
 *
 * Examples:
 *   SocketMetrics_counter_inc(SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL);
 *   SocketMetrics_gauge_inc(SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);
 *   SocketMetrics_counter_add(SOCKET_CTR_HTTP_SERVER_BYTES_SENT, bytes);
 *
 * Benefits:
 * - Centralized metrics with export (e.g., to Prometheus/StatsD)
 * - Atomic operations for multi-threaded safety
 * - Histogram support for latency percentiles
 * - Consistent naming across library modules
 *
 * Update calls in all src/http/ *.c files. Tests and examples updated accordingly.
 * Legacy macros undefined to prevent use.
 *
 * @see @ref utilities "Utilities Module" for SocketMetrics details.
 * @see SocketMetrics_counter_inc(), SocketMetrics_gauge_set(), etc.
 * @see HTTP server metric constants (SOCKET_CTR_HTTP_SERVER_*, SOCKET_HIST_HTTP_SERVER_*)
 */

/**
 * @defgroup http_error_macros HTTP Server Error Handling Macros
 * @ingroup http
 * @internal
 * @brief Macros for consistent error formatting and exception raising in HTTP server implementation.
 *
 * These provide uniform error handling across split .c files, using core Socket library infrastructure:
 * - Thread-local error buffering (socket_error_buf)
 * - Automatic errno/strerror integration
 * - Module exception registration for SocketHTTPServer exceptions
 *
 * Typical usage:
 *   HTTPSERVER_ERROR_FMT("invalid request on fd=%d", Socket_fd(conn->socket));
 *   RAISE_HTTPSERVER_ERROR(SocketHTTPServer_Failed);
 *
 * @see SocketUtil.h SOCKET_ERROR_* base macros
 * @see Except.h exception framework
 * @see SocketHTTPServer exceptions (SocketHTTPServer_Failed, etc.)
 * @{
 */

/**
 * @brief Error formatting macro including errno details for HTTP server errors.
 * @ingroup http_error_macros
 * @internal
 *
 * Formats message with printf-style args, appends ": <strerror(errno)>",
 * stores in thread-local buffer.
 *
 * @param fmt Format string.
 * @param ... Arguments.
 * @see HTTPSERVER_ERROR_MSG() without errno.
 * @see Socket_GetLastError() retrieve buffer.
 */
#define HTTPSERVER_ERROR_FMT(fmt, ...) SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__)

/**
 * @brief Error formatting macro without errno for HTTP server errors.
 * @ingroup http_error_macros
 * @internal
 *
 * Formats message without system error details.
 *
 * @param fmt Format string.
 * @param ... Arguments.
 * @see HTTPSERVER_ERROR_FMT() with errno.
 */
#define HTTPSERVER_ERROR_MSG(fmt, ...) SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__)

/**
 * @brief Raise module-specific HTTP server exception.
 * @ingroup http_error_macros
 * @internal
 *
 * Raises exception using current error buffer message and specified type.
 * Registers with HTTPServer module for proper TRY/EXCEPT matching.
 *
 * @param e Exception code (e.g., SocketHTTPServer_Failed).
 * @see SOCKET_RAISE_MODULE_ERROR base macro.
 * @see SocketHTTPServer.h for available exceptions.
 */
/** @} */ /* http_error_macros */

/**
 * @brief Raise HTTP server-specific exception using current error buffer.
 * @ingroup http_error_macros
 * @internal
 *
 * Raises a module-registered exception with the error message from the thread-local
 * buffer (populated by HTTPSERVER_ERROR_FMT or HTTPSERVER_ERROR_MSG).
 * Centralized for consistency across HTTP server implementation files.
 *
 * @param e Exception type (e.g., SocketHTTPServer_Failed, SocketHTTPServer_ProtocolError).
 *
 * @see HTTPSERVER_ERROR_FMT() and HTTPSERVER_ERROR_MSG() for setting the error message.
 * @see SOCKET_RAISE_MODULE_ERROR() underlying implementation.
 * @see Except.h for exception handling framework.
 * @see SocketHTTPServer.h for public exception types.
 */
#define RAISE_HTTPSERVER_ERROR(e) SOCKET_RAISE_MODULE_ERROR (HTTPServer, e)

/**
 * @defgroup http_server_connection_mgmt Internal HTTP Server Connection Management Helpers
 * @ingroup http
 * @internal
 * @brief Helper functions for managing individual HTTP server connections.
 *
 * These functions implement core connection lifecycle logic: creation, I/O handling,
 * request parsing, response generation, and cleanup. Designed for use in split
 * implementation files (src/http/ *.c). All functions assume single-threaded access
 * via the server's poll loop and are not thread-safe.
 *
 * Key areas:
 * - Connection allocation and teardown (@ref connection_new, @ref connection_close)
 * - I/O operations with buffering and timeouts (@ref connection_read, @ref connection_send_data)
 * - HTTP request parsing and validation (@ref connection_parse_request)
 * - Response serialization and error handling (@ref connection_send_response, @ref connection_send_error)
 *
 * @see ServerConnection structure for connection state details.
 * @see SocketHTTPServer_T for server-level management and integration.
 * @see SocketPoll_T for event-driven I/O multiplexing.
 * @see @ref event_system "Event System Group" for polling integration.
 * @see @ref core_io "Core I/O Group" for underlying socket operations.
 * @{
 */

/* Connection management */
/**
 * @brief Allocate and initialize a new ServerConnection for an accepted client socket.
 * @ingroup http
 * @internal
 * @param server Owning HTTP server instance.
 * @param socket Newly accepted client socket (non-blocking).
 * @return Allocated ServerConnection or NULL on failure.
 * @throws Socket_Failed on socket operations failure.
 * @throws Arena_Failed on memory allocation failure.
 * @note Initializes buffers, parser, timing, and adds to server connection list.
 * @see Socket_accept() for obtaining the socket.
 * @see connection_close() for paired cleanup.
 */
ServerConnection *connection_new (SocketHTTPServer_T server, Socket_T socket);

/**
 * @brief Close and cleanup a server connection, releasing resources.
 * @ingroup http
 * @internal
 * @param server Owning server (for list removal and stats update).
 * @param conn Connection to close (may be NULL).
 * @note Performs graceful close if possible; force closes on errors.
 *       Removes from server list, frees arena allocations, closes socket.
 *       Updates server stats and metrics.
 * @see Socket_close() for underlying socket close.
 * @see SocketHTTPServer_drain() for server-wide graceful shutdown.
 */
void connection_close (SocketHTTPServer_T server, ServerConnection *conn);

/**
 * @brief Perform read operation on connection, handling partial reads and timeouts.
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection to read from.
 * @return >0 bytes read, 0 EOF/disconnect, <0 error (sets errno).
 * @note Advances parser state based on read data.
 *       Enforces read timeouts and max header/body sizes.
 *       Handles HTTP/1.1 pipelining if keep-alive.
 * @see Socket_recv() for low-level read.
 * @see SocketHTTP1_Parser_execute() for parsing integration.
 */
int connection_read (SocketHTTPServer_T server, ServerConnection *conn);

/**
 * @brief Send data over connection, handling partial sends and buffering.
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection to write to.
 * @param data Data buffer to send.
 * @param len Length of data.
 * @return >0 bytes sent, <=0 error or closed.
 * @note Uses outbuf for buffering if non-blocking send incomplete.
 *       Enforces write timeouts and bandwidth limits if configured.
 * @see Socket_send() or SocketTLS_send() for transport.
 * @see SocketBuf_T for buffering details.
 */
int connection_send_data (SocketHTTPServer_T server, ServerConnection *conn,
                          const void *data, size_t len);

/**
 * @brief Reset connection state for new request on keep-alive connection.
 * @ingroup http
 * @internal
 * @param conn Connection to reset.
 * @note Clears parser, buffers, request/response data, but keeps socket open.
 *       Updates activity timestamp.
 *       Prepares for next HTTP request parsing.
 * @see SocketHTTP1_Parser_reset() for parser reset.
 * @see connection_parse_request() for next request handling.
 */
void connection_reset_for_keepalive (ServerConnection *conn);

/**
 * @brief Finalize current request processing and prepare for next or close.
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection to finish.
 * @note Updates metrics, frees request-specific resources.
 *       If keep-alive and idle timeout not exceeded, reset for next request.
 *       Otherwise, schedule close.
 * @see SocketHTTPServer_Config::keepalive_timeout_ms
 */
void connection_finish_request (SocketHTTPServer_T server,
                                ServerConnection *conn);

/**
 * @brief Parse incoming request data, handling headers and body.
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection with buffered data.
 * @return 0 continue, 1 request complete, <0 error (parse failure).
 * @throws SocketHTTP1_ParseError on malformed request.
 * @note Integrates with SocketHTTP1_Parser; validates via ::validator if set.
 *       Allocates request body if within limits.
 *       Sets up streaming if callback provided.
 * @see SocketHTTP1_Parser_execute() core parsing.
 * @see SocketHTTPServer_Validator for pre-handler validation.
 */
int connection_parse_request (SocketHTTPServer_T server,
                              ServerConnection *conn);

/**
 * @brief Serialize and send HTTP response (headers + body).
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection to respond on.
 * @note Serializes response status, headers, body (chunked if streaming/large).
 *       Handles HTTP/1.1 vs HTTP/2 differences.
 *       Updates response timing and metrics.
 * @see SocketHTTP1_serialize_response() for HTTP/1.1.
 * @see SocketHTTP2 for HTTP/2 response handling.
 */
void connection_send_response (SocketHTTPServer_T server,
                               ServerConnection *conn);

/**
 * @brief Send HTTP error response with status and optional body.
 * @ingroup http
 * @internal
 * @param server Owning server.
 * @param conn Connection to send error to.
 * @param status HTTP status code (e.g., 400, 500).
 * @param body Optional error body text (may be NULL).
 * @note Generates standard error headers (Content-Type: text/plain).
 *       Logs error via SocketLog.
 *       Increments error metrics.
 * @see SocketHTTP_status_reason() for reason phrase.
 * @see connection_send_response() for general response sending.
 */
void connection_send_error (SocketHTTPServer_T server, ServerConnection *conn,
                            int status, const char *body);

/** @} http_server_connection_mgmt */

/**
 * @brief Note on removed latency tracking for HTTP requests.
 * @ingroup http
 * @internal
 *
 * Direct latency tracking code removed; use SocketMetrics histograms:
 *
 *   SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS, latency_ms);
 *
 * Place observes at key points:
 * - Start: request_start_ms = Socket_get_monotonic_ms();
 * - End: latency_ms = Socket_get_monotonic_ms() - request_start_ms;
 *        SocketMetrics_histogram_observe(..., latency_ms);
 *
 * Supports p50/p95/p99 percentiles for monitoring.
 * @see SocketMetrics_histogram_observe() API details.
 * @see Socket_get_monotonic_ms() for high-res timing.
 * @see SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS constant.
 */

#endif /* SOCKETHTTPSERVER_PRIVATE_INCLUDED */
