/**
 * @file SocketHTTPServer-private.h
 * @brief Private implementation details for HTTP server connection and state
 * management.
 * @ingroup http
 * @internal
 *
 * Internal header exposing structures and helpers for HTTP server
 * implementation. Not part of public API** - intended for use only within C
 * implementation files (src/http/ *.c). For public interface, include
 * SocketHTTPServer.h.
 *
 * Key internals documented here:
 * - @ref ServerConnection active connection state and buffers
 * - @ref ServerConnState processing pipeline states
 * - Rate limiting integration (@ref RateLimitEntry)
 * - Error macros (@ref http_error_macros)
 * - Connection lifecycle helpers (connection_new(), etc.)
 *
 * Supports HTTP/1.1 parsing via SocketHTTP1, HTTP/2 via SocketHTTP2,
 * event-driven I/O with SocketPoll, and security features from utilities
 * modules. Includes graceful drain/shutdown, per-IP limits, and DoS
 * protections.
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

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

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
 * @brief Internal states tracking the processing pipeline of a server
 * connection.
 * @ingroup http
 * @internal
 *
 * State machine transitions:
 * - CONN_STATE_READING_REQUEST → CONN_STATE_READING_BODY (if
 * content-length/chunked) → CONN_STATE_HANDLING
 * - CONN_STATE_HANDLING → CONN_STATE_STREAMING_RESPONSE (if streaming
 * response) → CONN_STATE_SENDING_RESPONSE
 * - CONN_STATE_SENDING_RESPONSE → CONN_STATE_CLOSED or back to
 * CONN_STATE_READING_REQUEST (keep-alive)
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
 * @brief Core internal structure representing an active HTTP client
 * connection.
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
 * @brief Internal implementation details of the SocketHTTPServer_Request
 * opaque type.
 * @ingroup http
 * @internal
 *
 * This structure is passed to user-defined request handlers (@ref
 * SocketHTTPServer_Handler). It provides:
 * - Reference to owning server for configuration and stats access
 * - Underlying connection for low-level operations (internal use)
 * - Per-request Arena_T for temporary allocations (freed after handler
 * completes)
 * - Start timestamp for latency calculations
 *
 * Users MUST NOT access fields directly. Use public accessors like:
 * - SocketHTTPServer_request_server()
 * - SocketHTTPServer_request_arena()
 * - SocketHTTPServer_request_time()
 *
 * @see SocketHTTPServer_Request in SocketHTTPServer.h for public opaque
 * declaration.
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
 * - User callbacks for handling, validation, draining (::handler, ::validator,
 * ::drain_callback)
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
 * @note Statistics and latency tracking migrated to @ref SocketMetrics for
 * centralized, thread-safe metrics. Legacy fields (::stats_prev_requests,
 * etc.) retained for compatibility but deprecated.
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
 * Update calls in all src/http/ *.c files. Tests and examples updated
 * accordingly. Legacy macros undefined to prevent use.
 *
 * @see @ref utilities "Utilities Module" for SocketMetrics details.
 * @see SocketMetrics_counter_inc(), SocketMetrics_gauge_set(), etc.
 * @see HTTP server metric constants (SOCKET_CTR_HTTP_SERVER_*,
 * SOCKET_HIST_HTTP_SERVER_*)
 */

/**
 * @defgroup http_error_macros HTTP Server Error Handling Macros
 * @ingroup http
 * @internal
 * @brief Macros for consistent error formatting and exception raising in HTTP
 * server implementation.
 *
 * These provide uniform error handling across split .c files, using core
 * Socket library infrastructure:
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
 * @brief Error formatting macro including errno details for HTTP server
 * errors.
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
 * Raises a module-registered exception with the error message from the
 * thread-local buffer (populated by HTTPSERVER_ERROR_FMT or
 * HTTPSERVER_ERROR_MSG). Centralized for consistency across HTTP server
 * implementation files.
 *
 * @param e Exception type (e.g., SocketHTTPServer_Failed,
 * SocketHTTPServer_ProtocolError).
 *
 * @see HTTPSERVER_ERROR_FMT() and HTTPSERVER_ERROR_MSG() for setting the error
 * message.
 * @see SOCKET_RAISE_MODULE_ERROR() underlying implementation.
 * @see Except.h for exception handling framework.
 * @see SocketHTTPServer.h for public exception types.
 */
#define RAISE_HTTPSERVER_ERROR(e)                                             \
  SOCKET_RAISE_MODULE_ERROR (SocketHTTPServer, e)

/**
 * @defgroup http_server_connection_mgmt Internal HTTP Server Connection
 * Management Helpers
 * @ingroup http
 * @internal
 * @brief Helper functions for managing individual HTTP server connections.
 *
 * These functions implement core connection lifecycle logic: creation, I/O
 * handling, request parsing, response generation, and cleanup. Designed for
 * use in split implementation files (src/http/ *.c). All functions assume
 * single-threaded access via the server's poll loop and are not thread-safe.
 *
 * Key areas:
 * - Connection allocation and teardown (@ref connection_new, @ref
 * connection_close)
 * - I/O operations with buffering and timeouts (@ref connection_read, @ref
 * connection_send_data)
 * - HTTP request parsing and validation (@ref connection_parse_request)
 * - Response serialization and error handling (@ref connection_send_response,
 * @ref connection_send_error)
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
 * @brief Allocate and initialize a new ServerConnection for an accepted client
 * socket.
 * @ingroup http
 * @internal
 *
 * Allocates memory from the server's arena for a new connection structure and
 * initializes all fields including socket transfer, client address, state,
 * buffers, parser, timing, and server list integration. Checks limits
 * (max_connections, per-IP) and rate limiters before full init. On failure,
 * cleans up partial state and closes socket.
 *
 * Handles edge cases like immediate rejection due to limits or allocation
 * failure. Supports both TCP and Unix domain sockets. Initial state set to
 * CONN_STATE_READING_REQUEST for immediate polling readiness.
 *
 * @param[in] server Owning HTTP server instance providing config, arena, poll,
 * trackers.
 * @param[in] socket Newly accepted client socket (non-blocking; ownership
 * transferred).
 *
 * @return Initialized ServerConnection*, or NULL if rejected or init failed
 * (check errno or exceptions).
 *
 * @throws Socket_Failed Socket ops fail (getpeername, buffer setup).
 * @throws Arena_Failed Arena alloc fails for conn or sub-structures.
 * @throws SocketHTTPServer_Failed Internal validation or list ops fail.
 *
 * @threadsafe No - single-threaded event loop only; modifies
 * server->connections and counts.
 *
 * Usage Example (Internal)
 *
 * @code
 * // In server accept handler (e.g., SocketHTTPServer.c)
 * Socket_T client = Socket_accept(server.listen_socket);
 * if (client) {
 *     ServerConnection *conn = connection_new(server, client);
 *     if (conn) {
 *         SocketPoll_add(server.poll, conn->socket, POLLIN, conn);
 *         // conn already in server->connections
 *     } // else rejected, socket closed
 * }
 * @endcode
 *
 * @note Socket closed on failure. Buffers and parser sized per config. Metrics
 * updated on success.
 * @warning No TLS init; add separately if HTTPS.
 * @complexity O(1) average - allocs, hash lookups for trackers.
 *
 * @see Socket_accept() for socket acquisition.
 * @see connection_close() paired cleanup.
 * @see ServerConnection for state details.
 */

/**
 * @brief Close and cleanup a server connection, releasing resources.
 * @ingroup http
 * @internal
 *
 * Performs complete teardown of a ServerConnection: removes from server's
 * doubly-linked list, updates connection_count and metrics (decrements active
 * connections gauge), closes underlying socket (graceful half-close if in
 * response state, force otherwise), clears and releases buffers, resets
 * parser, frees arena allocations (request/response data, temp objects), and
 * clears sensitive data (e.g., body with secureclear if applicable). Handles
 * partial states like streaming body or pending response.
 *
 * Idempotent for NULL conn. Checks drain state: during draining, attempts
 * graceful shutdown before close. Logs closure reason via SocketLog if debug
 * enabled.
 *
 * Called from event loop on errors, timeouts, idle expiry, or explicit close.
 *
 * @param[in] server Owning server for list/stats/metrics updates (non-NULL
 * expected).
 * @param[in,out] conn Connection to close (set to NULL implicitly via
 * ownership; may be NULL).
 *
 * @return void - no return value; exceptions on critical failures (rare).
 *
 * @throws Socket_Failed If socket shutdown/close fails (e.g., EPIPE).
 * @throws SocketHTTPServer_Failed Internal list removal or metrics update
 * errors.
 *
 * @threadsafe No - modifies shared server->connections list and counts;
 * single-thread access only.
 *
 * Internal Usage
 *
 * Invoked when connection errors, times out, or finishes last request and
 * keep-alive expires.
 *
 * @code
 * // Example in error handling or timeout check
 * if (connection_timed_out(conn)) {
 *     connection_close(server, conn);
 *     // conn now invalid; server lists updated
 * } else if (Socket_isclosed(conn->socket)) {
 *     SocketLog_debug("Peer closed connection");
 *     connection_close(server, conn);
 * }
 * @endcode
 *
 * - Graceful Close During Drain
 *
 * @code
 * // In drain mode, attempt half-close
 * if (server->state == HTTPSERVER_STATE_DRAINING && conn->state ==
 * CONN_STATE_SENDING_RESPONSE) { Socket_shutdown(conn->socket, SHUT_WR);  //
 * Half-close
 *     // Wait brief period for peer ACK, then full close
 * }
 * connection_close(server, conn);
 * @endcode
 *
 * @note Arena cleared but not disposed (server-owned). Socket always closed.
 * @note Metrics: decrement active conns, increment closed counter with reason
 * tag if supported.
 * @note During drain, invokes drain_callback if last connection closes
 * gracefully.
 * @warning Force closes streaming connections; may leave client in
 * inconsistent state.
 * @warning Not called for listen socket; use SocketHTTPServer_stop() instead.
 *
 * @complexity O(1) - fixed cleanup steps, list removal O(1) with prev/next
 * pointers.
 *
 * @see Socket_close() low-level socket closure.
 * @see SocketHTTPServer_drain() server-level graceful shutdown coordinating
 * multiple closes.
 * @see ServerConnection for fields zeroed/cleared during teardown.
 * @see Socket_shutdown() for graceful half-closes in advanced scenarios.
 */

/**
 * @brief Perform read operation on connection, handling partial reads and
 * timeouts.
 * @ingroup http
 * @internal
 *
 * Reads data from the connection socket into the input buffer (SocketBuf),
 * handling non-blocking semantics, partial reads, and errors. Updates
 * last_activity timestamp and increments bytes received metric. On successful
 * read, feeds data to HTTP parser if in reading state, advancing state machine
 * (headers -> body -> complete). Checks and enforces read timeouts per config
 * (request_read_timeout_ms). Detects disconnect/EOF and transitions to CLOSED
 * state.
 *
 * Supports pipelining for HTTP/1.1 keep-alive (multiple requests on conn).
 * Handles TLS if enabled on socket (transparent via Socket_recv). Rejects
 * oversized reads exceeding max_header_size or max_body_size, triggering error
 * response or close.
 *
 * Called from poll event loop when POLLIN on conn->socket.
 *
 * @param[in] server Owning server (for config, metrics, timeouts; unused
 * directly but for API).
 * @param[in,out] conn Connection to read from (updates inbuf, state, timing).
 *
 * @return >0 number of bytes read and buffered, 0 on EOF/disconnect (sets
 * state CLOSED), <0 on error (errno set; e.g., EAGAIN means try later, others
 * close conn).
 *
 * @throws Socket_Closed Propagates if recv indicates peer close (handled as
 * return 0).
 * @throws Socket_Failed On recv errors beyond EAGAIN/EWOULDBLOCK (closes
 * conn).
 * @throws SocketHTTPServer_Failed If timeout exceeded or buffer overflow.
 *
 * @threadsafe No - modifies conn state and shared metrics; event loop thread
 * only.
 *
 * Internal Usage
 *
 * Dispatched in SocketHTTPServer_process() or poll loop on read events.
 *
 * @code
 * // In poll event processing
 * SocketEvent_T *events;
 * int nev = SocketPoll_wait(server.poll, &events, timeout);
 * for (int i = 0; i < nev; i++) {
 *     if (events[i].events & POLLIN) {
 *         ServerConnection *conn = events[i].data;
 *         int nread = connection_read(server, conn);
 *         if (nread < 0) {
 *             connection_close(server, conn);
 *         } else if (nread > 0) {
 *             // Process parsed data if request complete
 *             if (conn->state == CONN_STATE_HANDLING) {
 *                 // Invoke handler
 *             }
 *         }
 *     }
 * }
 * @endcode
 *
 * @note Uses fixed recv buffer (HTTPSERVER_RECV_BUFFER_SIZE ~4KB); multiple
 * calls for large data.
 * @note Updates SocketMetrics_counter_add for bytes_received.
 * @note On disconnect (n==0), sets state CLOSED and returns -1 for close
 * trigger.
 * @note Timeouts checked against request_start_ms or last_activity; aborts
 * slow reads.
 * @warning EAGAIN/WOULDBLOCK returns 0 (no error); retry on next poll.
 * @warning Does not feed to HTTP/2 frame parser; separate path for HTTP/2
 * conns.
 *
 * @complexity O(n) where n=bytes read - single recv + buf write + optional
 * parser exec.
 *
 * @see Socket_recv() underlying non-blocking recv call.
 * @see SocketHTTP1_Parser_execute() invoked internally for HTTP/1.1 parsing.
 * @see SocketBuf_write() for buffering incoming data.
 * @see Socket_get_monotonic_ms() for timeout enforcement.
 */

/**
 * @brief Send data over connection, handling partial sends and buffering.
 * @ingroup http
 * @internal
 *
 * Attempts to send data via Socket_sendall (blocking until complete or error),
 * handling non-blocking socket behavior by buffering unsent bytes in outbuf
 * for later retry on POLLOUT events. Updates last_activity and bytes_sent
 * metrics. Enforces response_write_timeout_ms; aborts if total send time
 * exceeds. Applies bandwidth limits if Socket_setbandwidth configured on
 * socket. On peer close or error, sets state CLOSED and propagates.
 *
 * Supports TLS transparently (uses SocketTLS_send if enabled). For large data,
 * caller should chunk or stream; this function handles one call's data.
 * Buffers to outbuf only if partial send (EAGAIN); drains buf on success.
 *
 * Called from response serialization, streaming callbacks, or buf drain on
 * write-ready.
 *
 * @param[in] server Owning server (for config, metrics; partial param for
 * future extensions).
 * @param[in,out] conn Connection to send on (updates outbuf, state, timing).
 * @param[in] data Pointer to data to send (may be NULL for 0 len flush).
 * @param[in] len Number of bytes from data to send (0 ok).
 *
 * @return 0 on full success (all bytes sent or buffered), <0 on fatal error
 * (closes conn).
 *
 * @throws Socket_Closed If peer closed during send (sets CLOSED, returns <0).
 * @throws Socket_Failed On send errors (EPIPE, ECONNRESET) or timeout.
 * @throws SocketHTTPServer_Failed If buffering fails or limits exceeded.
 *
 * @threadsafe No - modifies conn outbuf and state; event thread only.
 *
 * Internal Usage
 *
 * Used for sending response headers, body chunks, or draining buffered data.
 *
 * @code
 * // Sending response body chunk
 * int res = connection_send_data(server, conn, body_chunk, chunk_len);
 * if (res < 0) {
 *     connection_close(server, conn);
 * } else {
 *     // Success; continue streaming if more
 *     if (more_data) {
 *         // Schedule next on POLLOUT or continue if blocking
 *     }
 * }
 * @endcode
 *
 * - Buffered Partial Send
 *
 * @code
 * // If non-blocking and partial
 * ssize_t sent = Socket_send(conn->socket, data, len);  // Internal via
 * sendall if (sent < len) { SocketBuf_write(conn->outbuf, (char*)data + sent,
 * len - sent); SocketPoll_mod(server.poll, conn->socket, POLLIN | POLLOUT,
 * conn);
 * }
 * @endcode
 *
 * @note Uses Socket_sendall internally for complete-or-error semantics.
 * @note Buffers only remainder on partial; drains outbuf when possible.
 * @note Metrics: adds sent bytes to HTTP_SERVER_BYTES_SENT counter.
 * @note Timeouts cumulative for entire response; reset on state change.
 * @warning Large data without chunking may buffer excessively; use streaming
 * API.
 * @warning For HTTP/2, uses stream send with flow control; separate impl.
 *
 * @complexity O(n) where n=len - send + potential buf write; O(1) amortized.
 *
 * @see Socket_sendall() core blocking send logic.
 * @see SocketTLS_send() if TLS enabled on socket.
 * @see SocketBuf_write() for partial buffering.
 * @see SocketPoll_mod() to enable POLLOUT after buffering.
 */

/**
 * @brief Reset connection state for new request on keep-alive connection.
 * @ingroup http
 * @internal
 *
 * Prepares a keep-alive connection for processing the next HTTP request after
 * completing the previous one. Clears per-request state: resets HTTP/1.1
 * parser to initial request mode, empties inbuf and outbuf (discards any
 * residual data), clears response_headers, resets response status/body/flags,
 * frees request body memory (secure clear if sensitive), increments
 * request_count, updates last_activity_ms to now, and resets body_received and
 * streaming flags. Socket remains open and registered in poll.
 *
 * Validates keep-alive eligibility: checks Connection: keep-alive header,
 * HTTP/1.1 default, idle time < keepalive_timeout_ms, request_count <
 * max_requests_per_connection. Transitions state back to
 * CONN_STATE_READING_REQUEST.
 *
 * Called internally after connection_finish_request() if keep-alive conditions
 * met.
 *
 * @param[in,out] conn Keep-alive connection to reset (must be in valid
 * post-response state).
 *
 * @return void.
 *
 * @throws Arena_Failed If clearing/realloc during reset fails (rare).
 * @throws SocketHTTPServer_Failed If validation fails (e.g., max requests
 * exceeded).
 *
 * @threadsafe No - modifies conn fields; called from event thread
 * post-handler.
 *
 * Internal Usage
 *
 * Invoked after finishing a request if keep-alive allowed.
 *
 * @code
 * // In connection_finish_request() tail
 * if (SocketHTTP1_Parser_should_keepalive(conn->parser) &&
 *     (Socket_get_monotonic_ms() - conn->last_activity_ms <
 * server->config.keepalive_timeout_ms) && conn->request_count <
 * server->config.max_requests_per_connection) {
 *     connection_reset_for_keepalive(conn);
 *     conn->state = CONN_STATE_READING_REQUEST;
 *     // Continue polling for next request on same conn
 * } else {
 *     connection_close(server, conn);
 * }
 * @endcode
 *
 * @note Does not touch socket or poll registration; assumes still valid.
 * @note Parser reset preserves config (max_header etc.); new parse from
 * scratch.
 * @note Buffers cleared but capacity preserved for reuse efficiency.
 * @note For HTTP/2, resets stream count but conn remains for multiplexing.
 * @warning Fails if called mid-request or on closed conn; assert in debug.
 * @warning Sensitive data in body cleared with SocketBuf_secureclear() if
 * flagged.
 *
 * @complexity O(1) - fixed clears and resets; no loops or allocs.
 *
 * @see SocketHTTP1_Parser_reset() underlying parser state reset.
 * @see SocketHTTP1_Parser_should_keepalive() check for HTTP/1.1 keep-alive.
 * @see connection_parse_request() subsequent parsing after reset.
 * @see connection_finish_request() precursor call determining need for reset.
 */

/**
 * @brief Finalize current request processing and prepare for next or close.
 * @ingroup http
 * @internal
 *
 * Marks the end of request handling: records latency histogram, increments
 * request completed metric, frees per-request arena allocations (body, temp
 * headers), clears request fields (request ptr, body data), updates response
 * timing if applicable. Evaluates keep-alive viability: checks protocol
 * support, headers (Connection: close?), idle time vs keepalive_timeout_ms,
 * total requests vs max_per_conn. If viable, calls
 * connection_reset_for_keepalive() and keeps in poll; else queues for close
 * via connection_close() or timer.
 *
 * Triggered after handler returns and response fully sent (or error sent).
 * Ensures resources freed promptly to avoid leaks in long-lived conns.
 *
 * @param[in] server Owning server for metrics, config, timers.
 * @param[in,out] conn Connection post-handler (updates state to IDLE or
 * reset).
 *
 * @return void.
 *
 * @throws SocketHTTPServer_Failed On metrics update or reset failures.
 *
 * @threadsafe No - updates conn and server metrics/state.
 *
 * Internal Usage
 *
 * Called after response send complete or handler error.
 *
 * @code
 * // Post-response in send_response tail
 * SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
 *                                 Socket_get_monotonic_ms() -
 * conn->request_start_ms);
 * SocketMetrics_counter_inc(SOCKET_CTR_HTTP_SERVER_REQUESTS_COMPLETED);
 * connection_finish_request(server, conn);
 * // Now either reset for next or close
 * @endcode
 *
 * @note Latency observed here; requires request_start_ms set in parse.
 * @note Frees request arena; any handler-alloc'd objects invalid after.
 * @note If streaming response unfinished, aborts stream and closes.
 * @warning Handler userdata not cleared; manage externally if per-req.
 * @warning For HTTP/2, decrements active_streams; may keep conn open.
 *
 * @complexity O(1) - fixed updates and conditional reset/close.
 *
 * @see SocketHTTPServer_Config::keepalive_timeout_ms limit check.
 * @see connection_reset_for_keepalive() if keeping open.
 * @see connection_close() if terminating.
 * @see SocketMetrics_histogram_observe() latency recording.
 */

/**
 * @brief Parse incoming request data, handling headers and body.
 * @ingroup http
 * @internal
 *
 * Incrementally parses buffered input data using SocketHTTP1_Parser_execute(),
 * advancing through request line, headers, then body (content-length or
 * chunked). On complete headers, extracts method/path/version, builds headers
 * container, checks Content-Length vs max_body_size, sets up body buffering or
 * streaming callback. Runs validator callback if configured; rejects with
 * error status if returns 0. Transitions states: READING_REQUEST ->
 * READING_BODY -> HANDLING on complete. Handles pipelining by preparing for
 * next parse after body.
 *
 * Supports HTTP/1.1 features: chunked, expect/continue, upgrades
 * (WebSocket/proxy). For HTTP/2, dispatched to frame parser instead. Enforces
 * timeouts during parse.
 *
 * Called after reads fill inbuf until request complete or error.
 *
 * @param[in] server Owning server (config for limits, validator callback).
 * @param[in,out] conn Connection with inbuf data (updates parser, request
 * fields, state).
 *
 * @return 0 to continue parsing (more data needed), 1 request fully
 * parsed/validated and ready for handler, <0 parse/validation failure (sets
 * errno, sends error or closes).
 *
 * @throws SocketHTTP1_ParseError Malformed request (400 sent).
 * @throws SocketHTTPServer_Failed Limits exceeded, validator reject, or
 * internal.
 * @throws SocketHTTP_InvalidURI Bad URI syntax.
 * @throws Arena_Failed Body alloc exceeds limits.
 *
 * @threadsafe No - advances shared parser and conn state.
 *
 * Internal Usage
 *
 * Looped in process until return 1 or error.
 *
 * Called in the main event loop after reading data to parse HTTP requests
 * incrementally.
 *
 * @note Body alloc only if < max_body_size and not streaming; else setup
 * callback.
 * @note Validator runs post-headers pre-body; can access headers/path but not
 * body.
 * @note For chunked, parses extensions/trailers; rejects unknown.
 * @note Upgrades (e.g., WebSocket) pause parsing; handler decides
 * accept/respond.
 * @warning Slow header/body attacks detected via timeout and size limits.
 * @warning Pipelining: parses next request immediately after body if data
 * available.
 *
 * @complexity O(n) where n=parsed bytes - linear in input size.
 *
 * @see SocketHTTP1_Parser_execute() incremental parse core.
 * @see SocketHTTPServer_Validator pre-handler check.
 * @see SocketHTTP_Request built from parse results.
 * @see SocketHTTPServer_BodyCallback for streaming setup.
 */

/**
 * @brief Serialize and send HTTP response (headers + body).
 * @ingroup http
 * @internal
 *
 * Constructs and transmits the HTTP response: serializes status line and
 * headers (adding defaults like Date, Server,
 * Content-Length/Transfer-Encoding), then body data (direct if small/static,
 * chunked for streaming/large). For HTTP/1.1 uses
 * SocketHTTP1_serialize_response + chunk_encode if needed; for HTTP/2
 * dispatches to stream send_headers/send_data with HPACK. Sets
 * response_headers_sent flag, starts response_start_ms timing, updates metrics
 * (response size, status code counter). Handles errors by falling back to
 * error response or close.
 *
 * Manages transfer encoding: chunked if unknown length/streaming, compressed
 * if config enables and client accepts. Ensures Connection: close if
 * !keepalive. Transitions state to SENDING_RESPONSE or STREAMING_RESPONSE.
 *
 * Called after handler sets response via Request API or error paths.
 *
 * @param[in] server Owning server (config for defaults, compression).
 * @param[in,out] conn Connection with response data set (status, headers,
 * body; updates state).
 *
 * @return void - sends async; errors trigger close or retry.
 *
 * @throws SocketHTTPServer_Failed Serialize or send fails.
 * @throws Socket_Failed Underlying send errors.
 *
 * @threadsafe No - serializes and sends on conn.
 *
 * Internal Usage
 *
 * After handler or validator reject.
 *
 * @code
 * // Post-handler
 * conn->response_status = 200;
 * SocketHTTP_Headers_add(conn->response_headers, "Content-Type",
 * "text/plain"); conn->response_body = "Hello World"; conn->response_body_len
 * = 11; connection_send_response(server, conn);
 * // Async; state now SENDING_RESPONSE
 * @endcode
 *
 * @note Adds mandatory headers: Date (GMT), Content-Length or
 * Transfer-Encoding.
 * @note Chunked for unknown len; trailers if provided.
 * @note HTTP/2: end_headers/end_stream flags set per response_finished.
 * @note Compression (gzip) if Accept-Encoding and not no-transform.
 * @warning Buffers entire response if not streaming; use begin_stream for
 * large.
 * @warning Status 1xx informational handled specially (no body).
 *
 * @complexity O(n) for serialization and send where n=response size.
 *
 * @see SocketHTTP1_serialize_response() HTTP/1.1 header serialization.
 * @see SocketHTTP1_chunk_encode() for chunked body.
 * @see SocketHTTP2_Stream_send_headers/data() for HTTP/2.
 * @see SocketHTTP_date_format() for Date header.
 */

/**
 * @brief Send HTTP error response with status and optional body.
 * @ingroup http
 * @internal
 *
 * Quickly generates and sends a standard error response for common failures
 * (parse errors, limits exceeded, validation rejects). Sets status code and
 * reason phrase via SocketHTTP_status_reason(), adds minimal headers
 * (Content-Type: text/plain; charset=utf-8, Content-Length, Connection: close
 * if appropriate). Body is optional plain-text message or auto-generated
 * (e.g., "400 Bad Request"). Logs error at WARN/ERROR level with details
 * (status, client addr, request method/path if available). Increments error
 * counter metric tagged by status category (4xx/5xx).
 *
 * Bypasses full response setup; directly calls connection_send_response after
 * minimal conn response fields set. Resets any pending response state. For
 * security, omits sensitive details in body/log (no stack traces).
 *
 * Used in error paths: parse failures, timeouts, limits, validator rejects,
 * handler exceptions.
 *
 * @param[in] server Owning server (for logging, metrics, config).
 * @param[in,out] conn Connection to send error on (sets response, may close
 * after).
 * @param[in] status HTTP status code (100-599; validated via
 * SocketHTTP_status_valid).
 * @param[in] body Optional custom error message body (NULL for default; UTF-8
 * text).
 *
 * @return void - sends immediately; errors lead to connection_close.
 *
 * @throws SocketHTTPServer_Failed If serialization or send fails (closes
 * conn).
 * @throws Socket_Failed Underlying transport errors.
 *
 * @threadsafe No - sets conn response state.
 *
 * Internal Usage
 *
 * Quick error dispatch in failure paths.
 *
 * @code
 * // On parse error
 * if (parse_failed) {
 *     connection_send_error(server, conn, 400, "Invalid JSON");
 *     connection_finish_request(server, conn);  // Or direct close
 * }
 * // On limit
 * connection_send_error(server, conn, 429, "Rate limit exceeded");
 * @endcode
 *
 * @note Default body for common codes (e.g., 404 "Not Found", 500 "Internal
 * Server Error").
 * @note Logs with client addr, status, brief reason; debug includes request
 * info.
 * @note Metrics: SOCKET_CTR_HTTP_SERVER_RESPONSES_TOTAL with status tag.
 * @note Always closes connection for 5xx (server error); may keep for 4xx
 * client errors.
 * @warning Avoid sensitive info in custom body; use generic messages in prod.
 * @warning Overrides any prior response setup in conn.
 *
 * @complexity O(1) + O(m) where m=body len - fixed headers + send.
 *
 * @see SocketHTTP_status_reason() auto reason phrase.
 * @see connection_send_response() underlying general send (simplified path).
 * @see SocketLog_warn/error() for logging integration.
 * @see SocketHTTP_status_category() for metric tagging.
 */

/** @} http_server_connection_mgmt */

/**
 * @brief Note on removed latency tracking for HTTP requests.
 * @ingroup http
 * @internal
 *
 * Direct latency tracking code removed; use SocketMetrics histograms:
 *
 *   SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
 * latency_ms);
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

/* ============================================================================
 * Connection Helper Functions (implemented in SocketHTTPServer-connections.c)
 * ============================================================================
 */

/**
 * @brief Send an HTTP error response.
 * @param server HTTP server instance
 * @param conn Connection to send error on
 * @param status_code HTTP status code (e.g., 400, 404, 500)
 * @param reason Reason phrase for the status
 */
void connection_send_error (SocketHTTPServer_T server,
                            ServerConnection *conn,
                            int status_code,
                            const char *reason);

#endif /* SOCKETHTTPSERVER_PRIVATE_INCLUDED */
