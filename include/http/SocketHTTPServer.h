/**
 * @file SocketHTTPServer.h
 * @ingroup http
 * @brief High-level HTTP server supporting HTTP/1.1 and HTTP/2 protocols.
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
 * Platform Requirements:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - pthread for mutex synchronization
 * - OpenSSL for TLS (optional, via SOCKET_HAS_TLS)
 *
 * @see SocketHTTPServer_new() for creating HTTP servers.
 * @see SocketHTTPServer_listen() for starting the server.
 * @see SocketHTTPServer_poll() for event loop integration.
 * @see SocketHTTP_Headers_T for core HTTP types and utilities.
 * @see SocketHTTPClient_T for HTTP client functionality.
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
#if SOCKET_HAS_TLS
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
 *   HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN - 1000 - Max requests per
 * connection HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS - 100 - HTTP/2 streams
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
 *   - SOCKET_CTR_LIMIT_HEADER_SIZE_EXCEEDED incremented on header limit
 * violation
 */

/** Default listen backlog */
#ifndef HTTPSERVER_DEFAULT_BACKLOG
#define HTTPSERVER_DEFAULT_BACKLOG 128
#endif

/** Default listen port */
#ifndef HTTPSERVER_DEFAULT_PORT
#define HTTPSERVER_DEFAULT_PORT 8080
#endif

/** Default bind address */
#ifndef HTTPSERVER_DEFAULT_BIND_ADDR
#define HTTPSERVER_DEFAULT_BIND_ADDR "0.0.0.0"
#endif

/** Default enable H2C upgrade */
#ifndef HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE
#define HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE 0
#endif

/** Buffer sizes for strings and chunks */
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
#endif /* temporarily without #endif ? No, keep but to balance, wait */

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

/** Receive buffer size for reading from sockets (bytes) */
#ifndef HTTPSERVER_RECV_BUFFER_SIZE
#define HTTPSERVER_RECV_BUFFER_SIZE 4096
#endif

/** Response header serialization buffer size (bytes) */
#ifndef HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE
#define HTTPSERVER_RESPONSE_HEADER_BUFFER_SIZE 8192
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
 * ============================================================================
 */

/**
 * @brief Exception raised on general server failures such as allocation errors or internal state corruption.
 * @ingroup http
 * @see SocketHTTPServer_new(), SocketHTTPServer_free(), SocketHTTPServer_process()
 */
extern const Except_T SocketHTTPServer_Failed;

/**
 * @brief Exception raised when binding to address/port fails (EADDRINUSE, EADDRNOTAVAIL, etc.).
 * @ingroup http
 * @see SocketHTTPServer_start()
 */
extern const Except_T SocketHTTPServer_BindFailed;

/**
 * @brief Exception raised on HTTP protocol violations or parsing errors.
 * @ingroup http
 * @see SocketHTTPServer_process(), SocketHTTPServer_Request_T accessors
 */
extern const Except_T SocketHTTPServer_ProtocolError;

/* ============================================================================
 * Server State
 * ============================================================================
 */

/**
 * @brief Server lifecycle states for monitoring server operation and graceful shutdown.
 * @ingroup http
 *
 * Enum values indicate the current phase of the server lifecycle, particularly during
 * drain operations for graceful shutdown.
 *
 * @see SocketHTTPServer_state()
 * @see SocketHTTPServer_drain()
 */
typedef enum
{
  HTTPSERVER_STATE_RUNNING,  /**< Normal operation */
  HTTPSERVER_STATE_DRAINING, /**< Draining - finishing existing requests */
  HTTPSERVER_STATE_STOPPED   /**< Stopped - all requests complete */
} SocketHTTPServer_State;

/* ============================================================================
 * Server Configuration
 * ============================================================================
 */

/**
 * @brief HTTP server configuration structure.
 * @ingroup http
 *
 * Defines listening parameters, TLS settings, protocol options, resource limits,
 * and timeout behaviors for the HTTP server.
 *
 * Use SocketHTTPServer_config_defaults() to initialize with sensible defaults,
 * then customize as needed before passing to SocketHTTPServer_new().
 *
 * @see SocketHTTPServer_config_defaults()
 * @see SocketHTTPServer_new()
 */
typedef struct
{
  /* Listener */
  int port;                 /**< @brief Listen port (default: 8080). */
  const char *bind_address; /**< @brief Bind address (NULL = all interfaces, default: "0.0.0.0"). */
  int backlog;              /**< @brief Listen backlog (default: 128). */

  /* TLS */
  SocketTLSContext_T tls_context; /**< @brief TLS context for HTTPS (NULL = plain HTTP). 
 * Requires SOCKET_HAS_TLS and valid OpenSSL/LibreSSL context.
 * @see SocketTLSContext_new() for creating TLS contexts.
 */

  /* Protocol */
  SocketHTTP_Version max_version; /**< @brief Maximum supported HTTP version (default: HTTP_VERSION_2). 
 * Controls protocol negotiation and feature availability.
 * @see SocketHTTP_Version enum for values.
 */
  int enable_h2c_upgrade;         /**< @brief Enable HTTP/2 upgrade via HTTP/1.1 Upgrade header (default: 0). 
 * Allows clients to upgrade from HTTP/1.1 to HTTP/2 over cleartext (h2c).
 * Requires prior HTTP/1.1 connection; not for initial h2 connections.
 * @warning Security risk if not behind trusted proxy; prefer ALPN/TLS for h2.
 */

  /* Size Limits */
  size_t max_header_size;         /**< @brief Maximum total header size in bytes (default: 64KB). 
 * Exceeding triggers 431 Request Header Fields Too Large.
 * Enforced by underlying HTTP parsers.
 */
  size_t max_body_size;           /**< @brief Maximum request body size in bytes (default: 10MB). 
 * Exceeding triggers 413 Payload Too Large before body allocation.
 * Set to 0 for unlimited (use with caution).
 */

  /* Timeout Configuration */
  int request_timeout_ms;        /**< @brief Idle timeout between requests in ms (default: 30s). 
 * Closes idle keep-alive connections after this period.
 */
  int keepalive_timeout_ms;      /**< @brief Keep-alive timeout in ms (default: 60s). 
 * Maximum time a connection can remain idle before closure.
 * @note Overrides or complements request_timeout_ms for persistent connections.
 */
  int request_read_timeout_ms;   /**< @brief Maximum time to read complete request in ms (default: 30s). 
 * Applies to entire request parsing including headers and body.
 * Prevents slowloris-style attacks.
 */
  int response_write_timeout_ms; /**< @brief Maximum time to send complete response in ms (default: 60s). 
 * Ensures timely response delivery; aborts on timeout.
 */

  /* Connection Limits */
  size_t max_connections;             /**< @brief Total maximum concurrent connections (default: 1000). 
 * Enforced globally; new connections rejected when reached.
 */
  size_t max_requests_per_connection; /**< @brief Maximum requests per connection (default: 1000). 
 * Limits pipelining/abuse on single connection; closes after limit.
 * For HTTP/2, applies to total streams processed.
 */
  int max_connections_per_client;     /**< @brief Maximum connections per client IP (default: 100). 
 * Prevents abuse from single IP; uses SocketIPTracker internally.
 * Negative values disable limit.
 */
  size_t max_concurrent_requests;     /**< @brief Maximum concurrent requests/streams per connection (default: 100). 
 * For HTTP/2 multiplexing; limits open streams.
 * For HTTP/1.1, typically 1 but affects pipelining if enabled.
 */
} SocketHTTPServer_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================
 */

/**
 * @brief Opaque HTTP server instance managing connections, requests, and protocol handling.
 * @ingroup http
 *
 * Handles listening, accepting connections, parsing HTTP requests (1.1/2),
 * invoking handlers, and sending responses. Integrates with SocketPoll for
 * event-driven operation. Supports TLS, rate limiting, and graceful shutdown.
 *
 * @see SocketHTTPServer_new() for creation.
 * @see SocketHTTPServer_Config for configuration options.
 * @see SocketHTTPServer_process() for event processing.
 */
typedef struct SocketHTTPServer *SocketHTTPServer_T;

/**
 * @brief Opaque request context for handling individual HTTP requests.
 * @ingroup http
 *
 * Contains parsed request details (method, URI, headers, body) and provides
 * API for building responses (status, headers, body streaming). Lifetime
 * scoped to the handler callback; do not store beyond callback execution.
 * Memory managed by server arena.
 *
 * @see SocketHTTPServer_Handler callback usage.
 * @see SocketHTTPServer_Request_method(), SocketHTTPServer_Request_headers() etc.
 * @see SocketHTTPServer_Request_finish() to complete response.
 */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/* ============================================================================
 * Callback Types
 * ============================================================================
 */

/**
 * @brief Primary request handler callback invoked for each incoming HTTP request.
 * @ingroup http
 *
 * This is the main entry point for application logic. For each parsed HTTP request,
 * the server calls this callback with the request context. The handler is responsible
 * for:
 * 1. Inspecting request via accessors: method, path, headers, body.
 * 2. Setting response: status with SocketHTTPServer_Request_status(),
 *    headers with SocketHTTPServer_Request_header().
 * 3. Providing body: either static with SocketHTTPServer_Request_body_data() or
 *    streaming with SocketHTTPServer_Request_begin_stream().
 * 4. Finalizing with SocketHTTPServer_Request_finish() or SocketHTTPServer_Request_end_stream().
 *
 * The @p req context is valid only during callback execution. Do not store pointers
 * to it or its contents beyond the callback; they may be invalidated or freed.
 * All allocations use the per-request arena available via SocketHTTPServer_Request_arena().
 *
 * @param req Request context containing parsed request data and response builders.
 * @param userdata Arbitrary user data set via SocketHTTPServer_set_handler().
 *
 * @threadsafe No - invoked from server's event loop thread (SocketPoll integration).
 *              Server instances should not be shared across threads without external sync.
 *
 * @note For WebSocket upgrades, check SocketHTTPServer_Request_is_websocket() and
 *       use SocketHTTPServer_Request_upgrade_websocket() instead of standard response.
 * @note For HTTP/2 push, use SocketHTTPServer_Request_push() if supported.
 *
 * @see SocketHTTPServer_set_handler() to register this callback.
 * @see SocketHTTPServer_Request_T for full request/response API.
 * @see SocketHTTP_Headers_T for header manipulation.
 * @see @ref group__http "HTTP Module Group" for protocol details.
 */
typedef void (*SocketHTTPServer_Handler) (SocketHTTPServer_Request_T req,
                                          void *userdata);

/**
 * @brief Callback for streaming request body data incrementally.
 * @ingroup http
 *
 * Enables memory-efficient handling of large request bodies (e.g., file uploads)
 * by processing data in chunks as received, without loading the entire body into memory.
 * To use, call SocketHTTPServer_Request_body_stream() in the handler before finishing.
 * The server will then invoke this callback for each chunk parsed from the wire.
 *
 * @param req Request context (same as handler; use for response setup if needed).
 * @param chunk Pointer to body data chunk (valid only during callback; do not store or free).
 * @param len Length of the chunk in bytes.
 * @param is_final Non-zero if this is the final chunk (end of body), zero otherwise.
 * @param userdata User-provided data passed unchanged from SocketHTTPServer_Request_body_stream().
 *
 * @return 0 to continue receiving and processing more body chunks,
 *         non-zero to abort the request (server sends 400 Bad Request and closes connection).
 *
 * @note Chunks may arrive in any size up to internal buffer limits (typically 4-8KB).
 * @note For chunked encoding, @p is_final is set after final zero-length chunk.
 * @note Body data is temporary; copy if needed for later use (use request arena).
 * @note Thread-safety depends on server configuration; typically called from event thread.
 *
 * @warning Aborting mid-body closes the connection immediately; client may retry.
 * @see SocketHTTPServer_Request_body_stream() to enable streaming mode.
 * @see SocketHTTPServer_Request_body_expected() for expected total length.
 * @see SocketHTTPServer_Request_is_chunked() for transfer encoding info.
 */
typedef int (*SocketHTTPServer_BodyCallback) (SocketHTTPServer_Request_T req,
                                              const void *chunk, size_t len,
                                              int is_final, void *userdata);

/**
 * @brief Middleware callback for request validation and authentication.
 * @ingroup http
 *
 * Executed before the main handler for every request. Ideal for common checks
 * like authentication (e.g., API keys, JWT), authorization, rate limiting,
 * CORS preflight, or input sanitization. Can short-circuit and reject invalid
 * requests early, avoiding handler invocation and resource waste.
 *
 * Available data: method, path, query, headers (body not yet parsed/available).
 * To reject, set *reject_status to an HTTP error code (e.g., 401 Unauthorized,
 * 403 Forbidden, 429 Too Many Requests) and return 0.
 *
 * @param req Request context with method, path, headers accessible.
 * @param reject_status Output: HTTP status code for rejection response.
 *                      Ignored if allowing request (return non-zero).
 *                      Server sends basic error response with this status.
 * @param userdata User data set via SocketHTTPServer_set_validator().
 *
 * @return Non-zero (true) to approve request and proceed to handler callback,
 *         0 (false) to reject with the status in *reject_status (connection may close).
 *
 * @note Validator runs after initial parsing but before body handling; efficient for headers-only checks.
 * @note Multiple validators can be chained externally if needed, but server supports only one.
 * @note For per-endpoint validation, implement in handler or use rate limiting API.
 * @note Thread-safety: Called from event thread; ensure validator is reentrant if sharing state.
 *
 * @see SocketHTTPServer_set_validator() to register.
 * @see SocketHTTPServer_Request_headers() for header access in validator.
 * @see SocketHTTP_status_reason() for status code phrases.
 * @see @ref utilities "Utilities Group" for rate limiting integration.
 */
typedef int (*SocketHTTPServer_Validator) (SocketHTTPServer_Request_T req,
                                           int *reject_status, void *userdata);

/**
 * @brief Callback notified when graceful drain (shutdown) completes.
 * @ingroup http
 *
 * Invoked by the server when the drain process finishes: either all active
 * connections and requests have completed gracefully, or the timeout expired
 * forcing closure of remaining connections. Useful for cleanup, logging,
 * or signaling other services.
 *
 * Set via SocketHTTPServer_set_drain_callback() before initiating drain.
 *
 * @param server The server instance entering STOPPED state.
 * @param timed_out Non-zero if drain timed out (remaining connections force-closed),
 *                  zero if completed gracefully within timeout.
 * @param userdata User data provided at callback registration.
 *
 * @note Called from the event loop thread during or after drain_poll().
 * @note Server is still valid but in STOPPED state; do not start it again.
 * @note If timed_out, some requests may have been aborted; check stats for details.
 *
 * @see SocketHTTPServer_set_drain_callback() for registration.
 * @see SocketHTTPServer_drain() to initiate graceful shutdown.
 * @see SocketHTTPServer_drain_wait() for blocking variant.
 * @see SocketHTTPServer_state() to query state independently.
 */
typedef void (*SocketHTTPServer_DrainCallback) (SocketHTTPServer_T server,
                                                int timed_out, void *userdata);

/* ============================================================================
 * Server Lifecycle
 * ============================================================================
 */

/**
 * @brief Initialize SocketHTTPServer_Config with safe default values.
 * @ingroup http
 *
 * Populates the configuration structure with production-ready defaults:
 * - port: 8080
 * - bind_address: "0.0.0.0"
 * - backlog: 128
 * - max_header_size: 64KB
 * - max_body_size: 10MB
 * - timeouts: 30s request, 60s keepalive/write
 * - limits: 1000 connections, 100 per client, etc.
 * - TLS: NULL (HTTP)
 * - HTTP/2 upgrade: disabled
 *
 * Customize fields after initialization before passing to SocketHTTPServer_new().
 * Validates basic config sanity (e.g., positive limits) but does not bind/test.
 *
 * @param config Pointer to configuration structure to initialize.
 *               Must not be NULL; contents overwritten.
 *
 * @threadsafe Yes - pure function, no side effects or shared state.
 *
 * @note Defaults can be overridden at compile-time via #defines (e.g., HTTPSERVER_DEFAULT_PORT).
 * @see SocketHTTPServer_new() which consumes this config.
 * @see SocketHTTPServer_Config for field details and ranges.
 */
extern void SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config);

/**
 * @brief Allocate and initialize a new HTTP server instance.
 * @ingroup http
 *
 * Creates server with given configuration, allocating internal resources
 * (arena, poll instance, buffers). Does not start listening; call
 * SocketHTTPServer_start() or integrate with external poll loop.
 * Validates config for sanity (e.g., valid port, limits >0).
 *
 * Ownership: Caller owns the returned instance; free with SocketHTTPServer_free().
 * Internal resources (sockets, timers) managed automatically.
 *
 * @param config Configuration structure (copied internally; can be stack or reused).
 *               Must not be NULL. Invalid values may raise exceptions.
 *
 * @return Opaque SocketHTTPServer_T instance on success.
 * @throws SocketHTTPServer_Failed on memory allocation failure or invalid config.
 * @throws Arena_Failed if internal arena allocation fails (propagated).
 *
 * @threadsafe Yes - but concurrent calls may contend on system resources (e.g., ports).
 *
 * @note Config TLS context is referenced, not owned; manage its lifetime separately.
 * @note Server uses internal SocketPool for connection management if limits allow.
 * @see SocketHTTPServer_config_defaults() to prepare config.
 * @see SocketHTTPServer_start() to begin listening.
 * @see SocketHTTPServer_free() for cleanup.
 * @see @ref connection_mgmt "Connection Management" for pooling details.
 */
extern SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config);

/**
 * @brief Dispose of HTTP server instance and release all resources.
 * @ingroup http
 *
 * Closes listening socket, frees connection pool, timers, internal buffers,
 * and arena allocations. Any ongoing requests are aborted and connections
 * closed abruptly (no graceful drain). Call SocketHTTPServer_stop() or
 * SocketHTTPServer_drain() first for clean shutdown.
 *
 * Sets *server to NULL on success.
 * Idempotent: safe to call on NULL or already-freed server.
 *
 * @param server Pointer to server instance (set to NULL after free).
 *               Must not be NULL.
 *
 * @throws SocketHTTPServer_Failed on internal cleanup errors (rare).
 *
 * @threadsafe No - concurrent access to server undefined; use mutex if multi-threaded.
 *
 * @warning Does not wait for in-flight requests; data loss possible if called mid-process.
 * @note TLS contexts are not freed (referenced only).
 * @see SocketHTTPServer_drain_wait() for graceful shutdown before free.
 * @see SocketHTTPServer_stop() to halt without full cleanup.
 * @see Arena_T for memory management details.
 */
extern void SocketHTTPServer_free (SocketHTTPServer_T *server);

/**
 * @brief Bind to address/port and start listening for incoming connections.
 * @ingroup http
 *
 * Performs system bind(2)/listen(2) on configured address/port using dual-stack
 * IPv6 preferred (falls back to IPv4 if needed). Sets socket to non-blocking,
 * reuseaddr/reuseport, and integrates with internal poll loop.
 * Marks server as running; subsequent calls are no-ops (returns 0).
 *
 * Does not block; returns immediately after setup. Use SocketHTTPServer_process()
 * or external poll on SocketHTTPServer_fd() to accept/process connections.
 *
 * @param server Initialized server instance (from SocketHTTPServer_new()).
 *
 * @return 0 on success (already running or bind/listen succeeded),
 *         -1 on error (errno set; may also raise exceptions).
 * @throws SocketHTTPServer_BindFailed on bind/listen system errors (EADDRINUSE, etc.).
 * @throws SocketHTTPServer_Failed on socket creation or config issues.
 *
 * @threadsafe No - server state modified; concurrent calls undefined.
 *
 * @note Port 0 binds to ephemeral port; query Socket_getlocalport() after.
 * @note For HTTPS, ensure tls_context configured and SocketTLS_enable() integrated.
 * @note Conflicts with prior binds raise EADDRINUSE; check with netstat/ss.
 * @see SocketHTTPServer_stop() to cease listening.
 * @see SocketHTTPServer_fd() for poll integration.
 * @see SocketConfig for global socket options affecting behavior.
 * @see @ref core_io "Core I/O Group" for underlying socket primitives.
 */
extern int SocketHTTPServer_start (SocketHTTPServer_T server);

/**
 * @brief Stop accepting new connections while allowing existing ones to complete.
 * @ingroup http
 *
 * Closes the listening socket to prevent new accepts. Existing connections
 * continue processing requests until idle timeout, keep-alive expiry, or
 * explicit drain. Does not abort in-flight requests or close client sockets.
 * Server remains in running state until all connections drain or free().
 *
 * Idempotent: safe to call multiple times.
 *
 * @param server Running server instance.
 *
 * @threadsafe No - modifies server state.
 *
 * @note To force closure of all connections, use SocketHTTPServer_free() directly.
 * @note For graceful shutdown with timeout, prefer SocketHTTPServer_drain().
 * @see SocketHTTPServer_drain() for full graceful shutdown.
 * @see SocketHTTPServer_state() to check status.
 * @see SocketPoll_del() if using external poll (server handles internally).
 */
extern void SocketHTTPServer_stop (SocketHTTPServer_T server);

/**
 * @brief Register the primary request handler callback and associated user data.
 * @ingroup http
 *
 * Sets the callback invoked for every valid HTTP request after parsing and validation.
 * Previous handler (if any) is replaced. NULL handler disables request handling
 * (server accepts but immediately closes connections with 500).
 *
 * Userdata is stored and passed unchanged to every invocation of handler.
 * Can be changed dynamically; affects future requests only.
 *
 * @param server Server instance (must be created but not required to be started).
 * @param handler Callback function or NULL to disable handling.
 * @param userdata Opaque pointer passed to handler on each request.
 *
 * @threadsafe No - updates shared server state.
 *
 * @note Handler must be thread-safe if server uses multi-threaded poll (advanced).
 * @note Set before starting or processing to avoid missing requests.
 * @note For dynamic routing, implement path/method logic inside handler.
 * @see SocketHTTPServer_Handler for callback signature and responsibilities.
 * @see SocketHTTPServer_Validator for pre-handler middleware.
 * @see @ref http "HTTP Group" for request/response types.
 */
extern void SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                                          SocketHTTPServer_Handler handler,
                                          void *userdata);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief Retrieve the file descriptor of the listening socket for external polling.
 * @ingroup http
 *
 * Allows integration with custom event loops (e.g., external SocketPoll or other
 * libraries like libevent). Monitor for POLLIN to detect new connection attempts.
 * Server's internal poll is still active if using SocketHTTPServer_process();
 * for full external control, avoid internal processing and handle accepts manually.
 *
 * Returns -1 if server not started or stopped.
 *
 * @param server Server instance (started via SocketHTTPServer_start()).
 *
 * @return Valid file descriptor (>=0) for listening socket, or -1 if not listening.
 *
 * @threadsafe Yes - atomic read of cached fd.
 *
 * @note FD remains owned by server; do not close() it.
 * @note For accepts, use Socket_accept(server_fd) and add to your poll.
 * @note When using external poll, call server process functions manually or bypass.
 * @see SocketHTTPServer_poll() for full internal poll instance.
 * @see Socket_accept() for manual connection acceptance.
 * @see @ref event_system "Event System Group" for polling details.
 */
extern int SocketHTTPServer_fd (SocketHTTPServer_T server);

/**
 * @brief Main event loop step: poll, accept, parse, handle requests.
 * @ingroup http
 *
 * Performs a single iteration of the internal event loop:
 * - Polls registered fds (listening socket + client connections + timers) for timeout_ms.
 * - Accepts new connections up to configured limits (rate, per-IP).
 * - Reads/parses incoming data on connections (HTTP/1.1 or 2 frames).
 * - Invokes validator and handler for complete requests.
 * - Writes pending responses, applies flow control (HTTP/2).
 * - Cleans up idle/timeout connections.
 * - Triggers drain callback if applicable.
 *
 * For continuous operation, call in loop with timeout -1 (infinite, interruptible).
 * For integration, use smaller timeouts or external poll with SocketHTTPServer_fd().
 *
 * @param server Running server (started via SocketHTTPServer_start()).
 * @param timeout_ms Maximum wait time in ms (-1 = infinite/block until event).
 *
 * @return Number of requests fully processed (handler invoked + response sent),
 *         or -1 on fatal error (raises exception).
 *
 * @throws SocketHTTPServer_ProtocolError on malformed requests.
 * @throws SocketHTTPServer_Failed on I/O or internal errors.
 *
 * @threadsafe No - advances shared server state.
 *
 * @note Returns early on timeout even if events pending; call repeatedly.
 * @note For high performance, tune SocketPoll via SocketHTTPServer_poll().
 * @note Metrics updated internally; query with SocketHTTPServer_stats().
 * @see SocketHTTPServer_poll() for low-level poll access.
 * @see SocketHTTPServer_fd() for hybrid external/internal loop.
 * @see @ref event_system "Event System" for polling backend details.
 * @see Socket_get_monotonic_ms() for timing consistency.
 */
extern int SocketHTTPServer_process (SocketHTTPServer_T server,
                                     int timeout_ms);

/**
 * @brief Access the internal SocketPoll_T instance for custom event handling.
 * @ingroup http
 *
 * Provides direct access to server's poll multiplexer for advanced use cases:
 * - Add custom fds/timers to the same poll loop.
 * - Inspect registered sockets or events.
 * - Replace or augment internal polling logic.
 *
 * Returned poll is shared; modifications affect server behavior.
 * Do not free() the returned poll (owned by server).
 *
 * @param server Server instance (started or not; NULL if not initialized).
 *
 * @return Pointer to internal SocketPoll_T, or NULL if server invalid/not started.
 *
 * @threadsafe Yes - returns const view, but modifications not thread-safe.
 *
 * @warning Adding/removing affects server; use cautiously to avoid races.
 * @warning Internal timers/connections registered; do not del() them arbitrarily.
 * @see SocketPoll_add(), SocketPoll_mod() for usage.
 * @see SocketHTTPServer_process() which uses this internally.
 * @see @ref event_system "Event System Group" for poll API details.
 * @see SocketTimer_add() for timer integration example.
 */
extern SocketPoll_T SocketHTTPServer_poll (SocketHTTPServer_T server);

/* ============================================================================
 * Request Accessors
 * ============================================================================
 */

/**
 * @brief Retrieve the parsed HTTP method from the request.
 * @ingroup http
 *
 * Extracts the method from the request line (e.g., GET, POST, PUT).
 * Valid after request parsing in handler or validator callbacks.
 *
 * @param req Request context.
 * @return SocketHTTP_Method enum value corresponding to the method.
 *
 * @see SocketHTTP_method_name() to convert to string (e.g., "GET").
 * @see SocketHTTP_method_properties() for method attributes (safe, idempotent, etc.).
 * @see SocketHTTP_method_parse() for parsing raw strings.
 */
/**
 * @brief Retrieve the parsed HTTP method from the request.
 * @ingroup http
 *
 * Extracts the method from the request line (e.g., GET, POST, PUT).
 * Valid after request parsing in handler or validator callbacks.
 *
 * @param req Request context.
 * @return SocketHTTP_Method enum value corresponding to the method.
 *
 * @see SocketHTTP_method_name() to convert to string (e.g., "GET").
 * @see SocketHTTP_method_properties() for method attributes (safe, idempotent, etc.).
 * @see SocketHTTP_method_parse() for parsing raw strings.
 */
extern SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req);

/**
 * @brief Get the request path (URI path component).
 * @ingroup http
 *
 * Returns the path part of the request URI after parsing (e.g., "/api/users/123").
 * Decoded and normalized; does not include query string.
 * Points to internal buffer; valid during request lifetime.
 *
 * @param req Request context.
 * @return Null-terminated path string, or NULL if invalid/unparsed.
 *
 * @note Path is percent-decoded; use SocketHTTP_URI_decode() for custom.
 * @see SocketHTTPServer_Request_query() for query parameters.
 * @see SocketHTTP_URI_parse() for URI handling details.
 */
extern const char *
SocketHTTPServer_Request_path (SocketHTTPServer_Request_T req);

/**
 * @brief Get the query string portion of the request URI.
 * @ingroup http
 *
 * Returns raw query string after '?' in URI (e.g., "id=123&name=foo").
 * Not parsed into params; caller must parse (see SocketHTTP for helpers).
 * Points to internal buffer; valid during request.
 *
 * @param req Request context.
 * @return Query string (may be empty ""), or NULL if no query.
 *
 * @note Includes leading '?' if present; trim if needed.
 * @see SocketHTTP_URI_parse() for full URI breakdown.
 * @see Query parsing utilities in SocketHTTP (future or custom).
 */
extern const char *
SocketHTTPServer_Request_query (SocketHTTPServer_Request_T req);

/**
 * @brief Access the parsed request headers as a headers container.
 * @ingroup http
 *
 * Returns view of all request headers parsed from HTTP message.
 * Headers are case-insensitive keys with multi-value support.
 * Modifications to returned headers affect response (but not request).
 * Valid during request lifetime.
 *
 * @param req Request context.
 * @return SocketHTTP_Headers_T instance (do not free; server-owned).
 *
 * @note Common headers like Host, Content-Length auto-parsed/extracted.
 * @note For streaming body, body not available; use callback instead.
 * @see SocketHTTP_Headers_add(), get(), etc. for manipulation.
 * @see SocketHTTP_Headers_get() for single header lookup.
 */
extern SocketHTTP_Headers_T
SocketHTTPServer_Request_headers (SocketHTTPServer_Request_T req);

/**
 * @brief Get pointer to fully buffered request body data.
 * @ingroup http
 *
 * Returns the complete request body after full read/parse.
 * Only valid if not using body streaming (default buffering mode).
 * For large bodies exceeding max_body_size, returns NULL (413 sent).
 * Data owned by server; valid until request finish, do not free/modify.
 *
 * @param req Request context.
 * @return Pointer to body bytes, or NULL if no body, streaming, or error.
 *
 * @warning For security, avoid trusting large bodies; validate Content-Type/Length.
 * @see SocketHTTPServer_Request_body_len() for size.
 * @see SocketHTTPServer_Request_body_stream() to enable chunked processing.
 * @see SocketBuf_secureclear() if handling sensitive data post-use.
 */
extern const void *
SocketHTTPServer_Request_body (SocketHTTPServer_Request_T req);

/**
 * @brief Retrieve the length of the request body in bytes.
 * @ingroup http
 *
 * Returns size of body from Content-Length or parsed chunked total.
 * 0 for no body (e.g., GET). Matches body() return if buffered.
 * Accurate even if streaming (tracks total received).
 *
 * @param req Request context.
 * @return Body length in bytes, or 0 if unknown/no body.
 *
 * @see SocketHTTPServer_Request_body() for data access.
 * @see SocketHTTPServer_Request_body_expected() for advertised length (pre-read).
 * @see SocketHTTP1_Parser_content_length() underlying parser info.
 */
extern size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req);

/**
 * @brief Get the client (peer) IP address as string.
 * @ingroup http
 *
 * Returns formatted string representation of remote client address (IPv4/IPv6).
 * From getpeername(); for proxied requests, use X-Forwarded-For header.
 * Points to internal static buffer; valid during request, do not free.
 * Format: "IP:port" or "unix:/path/to/socket".
 *
 * @param req Request context.
 * @return Client address string, or NULL if unknown (e.g., Unix domain).
 *
 * @note For rate limiting/IP tracking, prefer this over headers for accuracy.
 * @see Socket_getpeeraddr() underlying call.
 * @see SocketIPTracker for IP-based limits.
 */
extern const char *
SocketHTTPServer_Request_client_addr (SocketHTTPServer_Request_T req);

/**
 * @brief Determine the HTTP protocol version of the request.
 * @ingroup http
 *
 * Parsed from request line or negotiated via ALPN/Upgrade (HTTP/2).
 * Indicates capabilities: e.g., HTTP/1.1 supports keep-alive/chunked,
 * HTTP/2 supports multiplexing/push.
 *
 * @param req Request context.
 * @return SocketHTTP_Version enum (HTTP_VERSION_1_1, HTTP_VERSION_2, etc.).
 *
 * @see SocketHTTP_Version for possible values.
 * @see SocketHTTPServer_Request_is_http2() convenience check.
 * @see SocketHTTP2_Conn for HTTP/2 specific handling.
 */
extern SocketHTTP_Version
SocketHTTPServer_Request_version (SocketHTTPServer_Request_T req);

/**
 * @brief Get the Arena_T used for this request's allocations.
 * @ingroup http
 *
 * Provides per-request arena for temporary allocations (e.g., parsing buffers,
 * response data). All request-local memory freed automatically after finish().
 * Use for short-lived objects during handler execution.
 *
 * @param req Request context.
 * @return Arena_T instance owned by connection/request (do not dispose).
 *
 * @see Arena_alloc(), Arena_calloc() for allocation.
 * @see Arena_clear() if needing reset mid-request (rare).
 * @see @ref foundation "Foundation Group" for arena details.
 * @see @ref memory for allocation best practices.
 */
extern Arena_T SocketHTTPServer_Request_arena (SocketHTTPServer_Request_T req);

/**
 * @brief Query approximate memory usage for the underlying connection.
 * @ingroup http
 *
 * Sums allocations in connection arena, buffers (in/out), parsed structures,
 * and body if buffered. Useful for monitoring/leak detection or limits.
 * Does not include listening socket or global server memory.
 *
 * @param req Request context (per-connection view).
 * @return Estimated bytes allocated for this connection's resources.
 *
 * @threadsafe No - snapshot of volatile state.
 * @note Approximate; excludes kernel buffers, threads, etc.
 * @note Decreases after response sent and idle connections cleaned.
 * @see SocketHTTPServer_stats() for aggregate server memory via pools.
 * @see Socket_debug_live_count() for global leak checks.
 */
extern size_t
SocketHTTPServer_Request_memory_used (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Building
 * ============================================================================
 */

/**
 * @brief Set response status
 * @ingroup http
 * @param req Request context
 * @param code HTTP status code
 */
extern void SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req,
                                             int code);

/**
 * @brief Add response header
 * @ingroup http
 * @param req Request context
 * @param name Header name
 * @param value Header value
 */
extern void SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);

/**
 * @brief Set response body
 * @ingroup http
 * @param req Request context
 * @param data Body data
 * @len  Body length
 */
extern void SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * @brief Set response body from string
 * @ingroup http
 * @param req Request context
 * @param str Null-terminated string
 */
extern void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str);

/**
 * @brief Finish and send response
 * @ingroup http
 * @param req Request context
 *
 * Must be called to complete the response.
 */
extern void SocketHTTPServer_Request_finish (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Request Body Streaming
 * ============================================================================
 */

/**
 * @brief Enable streaming body callback
 * @ingroup http
 * @param req Request context
 * @param callback Callback invoked for each body chunk
 * @userdata  User data passed to callback
 *
 * Enables streaming mode for receiving request body. When enabled:
 * - Body chunks are delivered via callback as they arrive
 * - Body is NOT buffered in memory
 * - SocketHTTPServer_Request_body() returns NULL
 *
 * Call this before calling finish() to receive body data.
 * @threadsafe No
 */
extern void
SocketHTTPServer_Request_body_stream (SocketHTTPServer_Request_T req,
                                      SocketHTTPServer_BodyCallback callback,
                                      void *userdata);

/**
 * @brief Get expected body length
 * @ingroup http
 * @param req Request context
 *
 * @return Content-Length if known, -1 if chunked/unknown
 * @threadsafe No
 */
extern int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req);

/**
 * @brief Check if request uses chunked encoding
 * @ingroup http
 * @param req Request context
 *
 * @return 1 if chunked transfer encoding, 0 otherwise
 * @threadsafe No
 */
extern int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Body Streaming
 * ============================================================================
 */

/**
 * @brief Begin streaming response
 * @ingroup http
 * @param req Request context
 *
 * Begins a chunked transfer-encoding response. After calling:
 * - Response headers are sent with Transfer-Encoding: chunked
 * - Use send_chunk() to send body data
 * - Use end_stream() to complete the response
 * - Do NOT call body_data(), body_string(), or finish()
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int
SocketHTTPServer_Request_begin_stream (SocketHTTPServer_Request_T req);

/**
 * @brief Send response chunk
 * @ingroup http
 * @param req Request context
 * @data  Chunk data
 * @param len Chunk length
 *
 * Sends a chunk of the response body. Can be called multiple times.
 * begin_stream() must be called first.
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTPServer_Request_send_chunk (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * @brief End streaming response
 * @ingroup http
 * @param req Request context
 *
 * Sends the final zero-length chunk and completes the response.
 * After calling, the request context is complete.
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int
SocketHTTPServer_Request_end_stream (SocketHTTPServer_Request_T req);

/* ============================================================================
 * HTTP/2 Server Push
 * ============================================================================
 */

/**
 * @brief Push a resource (HTTP/2 only)
 * @ingroup http
 * @param req Request context
 * @param path Path of resource to push
 * @param headers Headers for pushed request (can be NULL)
 *
 * Initiates HTTP/2 server push for a resource. Only works for HTTP/2
 * connections. For HTTP/1.1 connections, returns -1.
 *
 * @return 0 on success, -1 on error or not supported
 * @threadsafe No
 */
extern int SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                                          const char *path,
                                          SocketHTTP_Headers_T headers);

/**
 * @brief Check if connection is HTTP/2
 * @ingroup http
 * @param req Request context
 *
 * @return 1 if HTTP/2, 0 if HTTP/1.x
 * @threadsafe No
 */
extern int SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req);

/* ============================================================================
 * WebSocket Upgrade
 * ============================================================================
 */

/**
 * @brief Check WebSocket upgrade
 * @ingroup http
 * @param req Request context
 *
 * @return 1 if WebSocket upgrade requested, 0 otherwise
 */
extern int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req);

/**
 * @brief Upgrade to WebSocket
 * @ingroup http
 * @param req Request context
 *
 * @return WebSocket instance (Phase 9), or NULL on error
 * @threadsafe No
 *
 * Sends 101 Switching Protocols and returns WebSocket handle.
 * The request context is invalid after this call.
 */
extern SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Rate Limiting
 * ============================================================================
 */

/**
 * @brief Set rate limiter for endpoint
 * @ingroup http
 * @param server Server instance
 * @param path_prefix Path prefix to limit (NULL for global default)
 * @param limiter Rate limiter instance
 *
 * Registers a rate limiter for requests matching path_prefix.
 * When rate limit exceeded, server returns 429 Too Many Requests.
 * NULL limiter removes rate limiting for the path.
 *
 * @threadsafe No
 */
extern void SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                             const char *path_prefix,
                                             SocketRateLimit_T limiter);

/* ============================================================================
 * Request Validation Middleware
 * ============================================================================
 */

/**
 * @brief Set request validation callback
 * @ingroup http
 * @param server Server instance
 * @param validator Validation callback (NULL to disable)
 * @userdata  User data passed to callback
 *
 * Sets a middleware callback that runs before each request handler.
 * Can be used for authentication, authorization, input validation.
 *
 * @threadsafe No
 */
extern void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata);

/* ============================================================================
 * Graceful Shutdown
 * ============================================================================
 */

/**
 * @brief Begin graceful shutdown
 * @ingroup http
 * @param server Server instance
 * @timeout_ms  Maximum time to wait for requests to complete (-1 = infinite)
 *
 * Begins draining the server:
 * - Stops accepting new connections
 * - Existing connections continue processing
 * - After timeout, force-closes remaining connections
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms);

/**
 * @brief Poll drain progress
 * @ingroup http
 * @param server Server instance
 *
 * Check drain status. Call repeatedly until returns 0 or negative.
 *
 * @return >0 remaining connections, 0 drain complete, -1 timed out (forced)
 * @threadsafe No
 */
extern int SocketHTTPServer_drain_poll (SocketHTTPServer_T server);

/**
 * @brief Blocking wait for drain
 * @ingroup http
 * @param server Server instance
 * @timeout_ms  Maximum time to wait (-1 = use drain timeout)
 *
 * Blocks until drain completes or timeout. Convenience wrapper around
 * drain + drain_poll loop.
 *
 * @return 0 on graceful completion, -1 on timeout (forced)
 * @threadsafe No
 */
extern int SocketHTTPServer_drain_wait (SocketHTTPServer_T server,
                                        int timeout_ms);

/**
 * @brief Get time until forced shutdown
 * @ingroup http
 * @param server Server instance
 *
 * @return Milliseconds until drain timeout, 0 if not draining, -1 if infinite
 * @threadsafe Yes (atomic read)
 */
extern int64_t SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server);

/**
 * @brief Set drain completion callback
 * @ingroup http
 * @param server Server instance
 * @callback  Callback (NULL to disable)
 * @userdata  User data passed to callback
 *
 * @threadsafe No
 */
extern void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata);

/**
 * @brief Get server lifecycle state
 * @ingroup http
 * @param server Server instance
 *
 * @return Current state (RUNNING, DRAINING, or STOPPED)
 * @threadsafe Yes (atomic read)
 */
extern SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server);

/* ============================================================================
 * Server Statistics
 * ============================================================================
 */

/**
 * @brief Comprehensive server statistics structure for monitoring and debugging.
 * @ingroup http
 *
 * Aggregates counters, gauges, and histograms for server health, performance,
 * and error tracking. Updated atomically during operation; snapshot via
 * SocketHTTPServer_stats(). Includes connections, requests, bytes, errors,
 * timeouts, rate limits, and latency percentiles (us resolution).
 *
 * Reset with SocketHTTPServer_stats_reset() (preserves active_connections).
 * Use for logging, metrics export (Prometheus), or alerting.
 *
 * @see SocketHTTPServer_stats() to populate.
 * @see SocketMetrics for global library metrics.
 * @see SocketPool stats for connection pool details.
 */
typedef struct
{
  /* Connection stats */
  size_t active_connections;   /**< @brief Current number of active client connections. */
  size_t total_connections;    /**< @brief Cumulative connections accepted since start/reset. */
  size_t connections_rejected; /**< @brief Connections rejected due to limits (max_conns, per-IP). */

  /* Request stats */
  size_t total_requests;      /**< @brief Total HTTP requests processed (successful + errors). */
  size_t requests_per_second; /**< @brief Recent RPS calculated over config window (10s default). */

  /* Byte counters */
  size_t total_bytes_sent;     /**< @brief Total response bytes sent to clients (headers + body). */
  size_t total_bytes_received; /**< @brief Total request bytes received (headers + body). */

  /* Error stats */
  size_t errors_4xx;   /**< @brief Count of 4xx client errors returned. */
  size_t errors_5xx;   /**< @brief Count of 5xx server errors returned. */
  size_t timeouts;     /**< @brief Connections/requests closed due to timeout. */
  size_t rate_limited; /**< @brief Requests rejected by rate limiters (429). */

  /* Latency stats (microseconds) */
  int64_t avg_request_time_us; /**< @brief Arithmetic mean of request processing times. */
  int64_t max_request_time_us; /**< @brief Maximum observed request latency (reset on stats reset). */
  int64_t p50_request_time_us; /**< @brief Median (50th percentile) request latency. */
  int64_t p95_request_time_us; /**< @brief 95th percentile request latency (tail latency). */
  int64_t p99_request_time_us; /**< @brief 99th percentile request latency (extreme tail). */
} SocketHTTPServer_Stats;

/**
 * @brief Populate statistics structure with current server metrics snapshot.
 * @ingroup http
 *
 * Atomically copies all counters, gauges, and computed values (RPS, percentiles)
 * into the provided struct. Includes reset-tolerant fields like active_connections.
 * Latency stats based on recent samples (ring buffer of last N requests).
 *
 * @param server Server instance.
 * @param stats Pointer to SocketHTTPServer_Stats to fill (must not be NULL).
 *
 * @threadsafe No - brief pause on some counters during copy.
 *
 * @note RPS window fixed at compile-time (HTTPSERVER_RPS_WINDOW_SECONDS).
 * @note Latency percentiles approximate; exact via external sampling.
 * @note Bytes counters include headers; net of compression if enabled.
 * @see SocketHTTPServer_Stats for field meanings.
 * @see SocketHTTPServer_stats_reset() to clear counters.
 * @see SocketMetrics_getsnapshot() for library-wide metrics.
 */
extern void SocketHTTPServer_stats (SocketHTTPServer_T server,
                                    SocketHTTPServer_Stats *stats);

/**
 * @brief Reset all resettable statistics counters to zero.
 * @ingroup http
 *
 * Clears cumulative counts (total_requests, bytes, errors, etc.) for fresh
 * monitoring period. active_connections and current latencies preserved
 * (reflect live state). Max latency reset to current if desired.
 * Idempotent but concurrent calls race (use mutex if needed).
 *
 * @param server Server instance.
 *
 * @threadsafe No - modifies shared counters.
 *
 * @note Does not affect per-connection stats or pool internals.
 * @note Call periodically for rate calculations or after restarts.
 * @see SocketHTTPServer_stats() to read before/after reset.
 * @see SocketPool for connection-specific resets.
 */
extern void SocketHTTPServer_stats_reset (SocketHTTPServer_T server);

#endif /* SOCKETHTTPSERVER_INCLUDED */
