/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * @brief Exception raised on general server failures such as allocation errors
 * or internal state corruption.
 * @ingroup http
 * @see SocketHTTPServer_new(), SocketHTTPServer_free(),
 * SocketHTTPServer_process()
 */
extern const Except_T SocketHTTPServer_Failed;

/**
 * @brief Exception raised when binding to address/port fails (EADDRINUSE,
 * EADDRNOTAVAIL, etc.).
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
 * @brief Server lifecycle states for monitoring server operation and graceful
 * shutdown.
 * @ingroup http
 *
 * Enum values indicate the current phase of the server lifecycle, particularly
 * during drain operations for graceful shutdown.
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
 * Defines listening parameters, TLS settings, protocol options, resource
 * limits, and timeout behaviors for the HTTP server.
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
  const char *bind_address; /**< @brief Bind address (NULL = all interfaces,
                               default: "0.0.0.0"). */
  int backlog;              /**< @brief Listen backlog (default: 128). */

  /* TLS */
  SocketTLSContext_T
      tls_context; /**< @brief TLS context for HTTPS (NULL = plain HTTP).
                    * Requires SOCKET_HAS_TLS and valid OpenSSL/LibreSSL
                    * context.
                    * @see SocketTLSContext_new() for creating TLS contexts.
                    */

  /* Protocol */
  SocketHTTP_Version
      max_version;        /**< @brief Maximum supported HTTP version (default:
                           * HTTP_VERSION_2).        Controls protocol negotiation and
                           * feature availability.
                           * @see SocketHTTP_Version enum for values.
                           */
  int enable_h2c_upgrade; /**< @brief Enable HTTP/2 upgrade via HTTP/1.1
                           * Upgrade header (default: 0). Allows clients to
                           * upgrade from HTTP/1.1 to HTTP/2 over cleartext
                           * (h2c). Requires prior HTTP/1.1 connection; not for
                           * initial h2 connections.
                           * @warning Security risk if not behind trusted
                           * proxy; prefer ALPN/TLS for h2.
                           */

  /* Size Limits */
  size_t
      max_header_size; /**< @brief Maximum total header size in bytes (default:
                        * 64KB). Exceeding triggers 431 Request Header Fields
                        * Too Large. Enforced by underlying HTTP parsers.
                        */
  size_t max_body_size; /**< @brief Maximum request body size in bytes
                         * (default: 10MB). Exceeding triggers 413 Payload Too
                         * Large before body allocation. Set to 0 for unlimited
                         * (use with caution).
                         */

  /* Timeout Configuration */
  int request_timeout_ms;      /**< @brief Idle timeout between requests in ms
                                * (default: 30s).      Closes idle keep-alive connections
                                * after this period.
                                */
  int keepalive_timeout_ms;    /**< @brief Keep-alive timeout in ms (default:
                                * 60s).    Maximum time a connection can remain idle
                                * before closure.
                                * @note Overrides or complements
                                * request_timeout_ms for persistent connections.
                                */
  int request_read_timeout_ms; /**< @brief Maximum time to read complete
                                * request in ms (default: 30s). Applies to
                                * entire request parsing including headers and
                                * body. Prevents slowloris-style attacks.
                                */
  int response_write_timeout_ms; /**< @brief Maximum time to send complete
                                  * response in ms (default: 60s). Ensures
                                  * timely response delivery; aborts on
                                  * timeout.
                                  */

  /* Connection Limits */
  size_t max_connections; /**< @brief Total maximum concurrent connections
                           * (default: 1000). Enforced globally; new
                           * connections rejected when reached.
                           */
  size_t max_requests_per_connection; /**< @brief Maximum requests per
                                       * connection (default: 1000). Limits
                                       * pipelining/abuse on single connection;
                                       * closes after limit. For HTTP/2,
                                       * applies to total streams processed.
                                       */
  int max_connections_per_client; /**< @brief Maximum connections per client IP
                                   * (default: 100). Prevents abuse from single
                                   * IP; uses SocketIPTracker internally.
                                   * Negative values disable limit.
                                   */
  size_t max_concurrent_requests; /**< @brief Maximum concurrent
                                   * requests/streams per connection (default:
                                   * 100). For HTTP/2 multiplexing; limits open
                                   * streams. For HTTP/1.1, typically 1 but
                                   * affects pipelining if enabled.
                                   */
} SocketHTTPServer_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================
 */

/**
 * @brief Opaque HTTP server instance managing connections, requests, and
 * protocol handling.
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
 * @see SocketHTTPServer_Request_method(), SocketHTTPServer_Request_headers()
 * etc.
 * @see SocketHTTPServer_Request_finish() to complete response.
 */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/* ============================================================================
 * Callback Types
 * ============================================================================
 */

/**
 * @brief Primary request handler callback invoked for each incoming HTTP
 * request.
 * @ingroup http
 *
 * This is the main entry point for application logic. For each parsed HTTP
 * request, the server calls this callback with the request context. The
 * handler is responsible for:
 * 1. Inspecting request via accessors: method, path, headers, body.
 * 2. Setting response: status with SocketHTTPServer_Request_status(),
 *    headers with SocketHTTPServer_Request_header().
 * 3. Providing body: either static with SocketHTTPServer_Request_body_data()
 * or streaming with SocketHTTPServer_Request_begin_stream().
 * 4. Finalizing with SocketHTTPServer_Request_finish() or
 * SocketHTTPServer_Request_end_stream().
 *
 * The @p req context is valid only during callback execution. Do not store
 * pointers to it or its contents beyond the callback; they may be invalidated
 * or freed. All allocations use the per-request arena available via
 * SocketHTTPServer_Request_arena().
 *
 * @param req Request context containing parsed request data and response
 * builders.
 * @param userdata Arbitrary user data set via SocketHTTPServer_set_handler().
 *
 * @threadsafe No - invoked from server's event loop thread (SocketPoll
 * integration). Server instances should not be shared across threads without
 * external sync.
 *
 * @note For WebSocket upgrades, check SocketHTTPServer_Request_is_websocket()
 * and use SocketHTTPServer_Request_upgrade_websocket() instead of standard
 * response.
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
 * Enables memory-efficient handling of large request bodies (e.g., file
 * uploads) by processing data in chunks as received, without loading the
 * entire body into memory. To use, call SocketHTTPServer_Request_body_stream()
 * in the handler before finishing. The server will then invoke this callback
 * for each chunk parsed from the wire.
 *
 * @param req Request context (same as handler; use for response setup if
 * needed).
 * @param chunk Pointer to body data chunk (valid only during callback; do not
 * store or free).
 * @param len Length of the chunk in bytes.
 * @param is_final Non-zero if this is the final chunk (end of body), zero
 * otherwise.
 * @param userdata User-provided data passed unchanged from
 * SocketHTTPServer_Request_body_stream().
 *
 * @return 0 to continue receiving and processing more body chunks,
 *         non-zero to abort the request (server sends 400 Bad Request and
 * closes connection).
 *
 * @note Chunks may arrive in any size up to internal buffer limits (typically
 * 4-8KB).
 * @note For chunked encoding, @p is_final is set after final zero-length
 * chunk.
 * @note Body data is temporary; copy if needed for later use (use request
 * arena).
 * @note Thread-safety depends on server configuration; typically called from
 * event thread.
 *
 * @warning Aborting mid-body closes the connection immediately; client may
 * retry.
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
 * Available data: method, path, query, headers (body not yet
 * parsed/available). To reject, set *reject_status to an HTTP error code
 * (e.g., 401 Unauthorized, 403 Forbidden, 429 Too Many Requests) and return 0.
 *
 * @param req Request context with method, path, headers accessible.
 * @param reject_status Output: HTTP status code for rejection response.
 *                      Ignored if allowing request (return non-zero).
 *                      Server sends basic error response with this status.
 * @param userdata User data set via SocketHTTPServer_set_validator().
 *
 * @return Non-zero (true) to approve request and proceed to handler callback,
 *         0 (false) to reject with the status in *reject_status (connection
 * may close).
 *
 * @note Validator runs after initial parsing but before body handling;
 * efficient for headers-only checks.
 * @note Multiple validators can be chained externally if needed, but server
 * supports only one.
 * @note For per-endpoint validation, implement in handler or use rate limiting
 * API.
 * @note Thread-safety: Called from event thread; ensure validator is reentrant
 * if sharing state.
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
 * @param timed_out Non-zero if drain timed out (remaining connections
 * force-closed), zero if completed gracefully within timeout.
 * @param userdata User data provided at callback registration.
 *
 * @note Called from the event loop thread during or after drain_poll().
 * @note Server is still valid but in STOPPED state; do not start it again.
 * @note If timed_out, some requests may have been aborted; check stats for
 * details.
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
 * Customize fields after initialization before passing to
 * SocketHTTPServer_new(). Validates basic config sanity (e.g., positive
 * limits) but does not bind/test.
 *
 * @param config Pointer to configuration structure to initialize.
 *               Must not be NULL; contents overwritten.
 *
 * @threadsafe Yes - pure function, no side effects or shared state.
 *
 * @note Defaults can be overridden at compile-time via #defines (e.g.,
 * HTTPSERVER_DEFAULT_PORT).
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
 * Ownership: Caller owns the returned instance; free with
 * SocketHTTPServer_free(). Internal resources (sockets, timers) managed
 * automatically.
 *
 * @param config Configuration structure (copied internally; can be stack or
 * reused). Must not be NULL. Invalid values may raise exceptions.
 *
 * @return Opaque SocketHTTPServer_T instance on success.
 * @throws SocketHTTPServer_Failed on memory allocation failure or invalid
 * config.
 * @throws Arena_Failed if internal arena allocation fails (propagated).
 *
 * @threadsafe Yes - but concurrent calls may contend on system resources
 * (e.g., ports).
 *
 * @note Config TLS context is referenced, not owned; manage its lifetime
 * separately.
 * @note Server uses internal SocketPool for connection management if limits
 * allow.
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
 * @threadsafe No - concurrent access to server undefined; use mutex if
 * multi-threaded.
 *
 * @warning Does not wait for in-flight requests; data loss possible if called
 * mid-process.
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
 * Performs system bind(2)/listen(2) on configured address/port using
 * dual-stack IPv6 preferred (falls back to IPv4 if needed). Sets socket to
 * non-blocking, reuseaddr/reuseport, and integrates with internal poll loop.
 * Marks server as running; subsequent calls are no-ops (returns 0).
 *
 * Does not block; returns immediately after setup. Use
 * SocketHTTPServer_process() or external poll on SocketHTTPServer_fd() to
 * accept/process connections.
 *
 * @param server Initialized server instance (from SocketHTTPServer_new()).
 *
 * @return 0 on success (already running or bind/listen succeeded),
 *         -1 on error (errno set; may also raise exceptions).
 * @throws SocketHTTPServer_BindFailed on bind/listen system errors
 * (EADDRINUSE, etc.).
 * @throws SocketHTTPServer_Failed on socket creation or config issues.
 *
 * @threadsafe No - server state modified; concurrent calls undefined.
 *
 * @note Port 0 binds to ephemeral port; query Socket_getlocalport() after.
 * @note For HTTPS, ensure tls_context configured and SocketTLS_enable()
 * integrated.
 * @note Conflicts with prior binds raise EADDRINUSE; check with netstat/ss.
 * @see SocketHTTPServer_stop() to cease listening.
 * @see SocketHTTPServer_fd() for poll integration.
 * @see SocketConfig for global socket options affecting behavior.
 * @see @ref core_io "Core I/O Group" for underlying socket primitives.
 */
extern int SocketHTTPServer_start (SocketHTTPServer_T server);

/**
 * @brief Stop accepting new connections while allowing existing ones to
 * complete.
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
 * @note To force closure of all connections, use SocketHTTPServer_free()
 * directly.
 * @note For graceful shutdown with timeout, prefer SocketHTTPServer_drain().
 * @see SocketHTTPServer_drain() for full graceful shutdown.
 * @see SocketHTTPServer_state() to check status.
 * @see SocketPoll_del() if using external poll (server handles internally).
 */
extern void SocketHTTPServer_stop (SocketHTTPServer_T server);

/**
 * @brief Register the primary request handler callback and associated user
 * data.
 * @ingroup http
 *
 * Sets the callback invoked for every valid HTTP request after parsing and
 * validation. Previous handler (if any) is replaced. NULL handler disables
 * request handling (server accepts but immediately closes connections with
 * 500).
 *
 * Userdata is stored and passed unchanged to every invocation of handler.
 * Can be changed dynamically; affects future requests only.
 *
 * @param server Server instance (must be created but not required to be
 * started).
 * @param handler Callback function or NULL to disable handling.
 * @param userdata Opaque pointer passed to handler on each request.
 *
 * @threadsafe No - updates shared server state.
 *
 * @note Handler must be thread-safe if server uses multi-threaded poll
 * (advanced).
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
 * @brief Retrieve the file descriptor of the listening socket for external
 * polling.
 * @ingroup http
 *
 * Allows integration with custom event loops (e.g., external SocketPoll or
 * other libraries like libevent). Monitor for POLLIN to detect new connection
 * attempts. Server's internal poll is still active if using
 * SocketHTTPServer_process(); for full external control, avoid internal
 * processing and handle accepts manually.
 *
 * Returns -1 if server not started or stopped.
 *
 * @param server Server instance (started via SocketHTTPServer_start()).
 *
 * @return Valid file descriptor (>=0) for listening socket, or -1 if not
 * listening.
 *
 * @threadsafe Yes - atomic read of cached fd.
 *
 * @note FD remains owned by server; do not close() it.
 * @note For accepts, use Socket_accept(server_fd) and add to your poll.
 * @note When using external poll, call server process functions manually or
 * bypass.
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
 * - Polls registered fds (listening socket + client connections + timers) for
 * timeout_ms.
 * - Accepts new connections up to configured limits (rate, per-IP).
 * - Reads/parses incoming data on connections (HTTP/1.1 or 2 frames).
 * - Invokes validator and handler for complete requests.
 * - Writes pending responses, applies flow control (HTTP/2).
 * - Cleans up idle/timeout connections.
 * - Triggers drain callback if applicable.
 *
 * For continuous operation, call in loop with timeout -1 (infinite,
 * interruptible). For integration, use smaller timeouts or external poll with
 * SocketHTTPServer_fd().
 *
 * @param server Running server (started via SocketHTTPServer_start()).
 * @param timeout_ms Maximum wait time in ms (-1 = infinite/block until event).
 *
 * @return Number of requests fully processed (handler invoked + response
 * sent), or -1 on fatal error (raises exception).
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
 * @return Pointer to internal SocketPoll_T, or NULL if server invalid/not
 * started.
 *
 * @threadsafe Yes - returns const view, but modifications not thread-safe.
 *
 * @warning Adding/removing affects server; use cautiously to avoid races.
 * @warning Internal timers/connections registered; do not del() them
 * arbitrarily.
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
 * @see SocketHTTP_method_properties() for method attributes (safe, idempotent,
 * etc.).
 * @see SocketHTTP_method_parse() for parsing raw strings.
 */
extern SocketHTTP_Method
SocketHTTPServer_Request_method (SocketHTTPServer_Request_T req);

/**
 * @brief Get the request path (URI path component).
 * @ingroup http
 *
 * Returns the path part of the request URI after parsing (e.g.,
 * "/api/users/123"). Decoded and normalized; does not include query string.
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
 * @warning For security, avoid trusting large bodies; validate
 * Content-Type/Length.
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
 * @see SocketHTTPServer_Request_body_expected() for advertised length
 * (pre-read).
 * @see SocketHTTP1_Parser_content_length() underlying parser info.
 */
extern size_t
SocketHTTPServer_Request_body_len (SocketHTTPServer_Request_T req);

/**
 * @brief Get the client (peer) IP address as string.
 * @ingroup http
 *
 * Returns formatted string representation of remote client address
 * (IPv4/IPv6). From getpeername(); for proxied requests, use X-Forwarded-For
 * header. Points to internal static buffer; valid during request, do not free.
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
 * @brief Set the HTTP status code for the response.
 * @ingroup http
 *
 * Specifies the status code to send in the response (e.g., 200 OK, 404 Not
 * Found, 500 Internal Server Error). Must be called before adding headers,
 * body, or calling finish(). If not set, defaults to 200 OK. Server may
 * override in error cases (e.g., parsing failures -> 400/500).
 *
 * @param req Request context (valid during handler callback).
 * @param code HTTP status code (100-599 range recommended; validated).
 *
 * @note Reason phrase auto-appended using SocketHTTP_status_reason(code).
 * @note For client errors (4xx), consider logging request details for
 * debugging.
 * @note For redirects (3xx), pair with Location header.
 *
 * @see SocketHTTP_status_reason(int) for standard reason phrases.
 * @see SocketHTTP_status_category(int) to classify codes (1xx informational,
 * 2xx success, etc.).
 * @see SocketHTTP_status_valid(int) to check valid range.
 * @see SocketHTTPServer_Request_header() to add response headers (e.g.,
 * Location for redirects).
 * @see SocketHTTPServer_Request_finish() to send after setting
 * status/headers/body.
 * @see docs/HTTP.md "HTTP Response Guidelines" for best practices.
 *
 * @threadsafe No - modifies shared request state.
 */
extern void SocketHTTPServer_Request_status (SocketHTTPServer_Request_T req,
                                             int code);

/**
 * @brief Add a header field to the HTTP response.
 * @ingroup http
 *
 * Appends a name-value pair to the response headers collection. Headers are
 * sent immediately after the status line when finish() or streaming begins.
 * Supports multiple values for the same header (e.g., repeated Set-Cookie).
 * Header names are normalized to lowercase for consistency.
 *
 * @param req Request context (valid during handler or validator).
 * @param name Null-terminated header name string (e.g., "Content-Type",
 * "Authorization").
 * @param value Null-terminated header value string (may contain commas for
 * multi-value).
 *
 * @note Validates header name and value per RFC 7230/9110: tokens, no invalid
 * chars.
 * @note Server automatically adds mandatory headers: Date, Connection, Server
 * (configurable).
 * @note Content-Length auto-set if body provided and not chunked.
 * @note For security, sanitize values to prevent injection (e.g., CRLF in
 * values -> header smuggling).
 *
 * @see SocketHTTP_Headers_T for underlying header storage and advanced ops.
 * @see SocketHTTP_Headers_add() similar low-level function.
 * @see SocketHTTPServer_Request_headers() for direct access/modification.
 * @see docs/SECURITY.md "HTTP Header Security" for best practices and risks.
 * @see SocketHTTP_Headers_get() to query existing headers.
 *
 * @threadsafe No - concurrent modifications to same req may corrupt headers.
 * @throws SocketHTTPServer_ProtocolError if name/value invalid (e.g., empty
 * name, control chars).
 */
extern void SocketHTTPServer_Request_header (SocketHTTPServer_Request_T req,
                                             const char *name,
                                             const char *value);

/**
 * @brief Set the complete response body from a data buffer.
 * @ingroup http
 *
 * Provides the full response body content. The body is sent after headers
 * during finish(). Automatically computes and sets Content-Length header.
 * For large or dynamic bodies (e.g., file streams), prefer streaming API.
 * Data is referenced or copied internally; remains valid until finish().
 *
 * @param req Request context.
 * @param data Pointer to response body bytes (may be NULL if len=0).
 * @param len Exact length of body in bytes.
 *
 * @note Sets Content-Type to application/octet-stream if unspecified.
 * @note Supports zero-length bodies (no Content-Length or Transfer-Encoding).
 * @note Compression (e.g., gzip) applied if client accepts via
 * Accept-Encoding.
 * @note For text content, explicitly set Content-Type with charset.
 *
 * @see SocketHTTPServer_Request_body_string() for null-terminated strings.
 * @see SocketHTTPServer_Request_begin_stream() for chunked/dynamic streaming.
 * @see SocketHTTPServer_Request_header("Content-Type", "application/json") for
 * type.
 * @see SocketHTTP_Headers_set() for advanced header control.
 *
 * @threadsafe No - sets shared body state.
 * @throws SocketHTTPServer_Failed if len exceeds max_body_size or allocation
 * fails.
 */
extern void SocketHTTPServer_Request_body_data (SocketHTTPServer_Request_T req,
                                                const void *data, size_t len);

/**
 * @brief Set the response body from a null-terminated C string.
 * @ingroup http
 *
 * Convenience function for text-based responses. Computes length via strlen()
 * and sets body accordingly. Equivalent to body_data(str, strlen(str)).
 * Ideal for simple responses like JSON, HTML fragments, or plain text.
 *
 * @param req Request context.
 * @param str Pointer to null-terminated string (NULL for empty body).
 *
 * @note strlen() excludes null terminator; binary data with \0 requires
 * body_data().
 * @note Sets Content-Type to text/plain; charset=utf-8 if not overridden.
 * @note Large strings buffered in memory; stream for generated content.
 *
 * @see SocketHTTPServer_Request_body_data() for binary data with explicit
 * length.
 * @see SocketHTTPServer_Request_header("Content-Type", ...) to override type.
 * @see SocketHTTPServer_Request_begin_stream() for streaming text generation.
 *
 * @threadsafe No.
 * @throws Same as body_data(): allocation or size limit violations.
 */
extern void
SocketHTTPServer_Request_body_string (SocketHTTPServer_Request_T req,
                                      const char *str);

/**
 * @brief Finalize the response and transmit it to the client.
 * @ingroup http
 *
 * Serializes the configured status, headers, and body into an HTTP message
 * and sends it over the connection. For non-streaming responses, full body
 * sent. Marks the request as complete; subsequent modifications ignored.
 * Handles protocol specifics: chunked for HTTP/1.1 without length, frames for
 * HTTP/2. Connection kept alive if possible (protocol, headers, timeouts
 * allow).
 *
 * @param req Request context (invalidated after this call; do not use
 * further).
 *
 * @note Call exactly once per request, typically at end of handler.
 * @note If streaming enabled, call after end_stream() (finish() not needed).
 * @note Auto-flushes buffers; blocks until sent or error/timeout.
 * @note Updates server stats (bytes sent, latency, error counters if fails).
 * @warning After call, req and its contents may be freed/recycled.
 *
 * @see SocketHTTPServer_Request_status() and Request_header() before finish.
 * @see SocketHTTPServer_Request_body_data() or streaming alternatives.
 * @see SocketHTTPServer_Request_end_stream() for streaming completion.
 * @see SocketHTTPServer_process() underlying transmission loop.
 *
 * @threadsafe No - finalizes shared state, sends on connection fd.
 * @throws SocketHTTPServer_Failed on I/O errors (e.g., broken pipe, timeout).
 * @throws SocketHTTPServer_ProtocolError on serialization failures (rare).
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
 * @brief Retrieve the expected total length of the request body.
 * @ingroup http
 *
 * Returns the advertised body size from Content-Length header or -1 if unknown
 * (e.g., chunked transfer-encoding or missing header). Useful for
 * pre-allocating buffers or deciding streaming vs. buffering in
 * handler/validator. Accurate after headers parsed, before body read (even if
 * streaming enabled).
 *
 * @param req Request context (valid during handler or body callback).
 *
 * @return >=0 exact expected bytes (Content-Length), or -1 if
 * undetermined/chunked.
 *
 * @note For chunked, total unknown until final chunk; use body_len()
 * post-complete.
 * @note 0 indicates empty body (common for GET/HEAD).
 * @note May differ from actual received if client lies/truncated.
 *
 * @see SocketHTTPServer_Request_body_len() for actual received length
 * (post-read).
 * @see SocketHTTPServer_Request_is_chunked() to detect transfer encoding.
 * @see SocketHTTP1_Parser_content_length() underlying parser value.
 * @see docs/HTTP.md "Request Body Handling" for details.
 *
 * @threadsafe No - reads request state snapshot.
 */
extern int64_t
SocketHTTPServer_Request_body_expected (SocketHTTPServer_Request_T req);

/**
 * @brief Determine if the request body uses chunked transfer encoding.
 * @ingroup http
 *
 * Checks the Transfer-Encoding header for "chunked" (case-insensitive).
 * Chunked used when Content-Length absent (HTTP/1.1 requirement for unknown
 * length). Indicates body arrives in delimited chunks; total length unknown
 * until end. Relevant for streaming decisions or buffer management.
 *
 * @param req Request context (after headers parsed).
 *
 * @return 1 if chunked encoding detected, 0 if not (fixed length or no body).
 *
 * @note HTTP/2 uses DATA frames (similar to chunked, but protocol-handled).
 * @note False for fixed-length bodies or GET/HEAD (no body).
 * @note In validator/handler, before body read; remains constant.
 *
 * @see SocketHTTPServer_Request_body_expected() for length if not chunked.
 * @see SocketHTTPServer_Request_body_stream() compatible with chunked.
 * @see SocketHTTP1_chunk_encode() for response chunking.
 * @see RFC 9112 Section 7.1 "Chunked Transfer Coding".
 *
 * @threadsafe Yes - const query on parsed headers.
 */
extern int
SocketHTTPServer_Request_is_chunked (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Response Body Streaming
 * ============================================================================
 */

/**
 * @brief Initiate a streaming (chunked) response to the client.
 * @ingroup http
 *
 * Starts the response by sending status and headers with Transfer-Encoding:
 * chunked (or equivalent HTTP/2 frames). Enables sending body in arbitrary
 * chunks without knowing total length upfront. Ideal for dynamic content
 * generation, large files, or real-time data (e.g., SSE, progress updates).
 * Headers sent immediately; subsequent send_chunk() append body chunks.
 * Must follow with end_stream() to finalize (sends trailers if any).
 *
 * @param req Request context (headers/status must be set prior).
 *
 * @return 0 on success (headers sent, ready for chunks), -1 on failure.
 *
 * @note Do not call status(), header(), body_data(), body_string(), or
 * finish() after.
 * @note Chunk size unlimited per call, but internal buffers apply (8KB
 * typical).
 * @note Client must support chunked (HTTP/1.1 default); HTTP/1.0 may fail.
 * @note For HTTP/2, translates to multiple DATA frames with end-stream flag on
 * last.
 * @warning No Content-Length set; clients buffer until end_stream().
 *
 * @see SocketHTTPServer_Request_send_chunk() to emit body chunks.
 * @see SocketHTTPServer_Request_end_stream() to finalize and close body.
 * @see SocketHTTP1_chunk_encode() low-level chunk formatting.
 * @see RFC 9112 Section 7.1 for chunked encoding spec.
 * @see docs/HTTP.md "Streaming Responses" for examples.
 *
 * @threadsafe No - commits response, modifies connection state.
 * @throws SocketHTTPServer_Failed on immediate send failure (e.g., closed
 * conn).
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
 * @brief Initiate an HTTP/2 server push of a related resource to the client.
 * @ingroup http
 *
 * Sends a promised PUSH_PROMISE frame followed by pushed response (HEADERS +
 * DATA). Allows server to preemptively send resources likely needed by client
 * (e.g., CSS/JS for HTML). Only functional on HTTP/2 connections; HTTP/1.x
 * returns -1 (no push support). Client may refuse (via RST_STREAM); check
 * return for success. Path relative to request URI authority; full URL
 * constructed internally.
 *
 * @param req Request context on HTTP/2 stream.
 * @param path Target resource path (e.g., "/style.css"; relative).
 * @param headers Optional headers for pushed request (method GET assumed;
 * :method can override).
 *
 * @return 0 if push initiated successfully, -1 if failed/unsupported (not
 * HTTP/2, client refused, error).
 *
 * @note Push streams consume window/bandwidth; use judiciously to avoid DoS.
 * @note Client settings (e.g., ENABLE_PUSH=0) or GOAWAY may disable.
 * @note Pushed responses still subject to server config limits/timeouts.
 * @warning Over-pushing harms performance; base on Cache-Control, Link
 * headers.
 *
 * @see SocketHTTPServer_Request_is_http2() to check protocol support.
 * @see SocketHTTP2_Stream for low-level push control.
 * @see RFC 9113 Section 6.6 "Server Push" for specification.
 * @see docs/HTTP.md "HTTP/2 Server Push" for usage patterns.
 *
 * @threadsafe No - allocates push stream on connection.
 * @throws SocketHTTPServer_ProtocolError if HTTP/2 frame errors.
 */
extern int SocketHTTPServer_Request_push (SocketHTTPServer_Request_T req,
                                          const char *path,
                                          SocketHTTP_Headers_T headers);

/**
 * @brief Check if the underlying connection uses HTTP/2 protocol.
 * @ingroup http
 *
 * Queries the negotiated protocol version for the connection/stream.
 * HTTP/2 detected via ALPN (TLS), prior-knowledge, or upgrade (h2c).
 * Enables/disables HTTP/2 features: multiplexing, push, header compression.
 *
 * @param req Request context (any stream on connection).
 *
 * @return 1 if HTTP/2 (or h2 via upgrade), 0 if HTTP/1.1 or lower.
 *
 * @note Constant for connection lifetime; not per-request.
 * @note HTTP/2 requires prior negotiation; plain HTTP/1.1 cannot upgrade
 * post-start.
 * @note For h2c (cleartext HTTP/2), requires config enable_h2c_upgrade.
 *
 * @see SocketHTTPServer_Request_version() for exact version enum.
 * @see SocketHTTPServer_Config.max_version to control support.
 * @see SocketHTTP2_Conn for HTTP/2-specific APIs.
 * @see docs/HTTP.md "HTTP/2 Negotiation" for details.
 *
 * @threadsafe Yes - reads immutable connection flag.
 */
extern int SocketHTTPServer_Request_is_http2 (SocketHTTPServer_Request_T req);

/* ============================================================================
 * WebSocket Upgrade
 * ============================================================================
 */

/**
 * @brief Check if the request is a WebSocket upgrade attempt.
 * @ingroup http
 *
 * Inspects Upgrade: websocket header, Sec-WebSocket-Key, etc., per RFC 9112.
 * True if client requests protocol switch from HTTP to WebSocket (ws/wss).
 * Typically on GET with specific headers; server can accept/reject.
 *
 * @param req Request context (after headers parsed, in handler/validator).
 *
 * @return 1 if valid WebSocket upgrade request, 0 if not (standard HTTP).
 *
 * @note Requires HTTP/1.1+; HTTP/2 uses extended CONNECT but not standard
 * here.
 * @note Validates all required headers (Upgrade, Connection: Upgrade,
 * Sec-WebSocket-Key).
 * @note Origin header checked against config if security enabled.
 *
 * @see SocketHTTPServer_Request_upgrade_websocket() to accept and get WS
 * handle.
 * @see SocketWS_T for WebSocket protocol handling.
 * @see RFC 9112 Appendix B "WebSocket Upgrade" for handshake details.
 * @see docs/WEBSOCKET.md for WebSocket integration guide.
 *
 * @threadsafe Yes - const header check.
 */
extern int
SocketHTTPServer_Request_is_websocket (SocketHTTPServer_Request_T req);

/**
 * @brief Accept WebSocket upgrade and switch protocol.
 * @ingroup http
 *
 * Performs WebSocket handshake: sends 101 Switching Protocols response with
 * Sec-WebSocket-Accept key, then returns opaque WebSocket_T handle for
 * framing. Transitions connection from HTTP to WebSocket (ws:// or wss:// over
 * TLS). After upgrade, use SocketWS APIs for messages, close, etc.; HTTP
 * functions invalid. Request context and HTTP state discarded post-upgrade.
 *
 * @param req Request context with valid upgrade request (is_websocket() true).
 *
 * @return SocketWS_T instance for WebSocket operations, or NULL on failure
 * (e.g., invalid handshake).
 *
 * @note Validates client key, computes accept value per RFC 6455.
 * @note Sec-WebSocket-Protocol negotiated if offered (config or first).
 * @note TLS remains active if HTTPS (becomes wss://).
 * @warning Connection now WebSocket-only; no revert to HTTP.
 * @note Metrics: upgrades counted in stats; errors logged.
 *
 * @see SocketHTTPServer_Request_is_websocket() to check before upgrade.
 * @see SocketWS_T and group__websocket for WebSocket API.
 * @see RFC 6455 "The WebSocket Protocol" for handshake spec.
 * @see docs/WEBSOCKET.md "Upgrading from HTTP" for examples and config.
 *
 * @threadsafe No - switches connection state, consumes req.
 * @throws SocketHTTPServer_ProtocolError on handshake validation failure.
 * @throws SocketHTTPServer_Failed on response send error.
 */
extern SocketWS_T
SocketHTTPServer_Request_upgrade_websocket (SocketHTTPServer_Request_T req);

/* ============================================================================
 * Rate Limiting
 * ============================================================================
 */

/**
 * @brief Register a rate limiter for specific endpoints or globally.
 * @ingroup http
 *
 * Associates a SocketRateLimit_T instance with a path prefix (e.g., "/api/").
 * Incoming requests matching prefix (via Request_path() starts-with) checked
 * against limiter before handler invocation. Exceeded limits trigger 429 Too
 * Many Requests with Retry-After. NULL path_prefix applies globally (all
 * requests). NULL limiter disables for prefix. Supports dynamic updates;
 * affects new requests only.
 *
 * @param server Server instance (running or not).
 * @param path_prefix Path prefix to match (e.g., "/api/v1", NULL=global),
 * case-sensitive.
 * @param limiter Rate limiter (owned by caller; server references, not frees).
 *
 * @note Up to HTTPSERVER_MAX_RATE_LIMIT_ENDPOINTS (64 default) slots.
 * @note Path matching simple prefix; for regex/glob, implement in validator.
 * @note Per-IP limits via max_connections_per_client; this is per-endpoint
 * RPS.
 * @note Stats: rate_limited counter incremented on rejections.
 *
 * @see SocketRateLimit_T from utilities group for token bucket config.
 * @see SocketHTTPServer_set_validator() for custom rate logic.
 * @see SocketHTTPServer_Stats.rate_limited for monitoring.
 * @see @ref utilities "Utilities Group" for SocketRateLimit details.
 * @see docs/SECURITY.md "Rate Limiting" for deployment tips.
 *
 * @threadsafe No - updates server map; use mutex for multi-thread.
 */
extern void SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                             const char *path_prefix,
                                             SocketRateLimit_T limiter);

/* ============================================================================
 * Request Validation Middleware
 * ============================================================================
 */

/**
 * @brief Install a middleware validator callback for incoming requests.
 * @ingroup http
 *
 * Registers a function executed after parsing headers but before body
 * read/handler. Ideal for early rejection: auth (tokens, JWT), rate limiting,
 * CORS, schema validation. Validator can set reject_status (e.g., 401) and
 * return 0 to short-circuit (no handler). Runs per-request; stateful
 * validators must be thread-safe or per-connection. Replaces prior validator;
 * NULL disables.
 *
 * @param server Server instance.
 * @param validator Callback or NULL to disable validation.
 * @param userdata Opaque data passed to each invocation.
 *
 * @note Executes in event thread; fast operations preferred to avoid blocking
 * poll.
 * @note Access to method, path, query, headers; body unavailable yet (use
 * stream for large).
 * @note Rejection sends minimal error response (status + basic headers);
 * customize via validator.
 * @note Chain multiple via wrapper if needed, but single slot provided.
 *
 * @see SocketHTTPServer_Validator callback signature and usage.
 * @see SocketHTTPServer_Request_* accessors available in validator (no
 * body()).
 * @see SocketHTTPServer_set_rate_limit() for built-in endpoint limiting.
 * @see docs/SECURITY.md "Middleware and Validation" for patterns.
 *
 * @threadsafe No - replaces server callback; concurrent set races.
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
 * @brief Initiate graceful server shutdown by draining active connections.
 * @ingroup http
 *
 * Transitions server to DRAINING state: closes listening socket (no new
 * accepts), allows in-flight requests/connections to complete naturally via
 * timeouts or finish(). After specified timeout (or infinite), force-closes
 * any remaining to STOPPED. Integrates with poll/process loop; call
 * drain_poll() or drain_wait() to monitor. Signals OS/epoll to stop queuing
 * new SYNs if possible.
 *
 * @param server Server instance (running state).
 * @param timeout_ms Max ms to wait for graceful completion (-1=infinite,
 * 0=immediate force).
 *
 * @return 0 if drain started successfully, -1 on error (already
 * stopped/draining).
 *
 * @note Existing connections: requests handled, but no new on them after
 * start.
 * @note Timeout triggers abrupt close (possible data loss for unfinished
 * responses).
 * @note Call before free() for clean shutdown; drain_wait() for blocking.
 * @note Stats preserved; errors during drain logged/incremented.
 *
 * @see SocketHTTPServer_drain_poll() to check progress in loop.
 * @see SocketHTTPServer_drain_wait() blocking convenience.
 * @see SocketHTTPServer_state() to query current state.
 * @see SocketHTTPServer_set_drain_callback() for completion notification.
 * @see docs/SIGNALS.md "Graceful Shutdown" for signal integration.
 *
 * @threadsafe No - changes server state globally.
 * @throws SocketHTTPServer_Failed if internal timer/setup fails.
 */
extern int SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms);

/**
 * @brief Non-blocking check of drain progress and remaining work.
 * @ingroup http
 *
 * Queries number of active connections during DRAINING: polls internal
 * pool/timer. Returns count of connections needing completion (processing or
 * idle but open). Call in event loop (with process()) until 0 (complete) or -1
 * (timed out, force-closed). Complements drain_wait() for custom loops or
 * integration.
 *
 * @param server Server in DRAINING (ignore otherwise).
 *
 * @return >0 active connections remaining, 0 fully drained (STOPPED soon),
 *         -1 drain timed out (force-close triggered, state STOPPED).
 *
 * @note Decreases as requests finish/connections idle-timeout.
 * @note Call frequently during drain; pairs with process() for progress.
 * @note On -1, remaining connections closed abruptly (possible aborted
 * requests).
 * @note Callback invoked on 0 or -1 transition.
 *
 * @see SocketHTTPServer_drain() initiates draining.
 * @see SocketHTTPServer_drain_wait() blocking wrapper using this.
 * @see SocketHTTPServer_state() alternative state query.
 * @see SocketHTTPServer_Stats.active_connections cross-check.
 * @see docs/SIGNALS.md for poll in signal handlers.
 *
 * @threadsafe No - snapshots internal counts, may race.
 */
extern int SocketHTTPServer_drain_poll (SocketHTTPServer_T server);

/**
 * @brief Block until graceful drain completes or times out.
 * @ingroup http
 *
 * Convenience function to wait for drain process: repeatedly calls process(0)
 * and drain_poll() until STOPPED or timeout. Handles the loop internally.
 * Uses provided timeout or falls back to drain() timeout if -1.
 * Non-blocking alternative: manual loop with drain_poll().
 *
 * @param server Server in DRAINING state (after drain()).
 * @param timeout_ms Max additional ms to wait (-1=use drain timeout, 0=check
 * once).
 *
 * @return 0 if fully drained gracefully (STOPPED, no force-close),
 *         -1 if timed out (remaining connections force-closed).
 *
 * @note Continues processing events during wait (requests complete).
 * @note Infinite timeout (-1) blocks forever if stuck (e.g., hanging client).
 * @note After return, server STOPPED; safe to free().
 * @note Callback (if set) invoked on completion regardless.
 *
 * @see SocketHTTPServer_drain() to initiate.
 * @see SocketHTTPServer_drain_poll() for non-blocking progress.
 * @see SocketHTTPServer_state() post-wait verification.
 * @see SocketHTTPServer_drain_remaining_ms() for time left.
 *
 * @threadsafe No - blocks calling thread, modifies state.
 * @throws Propagates from process()/drain_poll() (rare during shutdown).
 */
extern int SocketHTTPServer_drain_wait (SocketHTTPServer_T server,
                                        int timeout_ms);

/**
 * @brief Calculate remaining time before drain timeout forces connection
 * closure.
 * @ingroup http
 *
 * Returns ms left until DRAINING state force-closes lingering connections.
 * Uses monotonic clock for accuracy; accounts for elapsed since drain start.
 * 0 indicates immediate force-close imminent or already STOPPED.
 * Useful for logging warnings or client notifications during shutdown.
 *
 * @param server Server instance (in DRAINING for meaningful >0).
 *
 * @return >0 ms remaining, 0 not draining/imminent force, -1 infinite timeout.
 *
 * @note Precision ~1ms; negative not returned (clamped).
 * @note Updates dynamically as drain progresses/time passes.
 * @note When <=0, server may transition to STOPPED soon.
 *
 * @see SocketHTTPServer_state() pair with for full status.
 * @see SocketHTTPServer_drain() sets initial timeout.
 * @see Socket_get_monotonic_ms() underlying time source.
 * @see SocketHTTPServer_drain_wait() uses similar logic.
 *
 * @threadsafe Yes - atomic computation from cached deadlines.
 */
extern int64_t SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server);

/**
 * @brief Register callback for graceful drain completion notification.
 * @ingroup http
 *
 * Sets function invoked when drain reaches STOPPED: either graceful (all done)
 * or timed-out (force-closed). Called from event thread during/after
 * process(). Useful for final cleanup, logging shutdown stats, or signaling
 * parent process. Replaces prior callback; NULL disables. Set before drain()
 * for immediate effect.
 *
 * @param server Server instance.
 * @param callback Drain completion handler or NULL to disable.
 * @param userdata User data forwarded to callback unchanged.
 *
 * @note Invoked once per drain cycle, even if multiple drain() calls.
 * @note If timed_out=1, check stats for aborted connections.
 * @note Safe to free() server from callback (after invocation).
 * @note Not called on abrupt free()/errors; use atexit or signals for those.
 *
 * @see SocketHTTPServer_DrainCallback signature: receives server, timed_out
 * flag.
 * @see SocketHTTPServer_drain() to start process triggering callback.
 * @see SocketHTTPServer_Stats for post-drain metrics snapshot.
 * @see docs/SIGNALS.md "Shutdown Hooks" for integration.
 *
 * @threadsafe No - updates server callback slot.
 */
extern void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata);

/**
 * @brief Query the current lifecycle state of the server.
 * @ingroup http
 *
 * Returns enum indicating operational phase: RUNNING (normal), DRAINING
 * (shutdown initiated), or STOPPED (no activity). Useful for monitoring,
 * logging, or conditional logic during shutdown. Atomic read for concurrency
 * safety.
 *
 * @param server Server instance (any state).
 *
 * @return SocketHTTPServer_State: RUNNING, DRAINING, or STOPPED.
 *
 * @note RUNNING: accepting/processing; DRAINING: finishing existing; STOPPED:
 * idle/closed.
 * @note State changes via start()/stop()/drain()/free().
 * @note During DRAINING, process()/poll continue until complete.
 *
 * @see SocketHTTPServer_State enum definition.
 * @see SocketHTTPServer_drain() triggers DRAINING.
 * @see SocketHTTPServer_stop() may lead to DRAINING if connections active.
 * @see SocketHTTPServer_free() finalizes to implicit STOPPED.
 * @see docs/SIGNALS.md for state in signal handlers.
 *
 * @threadsafe Yes - atomic enum read, no side effects.
 */
extern SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server);

/* ============================================================================
 * Server Statistics
 * ============================================================================
 */

/**
 * @brief Comprehensive server statistics structure for monitoring and
 * debugging.
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
  size_t active_connections; /**< @brief Current number of active client
                                connections. */
  size_t total_connections;  /**< @brief Cumulative connections accepted since
                                start/reset. */
  size_t connections_rejected; /**< @brief Connections rejected due to limits
                                  (max_conns, per-IP). */

  /* Request stats */
  size_t total_requests; /**< @brief Total HTTP requests processed (successful
                            + errors). */
  size_t requests_per_second; /**< @brief Recent RPS calculated over config
                                 window (10s default). */

  /* Byte counters */
  size_t total_bytes_sent;     /**< @brief Total response bytes sent to clients
                                  (headers + body). */
  size_t total_bytes_received; /**< @brief Total request bytes received
                                  (headers + body). */

  /* Error stats */
  size_t errors_4xx; /**< @brief Count of 4xx client errors returned. */
  size_t errors_5xx; /**< @brief Count of 5xx server errors returned. */
  size_t timeouts;   /**< @brief Connections/requests closed due to timeout. */
  size_t rate_limited; /**< @brief Requests rejected by rate limiters (429). */

  /* Latency stats (microseconds) */
  int64_t avg_request_time_us; /**< @brief Arithmetic mean of request
                                  processing times. */
  int64_t max_request_time_us; /**< @brief Maximum observed request latency
                                  (reset on stats reset). */
  int64_t p50_request_time_us; /**< @brief Median (50th percentile) request
                                  latency. */
  int64_t p95_request_time_us; /**< @brief 95th percentile request latency
                                  (tail latency). */
  int64_t p99_request_time_us; /**< @brief 99th percentile request latency
                                  (extreme tail). */
} SocketHTTPServer_Stats;

/**
 * @brief Populate statistics structure with current server metrics snapshot.
 * @ingroup http
 *
 * Atomically copies all counters, gauges, and computed values (RPS,
 * percentiles) into the provided struct. Includes reset-tolerant fields like
 * active_connections. Latency stats based on recent samples (ring buffer of
 * last N requests).
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

/* ============================================================================
 * Static File Serving
 * ============================================================================
 */

/**
 * @brief Add static file serving for a directory
 * @ingroup http
 * @param[in] server Server instance
 * @param[in] prefix URL prefix to match (e.g., "/static")
 * @param[in] directory Filesystem directory to serve from
 *
 * Configures the server to serve static files from the specified directory
 * for requests matching the URL prefix. Supports common content types,
 * conditional requests (If-Modified-Since), and range requests.
 *
 * @return 0 on success, -1 on error (directory not accessible)
 *
 * @throws SocketHTTPServer_Failed if directory invalid
 * @threadsafe No - modifies server configuration
 *
 * ## Security Notes
 *
 * - Path traversal attacks prevented (.. normalized)
 * - Symlinks followed only within directory (configurable)
 * - No directory listing by default
 * - Hidden files (dot-files) not served by default
 *
 * ## Example
 *
 * @code{.c}
 * // Serve /static/foo.js from ./public/foo.js
 * SocketHTTPServer_add_static_dir(server, "/static", "./public");
 *
 * // Serve /assets/* from /var/www/assets/
 * SocketHTTPServer_add_static_dir(server, "/assets", "/var/www/assets");
 * @endcode
 *
 * @note Requests not matching static files fall through to handler
 * @see SocketHTTPServer_set_handler() for dynamic handling
 */
extern int SocketHTTPServer_add_static_dir (SocketHTTPServer_T server,
                                            const char *prefix,
                                            const char *directory);

/* ============================================================================
 * Middleware
 * ============================================================================
 */

/**
 * @brief Middleware callback type
 * @ingroup http
 *
 * Middleware functions are called before the main handler for each request.
 * They can inspect/modify the request, set response headers, or short-circuit
 * by returning non-zero.
 *
 * @param req Request context
 * @param userdata Middleware-specific data
 * @return 0 to continue to next middleware/handler, non-zero to stop
 *         (request considered handled)
 */
typedef int (*SocketHTTPServer_Middleware) (SocketHTTPServer_Request_T req,
                                            void *userdata);

/**
 * @brief Add request middleware
 * @ingroup http
 * @param[in] server Server instance
 * @param[in] middleware Middleware callback
 * @param[in] userdata User data passed to callback
 *
 * Adds middleware to the processing chain. Middleware is executed in order
 * of addition, before the main request handler. Common uses:
 * - Logging and metrics
 * - Authentication/authorization
 * - CORS headers
 * - Request validation
 * - Rate limiting
 *
 * @return 0 on success, -1 on error (too many middleware)
 *
 * @threadsafe No - modifies server configuration
 *
 * ## Execution Order
 *
 * ```
 * Request → Middleware 1 → Middleware 2 → ... → Handler → Response
 *                ↓             ↓
 *           (can short-circuit and send response)
 * ```
 *
 * ## Example
 *
 * @code{.c}
 * int log_middleware(SocketHTTPServer_Request_T req, void *data) {
 *     printf("[%s] %s\n",
 *            SocketHTTP_method_name(SocketHTTPServer_Request_method(req)),
 *            SocketHTTPServer_Request_path(req));
 *     return 0;  // Continue to next
 * }
 *
 * int auth_middleware(SocketHTTPServer_Request_T req, void *data) {
 *     const char *token = SocketHTTPServer_Request_header(req, "Authorization");
 *     if (!token || !validate_token(token)) {
 *         SocketHTTPServer_Request_status(req, 401);
 *         SocketHTTPServer_Request_body_data(req, "Unauthorized", 12);
 *         SocketHTTPServer_Request_finish(req);
 *         return 1;  // Stop processing
 *     }
 *     return 0;  // Continue
 * }
 *
 * SocketHTTPServer_add_middleware(server, log_middleware, NULL);
 * SocketHTTPServer_add_middleware(server, auth_middleware, &auth_config);
 * @endcode
 *
 * @see SocketHTTPServer_set_handler() for main handler
 * @see SocketHTTPServer_Validator for validation-only middleware
 */
extern int SocketHTTPServer_add_middleware (SocketHTTPServer_T server,
                                            SocketHTTPServer_Middleware middleware,
                                            void *userdata);

/**
 * @brief Error handler callback type
 * @ingroup http
 *
 * Called when the server generates an error response (4xx, 5xx).
 * Allows customization of error pages.
 *
 * @param req Request context (status already set)
 * @param status_code HTTP status code (400-599)
 * @param userdata Handler-specific data
 */
typedef void (*SocketHTTPServer_ErrorHandler) (SocketHTTPServer_Request_T req,
                                               int status_code, void *userdata);

/**
 * @brief Set custom error page handler
 * @ingroup http
 * @param[in] server Server instance
 * @param[in] handler Error handler callback (NULL to reset to default)
 * @param[in] userdata User data passed to callback
 *
 * Sets a custom handler for generating error responses. Called for all
 * server-generated errors (not application-generated via handler).
 *
 * @threadsafe No - modifies server configuration
 *
 * ## Example
 *
 * @code{.c}
 * void custom_error(SocketHTTPServer_Request_T req, int code, void *data) {
 *     char body[256];
 *     snprintf(body, sizeof(body),
 *              "<html><body><h1>Error %d</h1>"
 *              "<p>%s</p></body></html>",
 *              code, http_status_message(code));
 *     SocketHTTPServer_Request_header(req, "Content-Type", "text/html");
 *     SocketHTTPServer_Request_body_data(req, body, strlen(body));
 *     SocketHTTPServer_Request_finish(req);
 * }
 *
 * SocketHTTPServer_set_error_handler(server, custom_error, NULL);
 * @endcode
 *
 * @note Default handler sends minimal text/plain response
 * @see SocketHTTPServer_Request_status() to check/set status
 */
extern void SocketHTTPServer_set_error_handler (SocketHTTPServer_T server,
                                                SocketHTTPServer_ErrorHandler handler,
                                                void *userdata);

#endif /* SOCKETHTTPSERVER_INCLUDED */
