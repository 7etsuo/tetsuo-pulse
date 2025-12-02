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
 * - Request body handling (Content-Length and chunked)
 * - Streaming response support
 *
 * Dependencies (leveraged, not duplicated):
 * - SocketHTTP for headers, URI, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing
 * - SocketHTTP2 for HTTP/2 protocol
 * - SocketPoll for event loop integration
 * - SocketPool for connection management
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
#include "http/SocketHTTP.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/* Forward declarations for optional TLS */
#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/* Forward declaration for WebSocket (Phase 9) */
typedef struct SocketWS *SocketWS_T;

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Default listen backlog */
#ifndef HTTPSERVER_DEFAULT_BACKLOG
#define HTTPSERVER_DEFAULT_BACKLOG 128
#endif

/** Default maximum connections */
#ifndef HTTPSERVER_DEFAULT_MAX_CONNECTIONS
#define HTTPSERVER_DEFAULT_MAX_CONNECTIONS 1000
#endif

/** Default request timeout (ms) */
#ifndef HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS 30000
#endif

/** Default keep-alive timeout (ms) */
#ifndef HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS
#define HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS 60000
#endif

/** Default maximum header size */
#ifndef HTTPSERVER_DEFAULT_MAX_HEADER_SIZE
#define HTTPSERVER_DEFAULT_MAX_HEADER_SIZE (64 * 1024)
#endif

/** Default maximum body size */
#ifndef HTTPSERVER_DEFAULT_MAX_BODY_SIZE
#define HTTPSERVER_DEFAULT_MAX_BODY_SIZE (10 * 1024 * 1024)
#endif

/** Default maximum requests per connection */
#ifndef HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN
#define HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN 1000
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
 * Server Configuration
 * ============================================================================ */

/**
 * HTTP server configuration
 */
typedef struct
{
  /* Listener */
  int port;                  /**< Listen port */
  const char *bind_address;  /**< Bind address (NULL = all interfaces) */
  int backlog;               /**< Listen backlog */

  /* TLS */
  SocketTLSContext_T tls_context; /**< TLS context (NULL = HTTP only) */

  /* Protocol */
  SocketHTTP_Version max_version; /**< Max HTTP version (default: HTTP/2) */
  int enable_h2c_upgrade;         /**< Allow HTTP/2 upgrade (default: 0) */

  /* Limits */
  size_t max_header_size;
  size_t max_body_size;
  int request_timeout_ms;
  int keepalive_timeout_ms;
  size_t max_connections;
  size_t max_requests_per_connection;
} SocketHTTPServer_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/** HTTP server instance */
typedef struct SocketHTTPServer *SocketHTTPServer_T;

/** Server request context */
typedef struct SocketHTTPServer_Request *SocketHTTPServer_Request_T;

/* ============================================================================
 * Request Handler Callback
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
 * Server Statistics
 * ============================================================================ */

/**
 * Server statistics
 */
typedef struct
{
  size_t active_connections;
  size_t total_requests;
  size_t total_bytes_sent;
  size_t total_bytes_received;
} SocketHTTPServer_Stats;

/**
 * SocketHTTPServer_stats - Get server statistics
 * @server: Server instance
 * @stats: Output statistics
 */
extern void SocketHTTPServer_stats (SocketHTTPServer_T server,
                                    SocketHTTPServer_Stats *stats);

#endif /* SOCKETHTTPSERVER_INCLUDED */

