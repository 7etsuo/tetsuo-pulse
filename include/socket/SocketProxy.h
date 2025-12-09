/**
 * @file SocketProxy.h
 * @ingroup core_io
 * @brief Proxy tunneling support for HTTP CONNECT and SOCKS protocols.
 *
 * Provides transparent proxy tunneling for TCP connections, supporting
 * HTTP CONNECT and SOCKS4/4a/5 protocols. The implementation follows
 * the same patterns as SocketHappyEyeballs with both synchronous and
 * asynchronous APIs.
 *
 * Supported Proxy Types:
 * - HTTP CONNECT (RFC 7231) with optional Basic authentication
 * - HTTPS CONNECT (TLS to proxy)
 * - SOCKS4 (IPv4 only)
 * - SOCKS4a (hostname resolution at proxy)
 * - SOCKS5 (RFC 1928) with no auth or username/password
 * - SOCKS5H (SOCKS5 with hostname resolution at proxy)
 *
 * Features:
 * - Synchronous and asynchronous APIs
 * - URL parsing (socks5://user:pass@host:port)
 * - Configurable timeouts
 * - Secure credential handling
 * - Integration with SocketHappyEyeballs for fast proxy connection
 *
 * Module Reuse (no code duplication):
 * - SocketHappyEyeballs for proxy server connection (handles DNS internally)
 * - SocketHTTP1_Parser_T for HTTP CONNECT response parsing
 * - SocketCrypto for Basic auth encoding and secure memory clearing
 * - SocketBuf for buffered protocol I/O
 *
 * Thread Safety:
 * - SocketProxy_Conn_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Synchronous API is thread-safe (uses internal resources)
 *
 * Security Notes:
 * - Credentials are cleared from memory after use via
 * SocketCrypto_secure_clear()
 * - Hostnames are validated (SOCKS5 max 255 bytes)
 * - HTTP response parsing uses strict mode to prevent smuggling
 * - All protocol responses are bounds-checked
 *
 * Usage (Synchronous):
 *   SocketProxy_Result result = SocketProxy_connect(
 *       socket, &proxy, "target.example.com", 443);
 *   if (result == PROXY_OK) {
 *       // Socket is now tunneled to target
 *       // Perform TLS handshake if needed
 *   }
 *
 * Usage (Asynchronous):
 *   SocketProxy_Conn_T conn = SocketProxy_Conn_new(
 *       socket, &proxy, "target.example.com", 443);
 *   while (!SocketProxy_Conn_poll(conn)) {
 *       int timeout = SocketProxy_Conn_next_timeout_ms(conn);
 *       SocketPoll_wait(poll, &events, timeout);
 *       SocketProxy_Conn_process(conn);
 *   }
 *   SocketProxy_Result result = SocketProxy_Conn_result(conn);
 *   SocketProxy_Conn_free(&conn);
 *
 * Platform Requirements:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - SocketHappyEyeballs module for proxy connection
 * - Optional: SocketTLS for HTTPS proxy support
 *
 * @see SocketProxy_connect() for synchronous proxy connection.
 * @see SocketProxy_new() for asynchronous proxy connection setup.
 * @see SocketHappyEyeballs.h for connection racing integration.
 * @see SocketTLS.h for TLS proxy support.
 */

#ifndef SOCKETPROXY_INCLUDED
#define SOCKETPROXY_INCLUDED

#include <stddef.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/* Forward declarations for optional TLS */
#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/* Forward declaration for optional HTTP headers */
struct SocketHTTP_Headers;
typedef struct SocketHTTP_Headers *SocketHTTP_Headers_T;

/* ============================================================================
 * Opaque Type
 * ============================================================================
 */

#define T SocketProxy_Conn_T
typedef struct T *T;

/* ============================================================================
 * Exception
 * ============================================================================
 */

/**
 * SocketProxy_Failed - General proxy operation failure
 *
 * Raised when proxy connection or handshake fails.
 * Use SocketProxy_Conn_result() for specific error codes.
 */
extern const Except_T SocketProxy_Failed;

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 */

/** Default timeout for connecting to proxy server (ms) */
#ifndef SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS 30000
#endif

/** Default timeout for proxy handshake (ms) */
#ifndef SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000
#endif

/** Maximum hostname length for SOCKS5 (RFC 1928) */
#ifndef SOCKET_PROXY_MAX_HOSTNAME_LEN
#define SOCKET_PROXY_MAX_HOSTNAME_LEN 255
#endif

/** Maximum username length for SOCKS5 (RFC 1929) */
#ifndef SOCKET_PROXY_MAX_USERNAME_LEN
#define SOCKET_PROXY_MAX_USERNAME_LEN 255
#endif

/** Maximum password length for SOCKS5 (RFC 1929) */
#ifndef SOCKET_PROXY_MAX_PASSWORD_LEN
#define SOCKET_PROXY_MAX_PASSWORD_LEN 255
#endif

/** Maximum userinfo length (user + : + pass + @) */
#ifndef SOCKET_PROXY_MAX_USERINFO_LEN
#define SOCKET_PROXY_MAX_USERINFO_LEN 512
#endif

/** Default SOCKS port */
#ifndef SOCKET_PROXY_DEFAULT_SOCKS_PORT
#define SOCKET_PROXY_DEFAULT_SOCKS_PORT 1080
#endif

/** Default HTTP proxy port */
#ifndef SOCKET_PROXY_DEFAULT_HTTP_PORT
#define SOCKET_PROXY_DEFAULT_HTTP_PORT 8080
#endif

/** Default HTTPS proxy port */
#ifndef SOCKET_PROXY_DEFAULT_HTTPS_PORT
#define SOCKET_PROXY_DEFAULT_HTTPS_PORT 8080
#endif

/* ============================================================================
 * Proxy Types
 * ============================================================================
 */

/**
 * SocketProxyType - Supported proxy protocol types
 */
typedef enum
{
  SOCKET_PROXY_NONE = 0, /**< No proxy (direct connection) */
  SOCKET_PROXY_HTTP,     /**< HTTP CONNECT proxy */
  SOCKET_PROXY_HTTPS,    /**< HTTPS CONNECT proxy (TLS to proxy) */
  SOCKET_PROXY_SOCKS4,   /**< SOCKS4 proxy (IPv4 only) */
  SOCKET_PROXY_SOCKS4A,  /**< SOCKS4a proxy (hostname at proxy) */
  SOCKET_PROXY_SOCKS5,   /**< SOCKS5 proxy (RFC 1928) */
  SOCKET_PROXY_SOCKS5H   /**< SOCKS5 with hostname at proxy */
} SocketProxyType;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * SocketProxy_Result - Proxy operation result codes
 *
 * Maps protocol-specific errors to unified result codes.
 */
typedef enum
{
  PROXY_OK = 0,                    /**< Success - tunnel established */
  PROXY_IN_PROGRESS,               /**< Operation in progress (async) */
  PROXY_ERROR,                     /**< Generic error */
  PROXY_ERROR_CONNECT,             /**< Failed to connect to proxy */
  PROXY_ERROR_AUTH_REQUIRED,       /**< Proxy requires authentication */
  PROXY_ERROR_AUTH_FAILED,         /**< Authentication rejected */
  PROXY_ERROR_FORBIDDEN,           /**< Proxy refused connection to target */
  PROXY_ERROR_HOST_UNREACHABLE,    /**< Target host unreachable */
  PROXY_ERROR_NETWORK_UNREACHABLE, /**< Target network unreachable */
  PROXY_ERROR_CONNECTION_REFUSED,  /**< Target connection refused */
  PROXY_ERROR_TTL_EXPIRED,         /**< TTL expired */
  PROXY_ERROR_PROTOCOL,            /**< Protocol error */
  PROXY_ERROR_UNSUPPORTED,         /**< Unsupported command/feature */
  PROXY_ERROR_TIMEOUT,             /**< Operation timed out */
  PROXY_ERROR_CANCELLED            /**< Operation cancelled */
} SocketProxy_Result;

/* ============================================================================
 * Connection State
 * ============================================================================
 */

/**
 * SocketProxy_State - Proxy connection state machine
 *
 * State transitions:
 *   IDLE -> CONNECTING_PROXY -> HANDSHAKE_* -> CONNECTED (success)
 *                                          \-> FAILED (error)
 *   Any state -> CANCELLED (explicit cancel)
 */
typedef enum
{
  PROXY_STATE_IDLE = 0,         /**< Not started */
  PROXY_STATE_CONNECTING_PROXY, /**< Connecting to proxy (HappyEyeballs) */
  PROXY_STATE_TLS_TO_PROXY,     /**< TLS handshake to proxy (HTTPS) */
  PROXY_STATE_HANDSHAKE_SEND,   /**< Sending protocol request */
  PROXY_STATE_HANDSHAKE_RECV,   /**< Receiving protocol response */
  PROXY_STATE_AUTH_SEND,        /**< Sending SOCKS5 auth */
  PROXY_STATE_AUTH_RECV,        /**< Receiving SOCKS5 auth response */
  PROXY_STATE_CONNECTED,        /**< Tunnel established */
  PROXY_STATE_FAILED,           /**< Error occurred */
  PROXY_STATE_CANCELLED         /**< User cancelled */
} SocketProxy_State;

/* ============================================================================
 * Configuration
 * ============================================================================
 */

/**
 * SocketProxy_Config - Proxy configuration
 *
 * All strings are borrowed (not copied) - caller must ensure they remain
 * valid for the duration of the proxy operation.
 */
typedef struct SocketProxy_Config
{
  SocketProxyType type; /**< Proxy type */

  /* Proxy server */
  const char *host; /**< Proxy hostname or IP */
  int port;         /**< Proxy port (0 = default for type) */

  /* Authentication (optional) */
  const char *username; /**< Username for SOCKS5/HTTP Basic auth */
  const char *password; /**< Password for SOCKS5/HTTP Basic auth */

  /* HTTP CONNECT specific */
  SocketHTTP_Headers_T extra_headers; /**< Additional headers (optional) */
                                      /* TLS for HTTPS proxy (optional) */
#if SOCKET_HAS_TLS
  SocketTLSContext_T tls_ctx; /**< TLS context for HTTPS proxies (NULL = use
                                 secure defaults) */
#endif

  /* Timeouts (0 = use defaults) */
  int connect_timeout_ms;   /**< Timeout connecting to proxy */
  int handshake_timeout_ms; /**< Timeout for proxy handshake */
} SocketProxy_Config;

/* ============================================================================
 * Configuration Helpers
 * ============================================================================
 */

/**
 * SocketProxy_config_defaults - Initialize config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes
 *
 * Sets all fields to zero/NULL except timeouts which get defaults.
 */
extern void SocketProxy_config_defaults (SocketProxy_Config *config);

/**
 * SocketProxy_parse_url - Parse proxy URL into config
 * @url: Proxy URL (e.g., "socks5://user:pass@proxy:1080")
 * @config: Output configuration
 * @arena: Arena for string allocation (NULL to use static buffer)
 *
 * Returns: 0 on success, -1 on parse error
 * Thread-safe: Yes (if arena is thread-safe or NULL)
 *
 * Supported URL formats:
 *   http://[user:pass@]host[:port]
 *   https://[user:pass@]host[:port]
 *   socks4://host[:port]
 *   socks4a://host[:port]
 *   socks5://[user:pass@]host[:port]
 *   socks5h://[user:pass@]host[:port]
 *
 * When arena is NULL, strings are allocated from a static thread-local
 * buffer and are valid until the next call to SocketProxy_parse_url()
 * from the same thread.
 */
extern int SocketProxy_parse_url (const char *url, SocketProxy_Config *config,
                                  Arena_T arena);

/* ============================================================================
 * Synchronous API
 * ============================================================================
 */

/**
 * SocketProxy_connect - Connect to target through proxy (blocking)
 * @proxy: Proxy configuration
 * @target_host: Target hostname or IP
 * @target_port: Target port (1-65535)
 *
 * Returns: Connected socket on success, NULL on failure
 * Raises: SocketProxy_Failed on error
 * Thread-safe: Yes (uses internal resources)
 *
 * Creates a new socket, connects to the proxy server using HappyEyeballs,
 * performs the proxy handshake, and returns the tunneled socket.
 *
 * After success, the returned socket is connected to the target through
 * the proxy tunnel. Perform TLS handshake after this if connecting to
 * an HTTPS endpoint.
 *
 * WARNING: This function may block for up to connect_timeout_ms +
 * handshake_timeout_ms during proxy connection and handshake.
 */
extern Socket_T SocketProxy_connect (const SocketProxy_Config *proxy,
                                     const char *target_host, int target_port);

/**
 * SocketProxy_tunnel - Establish tunnel on existing socket (blocking)
 * @socket: Already-connected socket to proxy server
 * @proxy: Proxy configuration (type, auth, timeouts)
 * @target_host: Target hostname or IP
 * @target_port: Target port (1-65535)
 * @arena: Optional arena for internal allocations (e.g., TLS context for
 * HTTPS)
 *
 * Returns: PROXY_OK on success, error code on failure
 * Thread-safe: No
 *
 * Performs proxy handshake on an already-connected socket. For HTTPS proxies,
 * performs TLS handshake if tls_ctx in config or auto-creates secure one using
 * arena. Use this when you need control over the proxy connection
 * establishment.
 *
 * The socket should already be connected to proxy->host:proxy->port.
 * If arena NULL and HTTPS, may fail if no pre-provided tls_ctx.
 */
extern SocketProxy_Result
SocketProxy_tunnel (Socket_T socket, const SocketProxy_Config *proxy,
                    const char *target_host, int target_port,
                    Arena_T arena /* optional for TLS context allocation */);

/* ============================================================================
 * Asynchronous API
 * ============================================================================
 */

/**
 * SocketProxy_Conn_start - Start truly async proxy connection (event-driven)
 * @dns: DNS resolver instance (caller-owned, must outlive operation)
 * @poll: Poll instance for connection monitoring (caller-owned)
 * @proxy: Proxy configuration
 * @target_host: Target hostname or IP
 * @target_port: Target port (1-65535)
 *
 * Returns: Proxy connection context
 * Raises: SocketProxy_Failed on initialization failure
 * Thread-safe: No (operate from single thread)
 *
 * Starts fully asynchronous proxy connection using external DNS and poll
 * resources. This is the preferred API for event-driven applications.
 * The operation is completely non-blocking from the start.
 *
 * Caller must:
 * 1. Call SocketProxy_Conn_process() after each poll wait
 * 2. Check SocketProxy_Conn_poll() for completion
 * 3. Call SocketProxy_Conn_socket() to get the tunneled socket
 * 4. Call SocketProxy_Conn_free() to release context
 *
 * Usage example:
 *   SocketProxy_Conn_T conn = SocketProxy_Conn_start(dns, poll, &proxy,
 *                                                    "target.com", 443);
 *   while (!SocketProxy_Conn_poll(conn)) {
 *       int timeout = SocketProxy_Conn_next_timeout_ms(conn);
 *       SocketPoll_wait(poll, &events, timeout);
 *       SocketProxy_Conn_process(conn);
 *   }
 *   Socket_T sock = SocketProxy_Conn_socket(conn);
 *   SocketProxy_Conn_free(&conn);
 */
extern T SocketProxy_Conn_start (SocketDNS_T dns, SocketPoll_T poll,
                                 const SocketProxy_Config *proxy,
                                 const char *target_host, int target_port);

/**
 * SocketProxy_Conn_new - Start async proxy connection (blocking connect)
 * @proxy: Proxy configuration
 * @target_host: Target hostname or IP
 * @target_port: Target port (1-65535)
 *
 * Returns: Proxy connection context
 * Raises: SocketProxy_Failed on initialization failure
 * Thread-safe: Yes (creates new instance)
 *
 * NOTE: This function blocks during the initial proxy connection phase.
 * For fully non-blocking operation, use SocketProxy_Conn_start() instead.
 *
 * Starts proxy connection with blocking connect to proxy server, then
 * async handshake. This is a convenience wrapper that creates internal
 * DNS and poll resources.
 *
 * Caller must:
 * 1. Call SocketProxy_Conn_process() after each poll wait
 * 2. Check SocketProxy_Conn_poll() for completion
 * 3. Call SocketProxy_Conn_socket() to get the tunneled socket
 * 4. Call SocketProxy_Conn_free() to release context
 */
extern T SocketProxy_Conn_new (const SocketProxy_Config *proxy,
                               const char *target_host, int target_port);

/**
 * SocketProxy_Conn_poll - Check if operation is complete
 * @conn: Proxy connection context
 *
 * Returns: 1 if complete (success, failure, or cancelled), 0 if in progress
 * Thread-safe: No
 */
extern int SocketProxy_Conn_poll (T conn);

/**
 * SocketProxy_Conn_process - Process async connection
 * @conn: Proxy connection context
 *
 * Thread-safe: No
 *
 * Call after SocketPoll_wait() returns with events on the connection fd.
 * This advances the state machine and handles protocol I/O.
 */
extern void SocketProxy_Conn_process (T conn);

/**
 * SocketProxy_Conn_socket - Get tunneled socket from completed operation
 * @conn: Proxy connection context
 *
 * Returns: Tunneled socket, or NULL if failed/cancelled/pending
 * Thread-safe: No
 *
 * Transfers socket ownership to caller. Caller must Socket_free() when done.
 * Can only be called once per successful connection - subsequent calls
 * return NULL.
 */
extern Socket_T SocketProxy_Conn_socket (T conn);

/**
 * SocketProxy_Conn_cancel - Cancel in-progress operation
 * @conn: Proxy connection context
 *
 * Thread-safe: No
 *
 * Closes the connection and transitions to CANCELLED state.
 */
extern void SocketProxy_Conn_cancel (T conn);

/**
 * SocketProxy_Conn_free - Free proxy connection context
 * @conn: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 *
 * Releases all resources. If operation is still in progress, it will
 * be cancelled first. Safe to call with NULL or *conn == NULL.
 */
extern void SocketProxy_Conn_free (T *conn);

/* ============================================================================
 * State Query
 * ============================================================================
 */

/**
 * SocketProxy_Conn_state - Get current connection state
 * @conn: Proxy connection context
 *
 * Returns: Current state
 * Thread-safe: No
 */
extern SocketProxy_State SocketProxy_Conn_state (T conn);

/**
 * SocketProxy_Conn_result - Get result after completion
 * @conn: Proxy connection context
 *
 * Returns: Result code (only valid after SocketProxy_Conn_poll() returns 1)
 * Thread-safe: No
 */
extern SocketProxy_Result SocketProxy_Conn_result (T conn);

/**
 * SocketProxy_Conn_error - Get error message for failed operation
 * @conn: Proxy connection context
 *
 * Returns: Error message string, or NULL if not in FAILED state
 * Thread-safe: No
 *
 * The returned string is valid until SocketProxy_Conn_free() is called.
 */
extern const char *SocketProxy_Conn_error (T conn);

/* ============================================================================
 * Poll Integration
 * ============================================================================
 */

/**
 * SocketProxy_Conn_fd - Get file descriptor for poll
 * @conn: Proxy connection context
 *
 * Returns: File descriptor to poll, or -1 if none active
 * Thread-safe: No
 */
extern int SocketProxy_Conn_fd (T conn);

/**
 * SocketProxy_Conn_events - Get events to poll for
 * @conn: Proxy connection context
 *
 * Returns: Poll events bitmask (POLL_READ, POLL_WRITE)
 * Thread-safe: No
 */
extern unsigned SocketProxy_Conn_events (T conn);

/**
 * SocketProxy_Conn_next_timeout_ms - Get time until next timeout
 * @conn: Proxy connection context
 *
 * Returns: Milliseconds until timeout, or -1 if no pending timeout
 * Thread-safe: No
 *
 * Use as timeout argument to SocketPoll_wait().
 */
extern int SocketProxy_Conn_next_timeout_ms (T conn);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * SocketProxy_result_string - Get human-readable result description
 * @result: Result code
 *
 * Returns: Static string describing the result
 * Thread-safe: Yes
 */
extern const char *SocketProxy_result_string (SocketProxy_Result result);

/**
 * SocketProxy_state_string - Get human-readable state name
 * @state: State value
 *
 * Returns: Static string with state name
 * Thread-safe: Yes
 */
extern const char *SocketProxy_state_string (SocketProxy_State state);

/**
 * SocketProxy_type_string - Get human-readable proxy type name
 * @type: Proxy type
 *
 * Returns: Static string (e.g., "SOCKS5", "HTTP CONNECT")
 * Thread-safe: Yes
 */
extern const char *SocketProxy_type_string (SocketProxyType type);

#undef T
#endif /* SOCKETPROXY_INCLUDED */
