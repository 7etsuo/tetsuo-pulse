/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketProxy.h
 * @brief Proxy tunneling module for HTTP CONNECT and SOCKS protocols.
 * @ingroup core_io
 * @defgroup proxy Proxy Tunneling Module
 * @ingroup core_io
 *
 * @brief Transparent TCP proxy support with sync/async APIs.
 *
 * Provides high-performance proxy tunneling for applications requiring
 * HTTP CONNECT (RFC 7230) or SOCKS (RFC 1928/1929) protocols.
 * Integrates seamlessly with core socket primitives, async I/O, DNS
 * resolution, and TLS for end-to-end secure tunneling.
 *
 * Key capabilities:
 * - **Protocols**: HTTP CONNECT (with Basic auth), SOCKS4/4a/5/5H (with
 * password auth).
 * - **Modes**: Synchronous convenience or full asynchronous with event loop
 * integration.
 * - **Features**: URL-based config parsing, timeouts, secure credential
 * handling, HappyEyeballs racing.
 * - **Integration**: SocketHTTP1 for parsing, SocketTLS for HTTPS proxies,
 * SocketPool for management.
 *
 * Usage patterns:
 * - Direct connect: `SocketProxy_connect(config, target, port)` - blocks until
 * tunneled socket ready.
 * - Tunnel existing: `SocketProxy_tunnel(sock, config, target, port)` -
 * handshake on pre-connected sock.
 * - Async full: `SocketProxy_Conn_start(dns, poll, config, target, port)` -
 * non-blocking from resolution.
 * - Async hybrid: `SocketProxy_Conn_new(config, target, port)` - block
 * connect, async handshake.
 *
 * Security:
 * - Credentials zeroed after use.
 * - Strict parsing prevents buffer attacks.
 * - Timeouts mitigate DoS.
 * - Optional TLS to proxy for encrypted handshakes.
 *
 * Thread safety:
 * - Sync APIs thread-safe.
 * - Async Conn_T instances not thread-safe (single-thread per conn).
 *
 * Platform:
 * - POSIX (Linux/BSD/macOS).
 * - Requires SocketHappyEyeballs for optimal connects.
 * - TLS optional via SOCKET_HAS_TLS.
 *
 * Examples in examples/proxy_connect.c and docs/PROXY.md.
 *
 * @{
 *
 * @see SocketProxy_connect() synchronous API entry.
 * @see SocketProxy_Conn_new() async convenience.
 * @see SocketProxy_Conn_start() full async.
 * @see SocketProxy_Config for setup.
 * @see SocketProxy_parse_url() URL parsing.
 * @see SocketProxy_Result for error codes.
 * @see @ref async_io for event integration.
 * @see @ref dns for resolution.
 * @see @ref security for TLS.
 * @see @ref http for CONNECT headers.
 * @see docs/PROXY.md detailed guide.
 * @see docs/SECURITY.md credential/TLS best practices.
 * @see docs/ERROR_HANDLING.md exception handling.
 * @see docs/ASYNC_IO.md async patterns.
 *
 * Related primitives:
 * @see Socket for base I/O.
 * @see SocketHappyEyeballs for connects.
 * @see SocketPool for management.
 */

#ifndef SOCKETPROXY_INCLUDED
#define SOCKETPROXY_INCLUDED

#include <stddef.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSResolver.h"
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

/**
 * @brief Opaque context for managing asynchronous proxy tunneling operations.
 * @ingroup core_io
 *
 * Handles connection to proxy server, protocol handshake, authentication,
 * and state transitions for various proxy types (HTTP CONNECT, SOCKS).
 * Integrates with SocketPoll for event-driven processing and SocketDNS
 * for proxy server resolution.
 *
 * @see SocketProxy_Conn_new() for creating a new connection context.
 * @see SocketProxy_Conn_start() for fully asynchronous start.
 * @see SocketProxy_Conn_free() for resource cleanup.
 * @see SocketProxy_State for connection states.
 * @see docs/PROXY.md for detailed proxy configuration and usage.
 */
#define T SocketProxy_Conn_T
typedef struct T *T;

/* ============================================================================
 * Exception
 * ============================================================================
 */

/**
 * @brief Exception raised on general proxy operation failures.
 * @ingroup core_io
 *
 * Thrown when proxy connection establishment, authentication, or handshake
 * fails for any reason. For detailed error information in asynchronous
 * operations, query SocketProxy_Conn_result() after completion.
 *
 * @see SocketProxy_Conn_result() for specific SocketProxy_Result codes.
 * @see SocketProxy_Failed for common triggers like network errors,
 *   authentication failures, or protocol violations.
 * @see docs/ERROR_HANDLING.md for exception handling guidelines.
 */
extern const Except_T SocketProxy_Failed;

/* ============================================================================
 * Configuration Constants
 * @ingroup core_io
 * ============================================================================
 */

/**
 * @brief Default timeout for establishing connection to proxy server.
 * Value: 30000 ms (30 seconds).
 * Used when config.connect_timeout_ms = 0.
 * @see SocketProxy_Config::connect_timeout_ms
 */
#ifndef SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS 30000
#endif

/**
 * @brief Default timeout for proxy protocol handshake and authentication.
 * Value: 30000 ms (30 seconds).
 * Covers TLS, request send/recv, auth subnegotiation.
 * @see SocketProxy_Config::handshake_timeout_ms
 */
#ifndef SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000
#endif

/**
 * @brief Maximum allowed hostname/domain length in SOCKS5 requests (RFC 1928).
 * Value: 255 bytes.
 * Enforced for security against buffer overflows.
 * @see SocketProxy_parse_url() for URL validation.
 */
#ifndef SOCKET_PROXY_MAX_HOSTNAME_LEN
#define SOCKET_PROXY_MAX_HOSTNAME_LEN 255
#endif

/**
 * @brief Maximum username length for SOCKS5 authentication (RFC 1929).
 * Value: 255 bytes.
 * @see SocketProxy_Config::username
 */
#ifndef SOCKET_PROXY_MAX_USERNAME_LEN
#define SOCKET_PROXY_MAX_USERNAME_LEN 255
#endif

/**
 * @brief Maximum password length for SOCKS5 authentication (RFC 1929).
 * Value: 255 bytes.
 * Handled securely with memory clearing.
 * @see SocketProxy_Config::password
 * @see SocketCrypto_secure_clear()
 */
#ifndef SOCKET_PROXY_MAX_PASSWORD_LEN
#define SOCKET_PROXY_MAX_PASSWORD_LEN 255
#endif

/**
 * @brief Maximum length for userinfo in proxy URLs (user:pass@).
 * Value: 512 bytes (conservative for user + pass + delimiters).
 * Used in parsing to prevent buffer issues.
 * @see SocketProxy_parse_url()
 */
#ifndef SOCKET_PROXY_MAX_USERINFO_LEN
#define SOCKET_PROXY_MAX_USERINFO_LEN 512
#endif

/**
 * @brief Default port for SOCKS proxies.
 * Value: 1080 (standard IANA assignment).
 * Used when config.port = 0 and type is SOCKS*.
 * @see SocketProxyType
 */
#ifndef SOCKET_PROXY_DEFAULT_SOCKS_PORT
#define SOCKET_PROXY_DEFAULT_SOCKS_PORT 1080
#endif

/**
 * @brief Default port for HTTP proxies.
 * Value: 8080 (common convention).
 * Used for SOCKET_PROXY_HTTP when port unspecified.
 * @see SocketProxyType
 */
#ifndef SOCKET_PROXY_DEFAULT_HTTP_PORT
#define SOCKET_PROXY_DEFAULT_HTTP_PORT 8080
#endif

/**
 * @brief Default port for HTTPS proxies.
 * Value: 8080 (same as HTTP; TLS on top).
 * Used for SOCKET_PROXY_HTTPS when port unspecified.
 * @see SocketProxyType
 * @see SocketTLSContext_T for TLS config.
 */
#ifndef SOCKET_PROXY_DEFAULT_HTTPS_PORT
#define SOCKET_PROXY_DEFAULT_HTTPS_PORT 8080
#endif

/* ============================================================================
 * Proxy Types
 * ============================================================================
 */

/**
 * @brief Enumeration of supported proxy protocol types.
 * @ingroup core_io
 *
 * Defines the proxy protocols handled by the SocketProxy module,
 * including HTTP CONNECT for web proxies and SOCKS variants for
 * general tunneling.
 *
 * @see SocketProxy_Config::type for configuration.
 * @see SocketProxy_type_string() for string representations.
 * @see docs/PROXY.md for protocol-specific details and limitations.
 */
typedef enum
{
  SOCKET_PROXY_NONE = 0, /**< No proxy - direct connection to target. */
  SOCKET_PROXY_HTTP,  /**< HTTP CONNECT method (RFC 7231). Supports Basic auth.
                       */
  SOCKET_PROXY_HTTPS, /**< HTTPS CONNECT - TLS-encrypted connection to proxy
                         before handshake. */
  SOCKET_PROXY_SOCKS4,  /**< SOCKS4 protocol - IPv4 addresses only, no auth. */
  SOCKET_PROXY_SOCKS4A, /**< SOCKS4a extension - supports domain name
                           resolution at proxy. */
  SOCKET_PROXY_SOCKS5,  /**< SOCKS5 protocol (RFC 1928) - supports IPv6, auth,
                           UDP. */
  SOCKET_PROXY_SOCKS5H  /**< SOCKS5 with hostname resolution performed by proxy
                           server. */
} SocketProxyType;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for proxy operations.
 * @ingroup core_io
 *
 * Standardized error and status codes mapping protocol-specific responses
 * (e.g., SOCKS5 reply codes, HTTP status) to a unified interface.
 * Use SocketProxy_result_string() for human-readable descriptions.
 *
 * @see SocketProxy_Conn_result() to retrieve after async completion.
 * @see SocketProxy_result_string() for string conversion.
 * @see docs/PROXY.md for mapping to specific protocol errors.
 */
typedef enum
{
  PROXY_OK = 0,        /**< Success: tunnel established and ready for use. */
  PROXY_IN_PROGRESS,   /**< Asynchronous operation still in progress. */
  PROXY_ERROR,         /**< Generic proxy error (unspecified cause). */
  PROXY_ERROR_CONNECT, /**< Failed to establish connection to proxy server. */
  PROXY_ERROR_AUTH_REQUIRED, /**< Proxy requires authentication not provided.
                              */
  PROXY_ERROR_AUTH_FAILED,   /**< Provided credentials rejected by proxy. */
  PROXY_ERROR_FORBIDDEN, /**< Proxy forbids connection to specified target. */
  PROXY_ERROR_HOST_UNREACHABLE, /**< Target host cannot be reached (SOCKS5 code
                                   3). */
  PROXY_ERROR_NETWORK_UNREACHABLE, /**< Target network unreachable (SOCKS5 code
                                      4). */
  PROXY_ERROR_CONNECTION_REFUSED,  /**< Connection refused by target (SOCKS5
                                      code 5). */
  PROXY_ERROR_TTL_EXPIRED, /**< TTL expired en route to target (SOCKS5 code 6).
                            */
  PROXY_ERROR_PROTOCOL, /**< Protocol-level error (invalid response, etc.). */
  PROXY_ERROR_UNSUPPORTED, /**< Command or address type not supported by proxy.
                            */
  PROXY_ERROR_TIMEOUT,     /**< Operation timed out (connect or handshake). */
  PROXY_ERROR_CANCELLED    /**< Operation explicitly cancelled by user. */
} SocketProxy_Result;

/* ============================================================================
 * Connection State
 * ============================================================================
 */

/**
 * @brief States in the proxy connection state machine.
 * @ingroup core_io
 *
 * Tracks progress through proxy connection phases: resolution, connection,
 * TLS (if HTTPS proxy), authentication, and protocol handshake.
 *
 * State transition diagram:
 * IDLE → CONNECTING_PROXY → [TLS_TO_PROXY (HTTPS only)] → HANDSHAKE_SEND
 *             ↓                        ↓
 *   CONNECTED ← HANDSHAKE_RECV ← [AUTH_SEND/AUTH_RECV (SOCKS5)]
 *             ↓
 *        FAILED or CANCELLED
 *
 * @see SocketProxy_Conn_state() to query current state.
 * @see SocketProxy_state_string() for string names.
 * @see docs/ASYNC_IO.md for integration with event loops.
 */
typedef enum
{
  PROXY_STATE_IDLE = 0,         /**< Initial state: connection not started. */
  PROXY_STATE_CONNECTING_PROXY, /**< Resolving/connecting to proxy server via
                                   HappyEyeballs. */
  PROXY_STATE_TLS_TO_PROXY,   /**< Performing TLS handshake to HTTPS proxy. */
  PROXY_STATE_HANDSHAKE_SEND, /**< Sending proxy protocol request (CONNECT or
                                 SOCKS). */
  PROXY_STATE_HANDSHAKE_RECV, /**< Awaiting and parsing proxy response. */
  PROXY_STATE_AUTH_SEND, /**< Sending SOCKS5 authentication subnegotiation. */
  PROXY_STATE_AUTH_RECV, /**< Receiving SOCKS5 auth response. */
  PROXY_STATE_CONNECTED, /**< Success: tunnel ready for target communication.
                          */
  PROXY_STATE_FAILED,    /**< Terminal: operation failed with error. */
  PROXY_STATE_CANCELLED  /**< Terminal: operation cancelled by user. */
} SocketProxy_State;

/* ============================================================================
 * Configuration
 * ============================================================================
 */

/**
 * @brief Configuration structure for proxy connections.
 * @ingroup core_io
 *
 * Specifies proxy type, server details, authentication credentials,
 * optional HTTP headers, TLS context (for HTTPS proxies), and timeouts.
 *
 * Important: String fields (host, username, password) are borrowed references.
 * The caller must ensure these pointers remain valid throughout the proxy
 * operation lifetime. Use Arena allocation or static strings accordingly.
 * Sensitive data in password is securely cleared after use where possible.
 *
 * Default ports per type:
 * - HTTP/HTTPS: 8080
 * - SOCKS: 1080
 *
 * @see SocketProxy_config_defaults() to initialize with safe defaults.
 * @see SocketProxy_parse_url() to populate from URL string.
 * @see @ref http "HTTP module" for extra_headers usage.
 * @see @ref security "Security module" for TLS configuration.
 * @see docs/SECURITY.md for credential handling best practices.
 */
typedef struct SocketProxy_Config
{
  SocketProxyType
      type; /**< @brief Proxy protocol type (e.g., SOCKET_PROXY_SOCKS5). */

  /** @brief Proxy server details. */
  const char *host; /**< Proxy hostname or IP address. Must remain valid during
                       operation. */
  int port; /**< Proxy port. 0 uses default for type (SOCKS:1080, HTTP:8080).
             */

  /** @brief Optional authentication credentials for SOCKS5 or HTTP Basic auth.
   */
  const char *username; /**< Username string. NULL if no auth required.
                           Borrowed reference. */
  const char *password; /**< Password string. NULL if no auth or username NULL.
                           Securely handled. */

  /** @brief HTTP CONNECT-specific options. */
  SocketHTTP_Headers_T extra_headers; /**< Additional request headers. NULL for
                                         none. Owned by caller. */

#if SOCKET_HAS_TLS
  /** @brief TLS configuration for HTTPS proxies (TLS to proxy server). */
  SocketTLSContext_T
      tls_ctx; /**< TLS context. NULL uses secure system defaults if available.
                  Requires #if SOCKET_HAS_TLS. */
#endif

  /** @brief Timeout configuration (0 = use module defaults). */
  int connect_timeout_ms; /**< Timeout for connecting to proxy server (default:
                             30s). */
  int handshake_timeout_ms; /**< Timeout for proxy protocol handshake and auth
                               (default: 30s). */
} SocketProxy_Config;

/* ============================================================================
 * Configuration Helpers
 * ============================================================================
 */

/**
 * @brief Initialize proxy configuration with safe default values.
 * @ingroup core_io
 * @param config Pointer to configuration structure to populate.
 *
 * Sets type to SOCKET_PROXY_NONE, clears strings and headers to NULL,
 * sets default ports implicitly via type, and applies module default timeouts.
 * For HTTPS proxies, tls_ctx remains NULL (uses secure defaults if needed).
 *
 * @threadsafe Yes - pure function, no shared state.
 *
 * @see SocketProxy_Config for field details.
 * @see SocketProxy_parse_url() for URL-based initialization.
 * @see docs/PROXY.md for configuration best practices.
 */
extern void SocketProxy_config_defaults (SocketProxy_Config *config);

/**
 * @brief Parse proxy URL string into configuration structure.
 * @ingroup core_io
 * @param url Null-terminated proxy URL string.
 * @param config Output: populated configuration structure.
 * @param arena Optional arena for allocating parsed strings (host, user,
 * pass). If NULL, uses thread-local static buffer (overwritten on next call).
 *
 * @return 0 on successful parse, -1 on invalid URL format or allocation
 * failure.
 *
 * Supported schemes (case-insensitive):
 * - http://[user:pass@]host[:port]   (HTTP CONNECT)
 * - https://[user:pass@]host[:port]  (HTTPS CONNECT, requires TLS)
 * - socks4://host[:port]             (SOCKS4)
 * - socks4a://host[:port]            (SOCKS4a)
 * - socks5://[user:pass@]host[:port] (SOCKS5)
 * - socks5h://[user:pass@]host[:port](SOCKS5 hostname resolution)
 *
 * Port defaults: HTTP/HTTPS=8080, SOCKS=1080.
 * Userinfo parsing supports % encoding; passwords securely handled.
 * Does not support IPv6 literals in URL (use hostname or SocketDNS).
 *
 * Thread safety: Conditional. Safe if arena provided and thread-safe;
 *                static buffer is per-thread if no arena.
 *
 * @see SocketProxy_config_defaults() for manual initialization.
 * @see SocketProxy_Config for field ownership rules.
 * @see docs/PROXY.md#url-format for extended URL features.
 * @see @ref foundation "Arena module" for memory management.
 */
extern int SocketProxy_parse_url (const char *url, SocketProxy_Config *config,
                                  Arena_T arena);

/* ============================================================================
 * Synchronous API
 * ============================================================================
 */

/**
 * @brief Establish synchronous connection to target via proxy tunnel.
 * @ingroup core_io
 * @param proxy Configuration specifying proxy type, server, auth, etc.
 * @param target_host Target hostname or IP address to tunnel to.
 * @param target_port Target TCP port (valid range: 1-65535).
 *
 * @return On success: new Socket_T connected through proxy to target.
 *         Caller must Socket_free() when done.
 *         On failure: NULL, with SocketProxy_Failed raised.
 *
 * @throws SocketProxy_Failed on proxy connection, handshake, or auth failure.
 *         Specific causes available via last error if using async variant.
 *
 * @threadsafe Yes - creates independent socket and resources.
 *
 * This convenience function handles full lifecycle:
 * 1. Socket creation (TCP)
 * 2. DNS resolution and connection to proxy (via HappyEyeballs for speed)
 * 3. Optional TLS to proxy (HTTPS proxy type)
 * 4. Protocol handshake (CONNECT or SOCKS)
 * 5. Returns tunneled socket ready for immediate use.
 *
 * Blocking behavior: May block up to config timeouts for connect + handshake.
 * For non-blocking, use SocketProxy_Conn_new() or SocketProxy_Conn_start().
 *
 * Post-success: Socket is in connected state to target; application can
 * immediately perform SocketTLS_handshake() for HTTPS targets or send data.
 *
 * @warning Config strings must outlive the returned socket.
 * @warning No connection reuse or pooling; new socket per call.
 *
 * @see SocketProxy_tunnel() for existing socket tunneling.
 * @see SocketProxy_Conn_new() for async version.
 * @see @ref async_io "Async I/O module" for event-driven alternatives.
 * @see @ref dns "DNS module" for resolution details.
 * @see docs/PROXY.md for proxy-specific behaviors and limitations.
 * @see docs/SECURITY.md for TLS and auth security considerations.
 */
extern Socket_T SocketProxy_connect (const SocketProxy_Config *proxy,
                                     const char *target_host, int target_port);

/**
 * @brief Perform proxy handshake on pre-connected socket to establish tunnel.
 * @ingroup core_io
 * @param socket Pre-connected Socket_T to proxy server (non-blocking
 * recommended).
 * @param proxy Proxy configuration (type, auth, headers, timeouts). Host/port
 * must match socket connection.
 * @param target_host Target hostname/IP to request tunnel for (sent to proxy).
 * @param target_port Target port to request (1-65535).
 * @param arena Optional arena for temporary allocations (e.g., TLS context,
 * buffers). If NULL, uses internal arena (limited lifetime).
 *
 * @return PROXY_OK on success (tunnel established), other SocketProxy_Result
 * on failure. Socket remains owned by caller; state updated for tunneling.
 *
 * @throws SocketProxy_Failed on handshake, auth, or protocol errors.
 *
 * @threadsafe No - modifies socket state and uses shared internal resources.
 *
 * Use this for custom connection flows (e.g., connection pooling, custom DNS).
 * Assumes socket already connected to proxy->host:proxy->port via
 * Socket_connect() or equivalent. Performs:
 * - Optional TLS handshake (HTTPS proxy)
 * - Protocol-specific handshake (CONNECT, SOCKS request/response)
 * - Authentication subnegotiation (SOCKS5)
 *
 * For HTTPS proxies: If proxy->tls_ctx NULL and arena provided, auto-creates
 * secure TLS context. Without arena or tls_ctx, fails with PROXY_ERROR.
 *
 * On success: Socket ready for read/write to target (proxy-transparent).
 * On failure: Socket may be closed; check SocketProxy_Result for details.
 *
 * @warning Socket must not be shared across threads during call.
 * @warning Config and arena must outlive the operation.
 * @warning For async, use SocketProxy_Conn_start() with external poll/DNS.
 *
 * @see SocketProxy_connect() for full synchronous connection (socket creation
 * included).
 * @see SocketProxy_Config for TLS and timeout config.
 * @see @ref security "Security module" for HTTPS proxy TLS requirements.
 * @see docs/PROXY.md#custom-socket for advanced usage examples.
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
 * @brief Initialize and start fully asynchronous proxy tunneling operation.
 * @ingroup core_io
 * @param dns Caller-provided SocketDNS_T instance for proxy server resolution.
 *            Must remain valid and operational during entire operation.
 * @param poll Caller-provided SocketPoll_T for event notifications.
 *             Connection FD auto-registered; must not be freed prematurely.
 * @param proxy Proxy configuration (copied internally; strings borrowed).
 * @param target_host Target hostname or IP to tunnel connection to.
 * @param target_port Target TCP port number (1-65535).
 *
 * @return New SocketProxy_Conn_T context on success, NULL on init failure.
 * @throws SocketProxy_Failed on invalid config or resource allocation error.
 *
 * @threadsafe No - context tied to specific dns/poll instances; single-thread
 * use.
 *
 * This low-level API provides complete control for integrating proxy tunneling
 * into custom event loops. It uses provided DNS for non-blocking resolution
 * and poll for I/O events. No blocking calls after initialization.
 *
 * Integration pattern:
 * - Register conn->fd with poll if not auto-registered.
 * - Loop: SocketPoll_wait() → SocketProxy_Conn_process() → check
 * SocketProxy_Conn_poll()
 * - On completion: Extract socket with SocketProxy_Conn_socket(), then free
 * conn.
 * - Cleanup: SocketProxy_Conn_cancel() or free during progress.
 *
 * Handles: DNS resolution, TCP connect (HappyEyeballs), TLS (HTTPS),
 * handshake, auth, error recovery within timeouts.
 *
 * @note dns and poll ownership remains with caller; conn does not free them.
 * @note Context internally manages timers via poll; no external SocketTimer
 * needed.
 * @warning Failure to process events promptly may cause timeouts or stalls.
 * @warning Cancel or free during active state closes underlying socket.
 *
 * @see SocketProxy_Conn_process() for advancing state machine.
 * @see SocketProxy_Conn_poll() for completion check.
 * @see SocketProxy_Conn_next_timeout_ms() for poll timeout calculation.
 * @see @ref event_system "Event System" for poll integration examples.
 * @see @ref dns "DNS module" for async resolution details.
 * @see docs/ASYNC_IO.md for full event loop patterns.
 * @see docs/PROXY.md#async-api for advanced async features.
 */
extern T SocketProxy_Conn_start (SocketDNSResolver_T resolver, SocketPoll_T poll,
                                 const SocketProxy_Config *proxy,
                                 const char *target_host, int target_port);

/**
 * @brief Create proxy connection context with blocking proxy connect, async
 * handshake.
 * @ingroup core_io
 * @param proxy Proxy configuration (copied; strings borrowed).
 * @param target_host Target hostname or IP for tunneling.
 * @param target_port Target port (1-65535).
 *
 * @return New SocketProxy_Conn_T on success, NULL on failure.
 * @throws SocketProxy_Failed on config validation or initial resource
 * allocation failure.
 *
 * @threadsafe Yes - creates isolated instance with internal resources.
 *
 * Convenience wrapper for simpler async integration: performs blocking TCP
 * connect and DNS resolution to proxy server (up to connect_timeout_ms), then
 * switches to non-blocking mode for handshake, TLS, auth via internal
 * poll/timer/DNS instances.
 *
 * Unlike SocketProxy_Conn_start(), this blocks briefly for proxy reachability
 * but allows event-driven completion of protocol negotiation.
 *
 * Post-init usage same as async API:
 * - Poll loop: process events → SocketProxy_Conn_process() → check completion
 * - On done: SocketProxy_Conn_socket() transfers ownership, then free conn
 *
 * Internal resources auto-managed; no external dns/poll required from caller.
 *
 * @note Blocks only for proxy connect phase; handshake fully async.
 * @note Suitable for apps with existing event loops but wanting quick proxy
 * validation.
 * @warning Still requires poll integration for full non-blocking after
 * connect.
 * @warning Internal poll uses epoll/kqueue; ensure compatible with app loop.
 *
 * @see SocketProxy_Conn_start() for fully non-blocking from start (requires
 * external resources).
 * @see SocketProxy_connect() for fully synchronous end-to-end.
 * @see SocketProxy_Conn_process() and friends for runtime management.
 * @see @ref event_system "Event System" for poll backend details.
 * @see docs/PROXY.md#hybrid-api for hybrid sync/async patterns.
 */
extern T SocketProxy_Conn_new (const SocketProxy_Config *proxy,
                               const char *target_host, int target_port);

/**
 * @brief Query if proxy operation has completed.
 * @ingroup core_io
 * @param conn Proxy connection context to check.
 *
 * @return 1 if operation finished (CONNECTED, FAILED, or CANCELLED state),
 *         0 if still in progress.
 *
 * Call after SocketProxy_Conn_process() in event loop to detect completion.
 * On true, check SocketProxy_Conn_state() or SocketProxy_Conn_result() for
 * outcome.
 *
 * @threadsafe No - reads shared connection state.
 *
 * @see SocketProxy_Conn_state() for detailed status.
 * @see SocketProxy_Conn_result() for error/success code.
 * @see SocketProxy_Conn_socket() to retrieve tunneled socket on success.
 */
extern int SocketProxy_Conn_poll (T conn);

/**
 * @brief Advance asynchronous proxy connection state machine.
 * @ingroup core_io
 * @param conn Proxy connection context to process.
 *
 * Call this after detecting events on SocketProxy_Conn_fd() via your poll
 * loop. Performs non-blocking I/O: reads/writes protocol messages, handles
 * timeouts, advances through handshake phases (TLS, auth, connect response).
 *
 * May transition state and potentially complete operation; always follow with
 * SocketProxy_Conn_poll() to check.
 *
 * Does nothing if no events pending or in terminal state.
 *
 * @threadsafe No - modifies connection state and socket buffers.
 *
 * @note Integrates with SocketPoll; deregisters FD on completion/close.
 * @warning Must call promptly after events to avoid protocol timeouts.
 * @warning Not for synchronous use; pair with event-driven polling.
 *
 * @see SocketProxy_Conn_fd() and SocketProxy_Conn_events() for poll setup.
 * @see SocketProxy_Conn_poll() to check post-process completion.
 * @see @ref event_system "Poll module" for event handling examples.
 */
extern void SocketProxy_Conn_process (T conn);

/**
 * @brief Extract successfully tunneled socket from completed context.
 * @ingroup core_io
 * @param conn Proxy connection context (must be in CONNECTED state).
 *
 * @return On success (PROXY_OK and CONNECTED): Socket_T tunneled to target.
 *         Ownership transferred to caller; must Socket_free() after use.
 *         Otherwise: NULL (failed, cancelled, or pending).
 *
 * Call only after SocketProxy_Conn_poll() returns true and result is PROXY_OK.
 * Detaches socket from context; subsequent calls return NULL.
 * Socket is non-blocking, connected, and ready for app I/O or TLS handshake.
 *
 * @threadsafe No - transfers ownership and clears internal reference.
 *
 * @note Socket retains proxy tunnel; transparent to application.
 * @warning Calling on non-success states leaks no resources but returns NULL.
 * @warning Free context after extraction to avoid double-free.
 *
 * @see SocketProxy_Conn_result() to verify success before extraction.
 * @see SocketProxy_Conn_free() after successful socket transfer.
 * @see Socket.h for socket operations post-tunnel.
 * @see @ref security "TLS module" for HTTPS target handshakes.
 */
extern Socket_T SocketProxy_Conn_socket (T conn);

/**
 * @brief Cancel ongoing proxy connection and cleanup resources.
 * @ingroup core_io
 * @param conn Proxy connection context to cancel.
 *
 * Immediately aborts operation: closes socket, cancels DNS/timers,
 * transitions to PROXY_STATE_CANCELLED and PROXY_ERROR_CANCELLED.
 * Safe to call from any state; idempotent.
 *
 * Use to gracefully stop long-running operations or handle app shutdown.
 * After cancel, SocketProxy_Conn_poll() will return true; result is CANCELLED.
 * SocketProxy_Conn_socket() returns NULL.
 *
 * @threadsafe No - modifies connection state and closes shared socket.
 *
 * @note Does not block; asynchronous cleanup via poll if needed.
 * @note Resources freed on next process or free; call free soon after.
 * @warning Cancelling mid-handshake may leave proxy in inconsistent state.
 *
 * @see SocketProxy_Conn_free() for complete cleanup (auto-cancels if pending).
 * @see SocketProxy_Conn_result() will return PROXY_ERROR_CANCELLED.
 * @see docs/ASYNC_IO.md for cancellation patterns in event loops.
 */
extern void SocketProxy_Conn_cancel (T conn);

/**
 * @brief Release proxy connection context and associated resources.
 * @ingroup core_io
 * @param conn Pointer to SocketProxy_Conn_T (set to NULL on success).
 *
 * Frees all allocated resources: socket, internal buffers, timers, DNS
 * requests. If operation pending, auto-cancels first (closes socket, signals
 * completion). Idempotent and null-safe: handles NULL pointer or already-freed
 * context.
 *
 * Call after successful socket extraction or on error/cancel.
 * For internal resources (from SocketProxy_Conn_new()), fully self-contained.
 * For external (SocketProxy_Conn_start()), does not free user-provided
 * dns/poll.
 *
 * @threadsafe No - frees shared state; avoid concurrent access.
 *
 * @note Follows Arena-managed pattern but uses internal arena for most allocs.
 * @note Socket ownership: If not extracted via SocketProxy_Conn_socket(),
 *       socket auto-closed here.
 * @warning Do not access conn after free; undefined behavior.
 *
 * @see SocketProxy_Conn_socket() before free to transfer socket ownership.
 * @see SocketProxy_Conn_cancel() for explicit abort without full free.
 * @see @ref foundation "Arena module" for memory management context.
 * @see docs/MEMORY_MANAGEMENT.md for resource lifecycle guidelines.
 */
extern void SocketProxy_Conn_free (T *conn);

/* ============================================================================
 * State Query
 * ============================================================================
 */

/**
 * @brief Retrieve current state of proxy connection.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * @return Current SocketProxy_State (e.g., CONNECTING_PROXY, CONNECTED).
 *
 * Use for logging, UI updates, or conditional logic during async progress.
 * Valid states reflect real-time progress through connection phases.
 *
 * @threadsafe No - reads volatile internal state.
 *
 * @see SocketProxy_State enumeration for state details and transitions.
 * @see SocketProxy_Conn_poll() to check if terminal state reached.
 * @see SocketProxy_state_string() for human-readable state name.
 */
extern SocketProxy_State SocketProxy_Conn_state (T conn);

/**
 * @brief Get final result code after operation completion.
 * @ingroup core_io
 * @param conn Completed proxy connection context.
 *
 * @return SocketProxy_Result indicating outcome (PROXY_OK on success,
 *         error code on failure).
 *
 * Valid only after SocketProxy_Conn_poll() returns 1 (terminal state).
 * Provides protocol-specific error mapping for debugging and retry logic.
 * On success, socket available via SocketProxy_Conn_socket().
 *
 * @threadsafe No - reads result stored in connection state.
 *
 * @see SocketProxy_Result for code meanings.
 * @see SocketProxy_result_string() for descriptive strings.
 * @see SocketProxy_Conn_error() for additional error details.
 * @see docs/ERROR_HANDLING.md for error categorization and recovery.
 */
extern SocketProxy_Result SocketProxy_Conn_result (T conn);

/**
 * @brief Retrieve human-readable error description for failed operations.
 * @ingroup core_io
 * @param conn Proxy connection context in FAILED state.
 *
 * @return Const string describing failure (e.g., "Authentication failed"),
 *         or NULL if not in FAILED state or no specific message.
 *         String allocated from internal arena; valid until
 * SocketProxy_Conn_free().
 *
 * Provides diagnostic details beyond SocketProxy_Conn_result() code,
 * including protocol responses, system errors, or timeout reasons.
 * Intended for logging; not for programmatic error handling (use result code).
 *
 * @threadsafe No - borrowed reference to internal string buffer.
 *
 * @note String may be truncated for long errors; use for display/logging.
 * @note Cleared on cancel or success; check state first.
 * @warning Do not free or modify returned string; internal ownership.
 *
 * @see SocketProxy_Conn_result() for structured error code.
 * @see SocketProxy_Conn_state() to confirm FAILED state.
 * @see SocketLog_emit() for logging this error.
 * @see docs/LOGGING.md for error logging best practices.
 */
extern const char *SocketProxy_Conn_error (T conn);

/* ============================================================================
 * Poll Integration
 * ============================================================================
 */

/**
 * @brief Get underlying file descriptor for poll integration.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * @return Socket FD to monitor with SocketPoll_add(), or -1 if no active
 * socket (init, completed, or failed state).
 *
 * For custom poll loops: add this FD with SocketProxy_Conn_events() mask.
 * Context auto-manages registration if using internal poll, but expose for
 * external or multi-poll scenarios.
 * FD valid while in progress states; deregister on completion/cancel.
 *
 * @threadsafe No - FD may change or close concurrently.
 *
 * @note FD is non-blocking after initial connect.
 * @note Use Socket_get_fd() on extracted socket post-success for app polling.
 * @warning Do not close or modify FD directly; use conn methods.
 *
 * @see SocketProxy_Conn_events() for required event mask.
 * @see SocketPoll_add() for registration example.
 * @see @ref event_system "Poll module" for FD management.
 */
extern int SocketProxy_Conn_fd (T conn);

/**
 * @brief Get poll event mask for current connection phase.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * @return Bitmask of SocketPoll_Events (POLL_READ | POLL_WRITE | POLL_ERROR)
 *         required for current state (e.g., READ for response, WRITE for
 * request). 0 if no polling needed (terminal states).
 *
 * Dynamically updates based on state: e.g., WRITE during send phases,
 * READ during recv. Use with SocketPoll_mod() to update registration.
 *
 * @threadsafe No - reflects current I/O direction.
 *
 * @note Compatible with SocketPoll events.
 * @note Call before/after state changes or process to refresh mask.
 * @warning Incorrect events may stall or error the handshake.
 *
 * @see SocketProxy_Conn_fd() to get FD for registration.
 * @see SocketPoll_mod() for updating event mask.
 * @see @ref event_system "Event System" for polling mechanics.
 */
extern unsigned SocketProxy_Conn_events (T conn);

/**
 * @brief Calculate milliseconds until next internal timeout.
 * @ingroup core_io
 * @param conn Proxy connection context.
 *
 * @return Positive: ms until timeout expiry (use for poll timeout).
 *         0: Immediate timeout pending (process urgently).
 *         -1: No timeout active (poll indefinitely or use defaults).
 *
 * Accounts for connect_timeout_ms, handshake_timeout_ms, and internal timers.
 * Decrements in real-time; call periodically in loop for accuracy.
 * Helps prevent unnecessary busy-polling while respecting deadlines.
 *
 * @threadsafe No - based on volatile monotonic time.
 *
 * @note Uses Socket_get_monotonic_ms() for precise timing.
 * @note Negative values indicate expired timeout (error imminent).
 * @warning Stale calls may lead to missed deadlines; refresh often.
 *
 * @see SocketPoll_wait() - pass this value as timeout param.
 * @see SocketTimeout utilities in SocketUtil for advanced timing.
 * @see docs/TIMEOUTS.md for timeout configuration and behavior.
 */
extern int SocketProxy_Conn_next_timeout_ms (T conn);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Convert SocketProxy_Result code to descriptive string.
 * @ingroup core_io
 * @param result Result code to stringify.
 *
 * @return Static const char* (e.g., "PROXY_OK", "PROXY_ERROR_AUTH_FAILED").
 *         Never NULL; valid for all valid codes.
 *
 * Utility for logging, debugging, or user-facing error messages.
 * Strings are interned static; no allocation.
 *
 * @threadsafe Yes - static read-only strings.
 *
 * @see SocketProxy_Conn_result() for runtime result retrieval.
 * @see SocketProxy_Result enum for code list.
 * @see docs/LOGGING.md for integration with SocketLog.
 */
extern const char *SocketProxy_result_string (SocketProxy_Result result);

/**
 * @brief Convert SocketProxy_State to descriptive string.
 * @ingroup core_io
 * @param state State enum value to stringify.
 *
 * @return Static const char* (e.g., "PROXY_STATE_CONNECTED",
 * "PROXY_STATE_FAILED"). Never NULL; covers all states.
 *
 * For debugging, logging, or state machine visualization.
 * Compact format suitable for trace output.
 *
 * @threadsafe Yes - static constants.
 *
 * @see SocketProxy_Conn_state() to get current state.
 * @see SocketProxy_State enum for state documentation.
 */
extern const char *SocketProxy_state_string (SocketProxy_State state);

/**
 * @brief Convert proxy type enum to protocol name string.
 * @ingroup core_io
 * @param type SocketProxyType enum value.
 *
 * @return Static const char* describing protocol (e.g., "HTTP CONNECT",
 *         "SOCKS5", "none"). Never NULL; user-friendly for logs/UI.
 *
 * Examples:
 * - SOCKET_PROXY_HTTP → "HTTP CONNECT"
 * - SOCKET_PROXY_SOCKS5 → "SOCKS5"
 * - SOCKET_PROXY_NONE → "direct"
 *
 * @threadsafe Yes - static strings.
 *
 * @see SocketProxyType enum for supported types.
 * @see SocketProxy_Config::type for runtime configuration.
 * @see docs/PROXY.md for type-specific protocol details.
 */
extern const char *SocketProxy_type_string (SocketProxyType type);

#undef T
/** @} */ /* proxy group */

/**
 * @page proxy_guide Proxy Tunneling Guide
 *
 * Detailed user guide for SocketProxy module.
 * @subpage proxy_usage
 * @subpage proxy_security
 * @subpage proxy_async
 *
 * @see SocketProxy.h API
 */

#endif /* SOCKETPROXY_INCLUDED */
