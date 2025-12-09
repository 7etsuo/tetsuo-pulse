/**
 * @defgroup http_client HTTP Client Module
 * @ingroup http
 * @brief High-level HTTP client library supporting HTTP/1.1, HTTP/2,
 * connection pooling, async I/O, authentication, cookies, redirects,
 * compression, and proxy support.
 *
 * The HTTP client module offers a production-ready implementation for making
 * HTTP requests with modern features, security, and performance optimizations.
 *
 * Key Features:
 * - Synchronous and asynchronous request execution
 * - Automatic protocol negotiation (HTTP/2 via ALPN prioritized)
 * - Efficient connection pooling with per-host limits, idle timeouts, and
 * reuse statistics
 * - RFC 6265-compliant cookie management including SameSite attributes
 * - Support for authentication schemes: Basic (RFC 7617), Digest (RFC 7616),
 * Bearer tokens (RFC 6750)
 * - Automatic compression handling (gzip, deflate, brotli) with decompression
 * - Intelligent redirect following with loop detection and method preservation
 * - Proxy configuration and Happy Eyeballs for dual-stack IPv6 preference
 * - Configurable timeouts, retries, and error recovery for resilience
 * - Comprehensive logging, metrics, and pool management APIs
 *
 * Components:
 * - @ref SocketHTTPClient_T: Core client instance managing pool and
 * configuration
 * - @ref SocketHTTPClient_Config: Detailed runtime configuration options
 * - @ref SocketHTTPClient_Request_T: Builder pattern for custom requests
 * (sync/async)
 * - @ref SocketHTTPClient_AsyncRequest_T: Handle for monitoring/canceling
 * async operations
 * - @ref SocketHTTPClient_Response: Structured access to response data and
 * metadata
 * - @ref SocketHTTPClient_CookieJar_T: Secure cookie storage, loading, and
 * saving
 * - @ref SocketHTTPClient_Auth: Configuration for authentication credentials
 * - @ref SocketHTTPClient_Error: Enumerated errors with retryability
 * classification
 * - @ref SocketHTTPClient_PoolStats: Connection pool performance metrics
 *
 * Dependencies and Integration:
 * - @ref http "HTTP Protocol Modules" for parsing, serialization, and HPACK
 * - @ref connection_mgmt "Connection Management" for advanced pooling and
 * reconnection
 * - @ref security "Security Modules" for TLS, certificate verification, and
 * SYN protection
 * - @ref async_io "Async I/O" and @ref event_system "Event System" for
 * non-blocking workflows
 * - @ref core_io::dns "DNS Resolution" for efficient hostname lookup
 * - @ref utilities "Utilities" for rate limiting, retry policies, and metrics
 * - @ref foundation "Foundation" for arena allocation and exception handling
 *
 * Security Considerations:
 * - Strict certificate validation and hostname matching (configurable bypass
 * for testing)
 * - Protection against memory exhaustion via response size limits and header
 * validation
 * - Secure handling of sensitive data (cleartext credentials warning;
 * recommend secure storage)
 * - Enforcement of cookie security flags (Secure, HttpOnly, SameSite)
 * - Rejection of malformed responses to mitigate injection and smuggling
 * attacks
 * - Configurable limits on redirects, retries, and connection counts to
 * prevent abuse
 *
 * Thread Safety:
 * - Client instances are NOT thread-safe; design for one instance per thread
 * or use mutexes
 * - Pure functions (e.g., config_defaults, error_is_retryable) are thread-safe
 * - Cookie jar is thread-safe with internal locking
 *
 * Platform Support:
 * - POSIX-compliant (Linux, BSD, macOS)
 * - Requires pthread for internal threading (DNS workers, timers)
 * - Optional TLS via CMake -DENABLE_TLS=ON (OpenSSL or LibreSSL)
 * - Poll backends auto-detected (epoll/kqueue/poll)
 *
 * Examples:
 * @include examples/http_get.c
 * @include examples/http_post.c
 * @include examples/http2_client.c
 *
 * Documentation:
 * @see docs/HTTP_CLIENT_GUIDE.md for tutorials and patterns
 * @see docs/SECURITY_GUIDE.md for authentication and TLS best practices
 * @see @ref http_client_cookie "Cookie Configuration Constants"
 * @see @ref http_client_encoding "Content Encoding Configuration"
 *
 * @{
 */

/**
 * @file SocketHTTPClient.h
 * @ingroup http_client http_client
 * @brief Public API for the HTTP client module, including types, functions,
 * and configuration.
 *
 * This header defines the high-level interface for HTTP requests and
 * responses. See module brief for features and @ref http_client "group
 * documentation" for details.
 *
 * Provides a robust HTTP client supporting HTTP/1.1 and HTTP/2 with advanced
 * features:
 * - @ref connection_mgmt "Connection pooling" with per-host limits and idle
 * timeouts
 * - Automatic protocol negotiation via ALPN (h2 preferred)
 * - RFC 6265 cookie handling with SameSite support
 * - Multiple authentication schemes: Basic (RFC 7617), Digest (RFC 7616),
 * Bearer (RFC 6750)
 * - Compression support: Accept gzip/deflate/brotli with auto-decompression
 * - Configurable redirect following with loop detection
 * - Synchronous and asynchronous APIs with event integration
 * - Integration with @ref security "TLS" for HTTPS (OpenSSL/LibreSSL)
 * - Proxy support via @ref core_io "SocketProxy"
 *
 * Underlying dependencies:
 * - @ref http "SocketHTTP" / SocketHTTP1 / SocketHTTP2 for protocol handling
 * - @ref async_io "SocketHappyEyeballs" for IPv6-preferred connections
 * - @ref core_io::dns "SocketDNS" for async resolution
 * - @ref foundation "Arena" for memory management
 *
 * Thread safety: Instances are NOT thread-safe. Use one per thread or
 * synchronize externally.
 *
 * Platform: POSIX (Linux/BSD/macOS), requires pthread. TLS optional via CMake
 * -DENABLE_TLS=ON.
 *
 * Example usage:
 * @include examples/http_get.c
 *
 * @see @ref http_client "HTTP Client Module" for full API reference.
 * @see SocketHTTPClient_new() for instantiation.
 * @see SocketHTTPClient_get() / SocketHTTPClient_get_async() for requests.
 * @see docs/HTTP_GUIDE.md for detailed usage and best practices.
 * @see docs/SECURITY_GUIDE.md for auth/TLS configuration.
 */

#ifndef SOCKETHTTPCLIENT_INCLUDED
#define SOCKETHTTPCLIENT_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient-config.h"

/* Forward declarations for optional TLS */
#if SOCKET_HAS_TLS
#include "tls/SocketTLSContext.h"
#else
typedef struct SocketTLSContext_T *SocketTLSContext_T;
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 * All configuration constants are defined in SocketHTTPClient-config.h.
 * This includes:
 *   - HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST (6)
 *   - HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS (100)
 *   - HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS (30000)
 *   - HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS (60000)
 *   - HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS (10000)
 *   - HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS (60000)
 *   - HTTPCLIENT_DEFAULT_MAX_REDIRECTS (10)
 *   - HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE (0)
 *   - HTTPCLIENT_DEFAULT_USER_AGENT
 *   - HTTPCLIENT_POOL_HASH_SIZE (127)
 *   - HTTPCLIENT_ENCODING_* flags
 * All constants support compile-time override via #ifndef guards.
 * ============================================================================
 */

/* ============================================================================
 * Exception Types
 * ============================================================================
 *
 * RETRYABILITY GUIDE:
 * - RETRYABLE exceptions indicate transient failures that may succeed on retry
 * - NON-RETRYABLE exceptions indicate permanent failures or configuration
 * errors
 * - Use SocketHTTPClient_error_is_retryable() to check programmatically
 */

/**
 * @brief General client failure
 * @ingroup http_client
 *
 * Category: Varies
 * Retryable: Depends on underlying cause - check errno
 *
 * Raised for unclassified errors. Check Socket_geterrno() for details.
 */
extern const Except_T SocketHTTPClient_Failed;

/**
 * @brief DNS resolution failure
 * @ingroup http_client
 *
 * Category: NETWORK
 * Retryable: YES - DNS servers may recover, cache may refresh
 *
 * Raised when hostname cannot be resolved. May be transient
 * (DNS server overloaded) or permanent (invalid hostname).
 */
extern const Except_T SocketHTTPClient_DNSFailed;

/**
 * @brief TCP connection failure
 * @ingroup http_client
 *
 * Category: NETWORK
 * Retryable: YES - Server may restart, network may recover
 *
 * Raised when TCP connect() fails. Common causes:
 * - ECONNREFUSED: Server not listening (may start later)
 * - ENETUNREACH: Network route unavailable (may recover)
 * - EHOSTUNREACH: Host unreachable (may become reachable)
 */
extern const Except_T SocketHTTPClient_ConnectFailed;

/**
 * @brief TLS/SSL handshake or I/O failure
 * @ingroup http_client
 *
 * Category: PROTOCOL
 * Retryable: NO - Usually indicates configuration mismatch
 *
 * Raised for TLS errors:
 * - Certificate verification failure
 * - Protocol version mismatch
 * - Cipher suite negotiation failure
 *
 * Retrying won't help unless TLS configuration is changed.
 */
extern const Except_T SocketHTTPClient_TLSFailed;

/**
 * @brief Request timeout exceeded
 * @ingroup http_client
 *
 * Category: TIMEOUT
 * Retryable: YES - Network congestion may clear
 *
 * Raised when request exceeds configured timeout. May succeed
 * on retry if server/network recovers.
 */
extern const Except_T SocketHTTPClient_Timeout;

/**
 * @brief HTTP protocol error
 * @ingroup http_client
 *
 * Category: PROTOCOL
 * Retryable: NO - Server response is malformed
 *
 * Raised when HTTP response cannot be parsed:
 * - Invalid status line
 * - Malformed headers
 * - Invalid chunked encoding
 *
 * Indicates server bug or proxy corruption.
 */
extern const Except_T SocketHTTPClient_ProtocolError;

/**
 * @brief Redirect limit exceeded
 * @ingroup http_client
 *
 * Category: APPLICATION
 * Retryable: NO - Indicates redirect loop or misconfiguration
 *
 * Raised when redirect count exceeds max_redirects config.
 * Usually indicates server misconfiguration (redirect loop).
 */
extern const Except_T SocketHTTPClient_TooManyRedirects;

/**
 * @brief Response body exceeds limit
 * @ingroup http_client
 *
 * Category: RESOURCE
 * Retryable: NO - Server response is too large
 *
 * Raised when response body exceeds max_response_size config.
 * Retry would produce same result. Increase limit or use
 * streaming API for large responses.
 */
extern const Except_T SocketHTTPClient_ResponseTooLarge;

/* ============================================================================
 * Error Codes
 * ============================================================================
 */

/**
 * @brief Error codes for HTTP client operations.
 * @ingroup http_client
 *
 * Used in asynchronous APIs and error reporting. Indicates specific failure
 * modes.
 *
 * Retryability guide:
 * - HTTPCLIENT_ERROR_DNS: YES - DNS may recover
 * - HTTPCLIENT_ERROR_CONNECT: YES - Server may restart
 * - HTTPCLIENT_ERROR_TLS: NO - Configuration issue
 * - HTTPCLIENT_ERROR_TIMEOUT: YES - Transient congestion
 * - HTTPCLIENT_ERROR_PROTOCOL: NO - Server bug
 * - HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS: NO - Redirect loop
 * - HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE: NO - Size limit
 * - HTTPCLIENT_ERROR_CANCELLED: NO - User cancelled
 * - HTTPCLIENT_ERROR_OUT_OF_MEMORY: NO - Resource exhaustion
 * - HTTPCLIENT_ERROR_LIMIT_EXCEEDED: NO - Pool limits reached
 *
 * @see SocketHTTPClient_error_is_retryable() to check programmatically.
 * @see SocketHTTPClient_error_string() for descriptions.
 */
typedef enum
{
  HTTPCLIENT_OK = 0,
  HTTPCLIENT_ERROR_DNS,
  HTTPCLIENT_ERROR_CONNECT,
  HTTPCLIENT_ERROR_TLS,
  HTTPCLIENT_ERROR_TIMEOUT,
  HTTPCLIENT_ERROR_PROTOCOL,
  HTTPCLIENT_ERROR_TOO_MANY_REDIRECTS,
  HTTPCLIENT_ERROR_RESPONSE_TOO_LARGE,
  HTTPCLIENT_ERROR_CANCELLED,
  HTTPCLIENT_ERROR_OUT_OF_MEMORY,
  HTTPCLIENT_ERROR_LIMIT_EXCEEDED
} SocketHTTPClient_Error;

/**
 * @brief Check if error code is retryable
 * @ingroup http_client
 * @param error Error code from async operation
 *
 * @return 1 if error is typically retryable, 0 if fatal
 * @threadsafe Yes (pure function)
 *
 * Use this to decide whether to retry a failed request:
 *
 * Example:
 *   SocketHTTPClient_Error err = SocketHTTPClient_Request_error(req);
 *   if (SocketHTTPClient_error_is_retryable(err))
 *     // Schedule retry with exponential backoff
 *   else
 *     // Log error and give up
 *
 * Retryable errors:
 * - DNS failures (server may recover)
 * - Connection failures (server may restart)
 * - Timeouts (network may clear)
 */
extern int SocketHTTPClient_error_is_retryable (SocketHTTPClient_Error error);

/* ============================================================================
 * Authentication Types
 * ============================================================================
 *
 * Supported authentication schemes:
 *
 * HTTP_AUTH_BASIC (RFC 7617):
 *   - Simple base64(username:password) encoding
 *   - Credentials sent with every request (no challenge-response)
 *   - Only use over HTTPS (credentials transmitted in cleartext)
 *
 * HTTP_AUTH_DIGEST (RFC 7616):
 *   - Challenge-response authentication with MD5 or SHA-256
 *   - Supports qop=auth (integrity protection of request)
 *   - Automatic 401 retry with proper response generation
 *   - Handles stale nonce refresh automatically
 *   - NOTE: qop=auth-int (body integrity) is NOT supported
 *
 * HTTP_AUTH_BEARER (RFC 6750):
 *   - OAuth 2.0 bearer token authentication
 *   - Token sent in Authorization header
 *   - Application responsible for token management/refresh
 *
 * NOT SUPPORTED:
 *   - NTLM (Microsoft proprietary, requires DES/MD4/NTLMv2)
 *   - Negotiate/SPNEGO (requires GSSAPI/Kerberos integration)
 *   - AWS Signature (v2/v4) - use dedicated AWS SDK
 *   - Hawk, HOBA, Mutual, OAuth 1.0a
 * ============================================================================
 */

/**
 * @brief Authentication scheme types supported by the HTTP client.
 * @ingroup http_client
 *
 * Supported schemes:
 * - HTTP_AUTH_BASIC: RFC 7617 - Simple base64-encoded credentials
 * - HTTP_AUTH_DIGEST: RFC 7616 - Challenge-response with MD5/SHA-256
 * - HTTP_AUTH_BEARER: RFC 6750 - OAuth 2.0 bearer tokens
 *
 * @see SocketHTTPClient_Auth for credential configuration.
 * @see SocketHTTPClient_set_auth() to set default credentials.
 */
typedef enum
{
  HTTP_AUTH_NONE = 0, /**< No authentication */
  HTTP_AUTH_BASIC,    /**< RFC 7617 - Basic Authentication */
  HTTP_AUTH_DIGEST,   /**< RFC 7616 - Digest Access Authentication */
  HTTP_AUTH_BEARER    /**< RFC 6750 - Bearer Token (OAuth 2.0) */
} SocketHTTPClient_AuthType;

/**
 * @brief Authentication credentials structure.
 * @ingroup http_client
 *
 * Configure authentication for requests using this structure.
 * Pass to SocketHTTPClient_set_auth() or SocketHTTPClient_Request_auth().
 *
 * Fields:
 * - type: Authentication scheme (Basic, Digest, Bearer)
 * - username/password: For Basic and Digest
 * - token: For Bearer authentication
 * - realm: Optional realm filter for Digest (matches server challenge)
 *
 * @note Credentials are stored in cleartext internally. Use secure storage
 * practices.
 * @note Basic auth sends credentials with every request; prefer over HTTPS
 * only.
 * @see SocketHTTPClient_AuthType for scheme details.
 * @see docs/SECURITY_GUIDE.md for best practices.
 */
typedef struct
{
  SocketHTTPClient_AuthType type;
  const char *username; /**< For Basic, Digest */
  const char *password; /**< For Basic, Digest */
  const char *token;    /**< For Bearer */
  const char *realm;    /**< Optional realm filter */
} SocketHTTPClient_Auth;

/* ============================================================================
 * Proxy Configuration (Forward declaration - implemented in Phase 8)
 * ============================================================================
 */

/**
 * @brief Proxy configuration structure (opaque).
 * @ingroup http_client
 * @see @ref connection_mgmt "Connection Management" for proxy details.
 * @see include/socket/SocketProxy.h for full proxy API.
 */
typedef struct SocketProxy_Config SocketProxy_Config;

/* ============================================================================
 * Client Configuration
 * ============================================================================
 */

/**
 * @brief HTTP client configuration structure.
 * @ingroup http_client
 *
 * Customize client behavior via this structure. Pass to
 * SocketHTTPClient_new(). Use SocketHTTPClient_config_defaults() to initialize
 * with sensible defaults.
 *
 * Key sections:
 * - Protocol: HTTP version negotiation and HTTP/2 settings
 * - Connection pooling: Reuse connections for performance
 * - Timeouts: Prevent hanging requests/connections
 * - Redirects: Automatic following with limits
 * - Compression: Accept and auto-decompress encoded responses
 * - TLS: Secure connections (requires SOCKET_HAS_TLS)
 * - Proxy: Forward requests through proxy
 * - Limits: Prevent resource exhaustion
 * - Retry: Automatic retries for transient failures (experimental)
 *
 * @see SocketHTTPClient_config_defaults() for initialization.
 * @see SocketHTTP_Version for protocol versions.
 * @see SocketTLSContext_T for TLS configuration.
 * @note Changes take effect on next SocketHTTPClient_new(). Existing clients
 * unaffected.
 * @threadsafe Yes - structure is plain data, no methods.
 */
typedef struct
{
  /* Protocol */
  SocketHTTP_Version max_version; /**< Max HTTP version (default: HTTP/2) */
  int allow_http2_cleartext;      /**< Allow h2c upgrade (default: 0) */

  /* Connection pooling */
  int enable_connection_pool;      /**< Enable pooling (default: 1) */
  size_t max_connections_per_host; /**< Per-host limit (default: 6) */
  size_t max_total_connections;    /**< Total limit (default: 100) */
  int idle_timeout_ms;             /**< Idle connection timeout */
  int max_connection_age_ms;       /**< Max connection age (0 = unlimited) */
  int acquire_timeout_ms;          /**< Timeout waiting for pool slot */

  /* Timeouts */
  int connect_timeout_ms; /**< Connection timeout */
  int request_timeout_ms; /**< Request timeout */
  int dns_timeout_ms;     /**< DNS resolution timeout */

  /* Redirects */
  int follow_redirects; /**< Max redirects (0 = disabled) */
  int redirect_on_post; /**< Follow redirects for POST (default: 0) */

  /* Compression */
  int accept_encoding; /**< Bitmask: GZIP | DEFLATE | BR */
  int auto_decompress; /**< Auto-decompress responses (default: 1) */

  /* TLS */
  SocketTLSContext_T tls_context; /**< Custom TLS context (NULL for default) */
  int verify_ssl;                 /**< Verify certificates (default: 1) */

  /* Proxy */
  SocketProxy_Config *proxy; /**< Default proxy (NULL for none) */

  /* User agent */
  const char *user_agent; /**< User-Agent header */

  /* Limits */
  size_t max_response_size; /**< Max response body (0 = unlimited) */

  /* Retry configuration (Phase 11)
   *
   * Automatic retry with exponential backoff for transient failures.
   *
   * IMPORTANT: Only enable retry_on_5xx for idempotent requests (GET, HEAD,
   * OPTIONS, PUT, DELETE). Non-idempotent requests (POST) may cause
   * duplicate side effects if retried.
   */
  int enable_retry;              /**< Enable automatic retry (default: 0) */
  int max_retries;               /**< Max retry attempts (default: 3) */
  int retry_initial_delay_ms;    /**< Initial backoff delay (default: 100ms) */
  int retry_max_delay_ms;        /**< Max backoff delay (default: 10s) */
  int retry_on_connection_error; /**< Retry on connect failures (default: 1) */
  int retry_on_timeout;          /**< Retry on timeouts (default: 1) */
  int retry_on_5xx;              /**< Retry on 5xx responses (default: 0) */

  /** Security configuration */
  int enforce_samesite; /**< Enforce SameSite attribute (default: 1) */
} SocketHTTPClient_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================
 */

/**
 * @brief HTTP client instance
 * @ingroup http_client
 */
typedef struct SocketHTTPClient *SocketHTTPClient_T;

/**
 * @brief HTTP request builder
 * @ingroup http_client
 */
typedef struct SocketHTTPClient_Request *SocketHTTPClient_Request_T;

/**
 * @brief Async request handle
 * @ingroup http_client
 */
typedef struct SocketHTTPClient_AsyncRequest *SocketHTTPClient_AsyncRequest_T;

/**
 * @brief Cookie jar
 * @ingroup http_client
 */
typedef struct SocketHTTPClient_CookieJar *SocketHTTPClient_CookieJar_T;

/* ============================================================================
 * Response Structure
 * ============================================================================
 */

/**
 * @brief HTTP response structure returned by client functions.
 * @ingroup http_client
 *
 * Contains status, headers, body, and metadata from server response.
 * Caller owns the response and must call SocketHTTPClient_Response_free()
 * to release resources (arena, headers, body).
 *
 * Fields:
 * - status_code: HTTP status (200, 404, etc.)
 * - headers: Parsed headers (SocketHTTP_Headers_T)
 * - body: Response body data (may be NULL for HEAD or empty)
 * - body_len: Length of body (0 if no body)
 * - version: Negotiated HTTP version
 * - arena: Arena used for allocation (dispose via Response_free)
 *
 * @note Body is allocated from response->arena. Do not free separately.
 * @note For large responses, consider streaming APIs to avoid memory usage.
 * @see SocketHTTPClient_get() for usage example.
 * @see SocketHTTPClient_Response_free() for cleanup.
 */
typedef struct
{
  int status_code;
  SocketHTTP_Headers_T headers;
  void *body;
  size_t body_len;
  SocketHTTP_Version version;
  Arena_T arena; /**< For cleanup - caller must dispose */
} SocketHTTPClient_Response;

/* ============================================================================
 * Client Lifecycle
 * ============================================================================
 */

/**
 * @brief Initialize SocketHTTPClient_Config structure with production-safe
 * defaults.
 * @ingroup http_client
 *
 * Populates the configuration with values optimized for secure, performant
 * HTTP client usage in production environments. This function sets up a
 * balanced configuration that prioritizes security (TLS verification, limited
 * redirects/connections), performance (HTTP/2 preference, pooling), and
 * resilience (timeouts, optional retries).
 *
 * Detailed defaults include:
 * - Protocol: Max HTTP/2 with ALPN negotiation for modern servers; falls back
 * to HTTP/1.1.
 * - Pooling: 6 connections per host (RFC 7540 recommendation), total 100 to
 * prevent resource exhaustion.
 * - Timeouts: Conservative values to avoid hanging: 30s connect, 60s request,
 * 10s DNS.
 * - Redirects: Follow up to 10 for GET/HEAD (safe methods); POST redirects
 * disabled to prevent unintended repeats.
 * - Compression: Accept all common encodings with auto-decompression to save
 * bandwidth.
 * - TLS: Strict verification; uses system default context (customizable via
 * tls_context).
 * - Retry: Disabled (safe default); enable for idempotent requests only.
 * - Limits: Unlimited response size (monitor max_response_size for memory
 * safety).
 * - Security: SameSite enforcement for cookies.
 *
 * After calling, override specific fields as needed for application
 * requirements (e.g., shorter timeouts for mobile). Invalid configs (e.g.,
 * negative timeouts) will cause SocketHTTPClient_new() to fail with
 * SocketHTTPClient_Failed.
 *
 * @param[in,out] config Pointer to SocketHTTPClient_Config structure to
 * initialize and modify.
 *
 * This function modifies the structure in place, setting all fields to
 * defaults. No allocation performed; pure data initialization.
 *
 * @threadsafe Yes - pure function with no side effects or shared state access.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketHTTPClient_Config config;
 * SocketHTTPClient_config_defaults(&config);
 *
 * // Override for custom needs
 * config.connect_timeout_ms = 5000;  // 5s for faster failure
 * config.follow_redirects = 5;       // Limit redirects
 * config.user_agent = "MyApp/1.0";   // Custom UA
 *
 * SocketHTTPClient_T client = SocketHTTPClient_new(&config);
 * if (client) {
 *     // Use client...
 *     SocketHTTPClient_free(&client);
 * }
 * @endcode
 *
 * ## Advanced Usage with TLS
 *
 * @code{.c}
 * TRY {
 *     SocketTLSContext_T tls_ctx = SocketTLSContext_new(); // Custom TLS
 *     SocketTLSContext_load_certs(tls_ctx, "ca.pem");
 *
 *     SocketHTTPClient_Config config;
 *     SocketHTTPClient_config_defaults(&config);
 *     config.tls_context = tls_ctx;
 *     config.verify_ssl = 1; // Strict verify
 *
 *     SocketHTTPClient_T client = SocketHTTPClient_new(&config);
 *     // HTTPS requests will use custom TLS
 * } EXCEPT(SocketHTTPClient_Failed) {
 *     // Handle config error
 * } END_TRY;
 * @endcode
 *
 * @note Defaults assume SOCKET_HAS_TLS=1 for HTTPS; disable via
 * config.verify_ssl=0 for testing (insecure!).
 * @warning Unlimited max_response_size can lead to memory exhaustion on large
 * responses; set limit for untrusted servers.
 * @complexity O(1) - constant time structure initialization, no loops or
 * allocations.
 *
 * @see SocketHTTPClient_new() to create client from config.
 * @see SocketHTTPClient_Config for all field descriptions and valid ranges.
 * @see docs/HTTP_CLIENT_GUIDE.md#configuration for tuning guide.
 * @see SocketTLSContext_new() for TLS customization.
 */
extern void SocketHTTPClient_config_defaults (SocketHTTPClient_Config *config);

/**
 * @brief Create new HTTP client instance.
 * @ingroup http_client
 * @param config Configuration structure (NULL uses defaults from
 * SocketHTTPClient_config_defaults())
 *
 * Initializes client with connection pool, DNS resolver, and optional TLS
 * context. Pool size, timeouts, and features configured via config.
 *
 * @return Opaque client handle or NULL on failure
 * @throws SocketHTTPClient_Failed on memory allocation failure or invalid
 * config
 * @throws Arena_Failed if underlying arena allocation fails
 * @threadsafe Yes - initialization is atomic
 *
 * @note Client must be freed with SocketHTTPClient_free() when done.
 * @note Default config enables pooling, HTTP/2, compression, and certificate
 * verification.
 * @see SocketHTTPClient_config_defaults() to populate config.
 * @see SocketHTTPClient_free() for cleanup.
 * @see SocketHTTPClient_Config for detailed options.
 */
extern SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config);

/**
 * @brief Destroy HTTP client and release all resources.
 * @ingroup http_client
 * @param client Pointer to client handle (set to NULL on success)
 *
 * Closes all pooled connections, frees internal arenas, DNS resolver, timers.
 * Any in-flight async requests are cancelled and callbacks invoked with
 * CANCELLED error. Safe to call on NULL.
 *
 * @threadsafe No - concurrent use may race with ongoing operations
 * @warning Call only when no threads are using the client.
 *
 * @see SocketHTTPClient_new() for creation.
 * @see SocketHTTPClient_pool_clear() to close connections without destroying
 * client.
 * @see SocketHTTPClient_process() to drain async before free.
 */
extern void SocketHTTPClient_free (SocketHTTPClient_T *client);

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================
 */

/**
 * @brief Perform synchronous GET request.
 * @ingroup http_client
 * @param client Client instance
 * @param url Full URL (http:// or https://). Supports http/https schemes;
 * relative URLs invalid.
 * @param response Output response structure (caller must free via
 * Response_free)
 *
 * Retrieves resource at URL. Automatically handles:
 * - DNS resolution (via SocketDNS)
 * - Connection establishment (TCP + optional TLS)
 * - Protocol negotiation (HTTP/1.1 or HTTP/2 via ALPN)
 * - Redirect following (configurable)
 * - Compression (gzip/deflate/brotli)
 * - Cookie handling (if jar configured)
 * - Authentication (if configured)
 *
 * Response body loaded fully into memory unless max_response_size limits it.
 * For streaming large responses, use custom Request API with body_stream
 * callback.
 *
 * @return 0 on success (status_code in response), -1 on error
 * @throws SocketHTTPClient_DNSFailed on hostname resolution failure
 * @throws SocketHTTPClient_ConnectFailed on TCP connection failure
 * @throws SocketHTTPClient_TLSFailed on TLS handshake/certificate issues
 * @throws SocketHTTPClient_Timeout on connect/request timeouts
 * @throws SocketHTTPClient_ProtocolError on malformed server response
 * @throws SocketHTTPClient_TooManyRedirects on redirect loops
 * @throws SocketHTTPClient_ResponseTooLarge if body exceeds limit
 * @throws SocketHTTPClient_Failed for other errors (check errno)
 * @threadsafe No - client not thread-safe
 *
 * @see SocketHTTPClient_head() for header-only request.
 * @see SocketHTTPClient_post() for requests with body.
 * @see SocketHTTPClient_get_async() for non-blocking version.
 * @see SocketHTTPClient_Config for customization (timeouts, pooling, etc.).
 * @see @ref core_io "Core I/O" for underlying socket operations.
 * @see @ref security "Security" for TLS details.
 */
extern int SocketHTTPClient_get (SocketHTTPClient_T client, const char *url,
                                 SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous HEAD request.
 * @ingroup http_client
 * @param client Client instance
 * @param url Full URL (http:// or https://)
 * @param response Output response (caller must free via Response_free)
 *
 * Sends HEAD request to retrieve headers only (no body).
 * Useful for checking resource existence, size, or modification time without
 * downloading body.
 *
 * @return 0 on success, -1 on error
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 * SocketHTTPClient_TLSFailed, SocketHTTPClient_Timeout,
 * SocketHTTPClient_ProtocolError, etc.
 * @threadsafe No
 *
 * @see SocketHTTPClient_get() for full GET request with body.
 * @see SocketHTTP_Method for other methods.
 * @see SocketHTTPClient_Response_free() for cleanup.
 */
extern int SocketHTTPClient_head (SocketHTTPClient_T client, const char *url,
                                  SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous POST request.
 * @ingroup http_client
 * @param client Client instance
 * @param url Full URL (http:// or https://)
 * @param content_type Content-Type header (e.g., "application/json")
 * @param body Request body data (may be NULL for empty)
 * @param body_len Length of body data
 * @param response Output response (caller must free via Response_free)
 *
 * Sends POST request with provided body. Automatically sets Content-Length
 * header. Supports connection pooling, redirects, compression, and
 * authentication.
 *
 * @return 0 on success, -1 on error
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 * SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError,
 * SocketHTTPClient_ResponseTooLarge, etc.
 * @threadsafe No
 * @note Non-idempotent: Retries may cause duplicate submissions if enabled.
 *
 * @see SocketHTTPClient_Request_new() for custom headers/body.
 * @see SocketHTTPClient_put() for PUT requests.
 * @see SocketHTTPClient_post_async() for asynchronous version.
 */
extern int SocketHTTPClient_post (SocketHTTPClient_T client, const char *url,
                                  const char *content_type, const void *body,
                                  size_t body_len,
                                  SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous PUT request.
 * @ingroup http_client
 * @param client Client instance
 * @param url Full URL (http:// or https://)
 * @param content_type Content-Type header (e.g., "application/json")
 * @param body Request body data (may be NULL for empty)
 * @param body_len Length of body data
 * @param response Output response (caller must free via Response_free)
 *
 * Sends PUT request to update/replace resource with provided body.
 * Idempotent operation; safe for retries.
 *
 * @return 0 on success, -1 on error
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 * SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError, etc.
 * @threadsafe No
 *
 * @see SocketHTTPClient_post() for creating new resources.
 * @see SocketHTTPClient_Request_new() for custom configuration.
 */
extern int SocketHTTPClient_put (SocketHTTPClient_T client, const char *url,
                                 const char *content_type, const void *body,
                                 size_t body_len,
                                 SocketHTTPClient_Response *response);

/**
 * @brief Perform synchronous DELETE request.
 * @ingroup http_client
 * @param client Client instance
 * @param url Full URL (http:// or https://)
 * @param response Output response (caller must free via Response_free)
 *
 * Sends DELETE request to remove resource at URL.
 * Idempotent; multiple calls have same effect.
 * Body is optional but rarely used.
 *
 * @return 0 on success, -1 on error
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 * SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError, etc.
 * @threadsafe No
 *
 * @see SocketHTTPClient_put() for resource updates.
 * @see SocketHTTPClient_get() for retrieval.
 */
extern int SocketHTTPClient_delete (SocketHTTPClient_T client, const char *url,
                                    SocketHTTPClient_Response *response);

/**
 * @brief Free response resources
 * @ingroup http_client
 * @param response Response to free
 *
 * @threadsafe No
 */
extern void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response);

/* ============================================================================
 * Custom Request API
 * ============================================================================
 */

/**
 * @brief Create request builder
 * @ingroup http_client
 * @param client Client instance
 * @param method HTTP method
 * @param url Full URL
 *
 * @return Request builder
 * @threadsafe No
 */
extern SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client,
                              SocketHTTP_Method method, const char *url);

/**
 * @brief Free request builder and release resources.
 * @ingroup http_client
 * @param req Pointer to request handle (set to NULL on success)
 *
 * Cleans up SocketHTTPClient_Request_T instance created by
 * SocketHTTPClient_Request_new(). Releases any temporary allocations (headers,
 * body buffers). Safe to call on NULL.
 *
 * @threadsafe No
 * @see SocketHTTPClient_Request_new() for creation.
 */
extern void SocketHTTPClient_Request_free (SocketHTTPClient_Request_T *req);

/**
 * @brief Add header
 * @ingroup http_client
 * @param req Request
 * @param name Header name
 * @param value Header value
 *
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                            const char *name,
                                            const char *value);

/**
 * @brief Set request body
 * @ingroup http_client
 * @param req Request
 * @param data Body data
 * @param len Data length
 *
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                                          const void *data, size_t len);

/**
 * @brief Set streaming body
 * @ingroup http_client
 * @param req Request
 * @param read_cb Callback to read body data
 * @param userdata User data for callback
 *
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body_stream (
    SocketHTTPClient_Request_T req,
    ssize_t (*read_cb) (void *buf, size_t len, void *userdata),
    void *userdata);

/**
 * @brief Set per-request timeout
 * @ingroup http_client
 * @param req Request
 * @param ms Timeout in milliseconds
 */
extern void SocketHTTPClient_Request_timeout (SocketHTTPClient_Request_T req,
                                              int ms);

/**
 * @brief Set per-request authentication
 * @ingroup http_client
 * @param req Request
 * @param auth Authentication credentials
 */
extern void SocketHTTPClient_Request_auth (SocketHTTPClient_Request_T req,
                                           const SocketHTTPClient_Auth *auth);

/**
 * @brief Execute request
 * @ingroup http_client
 * @param req Request
 * @param response Output response
 *
 * @return 0 on success, -1 on error
 * @threadsafe No
 */
extern int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response);

/* ============================================================================
 * Asynchronous API
 * ============================================================================
 */

/**
 * Async completion callback
 */
typedef void (*SocketHTTPClient_Callback) (SocketHTTPClient_AsyncRequest_T req,
                                           SocketHTTPClient_Response *response,
                                           SocketHTTPClient_Error error,
                                           void *userdata);

/**
 * @brief Start async GET
 * @ingroup http_client
 */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback,
                            void *userdata);

/**
 * @brief Start async POST
 * @ingroup http_client
 */
extern SocketHTTPClient_AsyncRequest_T SocketHTTPClient_post_async (
    SocketHTTPClient_T client, const char *url, const char *content_type,
    const void *body, size_t body_len, SocketHTTPClient_Callback callback,
    void *userdata);

/**
 * @brief Start async custom request
 * @ingroup http_client
 */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata);

/**
 * @brief Cancel async request
 * @ingroup http_client
 */
extern void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req);

/**
 * @brief Process async requests
 * @ingroup http_client
 * @param client Client
 * @param timeout_ms Poll timeout
 *
 * @return Number of completed requests
 * @threadsafe No
 *
 * Call in event loop to process pending async requests.
 */
extern int SocketHTTPClient_process (SocketHTTPClient_T client,
                                     int timeout_ms);

/* ============================================================================
 * Cookie Jar (RFC 6265)
 * ============================================================================
 */

/**
 * @brief Cookie SameSite attribute values (RFC 6265bis draft).
 * @ingroup http_client
 *
 * Controls cross-site request protection:
 * - NONE: No restrictions (requires Secure flag)
 * - LAX: Allows safe methods (GET, HEAD) on top-level navigation
 * - STRICT: Blocks all cross-site requests
 *
 * @see SocketHTTPClient_Cookie for full cookie structure.
 * @see SocketHTTPClient_CookieJar_set() for setting cookies.
 */
typedef enum
{
  COOKIE_SAMESITE_NONE = 0,
  COOKIE_SAMESITE_LAX = 1,
  COOKIE_SAMESITE_STRICT = 2
} SocketHTTPClient_SameSite;

/**
 * @brief Cookie attributes structure (RFC 6265).
 * @ingroup http_client
 *
 * Represents a single HTTP cookie with attributes for storage and
 * transmission. Used for setting cookies via CookieJar_set() or parsing from
 * Set-Cookie headers.
 *
 * Key attributes:
 * - name/value: Cookie name-value pair
 * - domain/path: Scope for matching requests
 * - expires: Expiration time (0 = session cookie)
 * - secure: Transmit only over HTTPS
 * - http_only: Prevent JavaScript access (XSS protection)
 * - same_site: Cross-site request policy
 *
 * @note Fields are const char* pointers owned by caller or arena.
 * @see SocketHTTPClient_CookieJar for management.
 * @see docs/SECURITY_GUIDE.md for SameSite and security considerations.
 */
typedef struct
{
  const char *name;
  const char *value;
  const char *domain;
  const char *path;
  time_t expires;
  int secure;
  int http_only;
  SocketHTTPClient_SameSite same_site;
} SocketHTTPClient_Cookie;

/**
 * @brief Create cookie jar
 * @ingroup http_client
 *
 * @return New cookie jar
 * @threadsafe Yes
 */
extern SocketHTTPClient_CookieJar_T SocketHTTPClient_CookieJar_new (void);

/**
 * @brief Free cookie jar and all stored cookies.
 * @ingroup http_client
 * @param jar Pointer to jar handle (set to NULL on success)
 *
 * Releases all memory associated with the cookie jar, including all cookies.
 * Safe to call on NULL. Cookies are cleared before free.
 *
 * @threadsafe Yes - internal mutex protection
 * @see SocketHTTPClient_CookieJar_new() for creation.
 * @see SocketHTTPClient_CookieJar_clear() to clear without freeing jar.
 */
extern void
SocketHTTPClient_CookieJar_free (SocketHTTPClient_CookieJar_T *jar);

/**
 * @brief Associate jar with client
 * @ingroup http_client
 * @param client Client
 * @param jar Cookie jar (NULL to remove)
 */
extern void SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                             SocketHTTPClient_CookieJar_T jar);

/**
 * @brief Get associated cookie jar
 * @ingroup http_client
 * @param client Client
 *
 * @return Cookie jar or NULL
 */
extern SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client);

/**
 * @brief Set cookie
 * @ingroup http_client
 * @param jar Cookie jar
 * @param cookie Cookie to set
 *
 * @return 0 on success, -1 on error
 */
extern int
SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                const SocketHTTPClient_Cookie *cookie);

/**
 * @brief Get cookie by name
 * @ingroup http_client
 * @param jar Cookie jar
 * @param domain Domain to match
 * @param path Path to match
 * @name  Cookie name
 *
 * @return Cookie or NULL if not found
 */
extern const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name);

/**
 * @brief Clear all cookies
 * @ingroup http_client
 * @param jar Cookie jar
 */
extern void
SocketHTTPClient_CookieJar_clear (SocketHTTPClient_CookieJar_T jar);

/**
 * @brief Clear expired cookies
 * @ingroup http_client
 * @param jar Cookie jar
 */
extern void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar);

/**
 * @brief Load cookies from file
 * @ingroup http_client
 * @param jar Cookie jar
 * @param filename File path
 *
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/**
 * @brief Save cookies to file
 * @ingroup http_client
 * @param jar Cookie jar
 * @param filename File path
 *
 * @return 0 on success, -1 on error
 */
extern int SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/* ============================================================================
 * Client Authentication
 * ============================================================================
 */

/**
 * @brief Set default authentication credentials for all requests.
 * @ingroup http_client
 * @param client Client instance
 * @param auth Authentication configuration (may be NULL to disable)
 *
 * Applies auth to all subsequent requests unless overridden by Request_auth().
 * Supports Basic, Digest, and Bearer schemes.
 *
 * @threadsafe No
 * @note Digest auth requires server challenges; may require retry on 401.
 * @see SocketHTTPClient_Auth for scheme details.
 * @see SocketHTTPClient_Request_auth() for per-request override.
 */
extern void SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                                       const SocketHTTPClient_Auth *auth);

/* ============================================================================
 * Connection Pool Management
 * ============================================================================
 */

/**
 * @brief Connection pool statistics snapshot.
 * @ingroup http_client
 *
 * Provides metrics on pool usage, efficiency, and health.
 * Retrieved via SocketHTTPClient_pool_stats().
 *
 * Metrics include:
 * - Connection counts (active/idle)
 * - Request/reuse counters for performance
 * - Failure counters for debugging
 *
 * @see SocketHTTPClient_pool_stats() to populate.
 * @see SocketHTTPClient_Config for pool configuration.
 */
typedef struct
{
  size_t active_connections;    /**< Connections currently in use */
  size_t idle_connections;      /**< Connections available for reuse */
  size_t total_requests;        /**< Total requests made */
  size_t reused_connections;    /**< Times a pooled connection was reused */
  size_t connections_created;   /**< Total connections created */
  size_t connections_failed;    /**< Connection attempts that failed */
  size_t connections_timed_out; /**< Connections that timed out waiting */
  size_t stale_connections_removed; /**< Stale/dead connections cleaned up */
  size_t pool_exhausted_waits;      /**< Times we waited for pool slot */
} SocketHTTPClient_PoolStats;

/**
 * @brief Get pool statistics
 * @ingroup http_client
 * @param client Client
 * @param stats Output statistics
 */
extern void SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                                         SocketHTTPClient_PoolStats *stats);

/**
 * @brief Close and clear all connections in the pool.
 * @ingroup http_client
 * @param client Client instance
 *
 * Immediately closes all active and idle connections in the connection pool.
 * Useful for graceful shutdown, configuration changes, or error recovery.
 * Any in-flight requests will fail with SocketHTTPClient_ConnectFailed or
 * similar.
 *
 * Does not affect ongoing requests but prevents reuse of existing connections.
 *
 * @threadsafe No
 * @note Pool will repopulate on next request as needed.
 * @see SocketHTTPClient_pool_stats() to inspect pool before clearing.
 * @see SocketHTTPClient_new() for pool recreation.
 */
extern void SocketHTTPClient_pool_clear (SocketHTTPClient_T client);

/* ============================================================================
 * Error Handling
 * ============================================================================
 */

/**
 * @brief Get last error code
 * @ingroup http_client
 * @param client Client
 *
 * @return Error code
 */
extern SocketHTTPClient_Error
SocketHTTPClient_last_error (SocketHTTPClient_T client);

/**
 * @brief Get error description
 * @ingroup http_client
 * @param error Error code
 *
 * @return Static string
 * @threadsafe Yes
 */
extern const char *
SocketHTTPClient_error_string (SocketHTTPClient_Error error);

/* ============================================================================
 * Convenience Functions
 * ============================================================================
 */

/**
 * @brief Download URL content to a file
 * @ingroup http_client
 * @param[in] client HTTP client instance
 * @param[in] url URL to download from
 * @param[in] filepath Path to destination file
 *
 * Downloads the response body to the specified file. Uses streaming to
 * efficiently handle large files without loading entire content into memory.
 * Creates the file if it doesn't exist, overwrites if it does.
 *
 * @return 0 on success, -1 on HTTP error, -2 on file error
 *
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 *         SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * SocketHTTPClient_T client = SocketHTTPClient_new(NULL);
 * int ret = SocketHTTPClient_download(client, "https://example.com/file.zip",
 *                                     "/tmp/file.zip");
 * if (ret == 0) {
 *     printf("Download complete\n");
 * } else if (ret == -1) {
 *     printf("HTTP error: %s\n",
 *            SocketHTTPClient_error_string(SocketHTTPClient_last_error(client)));
 * } else {
 *     printf("File error: %s\n", strerror(errno));
 * }
 * SocketHTTPClient_free(&client);
 * @endcode
 *
 * @see SocketHTTPClient_upload() for uploading files
 * @see SocketHTTPClient_get() for in-memory downloads
 */
extern int SocketHTTPClient_download (SocketHTTPClient_T client, const char *url,
                                      const char *filepath);

/**
 * @brief Upload a file to URL
 * @ingroup http_client
 * @param[in] client HTTP client instance
 * @param[in] url URL to upload to
 * @param[in] filepath Path to source file
 *
 * Uploads the specified file using PUT request with streaming. The Content-Type
 * is set to application/octet-stream unless overridden. Efficiently handles
 * large files without loading entire content into memory.
 *
 * @return HTTP status code on success (2xx), -1 on HTTP error, -2 on file error
 *
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 *         SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * int status = SocketHTTPClient_upload(client,
 *     "https://storage.example.com/files/myfile.dat",
 *     "/path/to/local/file.dat");
 * if (status >= 200 && status < 300) {
 *     printf("Upload successful (HTTP %d)\n", status);
 * }
 * @endcode
 *
 * @see SocketHTTPClient_download() for downloading files
 * @see SocketHTTPClient_post() for custom uploads
 */
extern int SocketHTTPClient_upload (SocketHTTPClient_T client, const char *url,
                                    const char *filepath);

/**
 * @brief GET request with JSON response parsing
 * @ingroup http_client
 * @param[in] client HTTP client instance
 * @param[in] url URL to fetch
 * @param[out] json_out Output: JSON string (caller must free)
 * @param[out] json_len Output: JSON string length
 *
 * Performs GET request with Accept: application/json header. Validates
 * that response Content-Type is application/json. Returns the raw JSON
 * string which can be parsed by your preferred JSON library.
 *
 * @return HTTP status code on success, -1 on HTTP error, -2 on content-type
 * mismatch
 *
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 *         SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * char *json = NULL;
 * size_t len;
 * int status = SocketHTTPClient_json_get(client,
 *     "https://api.example.com/data", &json, &len);
 * if (status == 200 && json) {
 *     // Parse with your JSON library (cJSON, json-c, etc.)
 *     printf("Got JSON (%zu bytes): %.100s...\n", len, json);
 *     free(json);
 * }
 * @endcode
 *
 * @note Caller must free(json_out) on success
 * @see SocketHTTPClient_json_post() for POST with JSON
 */
extern int SocketHTTPClient_json_get (SocketHTTPClient_T client, const char *url,
                                      char **json_out, size_t *json_len);

/**
 * @brief POST JSON and receive JSON response
 * @ingroup http_client
 * @param[in] client HTTP client instance
 * @param[in] url URL to POST to
 * @param[in] json_body JSON string to send
 * @param[out] json_out Output: JSON response (caller must free, may be NULL)
 * @param[out] json_len Output: JSON response length
 *
 * Performs POST request with Content-Type: application/json and
 * Accept: application/json. Validates response content type if body returned.
 *
 * @return HTTP status code on success, -1 on HTTP error, -2 on content-type
 * mismatch
 *
 * @throws SocketHTTPClient_DNSFailed, SocketHTTPClient_ConnectFailed,
 *         SocketHTTPClient_Timeout, SocketHTTPClient_ProtocolError
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * const char *request = "{\"name\": \"test\", \"value\": 42}";
 * char *response = NULL;
 * size_t len;
 * int status = SocketHTTPClient_json_post(client,
 *     "https://api.example.com/create", request, &response, &len);
 * if (status == 201 && response) {
 *     printf("Created: %s\n", response);
 *     free(response);
 * }
 * @endcode
 *
 * @note Caller must free(json_out) on success
 * @see SocketHTTPClient_json_get() for GET with JSON
 */
extern int SocketHTTPClient_json_post (SocketHTTPClient_T client,
                                       const char *url, const char *json_body,
                                       char **json_out, size_t *json_len);

/** @} */

#endif /* SOCKETHTTPCLIENT_INCLUDED */
