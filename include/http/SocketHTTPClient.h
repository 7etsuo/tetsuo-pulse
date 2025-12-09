/**
 * @defgroup http HTTP Modules
 * @brief Complete HTTP/1.1 and HTTP/2 protocol implementation with client and server support.
 *
 * The HTTP group provides comprehensive HTTP protocol support including
 * parsing, serialization, client/server implementations, and advanced features.
 * Key components include:
 * - SocketHTTP (core): HTTP types, headers, URI parsing, status codes
 * - SocketHTTP1 (http1): HTTP/1.1 parsing and serialization
 * - SocketHTTP2 (http2): HTTP/2 protocol implementation
 * - SocketHTTPClient (client): High-level HTTP client with pooling
 * - SocketHTTPServer (server): HTTP server implementation
 * - SocketHPACK (hpack): HTTP/2 header compression
 *
 * @see foundation for base infrastructure.
 * @see core_io for socket primitives.
 * @see security for TLS integration.
 * @see SocketHTTPClient_T for HTTP client usage.
 * @see SocketHTTPServer_T for HTTP server implementation.
 * @{
 */

/**
 * @file SocketHTTPClient.h
 * @ingroup http
 * @brief High-level HTTP client with connection pooling and protocol negotiation.
 *
 * High-level HTTP client abstracting HTTP/1.1 and HTTP/2 with:
 * - Connection pooling with per-host limits
 * - Automatic protocol negotiation (ALPN for HTTP/2)
 * - Cookie handling (RFC 6265)
 * - Authentication (Basic/Digest/Bearer)
 * - Compression (gzip/deflate/brotli)
 * - Redirect following
 * - Both synchronous and asynchronous APIs
 *
 * Dependencies (leveraged, not duplicated):
 * - SocketHTTP for headers, URI, methods, status codes
 * - SocketHTTP1 for HTTP/1.1 parsing/serialization
 * - SocketHTTP2 for HTTP/2 protocol
 * - SocketHappyEyeballs for fast connection establishment
 * - SocketCrypto for authentication (base64, MD5, SHA256)
 *
 * Thread safety: Client instances are NOT thread-safe.
 * Use one client per thread or external synchronization.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - pthread for mutex synchronization
 * - OpenSSL for TLS (optional, via SOCKET_HAS_TLS)
 *
 * @see SocketHTTPClient_new() for client creation.
 * @see SocketHTTPClient_get() for synchronous requests.
 * @see SocketHTTPClient_get_async() for asynchronous requests.
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
 * ============================================================================ */

/* ============================================================================
 * Exception Types
 * ============================================================================
 *
 * RETRYABILITY GUIDE:
 * - RETRYABLE exceptions indicate transient failures that may succeed on retry
 * - NON-RETRYABLE exceptions indicate permanent failures or configuration errors
 * - Use SocketHTTPClient_error_is_retryable() to check programmatically
 */

/**
 * SocketHTTPClient_Failed - General client failure
 *
 * Category: Varies
 * Retryable: Depends on underlying cause - check errno
 *
 * Raised for unclassified errors. Check Socket_geterrno() for details.
 */
extern const Except_T SocketHTTPClient_Failed;

/**
 * SocketHTTPClient_DNSFailed - DNS resolution failure
 *
 * Category: NETWORK
 * Retryable: YES - DNS servers may recover, cache may refresh
 *
 * Raised when hostname cannot be resolved. May be transient
 * (DNS server overloaded) or permanent (invalid hostname).
 */
extern const Except_T SocketHTTPClient_DNSFailed;

/**
 * SocketHTTPClient_ConnectFailed - TCP connection failure
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
 * SocketHTTPClient_TLSFailed - TLS/SSL handshake or I/O failure
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
 * SocketHTTPClient_Timeout - Request timeout exceeded
 *
 * Category: TIMEOUT
 * Retryable: YES - Network congestion may clear
 *
 * Raised when request exceeds configured timeout. May succeed
 * on retry if server/network recovers.
 */
extern const Except_T SocketHTTPClient_Timeout;

/**
 * SocketHTTPClient_ProtocolError - HTTP protocol error
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
 * SocketHTTPClient_TooManyRedirects - Redirect limit exceeded
 *
 * Category: APPLICATION
 * Retryable: NO - Indicates redirect loop or misconfiguration
 *
 * Raised when redirect count exceeds max_redirects config.
 * Usually indicates server misconfiguration (redirect loop).
 */
extern const Except_T SocketHTTPClient_TooManyRedirects;

/**
 * SocketHTTPClient_ResponseTooLarge - Response body exceeds limit
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
 * ============================================================================ */

/**
 * Error codes for async operations
 *
 * Retryability by error code:
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
 * SocketHTTPClient_error_is_retryable - Check if error code is retryable
 * @error: Error code from async operation
 *
 * Returns: 1 if error is typically retryable, 0 if fatal
 * Thread-safe: Yes (pure function)
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
 *
 * Non-retryable errors:
 * - TLS failures (configuration issue)
 * - Protocol errors (server bug)
 * - Redirect loops (server misconfiguration)
 * - Size limits (won't change on retry)
 * - Cancellation (user initiated)
 * - Out of memory (system issue)
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
 * ============================================================================ */

/**
 * Authentication scheme types
 */
typedef enum
{
  HTTP_AUTH_NONE = 0, /**< No authentication */
  HTTP_AUTH_BASIC,    /**< RFC 7617 - Basic Authentication */
  HTTP_AUTH_DIGEST,   /**< RFC 7616 - Digest Access Authentication */
  HTTP_AUTH_BEARER    /**< RFC 6750 - Bearer Token (OAuth 2.0) */
} SocketHTTPClient_AuthType;

/**
 * Authentication credentials
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
 * ============================================================================ */

typedef struct SocketProxy_Config SocketProxy_Config;

/* ============================================================================
 * Client Configuration
 * ============================================================================ */

/**
 * HTTP client configuration
 */
typedef struct
{
  /* Protocol */
  SocketHTTP_Version max_version; /**< Max HTTP version (default: HTTP/2) */
  int allow_http2_cleartext;      /**< Allow h2c upgrade (default: 0) */

  /* Connection pooling */
  int enable_connection_pool;    /**< Enable pooling (default: 1) */
  size_t max_connections_per_host; /**< Per-host limit (default: 6) */
  size_t max_total_connections;  /**< Total limit (default: 100) */
  int idle_timeout_ms;           /**< Idle connection timeout */
  int max_connection_age_ms;     /**< Max connection age (0 = unlimited) */
  int acquire_timeout_ms;        /**< Timeout waiting for pool slot */

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
  int enforce_samesite;          /**< Enforce SameSite attribute (default: 1) */
} SocketHTTPClient_Config;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/** HTTP client instance */
typedef struct SocketHTTPClient *SocketHTTPClient_T;

/** HTTP request builder */
typedef struct SocketHTTPClient_Request *SocketHTTPClient_Request_T;

/** Async request handle */
typedef struct SocketHTTPClient_AsyncRequest *SocketHTTPClient_AsyncRequest_T;

/** Cookie jar */
typedef struct SocketHTTPClient_CookieJar *SocketHTTPClient_CookieJar_T;

/* ============================================================================
 * Response Structure
 * ============================================================================ */

/**
 * HTTP response (owned by caller)
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
 * ============================================================================ */

/**
 * SocketHTTPClient_config_defaults - Initialize config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes
 */
extern void SocketHTTPClient_config_defaults (SocketHTTPClient_Config *config);

/**
 * SocketHTTPClient_new - Create HTTP client
 * @config: Configuration (NULL for defaults)
 *
 * Returns: New client instance
 * Raises: SocketHTTPClient_Failed on allocation failure
 * Thread-safe: Yes
 */
extern SocketHTTPClient_T
SocketHTTPClient_new (const SocketHTTPClient_Config *config);

/**
 * SocketHTTPClient_free - Free client and all resources
 * @client: Pointer to client (set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHTTPClient_free (SocketHTTPClient_T *client);

/* ============================================================================
 * Simple Synchronous API
 * ============================================================================ */

/**
 * SocketHTTPClient_get - Perform GET request
 * @client: Client instance
 * @url: Full URL (http:// or https://)
 * @response: Output response (caller must free via Response_free)
 *
 * Returns: 0 on success, -1 on error
 * Raises: Various exceptions on failure
 * Thread-safe: No
 */
extern int SocketHTTPClient_get (SocketHTTPClient_T client, const char *url,
                                 SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_head - Perform HEAD request
 */
extern int SocketHTTPClient_head (SocketHTTPClient_T client, const char *url,
                                  SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_post - Perform POST request
 * @client: Client
 * @url: Full URL
 * @content_type: Content-Type header value
 * @body: Request body
 * @body_len: Body length
 * @response: Output response
 */
extern int SocketHTTPClient_post (SocketHTTPClient_T client, const char *url,
                                  const char *content_type, const void *body,
                                  size_t body_len,
                                  SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_put - Perform PUT request
 */
extern int SocketHTTPClient_put (SocketHTTPClient_T client, const char *url,
                                 const char *content_type, const void *body,
                                 size_t body_len,
                                 SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_delete - Perform DELETE request
 */
extern int SocketHTTPClient_delete (SocketHTTPClient_T client, const char *url,
                                    SocketHTTPClient_Response *response);

/**
 * SocketHTTPClient_Response_free - Free response resources
 * @response: Response to free
 *
 * Thread-safe: No
 */
extern void
SocketHTTPClient_Response_free (SocketHTTPClient_Response *response);

/* ============================================================================
 * Custom Request API
 * ============================================================================ */

/**
 * SocketHTTPClient_Request_new - Create request builder
 * @client: Client instance
 * @method: HTTP method
 * @url: Full URL
 *
 * Returns: Request builder
 * Thread-safe: No
 */
extern SocketHTTPClient_Request_T
SocketHTTPClient_Request_new (SocketHTTPClient_T client, SocketHTTP_Method method,
                              const char *url);

/**
 * SocketHTTPClient_Request_free - Free request builder
 * @req: Pointer to request (set to NULL)
 */
extern void SocketHTTPClient_Request_free (SocketHTTPClient_Request_T *req);

/**
 * SocketHTTPClient_Request_header - Add header
 * @req: Request
 * @name: Header name
 * @value: Header value
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_header (SocketHTTPClient_Request_T req,
                                            const char *name, const char *value);

/**
 * SocketHTTPClient_Request_body - Set request body
 * @req: Request
 * @data: Body data
 * @len: Data length
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body (SocketHTTPClient_Request_T req,
                                          const void *data, size_t len);

/**
 * SocketHTTPClient_Request_body_stream - Set streaming body
 * @req: Request
 * @read_cb: Callback to read body data
 * @userdata: User data for callback
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_Request_body_stream (
    SocketHTTPClient_Request_T req,
    ssize_t (*read_cb) (void *buf, size_t len, void *userdata), void *userdata);

/**
 * SocketHTTPClient_Request_timeout - Set per-request timeout
 * @req: Request
 * @ms: Timeout in milliseconds
 */
extern void SocketHTTPClient_Request_timeout (SocketHTTPClient_Request_T req,
                                              int ms);

/**
 * SocketHTTPClient_Request_auth - Set per-request authentication
 * @req: Request
 * @auth: Authentication credentials
 */
extern void SocketHTTPClient_Request_auth (SocketHTTPClient_Request_T req,
                                           const SocketHTTPClient_Auth *auth);

/**
 * SocketHTTPClient_Request_execute - Execute request
 * @req: Request
 * @response: Output response
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: No
 */
extern int
SocketHTTPClient_Request_execute (SocketHTTPClient_Request_T req,
                                  SocketHTTPClient_Response *response);

/* ============================================================================
 * Asynchronous API
 * ============================================================================ */

/**
 * Async completion callback
 */
typedef void (*SocketHTTPClient_Callback) (SocketHTTPClient_AsyncRequest_T req,
                                           SocketHTTPClient_Response *response,
                                           SocketHTTPClient_Error error,
                                           void *userdata);

/**
 * SocketHTTPClient_get_async - Start async GET
 */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_get_async (SocketHTTPClient_T client, const char *url,
                            SocketHTTPClient_Callback callback, void *userdata);

/**
 * SocketHTTPClient_post_async - Start async POST
 */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_post_async (SocketHTTPClient_T client, const char *url,
                             const char *content_type, const void *body,
                             size_t body_len, SocketHTTPClient_Callback callback,
                             void *userdata);

/**
 * SocketHTTPClient_Request_async - Start async custom request
 */
extern SocketHTTPClient_AsyncRequest_T
SocketHTTPClient_Request_async (SocketHTTPClient_Request_T req,
                                SocketHTTPClient_Callback callback,
                                void *userdata);

/**
 * SocketHTTPClient_AsyncRequest_cancel - Cancel async request
 */
extern void
SocketHTTPClient_AsyncRequest_cancel (SocketHTTPClient_AsyncRequest_T req);

/**
 * SocketHTTPClient_process - Process async requests
 * @client: Client
 * @timeout_ms: Poll timeout
 *
 * Returns: Number of completed requests
 * Thread-safe: No
 *
 * Call in event loop to process pending async requests.
 */
extern int SocketHTTPClient_process (SocketHTTPClient_T client, int timeout_ms);

/* ============================================================================
 * Cookie Jar (RFC 6265)
 * ============================================================================ */

/**
 * Cookie SameSite attribute values
 */
typedef enum
{
  COOKIE_SAMESITE_NONE = 0,
  COOKIE_SAMESITE_LAX = 1,
  COOKIE_SAMESITE_STRICT = 2
} SocketHTTPClient_SameSite;

/**
 * Cookie attributes
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
 * SocketHTTPClient_CookieJar_new - Create cookie jar
 *
 * Returns: New cookie jar
 * Thread-safe: Yes
 */
extern SocketHTTPClient_CookieJar_T SocketHTTPClient_CookieJar_new (void);

/**
 * SocketHTTPClient_CookieJar_free - Free cookie jar
 * @jar: Pointer to jar (set to NULL)
 */
extern void
SocketHTTPClient_CookieJar_free (SocketHTTPClient_CookieJar_T *jar);

/**
 * SocketHTTPClient_set_cookie_jar - Associate jar with client
 * @client: Client
 * @jar: Cookie jar (NULL to remove)
 */
extern void SocketHTTPClient_set_cookie_jar (SocketHTTPClient_T client,
                                             SocketHTTPClient_CookieJar_T jar);

/**
 * SocketHTTPClient_get_cookie_jar - Get associated cookie jar
 * @client: Client
 *
 * Returns: Cookie jar or NULL
 */
extern SocketHTTPClient_CookieJar_T
SocketHTTPClient_get_cookie_jar (SocketHTTPClient_T client);

/**
 * SocketHTTPClient_CookieJar_set - Set cookie
 * @jar: Cookie jar
 * @cookie: Cookie to set
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_CookieJar_set (SocketHTTPClient_CookieJar_T jar,
                                           const SocketHTTPClient_Cookie *cookie);

/**
 * SocketHTTPClient_CookieJar_get - Get cookie by name
 * @jar: Cookie jar
 * @domain: Domain to match
 * @path: Path to match
 * @name: Cookie name
 *
 * Returns: Cookie or NULL if not found
 */
extern const SocketHTTPClient_Cookie *
SocketHTTPClient_CookieJar_get (SocketHTTPClient_CookieJar_T jar,
                                const char *domain, const char *path,
                                const char *name);

/**
 * SocketHTTPClient_CookieJar_clear - Clear all cookies
 * @jar: Cookie jar
 */
extern void SocketHTTPClient_CookieJar_clear (SocketHTTPClient_CookieJar_T jar);

/**
 * SocketHTTPClient_CookieJar_clear_expired - Clear expired cookies
 * @jar: Cookie jar
 */
extern void
SocketHTTPClient_CookieJar_clear_expired (SocketHTTPClient_CookieJar_T jar);

/**
 * SocketHTTPClient_CookieJar_load - Load cookies from file
 * @jar: Cookie jar
 * @filename: File path
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_CookieJar_load (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/**
 * SocketHTTPClient_CookieJar_save - Save cookies to file
 * @jar: Cookie jar
 * @filename: File path
 *
 * Returns: 0 on success, -1 on error
 */
extern int SocketHTTPClient_CookieJar_save (SocketHTTPClient_CookieJar_T jar,
                                            const char *filename);

/* ============================================================================
 * Client Authentication
 * ============================================================================ */

/**
 * SocketHTTPClient_set_auth - Set default authentication
 * @client: Client
 * @auth: Authentication credentials
 */
extern void SocketHTTPClient_set_auth (SocketHTTPClient_T client,
                                       const SocketHTTPClient_Auth *auth);

/* ============================================================================
 * Connection Pool Management
 * ============================================================================ */

/**
 * Pool statistics
 */
typedef struct
{
  size_t active_connections;      /**< Connections currently in use */
  size_t idle_connections;        /**< Connections available for reuse */
  size_t total_requests;          /**< Total requests made */
  size_t reused_connections;      /**< Times a pooled connection was reused */
  size_t connections_created;     /**< Total connections created */
  size_t connections_failed;      /**< Connection attempts that failed */
  size_t connections_timed_out;   /**< Connections that timed out waiting */
  size_t stale_connections_removed; /**< Stale/dead connections cleaned up */
  size_t pool_exhausted_waits;    /**< Times we waited for pool slot */
} SocketHTTPClient_PoolStats;

/**
 * SocketHTTPClient_pool_stats - Get pool statistics
 * @client: Client
 * @stats: Output statistics
 */
extern void SocketHTTPClient_pool_stats (SocketHTTPClient_T client,
                                         SocketHTTPClient_PoolStats *stats);

/**
 * SocketHTTPClient_pool_clear - Clear all pooled connections
 * @client: Client
 */
extern void SocketHTTPClient_pool_clear (SocketHTTPClient_T client);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * SocketHTTPClient_last_error - Get last error code
 * @client: Client
 *
 * Returns: Error code
 */
extern SocketHTTPClient_Error
SocketHTTPClient_last_error (SocketHTTPClient_T client);

/**
 * SocketHTTPClient_error_string - Get error description
 * @error: Error code
 *
 * Returns: Static string
 * Thread-safe: Yes
 */
extern const char *SocketHTTPClient_error_string (SocketHTTPClient_Error error);

/** @} */ /* end of http group */

#endif /* SOCKETHTTPCLIENT_INCLUDED */

