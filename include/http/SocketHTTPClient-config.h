/**
 * @file SocketHTTPClient-config.h
 * @brief Configuration constants for HTTP client with compile-time override support.
 * @ingroup http
 *
 * Centralized configuration for HTTP client module.
 * All magic numbers are defined here with compile-time override support.
 *
 * Configurable Limits Summary:
 *
 * All limits can be overridden at compile time with -D flags or at runtime
 * via SocketHTTPClient_Config fields.
 *
 * Resource Limits:
 * - HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE: 10MB - Max response body size (0=unlimited via config)
 * - HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST: 6 - Per-host connection limit
 * - HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS: 100 - Total connection limit
 * - HTTPCLIENT_DEFAULT_MAX_REDIRECTS: 10 - Max redirect hops
 * - HTTPCLIENT_MAX_AUTH_RETRIES: 2 - Max auth retry attempts
 *
 * Timeout Limits:
 * - HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS: 30s - Connection establishment timeout
 * - HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS: 60s - Full request completion timeout
 * - HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS: 10s - DNS resolution timeout
 * - HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS: 60s - Idle connection timeout
 *
 * Enforcement:
 * - max_response_size: Checked during body accumulation (raises SocketHTTPClient_ResponseTooLarge)
 * - max_conns_per_host: Enforced by connection pool
 * - max_redirects: Checked before each redirect (raises SocketHTTPClient_TooManyRedirects)
 *
 * Metrics:
 * - SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED incremented on size violation
 *
 * Constants grouped by category:
 * - Error buffers
 * - Connection pool
 * - Timeouts
 * - Connection limits
 * - Retry configuration
 * - Cookie configuration
 * - Authentication buffers
 * - Request/Response limits
 * - Encoding flags
 *
 * @see SocketHTTPClient_config_defaults() for runtime defaults.
 * @see SocketHTTPClient_Config for full structure.
 * @see @ref http "HTTP Module" for related components.
 */

#ifndef SOCKETHTTPCLIENT_CONFIG_INCLUDED
#define SOCKETHTTPCLIENT_CONFIG_INCLUDED

/* ============================================================================
 * Error Buffer Configuration
 * ============================================================================
 */

/**
 * @brief Size of internal buffer for formatting HTTP client error messages.
 * @ingroup http
 * Used in SocketHTTPClient_error_format() and related functions to prevent buffer overflows.
 * @see SocketHTTPClient_Error
 */
#ifndef HTTPCLIENT_ERROR_BUFSIZE
#define HTTPCLIENT_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Connection Pool Configuration
 * ============================================================================
 */

/**
 * @brief Default initial hash table size for HTTP client connection pool.
 * @ingroup http
 * Prime number 127 chosen for good distribution with low load factor.
 * Automatically resizes to larger table when exceeding HTTPCLIENT_POOL_LARGE_THRESHOLD connections.
 * @see HTTPCLIENT_POOL_LARGE_HASH_SIZE
 * @see SocketHTTPClient_pool_init()
 */
#ifndef HTTPCLIENT_POOL_HASH_SIZE
#define HTTPCLIENT_POOL_HASH_SIZE 127
#endif

/** Larger hash table size for pools with >100 connections */
#ifndef HTTPCLIENT_POOL_LARGE_HASH_SIZE
#define HTTPCLIENT_POOL_LARGE_HASH_SIZE 251
#endif

/** Threshold for switching to larger hash table */
#ifndef HTTPCLIENT_POOL_LARGE_THRESHOLD
#define HTTPCLIENT_POOL_LARGE_THRESHOLD 100
#endif

/** I/O buffer size for pooled connections (bytes) */
#ifndef HTTPCLIENT_IO_BUFFER_SIZE
#define HTTPCLIENT_IO_BUFFER_SIZE 8192
#endif

/* ============================================================================
 * Default Timeouts (milliseconds)
 * ============================================================================
 */

/**
 * @brief Default timeout for establishing new connections (30 seconds).
 * @ingroup http
 * Applies to TCP connect, TLS handshake, and proxy connections.
 * Override via SocketHTTPClient_Config.connect_timeout_ms or per-request.
 * @see Socket_connect()
 * @see SocketTLS_handshake()
 * @see SocketHTTPClient_Request_timeout()
 */
#ifndef HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS 30000
#endif

/** Default request timeout */
#ifndef HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS 60000
#endif

/** Default DNS resolution timeout */
#ifndef HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS 10000
#endif

/** Default idle connection timeout */
#ifndef HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS 60000
#endif

/* ============================================================================
 * Connection Limits
 * ============================================================================
 */

/** Maximum redirects to follow (prevents infinite redirect loops) */
#ifndef HTTPCLIENT_DEFAULT_MAX_REDIRECTS
#define HTTPCLIENT_DEFAULT_MAX_REDIRECTS 10
#endif

/** Per-host connection limit (matches browser defaults) */
#ifndef HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST
#define HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST 6
#endif

/** Total connection limit across all hosts */
#ifndef HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS
#define HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS 100
#endif

/** Maximum authentication retries (prevents loops on bad credentials) */
#ifndef HTTPCLIENT_MAX_AUTH_RETRIES
#define HTTPCLIENT_MAX_AUTH_RETRIES 2
#endif

/* ============================================================================
 * Retry Configuration
 * ============================================================================
 *
 * Automatic retry for transient failures (DNS, connect, timeout).
 * Uses exponential backoff with jitter to prevent thundering herd.
 *
 * SAFETY: Only idempotent requests should enable retry_on_5xx.
 * Non-idempotent requests (POST/PUT/DELETE) may cause duplicate actions.
 */

/**
 * @brief Flag to enable automatic retry logic for transient failures.
 * @ingroup http
 * Default: 0 (disabled) for backward compatibility.
 * When enabled, client retries on connect errors, timeouts, and optionally 5xx responses.
 * @see HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT
 * @see SocketHTTPClient_Config::enable_retry
 */
#ifndef HTTPCLIENT_DEFAULT_ENABLE_RETRY
#define HTTPCLIENT_DEFAULT_ENABLE_RETRY 0
#endif

/** Maximum retry attempts (default: 3) */
#ifndef HTTPCLIENT_DEFAULT_MAX_RETRIES
#define HTTPCLIENT_DEFAULT_MAX_RETRIES 3
#endif

/** Initial backoff delay in milliseconds (default: 100ms) */
#ifndef HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS 100
#endif

/** Maximum backoff delay in milliseconds (default: 10s) */
#ifndef HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS 10000
#endif

/** Retry on connection errors (ECONNREFUSED, ENETUNREACH, etc.) */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT
#define HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT 1
#endif

/** Retry on request timeout */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT
#define HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT 1
#endif

/** Retry on 5xx server errors (use only for idempotent requests!) */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_5XX
#define HTTPCLIENT_DEFAULT_RETRY_ON_5XX 0
#endif

/** Enforce SameSite attribute for cookie matching (default: 1) */
#ifndef HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE
#define HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE 1
#endif

/** Maximum number of cookies per jar (default: 10000) */
#ifndef HTTPCLIENT_MAX_COOKIES
#define HTTPCLIENT_MAX_COOKIES 10000
#endif

/**
 * @brief Default maximum size for HTTP response bodies (10MB).
 * @ingroup http
 * @details 0 in SocketHTTPClient_Config allows unlimited, but compile-time default is 10MB to mitigate DoS.
 *
 * ENFORCEMENT: During response body accumulation in HTTP/1.1 parsing.
 * If exceeded, raises SocketHTTPClient_ResponseTooLarge exception.
 * Increments SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED metric for monitoring.
 *
 * Recommendation: Keep non-zero in production; adjust based on expected payload sizes
 * (e.g., 1MB for APIs, larger for file downloads).
 * Override at runtime via SocketHTTPClient_Config.max_response_size.
 *
 * @see SocketHTTPClient_ResponseTooLarge
 * @see SocketHTTPClient_Config::max_response_size
 * @see SocketMetrics for counter details.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE
#define HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE                                  \
  (10ULL * 1024 * 1024) /* 10MB default to prevent DoS */
#endif

/**
 * @defgroup http_client_cookie Cookie Configuration Constants
 * @brief Limits and buffer sizes for HTTP client cookie handling and jar management.
 * @ingroup http
 *
 * Controls cookie parsing, storage, and serialization for compliance with RFC 6265.
 * Includes hash table sizing, string limits, and DoS protections.
 *
 * @see SocketHTTPClient_CookieJar_T
 * @see SocketHTTPClient_set_cookie_jar()
 * @{

 */

/** Cookie jar hash table size (prime for better distribution) */
#ifndef HTTPCLIENT_COOKIE_HASH_SIZE
#define HTTPCLIENT_COOKIE_HASH_SIZE 127
#endif

/** Maximum cookie name length (bytes) */
#ifndef HTTPCLIENT_COOKIE_MAX_NAME_LEN
#define HTTPCLIENT_COOKIE_MAX_NAME_LEN 256
#endif

/** Maximum cookie value length (bytes) */
#ifndef HTTPCLIENT_COOKIE_MAX_VALUE_LEN
#define HTTPCLIENT_COOKIE_MAX_VALUE_LEN 4096
#endif

/** Maximum cookie domain length (bytes) */
#ifndef HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN 256
#endif

/** Maximum cookie path length (bytes) */
#ifndef HTTPCLIENT_COOKIE_MAX_PATH_LEN
#define HTTPCLIENT_COOKIE_MAX_PATH_LEN 1024
#endif

/** Cookie file line buffer size (Netscape format parsing) */
#ifndef HTTPCLIENT_COOKIE_FILE_LINE_SIZE
#define HTTPCLIENT_COOKIE_FILE_LINE_SIZE 4096
#endif

/** Maximum Max-Age attribute string length */
#ifndef HTTPCLIENT_COOKIE_MAX_AGE_SIZE
#define HTTPCLIENT_COOKIE_MAX_AGE_SIZE 32
#endif

/** Maximum SameSite attribute value length ("Strict" = 6 + NUL) */
#ifndef HTTPCLIENT_COOKIE_SAMESITE_SIZE
#define HTTPCLIENT_COOKIE_SAMESITE_SIZE 16
#endif

/** Maximum cookie age in seconds (10 years) */
#ifndef HTTPCLIENT_MAX_COOKIE_AGE_SEC
#define HTTPCLIENT_MAX_COOKIE_AGE_SEC (365LL * 24 * 3600 * 10)
#endif

/**
 * @brief Maximum allowed length of hash chains in cookie jar hash table.
 * @ingroup http
 * Exceeding this triggers eviction of oldest cookies to prevent DoS via hash collision attacks.
 * Balances performance and security.
 * @see http_client_cookie
 * @see SocketHTTPClient_CookieJar_add() for insertion logic.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_CHAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_CHAIN_LEN 100
#endif

/** @} */ /* end of http_client_cookie group */

/* ============================================================================
 * Authentication Buffer Sizes
 *
 * These are internal buffer sizes for authentication header generation.
 * They are sized to handle typical use cases with some margin.
 * ============================================================================
 */

/** Credentials buffer size (username:password before base64) */
#ifndef HTTPCLIENT_AUTH_CREDENTIALS_SIZE
#define HTTPCLIENT_AUTH_CREDENTIALS_SIZE 512
#endif

/** Maximum Digest auth A1/A2 buffer size */
#ifndef HTTPCLIENT_DIGEST_A_BUFFER_SIZE
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512
#endif

/** Maximum Digest auth response buffer size */
#ifndef HTTPCLIENT_DIGEST_RESPONSE_SIZE
#define HTTPCLIENT_DIGEST_RESPONSE_SIZE 256
#endif

/** Digest auth cnonce size (bytes of random data) */
#ifndef HTTPCLIENT_DIGEST_CNONCE_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16
#endif

/** Digest auth cnonce hex string size (2 chars per byte + null) */
#ifndef HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE 33
#endif

/** Nonce count buffer size (e.g., "00000001") */
#ifndef HTTPCLIENT_DIGEST_NC_SIZE
#define HTTPCLIENT_DIGEST_NC_SIZE 16
#endif

/* ============================================================================
 * Request/Response Buffer Limits
 * ============================================================================
 */

/** Request line/header serialization buffer size */
#ifndef HTTPCLIENT_REQUEST_BUFFER_SIZE
#define HTTPCLIENT_REQUEST_BUFFER_SIZE 8192
#endif

/** Response body read chunk size */
#ifndef HTTPCLIENT_BODY_CHUNK_SIZE
#define HTTPCLIENT_BODY_CHUNK_SIZE 4096
#endif

/** Host header buffer size */
#ifndef HTTPCLIENT_HOST_HEADER_SIZE
#define HTTPCLIENT_HOST_HEADER_SIZE 256
#endif

/** Cookie header buffer size (for outgoing requests) */
#ifndef HTTPCLIENT_COOKIE_HEADER_SIZE
#define HTTPCLIENT_COOKIE_HEADER_SIZE 4096
#endif

/** Authorization header buffer size (Basic/Digest/Bearer) */
#ifndef HTTPCLIENT_AUTH_HEADER_SIZE
#define HTTPCLIENT_AUTH_HEADER_SIZE 512
#endif

/** Large authorization header size (for Digest with long params) */
#ifndef HTTPCLIENT_AUTH_HEADER_LARGE_SIZE
#define HTTPCLIENT_AUTH_HEADER_LARGE_SIZE 1024
#endif

/** URI string buffer size for Digest auth */
#ifndef HTTPCLIENT_URI_BUFFER_SIZE
#define HTTPCLIENT_URI_BUFFER_SIZE 512
#endif

/** Maximum number of Set-Cookie headers to process per response */
#ifndef HTTPCLIENT_MAX_SET_COOKIES
#define HTTPCLIENT_MAX_SET_COOKIES 16
#endif

/** Accept-Encoding header buffer size */
#ifndef HTTPCLIENT_ACCEPT_ENCODING_SIZE
#define HTTPCLIENT_ACCEPT_ENCODING_SIZE 64
#endif

/** Content-Length header buffer size */
#ifndef HTTPCLIENT_CONTENT_LENGTH_SIZE
#define HTTPCLIENT_CONTENT_LENGTH_SIZE 32
#endif

/** Retry jitter factor (0.0 to 1.0, applied as +/- percentage) */
#ifndef HTTPCLIENT_RETRY_JITTER_FACTOR
#define HTTPCLIENT_RETRY_JITTER_FACTOR 0.25
#define HTTPCLIENT_RETRY_MULTIPLIER 2.0
#endif

/* ============================================================================
 * Default User-Agent
 * ============================================================================
 */

/** Default User-Agent string */
#ifndef HTTPCLIENT_DEFAULT_USER_AGENT
#define HTTPCLIENT_DEFAULT_USER_AGENT "SocketHTTPClient/1.0"
#endif

/**
 * @defgroup http_client_encoding Content-Encoding Flags
 * @brief Bit flags indicating supported Content-Encoding methods for HTTP client.
 * @ingroup http
 *
 * These flags are combined (bitwise OR) in SocketHTTPClient_Config.accept_encoding
 * to specify which encoding methods the client supports in Accept-Encoding header
 * and can decompress in responses.
 *
 * Default: GZIP | DEFLATE (Brotli optional for smaller payloads).
 *
 * @see SocketHTTPClient_Config::accept_encoding
 * @see SocketHTTPClient_config_defaults()
 * @{
 */

/**
 * @brief Identity (no compression) encoding flag.
 * @ingroup http
 * @details Bit value 0x00. Represents uncompressed data transfer.
 * Used as base flag or when no encoding is applied.
 * @see http_client_encoding
 */
#define HTTPCLIENT_ENCODING_IDENTITY 0x00
/**
 * @brief GZIP compression encoding flag.
 * @ingroup http
 * @details Bit value 0x01. Supports gzip compression (RFC 9110, formerly RFC 7230).
 * Advertises "gzip" in Accept-Encoding header. Client must decompress gzip-encoded responses.
 * @see http_client_encoding
 * @see SocketHTTPClient.c for header construction and decompression logic.
 */
#define HTTPCLIENT_ENCODING_GZIP 0x01
/**
 * @brief DEFLATE compression encoding flag.
 * @ingroup http
 * @details Bit value 0x02. Supports deflate compression (RFC 9110).
 * Advertises "deflate" in Accept-Encoding. Note: zlib wrapper often used; raw deflate deprecated.
 * Client handles decompression for responses with this encoding.
 * @see http_client_encoding
 * @see SocketHTTPClient.c line ~918 for Accept-Encoding handling.
 */
#define HTTPCLIENT_ENCODING_DEFLATE 0x02
/**
 * @brief Brotli compression encoding flag.
 * @ingroup http
 * @details Bit value 0x04. Supports Brotli compression (RFC 7932).
 * Advertises "br" in Accept-Encoding header. Modern, efficient for text; requires Brotli library support.
 * Client decompresses br-encoded responses if enabled.
 * @see http_client_encoding
 * @note Brotli support may require additional dependencies or conditional compilation.
 */
#define HTTPCLIENT_ENCODING_BR 0x04

/** @} */  /* end of http_client_encoding group */

#endif /* SOCKETHTTPCLIENT_CONFIG_INCLUDED */
