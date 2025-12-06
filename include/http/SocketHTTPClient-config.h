/**
 * SocketHTTPClient-config.h - HTTP Client Configuration Constants
 *
 * Part of the Socket Library
 *
 * Centralized configuration for HTTP client module.
 * All magic numbers are defined here with compile-time override support.
 *
 * CONFIGURABLE LIMITS SUMMARY
 *
 * All limits can be overridden at compile time with -D flags or at runtime
 * via SocketHTTPClient_Config fields.
 *
 * RESOURCE LIMITS:
 *   HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE - 0 (unlimited) - Max response body
 *   HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST - 6 - Per-host connection limit
 *   HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS - 100 - Total connection limit
 *   HTTPCLIENT_DEFAULT_MAX_REDIRECTS - 10 - Max redirect hops
 *   HTTPCLIENT_MAX_AUTH_RETRIES - 2 - Max auth retry attempts
 *
 * TIMEOUT LIMITS:
 *   HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS - 30s - Connection timeout
 *   HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS - 60s - Full request timeout
 *   HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS - 10s - DNS resolution timeout
 *   HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS - 60s - Idle connection timeout
 *
 * ENFORCEMENT:
 *   - max_response_size: Checked during body accumulation (raises exception)
 *   - max_conns_per_host: Enforced by connection pool
 *   - max_redirects: Checked before each redirect (raises TooManyRedirects)
 *
 * METRICS:
 *   - SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED incremented on size violation
 *
 * Constants are grouped by category:
 * - Error buffers
 * - Connection pool
 * - Timeouts
 * - Connection limits
 * - Cookie configuration
 * - Authentication buffers
 * - Request/Response limits
 */

#ifndef SOCKETHTTPCLIENT_CONFIG_INCLUDED
#define SOCKETHTTPCLIENT_CONFIG_INCLUDED

/* ============================================================================
 * Error Buffer Configuration
 * ============================================================================ */

/** Error message buffer size (bytes) */
#ifndef HTTPCLIENT_ERROR_BUFSIZE
#define HTTPCLIENT_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Connection Pool Configuration
 * ============================================================================ */

/** Default hash table size for connection pool (prime for better distribution) */
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
 * ============================================================================ */

/** Default connection timeout */
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
 * ============================================================================ */

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

/** Enable automatic retry (default: disabled for backward compatibility) */
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

/**
 * Default maximum response body size (0 = unlimited)
 *
 * ENFORCEMENT: Checked during body accumulation in receive_http1_response().
 * Raises SocketHTTPClient_ResponseTooLarge exception when exceeded.
 * Increments SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED metric.
 *
 * Recommendation: Set to non-zero value in production to prevent memory
 * exhaustion attacks (e.g., 10MB for typical API responses).
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE
#define HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE 0
#endif

/* ============================================================================
 * Cookie Configuration
 * ============================================================================ */

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

/* ============================================================================
 * Authentication Buffer Sizes
 *
 * These are internal buffer sizes for authentication header generation.
 * They are sized to handle typical use cases with some margin.
 * ============================================================================ */

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
 * ============================================================================ */

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

/* ============================================================================
 * Default User-Agent
 * ============================================================================ */

/** Default User-Agent string */
#ifndef HTTPCLIENT_DEFAULT_USER_AGENT
#define HTTPCLIENT_DEFAULT_USER_AGENT "SocketHTTPClient/1.0"
#endif

/* ============================================================================
 * Encoding Constants (Content-Encoding support flags)
 * ============================================================================ */

#define HTTPCLIENT_ENCODING_IDENTITY 0x00
#define HTTPCLIENT_ENCODING_GZIP     0x01
#define HTTPCLIENT_ENCODING_DEFLATE  0x02
#define HTTPCLIENT_ENCODING_BR       0x04

#endif /* SOCKETHTTPCLIENT_CONFIG_INCLUDED */

