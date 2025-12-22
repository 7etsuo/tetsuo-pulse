/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPClient-config.h
 * @brief Configuration constants for HTTP client with compile-time override.
 * @ingroup http_client
 *
 * Centralized configuration for HTTP client module.
 * All constants can be overridden at compile time with -D flags
 * or at runtime via SocketHTTPClient_Config fields.
 *
 * @see SocketHTTPClient_config_defaults() for runtime defaults.
 * @see SocketHTTPClient_Config for full structure.
 */

#ifndef SOCKETHTTPCLIENT_CONFIG_INCLUDED
#define SOCKETHTTPCLIENT_CONFIG_INCLUDED

/* ============================================================================
 * Error Buffer Configuration
 * ============================================================================
 */

/** @brief Size of error message buffer for SocketHTTPClient_error_format(). */
#ifndef HTTPCLIENT_ERROR_BUFSIZE
#define HTTPCLIENT_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Connection Pool Configuration
 * ============================================================================
 */

/** @brief Initial hash table size for connection pool (prime for distribution). */
#ifndef HTTPCLIENT_POOL_HASH_SIZE
#define HTTPCLIENT_POOL_HASH_SIZE 127
#endif

/** @brief Larger hash table size when pool exceeds LARGE_THRESHOLD connections. */
#ifndef HTTPCLIENT_POOL_LARGE_HASH_SIZE
#define HTTPCLIENT_POOL_LARGE_HASH_SIZE 251
#endif

/** @brief Connection count triggering resize to larger hash table. */
#ifndef HTTPCLIENT_POOL_LARGE_THRESHOLD
#define HTTPCLIENT_POOL_LARGE_THRESHOLD 100
#endif

/** @brief I/O buffer size per pooled connection. */
#ifndef HTTPCLIENT_IO_BUFFER_SIZE
#define HTTPCLIENT_IO_BUFFER_SIZE 8192
#endif

/* ============================================================================
 * Default Timeouts (milliseconds)
 * ============================================================================
 */

/** @brief Connection establishment timeout (TCP + TLS + proxy). */
#ifndef HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS 30000
#endif

/** @brief Full request completion timeout (DNS + connect + send + receive). */
#ifndef HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS 60000
#endif

/** @brief DNS resolution timeout. */
#ifndef HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS 10000
#endif

/** @brief Idle timeout for pooled connections before cleanup. */
#ifndef HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS 60000
#endif

/* ============================================================================
 * Connection Limits
 * ============================================================================
 */

/** @brief Maximum redirect hops (raises SocketHTTPClient_TooManyRedirects). */
#ifndef HTTPCLIENT_DEFAULT_MAX_REDIRECTS
#define HTTPCLIENT_DEFAULT_MAX_REDIRECTS 10
#endif

/** @brief Maximum concurrent connections per host. */
#ifndef HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST
#define HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST 6
#endif

/** @brief Total maximum connections across all hosts. */
#ifndef HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS
#define HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS 100
#endif

/** @brief Maximum authentication retries on 401 responses. */
#ifndef HTTPCLIENT_MAX_AUTH_RETRIES
#define HTTPCLIENT_MAX_AUTH_RETRIES 2
#endif

/* ============================================================================
 * Retry Configuration
 * ============================================================================
 */

/** @brief Enable automatic retry on transient failures (0=disabled). */
#ifndef HTTPCLIENT_DEFAULT_ENABLE_RETRY
#define HTTPCLIENT_DEFAULT_ENABLE_RETRY 0
#endif

/** @brief Maximum retry attempts for retryable errors. */
#ifndef HTTPCLIENT_DEFAULT_MAX_RETRIES
#define HTTPCLIENT_DEFAULT_MAX_RETRIES 3
#endif

/** @brief Initial backoff delay before first retry (ms). */
#ifndef HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS 100
#endif

/** @brief Maximum backoff delay cap (ms). */
#ifndef HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS 10000
#endif

/** @brief Retry on connection errors (ECONNREFUSED, ETIMEDOUT). */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT
#define HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT 1
#endif

/** @brief Retry on request timeouts. */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT
#define HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT 1
#endif

/**
 * @brief Retry on 5xx server errors (0=disabled).
 * @warning Only enable for idempotent requests (GET, HEAD, PUT, DELETE).
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_5XX
#define HTTPCLIENT_DEFAULT_RETRY_ON_5XX 0
#endif

/** @brief Exponential backoff multiplier (delay doubles each attempt). */
#ifndef HTTPCLIENT_RETRY_MULTIPLIER
#define HTTPCLIENT_RETRY_MULTIPLIER 2.0
#endif

/** @brief Jitter factor to prevent thundering herd (+/-25% variation). */
#ifndef HTTPCLIENT_RETRY_JITTER_FACTOR
#define HTTPCLIENT_RETRY_JITTER_FACTOR 0.25
#endif

/** @brief Minimum delay on invalid retry input (ms). */
#ifndef HTTPCLIENT_MIN_DELAY_MS
#define HTTPCLIENT_MIN_DELAY_MS 1
#endif

/* ============================================================================
 * Cookie Configuration
 * ============================================================================
 */

/** @brief Enforce SameSite cookie attribute for CSRF protection. */
#ifndef HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE
#define HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE 1
#endif

/** @brief Maximum cookies in a single jar (DoS protection). */
#ifndef HTTPCLIENT_MAX_COOKIES
#define HTTPCLIENT_MAX_COOKIES 10000
#endif

/** @brief Hash table size for cookie jar (prime for distribution). */
#ifndef HTTPCLIENT_COOKIE_HASH_SIZE
#define HTTPCLIENT_COOKIE_HASH_SIZE 127
#endif

/** @brief Maximum cookie name length. */
#ifndef HTTPCLIENT_COOKIE_MAX_NAME_LEN
#define HTTPCLIENT_COOKIE_MAX_NAME_LEN 256
#endif

/** @brief Maximum cookie value length. */
#ifndef HTTPCLIENT_COOKIE_MAX_VALUE_LEN
#define HTTPCLIENT_COOKIE_MAX_VALUE_LEN 4096
#endif

/** @brief Maximum cookie domain attribute length. */
#ifndef HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN 256
#endif

/** @brief Maximum cookie path attribute length. */
#ifndef HTTPCLIENT_COOKIE_MAX_PATH_LEN
#define HTTPCLIENT_COOKIE_MAX_PATH_LEN 1024
#endif

/** @brief Line buffer size for Netscape cookie file parsing. */
#ifndef HTTPCLIENT_COOKIE_FILE_LINE_SIZE
#define HTTPCLIENT_COOKIE_FILE_LINE_SIZE 4096
#endif

/** @brief Buffer for parsing Max-Age attribute. */
#ifndef HTTPCLIENT_COOKIE_MAX_AGE_SIZE
#define HTTPCLIENT_COOKIE_MAX_AGE_SIZE 32
#endif

/** @brief Buffer for parsing SameSite attribute. */
#ifndef HTTPCLIENT_COOKIE_SAMESITE_SIZE
#define HTTPCLIENT_COOKIE_SAMESITE_SIZE 16
#endif

/** @brief Maximum cookie lifetime (10 years). */
#ifndef HTTPCLIENT_MAX_COOKIE_AGE_SEC
#define HTTPCLIENT_MAX_COOKIE_AGE_SEC (365LL * 24 * 3600 * 10)
#endif

/** @brief Maximum hash chain length before eviction (DoS protection). */
#ifndef HTTPCLIENT_COOKIE_MAX_CHAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_CHAIN_LEN 100
#endif

/* ============================================================================
 * Response Limits
 * ============================================================================
 */

/**
 * @brief Default maximum response body size (10MB).
 * Set to 0 in config for unlimited. Raises SocketHTTPClient_ResponseTooLarge.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE
#define HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE (10ULL * 1024 * 1024)
#endif

/* ============================================================================
 * Authentication Buffers
 * ============================================================================
 */

/** @brief Buffer for Basic auth credentials (username:password). */
#ifndef HTTPCLIENT_AUTH_CREDENTIALS_SIZE
#define HTTPCLIENT_AUTH_CREDENTIALS_SIZE 512
#endif

/** @brief Buffer for Digest auth A1/A2 intermediate hashes. */
#ifndef HTTPCLIENT_DIGEST_A_BUFFER_SIZE
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512
#endif

/** @brief Buffer for Digest auth response value. */
#ifndef HTTPCLIENT_DIGEST_RESPONSE_SIZE
#define HTTPCLIENT_DIGEST_RESPONSE_SIZE 256
#endif

/** @brief Client nonce size for Digest auth (16 bytes = 128 bits entropy). */
#ifndef HTTPCLIENT_DIGEST_CNONCE_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16
#endif

/** @brief Hex-encoded cnonce buffer (32 hex chars + null). */
#ifndef HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE 33
#endif

/** @brief Buffer for nonce-count hex string (8 hex digits). */
#ifndef HTTPCLIENT_DIGEST_NC_SIZE
#define HTTPCLIENT_DIGEST_NC_SIZE 16
#endif

/* ============================================================================
 * Request/Response Buffers
 * ============================================================================
 */

/** @brief Buffer for serializing request line and headers. */
#ifndef HTTPCLIENT_REQUEST_BUFFER_SIZE
#define HTTPCLIENT_REQUEST_BUFFER_SIZE 8192
#endif

/** @brief Chunk size for incremental response body reads. */
#ifndef HTTPCLIENT_BODY_CHUNK_SIZE
#define HTTPCLIENT_BODY_CHUNK_SIZE 4096
#endif

/** @brief Initial HTTP/2 response body buffer (grows dynamically). */
#ifndef HTTPCLIENT_H2_BODY_INITIAL_CAPACITY
#define HTTPCLIENT_H2_BODY_INITIAL_CAPACITY (64 * 1024)
#endif

/** @brief Buffer for Host header construction. */
#ifndef HTTPCLIENT_HOST_HEADER_SIZE
#define HTTPCLIENT_HOST_HEADER_SIZE 256
#endif

/** @brief Buffer for Cookie header serialization. */
#ifndef HTTPCLIENT_COOKIE_HEADER_SIZE
#define HTTPCLIENT_COOKIE_HEADER_SIZE 4096
#endif

/** @brief Standard Authorization header buffer. */
#ifndef HTTPCLIENT_AUTH_HEADER_SIZE
#define HTTPCLIENT_AUTH_HEADER_SIZE 512
#endif

/** @brief Extended Authorization buffer for complex Digest params. */
#ifndef HTTPCLIENT_AUTH_HEADER_LARGE_SIZE
#define HTTPCLIENT_AUTH_HEADER_LARGE_SIZE 1024
#endif

/** @brief Buffer for URI in Digest auth calculations. */
#ifndef HTTPCLIENT_URI_BUFFER_SIZE
#define HTTPCLIENT_URI_BUFFER_SIZE 512
#endif

/** @brief Maximum Set-Cookie headers processed per response. */
#ifndef HTTPCLIENT_MAX_SET_COOKIES
#define HTTPCLIENT_MAX_SET_COOKIES 16
#endif

/** @brief Buffer for Accept-Encoding header construction. */
#ifndef HTTPCLIENT_ACCEPT_ENCODING_SIZE
#define HTTPCLIENT_ACCEPT_ENCODING_SIZE 64
#endif

/** @brief Buffer for Content-Length header value. */
#ifndef HTTPCLIENT_CONTENT_LENGTH_SIZE
#define HTTPCLIENT_CONTENT_LENGTH_SIZE 32
#endif

/* ============================================================================
 * Default User-Agent
 * ============================================================================
 */

/** @brief Default User-Agent header (override via config.user_agent). */
#ifndef HTTPCLIENT_DEFAULT_USER_AGENT
#define HTTPCLIENT_DEFAULT_USER_AGENT "SocketHTTPClient/1.0"
#endif

/* ============================================================================
 * Content-Encoding Flags
 * ============================================================================
 */

/** @brief Identity (no compression) encoding. */
#define HTTPCLIENT_ENCODING_IDENTITY 0x00

/** @brief GZIP compression (RFC 9110). */
#define HTTPCLIENT_ENCODING_GZIP 0x01

/** @brief DEFLATE compression (RFC 9110). */
#define HTTPCLIENT_ENCODING_DEFLATE 0x02

/** @brief Brotli compression (RFC 7932). */
#define HTTPCLIENT_ENCODING_BR 0x04

#endif /* SOCKETHTTPCLIENT_CONFIG_INCLUDED */
