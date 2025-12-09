/**
 * @file SocketHTTPClient-config.h
 * @brief Configuration constants for HTTP client with compile-time override
 * support.
 * @ingroup http_client
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
 * - HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE: 10MB - Max response body size
 * (0=unlimited via config)
 * - HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST: 6 - Per-host connection limit
 * - HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS: 100 - Total connection limit
 * - HTTPCLIENT_DEFAULT_MAX_REDIRECTS: 10 - Max redirect hops
 * - HTTPCLIENT_MAX_AUTH_RETRIES: 2 - Max auth retry attempts
 *
 * Timeout Limits:
 * - HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS: 30s - Connection establishment
 * timeout
 * - HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS: 60s - Full request completion
 * timeout
 * - HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS: 10s - DNS resolution timeout
 * - HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS: 60s - Idle connection timeout
 *
 * Enforcement:
 * - max_response_size: Checked during body accumulation (raises
 * SocketHTTPClient_ResponseTooLarge)
 * - max_conns_per_host: Enforced by connection pool
 * - max_redirects: Checked before each redirect (raises
 * SocketHTTPClient_TooManyRedirects)
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
 * @ingroup http_client
 * Used in SocketHTTPClient_error_format() and related functions to prevent
 * buffer overflows.
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
 * @ingroup http_client
 * Prime number 127 chosen for good distribution with low load factor.
 * Automatically resizes to larger table when exceeding
 * HTTPCLIENT_POOL_LARGE_THRESHOLD connections.
 * @see HTTPCLIENT_POOL_LARGE_HASH_SIZE
 * @see SocketHTTPClient_pool_init()
 */
#ifndef HTTPCLIENT_POOL_HASH_SIZE
#define HTTPCLIENT_POOL_HASH_SIZE 127
#endif

/**
 * @brief Larger hash table size for HTTP client connection pools exceeding 100
 * connections.
 * @ingroup http_client
 *
 * Prime number 251 selected for optimal hash distribution under higher load
 * factors. Automatically used when pool connection count exceeds
 * HTTPCLIENT_POOL_LARGE_THRESHOLD. Helps maintain O(1) average lookup
 * performance in larger pools.
 *
 * @see HTTPCLIENT_POOL_HASH_SIZE for initial small-pool hash table.
 * @see HTTPCLIENT_POOL_LARGE_THRESHOLD for automatic resize trigger.
 * @see SocketHTTPClient_Config::max_total_connections for pool capacity
 * configuration.
 * @see SocketHTTPClient_pool_init() internal pool initialization
 * (implementation detail).
 */
#ifndef HTTPCLIENT_POOL_LARGE_HASH_SIZE
#define HTTPCLIENT_POOL_LARGE_HASH_SIZE 251
#endif

/**
 * @brief Threshold for switching to larger hash table in connection pool.
 * @ingroup http_client
 *
 * When active connection count exceeds this value, the pool resizes its
 * internal hash table from HTTPCLIENT_POOL_HASH_SIZE to
 * HTTPCLIENT_POOL_LARGE_HASH_SIZE. Prevents performance degradation due to
 * hash collisions in growing pools.
 *
 * Default 100 balances memory usage and performance for typical workloads.
 *
 * @see HTTPCLIENT_POOL_HASH_SIZE initial table size.
 * @see HTTPCLIENT_POOL_LARGE_HASH_SIZE enlarged table size.
 * @see SocketHTTPClient_Config::max_total_connections influences when resize
 * occurs.
 */
#ifndef HTTPCLIENT_POOL_LARGE_THRESHOLD
#define HTTPCLIENT_POOL_LARGE_THRESHOLD 100
#endif

/**
 * @brief I/O buffer size for pooled connections in HTTP client.
 * @ingroup http_client
 *
 * Size of read/write buffers allocated per connection in the pool.
 * 8KB (8192 bytes) chosen as efficient size for typical HTTP
 * requests/responses while minimizing memory overhead. Affects performance for
 * small vs. large payloads.
 *
 * Larger buffers reduce system call overhead for large transfers but increase
 * memory usage per connection. Adjustable at compile-time for tuning.
 *
 * @see SocketHTTPClient_Config::enable_connection_pool to enable pooling.
 * @see SocketBuf_T underlying buffer implementation in core I/O.
 * @see HTTPCLIENT_REQUEST_BUFFER_SIZE for request serialization buffer.
 */
#ifndef HTTPCLIENT_IO_BUFFER_SIZE
#define HTTPCLIENT_IO_BUFFER_SIZE 8192
#endif

/* ============================================================================
 * Default Timeouts (milliseconds)
 * ============================================================================
 */

/**
 * @brief Default timeout for establishing new connections (30 seconds).
 * @ingroup http_client
 * Applies to TCP connect, TLS handshake, and proxy connections.
 * Override via SocketHTTPClient_Config.connect_timeout_ms or per-request.
 * @see Socket_connect()
 * @see SocketTLS_handshake()
 * @see SocketHTTPClient_Request_timeout()
 */
#ifndef HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS 30000
#endif

/**
 * @brief Default timeout for full HTTP request completion (60 seconds).
 * @ingroup http_client
 *
 * Total time allowed from request start to final response receipt, including
 * DNS, connect, TLS handshake, sending request, and receiving response.
 * Exceeding this raises SocketHTTPClient_Timeout exception.
 *
 * Override via SocketHTTPClient_Config.request_timeout_ms or per-request
 * timeout. 60s suitable for most APIs; reduce for latency-sensitive
 * operations.
 *
 * @see HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT_MS for connect-only timeout.
 * @see SocketHTTPClient_Timeout exception details.
 * @see SocketHTTPClient_Config::request_timeout_ms runtime override.
 * @see SocketHTTPClient_Request_timeout() per-request override.
 */
#ifndef HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS 60000
#endif

/**
 * @brief Default timeout for DNS resolution (10 seconds).
 * @ingroup http_client
 *
 * Maximum time allowed for hostname resolution via SocketDNS.
 * Includes query submission, worker thread processing, and result retrieval.
 * Exceeding this raises SocketHTTPClient_DNSFailed or contributes to overall
 * timeout.
 *
 * 10s accommodates slow DNS servers or network latency; reduce for faster
 * failure detection. Override via SocketHTTPClient_Config.dns_timeout_ms.
 *
 * @see SocketDNS for underlying async DNS implementation.
 * @see SocketHTTPClient_DNSFailed exception on resolution failure.
 * @see SocketHTTPClient_Config::dns_timeout_ms for runtime configuration.
 * @see HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS includes this timeout.
 */
#ifndef HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_DNS_TIMEOUT_MS 10000
#endif

/**
 * @brief Default idle timeout for pooled connections (60 seconds).
 * @ingroup http_client
 *
 * Time after which idle (unused) connections in the pool are closed and
 * removed. Prevents resource leaks from stale connections and reduces server
 * load. 60s allows reuse for typical web browsing patterns while reclaiming
 * unused slots.
 *
 * Override via SocketHTTPClient_Config.idle_timeout_ms. Set to 0 to disable
 * (not recommended). Affects pool efficiency and memory usage.
 *
 * @see SocketHTTPClient_Config::enable_connection_pool must be enabled.
 * @see SocketHTTPClient_Config::max_total_connections pool limits.
 * @see SocketPool_cleanup() underlying pool maintenance.
 */
#ifndef HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS
#define HTTPCLIENT_DEFAULT_IDLE_TIMEOUT_MS 60000
#endif

/**
 * @defgroup http_client_limits Connection and Resource Limits
 * @brief Limits on redirects, connections, and retries for safety and
 * performance.
 * @ingroup http_client
 *
 * Prevents abuse, loops, and resource exhaustion. Configurable for different
 * workloads.
 *
 * @see SocketHTTPClient_Config for runtime overrides where applicable.
 * @see SocketPool for connection pooling limits.
 * @{
 *
 * ============================================================================
 * Connection Limits
 * ============================================================================
 */

/**
 * @brief Default maximum number of redirects to follow (10).
 * @ingroup http_client
 *
 * Limits automatic redirect following to prevent infinite loops or excessive
 * hops. Exceeding this raises SocketHTTPClient_TooManyRedirects exception. 10
 * allows for common redirect chains (e.g., www -> non-www -> https) with
 * margin.
 *
 * Only follows 3xx status codes (301, 302, 303, 307, 308) per RFC 7231.
 * POST redirects converted to GET unless redirect_on_post configured.
 * Override via SocketHTTPClient_Config.follow_redirects (0 to disable).
 *
 * @see SocketHTTPClient_TooManyRedirects exception on limit exceed.
 * @see SocketHTTPClient_Config::follow_redirects runtime override.
 * @see SocketHTTPClient_Config::redirect_on_post for POST handling.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_REDIRECTS
#define HTTPCLIENT_DEFAULT_MAX_REDIRECTS 10
#endif

/**
 * @brief Default maximum concurrent connections per host (6).
 * @ingroup http_client
 *
 * Limits parallel connections to a single host to prevent overwhelming servers
 * and respect typical server connection limits. Matches common browser
 * behavior (Chrome/Firefox default ~6 per domain).
 *
 * Exceeding limit blocks new requests until connections free up or timeout.
 * Helps with fair resource sharing in multi-host scenarios.
 * Override via SocketHTTPClient_Config.max_connections_per_host.
 *
 * @see HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS global limit.
 * @see SocketHTTPClient_Config::max_connections_per_host runtime override.
 * @see SocketPool for underlying connection pooling mechanics.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST
#define HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST 6
#endif

/**
 * @brief Default total maximum connections across all hosts (100).
 * @ingroup http_client
 *
 * Global limit on pooled connections regardless of host. Prevents uncontrolled
 * memory and FD growth when connecting to many different hosts.
 * 100 suitable for client applications; servers may need higher.
 *
 * When reached, new connections block or fail based on acquire_timeout_ms.
 * Influences hash table resize via HTTPCLIENT_POOL_LARGE_THRESHOLD.
 * Override via SocketHTTPClient_Config.max_total_connections.
 *
 * @see HTTPCLIENT_DEFAULT_MAX_CONNS_PER_HOST per-host sub-limit.
 * @see SocketHTTPClient_Config::max_total_connections runtime override.
 * @see HTTPCLIENT_POOL_LARGE_THRESHOLD related pool performance tuning.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS
#define HTTPCLIENT_DEFAULT_MAX_TOTAL_CONNS 100
#endif

/**
 * @brief Maximum retries for HTTP authentication challenges (2).
 * @ingroup http_client
 * @ingroup http_client_limits
 *
 * Limits automatic retries on 401 Unauthorized responses when credentials are
 * provided. Prevents infinite loops from servers repeatedly challenging
 * without accepting valid creds. 2 allows for nonce refresh in Digest auth or
 * transient server issues.
 *
 * Applies to Basic (preemptive), Digest (challenge-response), and Bearer
 * (token validation). Exceeding limit raises SocketHTTPClient_ProtocolError or
 * falls back to 401 response. Not configurable at runtime; compile-time only
 * for security.
 *
 * @see SocketHTTPClient_Auth for configuring credentials.
 * @see HTTP_AUTH_DIGEST handling of stale nonces.
 * @see SocketHTTPClient_Config no direct field; fixed limit.
 */
#ifndef HTTPCLIENT_MAX_AUTH_RETRIES
#define HTTPCLIENT_MAX_AUTH_RETRIES 2
#endif

/** @} */ /* end of http_client_limits group */

/**
 * @defgroup http_client_retry Retry Configuration Constants
 * @brief Parameters for automatic retry logic on transient failures.
 * @ingroup http_client
 *
 * Enables resilient client behavior with configurable backoff and conditions.
 * Disabled by default; exponential backoff with jitter for safety.
 * Only retry idempotent operations to avoid side effects.
 *
 * @see SocketHTTPClient_Config::enable_retry master switch.
 * @see SocketHTTPClient_error_is_retryable() error classification.
 * @{
 *
 * ============================================================================
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
 * @ingroup http_client
 * @ingroup http_client_retry
 * Default: 0 (disabled) for backward compatibility.
 * When enabled, client retries on connect errors, timeouts, and optionally 5xx
 * responses. Uses configured backoff parameters for exponential retry with
 * jitter.
 * @see HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT connection-specific flag.
 * @see SocketHTTPClient_Config::enable_retry runtime master switch.
 * @see @ref http_client_retry "Retry Configuration Constants" for details.
 */
#ifndef HTTPCLIENT_DEFAULT_ENABLE_RETRY
#define HTTPCLIENT_DEFAULT_ENABLE_RETRY 0
#endif

/**
 * @brief Default maximum number of retry attempts for transient failures (3).
 * @ingroup http_client
 *
 * Limits retries for retryable errors (connect, timeout, DNS) when
 * enable_retry is true. Prevents excessive retries on persistent failures. 3
 * attempts with exponential backoff provides good balance of resilience and
 * efficiency.
 *
 * Total attempts = 1 initial + max_retries. Does not retry non-retryable
 * errors (TLS, protocol, redirects, size limits). Override via
 * SocketHTTPClient_Config.max_retries.
 *
 * @see HTTPCLIENT_DEFAULT_ENABLE_RETRY to enable retry logic.
 * @see SocketHTTPClient_error_is_retryable() determines retry eligibility.
 * @see SocketHTTPClient_Config::max_retries runtime override.
 * @see HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS backoff configuration.
 */
#ifndef HTTPCLIENT_DEFAULT_MAX_RETRIES
#define HTTPCLIENT_DEFAULT_MAX_RETRIES 3
#endif

/**
 * @brief Default initial backoff delay for retries (100ms).
 * @ingroup http_client
 *
 * Starting delay before first retry attempt. Subsequent retries use
 * exponential backoff: delay *= HTTPCLIENT_RETRY_MULTIPLIER + jitter. Short
 * initial delay (100ms) allows quick recovery from transient issues without
 * overwhelming servers.
 *
 * Jitter (HTTPCLIENT_RETRY_JITTER_FACTOR) adds randomness to prevent
 * thundering herd. Override via
 * SocketHTTPClient_Config.retry_initial_delay_ms.
 *
 * @see HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS upper bound on backoff.
 * @see HTTPCLIENT_RETRY_MULTIPLIER backoff factor (2.0).
 * @see HTTPCLIENT_RETRY_JITTER_FACTOR randomization (0.25).
 * @see SocketHTTPClient_Config::retry_initial_delay_ms runtime override.
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS 100
#endif

/**
 * @brief Default maximum backoff delay between retries (10 seconds).
 * @ingroup http_client
 *
 * Caps exponential backoff to prevent excessively long waits on repeated
 * failures. After reaching this, further retries use this fixed delay (no
 * further increase). 10s prevents client from hanging indefinitely while
 * allowing recovery time.
 *
 * Combined with initial delay and multiplier, provides graceful degradation.
 * Override via SocketHTTPClient_Config.retry_max_delay_ms.
 *
 * @see HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS starting delay.
 * @see HTTPCLIENT_RETRY_MULTIPLIER exponential factor.
 * @see SocketHTTPClient_Config::retry_max_delay_ms runtime override.
 * @see SocketHTTPClient_error_is_retryable() for retry conditions.
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS
#define HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS 10000
#endif

/**
 * @brief Default flag to retry on connection establishment errors (1 =
 * enabled).
 * @ingroup http_client
 *
 * When enabled (and overall retry enabled), retries on TCP connect failures
 * like ECONNREFUSED (server down), ENETUNREACH (network issue), ETIMEDOUT.
 * Common transient errors where server/network may recover quickly.
 *
 * Does not retry permanent errors (e.g., invalid address). Uses backoff logic.
 * Override via SocketHTTPClient_Config.retry_on_connection_error.
 *
 * @see SocketHTTPClient_ConnectFailed underlying exception.
 * @see SocketError_is_retryable_errno() for errno classification.
 * @see SocketHTTPClient_Config::retry_on_connection_error runtime flag.
 * @see HTTPCLIENT_DEFAULT_ENABLE_RETRY master retry switch.
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT
#define HTTPCLIENT_DEFAULT_RETRY_ON_CONNECT 1
#endif

/**
 * @brief Default flag to retry on request timeouts (1 = enabled).
 * @ingroup http_client
 *
 * When enabled (with overall retry), retries requests that exceed
 * request_timeout_ms. Timeouts often transient due to network congestion, slow
 * servers, or temporary load. Uses backoff to avoid immediate re-failure.
 *
 * Caution: May amplify load on struggling servers. Monitor metrics for retry
 * loops. Override via SocketHTTPClient_Config.retry_on_timeout.
 *
 * @see SocketHTTPClient_Timeout exception triggered by timeout.
 * @see HTTPCLIENT_DEFAULT_REQUEST_TIMEOUT_MS configurable timeout.
 * @see SocketHTTPClient_Config::retry_on_timeout runtime flag.
 * @see HTTPCLIENT_DEFAULT_ENABLE_RETRY required for any retries.
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT
#define HTTPCLIENT_DEFAULT_RETRY_ON_TIMEOUT 1
#endif

/**
 * @brief Default flag to retry on 5xx server errors (0 = disabled).
 * @ingroup http_client
 * @ingroup http_client_retry
 *
 * When enabled (with overall retry), retries requests receiving 5xx status
 * codes (500 Internal Server Error, 503 Service Unavailable, etc.) indicating
 * server-side issues. Disabled by default due to risk of duplicate side
 * effects on non-idempotent methods (POST).
 *
 * Only recommended for safe methods: GET, HEAD, OPTIONS, PUT, DELETE.
 * Servers may recover from temporary overload or bugs.
 * Override via SocketHTTPClient_Config.retry_on_5xx.
 *
 * @warning Enabling for POST/PATCH may cause unintended duplicate actions.
 * @see SocketHTTP_status_category() for 5xx classification.
 * @see SocketHTTPClient_Config::retry_on_5xx runtime flag.
 * @see HTTPCLIENT_DEFAULT_ENABLE_RETRY prerequisite.
 * @see docs/SECURITY_GUIDE.md idempotency considerations.
 */
#ifndef HTTPCLIENT_DEFAULT_RETRY_ON_5XX
#define HTTPCLIENT_DEFAULT_RETRY_ON_5XX 0
#endif

/** @} */ /* end of http_client_retry group */

/**
 * @brief Default flag to enforce SameSite cookie attribute in matching logic
 * (1 = enabled).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * When enabled, respects SameSite=Strict/Lax/None attributes per RFC 6265bis
 * during cookie inclusion in requests. Enhances security against CSRF attacks.
 * Strict: No cross-site cookies; Lax: Safe methods on top-level; None: All
 * (requires Secure).
 *
 * Disabled allows legacy cookies but reduces security. Modern browsers enforce
 * by default. Runtime override via SocketHTTPClient_Config.enforce_samesite.
 *
 * @see SocketHTTPClient_SameSite enum values.
 * @see SocketHTTPClient_Cookie::same_site cookie attribute.
 * @see SocketHTTPClient_Config::enforce_samesite runtime flag.
 * @see docs/SECURITY_GUIDE.md for SameSite best practices and CSRF protection.
 */
#ifndef HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE
#define HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE 1
#endif

/**
 * @brief Maximum total cookies allowed in a single cookie jar (10000).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Hard limit on stored cookies to prevent DoS via cookie flooding (Set-Cookie
 * headers). Exceeding triggers eviction of oldest/least-used cookies per
 * domain. 10000 accommodates large sites with session + tracking cookies;
 * adjust lower for embedded.
 *
 * Not runtime configurable; compile-time for memory predictability.
 * Monitors via SocketHTTPClient_pool_stats() or custom metrics.
 *
 * @see SocketHTTPClient_CookieJar_T management.
 * @see HTTPCLIENT_COOKIE_MAX_CHAIN_LEN per-chain limit for hash DoS
 * protection.
 * @see SocketHTTPClient_CookieJar_set() insertion with eviction logic.
 * @see http_client_cookie group for related constants.
 */
#ifndef HTTPCLIENT_MAX_COOKIES
#define HTTPCLIENT_MAX_COOKIES 10000
#endif

/**
 * @brief Default maximum size for HTTP response bodies (10MB).
 * @ingroup http_client
 * @details 0 in SocketHTTPClient_Config allows unlimited, but compile-time
 * default is 10MB to mitigate DoS.
 *
 * ENFORCEMENT: During response body accumulation in HTTP/1.1 parsing.
 * If exceeded, raises SocketHTTPClient_ResponseTooLarge exception.
 * Increments SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED metric for monitoring.
 *
 * Recommendation: Keep non-zero in production; adjust based on expected
 * payload sizes (e.g., 1MB for APIs, larger for file downloads). Override at
 * runtime via SocketHTTPClient_Config.max_response_size.
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
 * @brief Limits and buffer sizes for HTTP client cookie handling and jar
 management.
 * @ingroup http_client
 *
 * Controls cookie parsing, storage, and serialization for compliance with RFC
 6265.
 * Includes hash table sizing, string limits, and DoS protections.
 *
 * @see SocketHTTPClient_CookieJar_T
 * @see SocketHTTPClient_set_cookie_jar()
 * @{

 */

/**
 * @brief Initial hash table size for cookie jar (prime 127 for distribution).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Size of hash table buckets for storing cookies by domain/path.
 * Prime number minimizes collisions for typical cookie counts per domain.
 * Fixed size; no dynamic resize to simplify implementation and bound memory.
 *
 * @see socket_util_hash_djb2() underlying hash function for keys.
 * @see HTTPCLIENT_COOKIE_MAX_CHAIN_LEN max chain length before eviction.
 * @see SocketHTTPClient_CookieJar_new() jar initialization.
 */
#ifndef HTTPCLIENT_COOKIE_HASH_SIZE
#define HTTPCLIENT_COOKIE_HASH_SIZE 127
#endif

/**
 * @brief Maximum allowed length for cookie names (256 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Limits cookie name strings during parsing and storage from Set-Cookie
 * headers. Exceeding truncates or rejects cookie, preventing buffer overflows
 * and DoS. 256 bytes ample for standard names; RFC 6265 recommends short
 * names.
 *
 * @see SocketHTTPClient_Cookie::name field.
 * @see HTTPCLIENT_COOKIE_MAX_VALUE_LEN for value limit.
 * @see SocketHTTP_Headers_get() header parsing integration.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_NAME_LEN
#define HTTPCLIENT_COOKIE_MAX_NAME_LEN 256
#endif

/**
 * @brief Maximum allowed length for cookie values (4096 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Limits cookie value strings to prevent memory exhaustion from
 * large/malicious cookies. Values may contain session data or tokens; 4KB
 * sufficient for most use cases. Exceeding rejects or truncates during
 * Set-Cookie parsing.
 *
 * @see SocketHTTPClient_Cookie::value field.
 * @see HTTPCLIENT_COOKIE_MAX_NAME_LEN for name limit.
 * @see RFC 6265 section 5.1.1 for value syntax (octets excluding control
 * chars).
 */
#ifndef HTTPCLIENT_COOKIE_MAX_VALUE_LEN
#define HTTPCLIENT_COOKIE_MAX_VALUE_LEN 4096
#endif

/**
 * @brief Maximum allowed length for cookie domain attributes (256 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Limits Domain= attribute in Set-Cookie for scope matching.
 * Domains typically short (e.g., example.com); 256 covers FQDNs with paths.
 * Used for exact/subdomain matching per RFC 6265.
 * Exceeding rejects cookie.
 *
 * @see SocketHTTPClient_Cookie::domain field.
 * @see SocketHTTP_URI for domain parsing from requests.
 * @see RFC 6265 section 5.2.3 domain matching rules.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_DOMAIN_LEN 256
#endif

/**
 * @brief Maximum allowed length for cookie path attributes (1024 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Limits Path= attribute in Set-Cookie for URI path matching.
 * Paths can be longer for deep hierarchies; 1KB sufficient.
 * Prefix matching used: cookie path must be prefix of request path.
 * Exceeding rejects cookie.
 *
 * @see SocketHTTPClient_Cookie::path field.
 * @see SocketHTTP_URI::path for request path extraction.
 * @see RFC 6265 section 5.2.4 path matching rules.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_PATH_LEN
#define HTTPCLIENT_COOKIE_MAX_PATH_LEN 1024
#endif

/**
 * @brief Buffer size for parsing cookie files in Netscape format (4096 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Line buffer for reading cookie files (cookies.txt format used by curl,
 * wget). Supports loading persistent cookies from disk. 4KB handles long lines
 * with many attributes or tabs.
 *
 * @see SocketHTTPClient_CookieJar load from file functionality (future).
 * @see Netscape cookie file format spec for structure.
 * @see HTTPCLIENT_COOKIE_MAX_NAME_LEN etc. for field limits.
 */
#ifndef HTTPCLIENT_COOKIE_FILE_LINE_SIZE
#define HTTPCLIENT_COOKIE_FILE_LINE_SIZE 4096
#endif

/**
 * @brief Maximum length for Max-Age attribute string parsing (32 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Buffer size for parsing Max-Age= value in Set-Cookie (seconds until expiry).
 * Supports large values up to HTTPCLIENT_MAX_COOKIE_AGE_SEC; 32 chars for
 * digits + sign. Used during attribute parsing to prevent overflow.
 *
 * @see SocketHTTPClient_Cookie::expires computed from Max-Age or Expires.
 * @see HTTPCLIENT_MAX_COOKIE_AGE_SEC absolute max age limit.
 * @see RFC 6265 section 5.2.2 Set-Cookie syntax.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_AGE_SIZE
#define HTTPCLIENT_COOKIE_MAX_AGE_SIZE 32
#endif

/**
 * @brief Maximum length for SameSite attribute value strings (16 bytes).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Buffer for parsing SameSite=[Strict|Lax|None] from Set-Cookie.
 * Values are short enums; 16 allows variants or future extensions + null
 * terminator. Case-insensitive matching per spec.
 *
 * @see SocketHTTPClient_SameSite enum mapping.
 * @see SocketHTTPClient_Cookie::same_site parsed value.
 * @see HTTPCLIENT_DEFAULT_ENFORCE_SAMESITE enforcement flag.
 * @see RFC 6265bis draft for SameSite specification.
 */
#ifndef HTTPCLIENT_COOKIE_SAMESITE_SIZE
#define HTTPCLIENT_COOKIE_SAMESITE_SIZE 16
#endif

/**
 * @brief Absolute maximum cookie lifetime in seconds (10 years).
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Hard cap on cookie expiry from Max-Age or Expires attributes to prevent
 * near-permanent cookies causing storage bloat or security issues.
 * 10 years (~315360000 seconds) far exceeds typical session/persistent needs.
 * Exceeding clamped to this value; rejects invalid negative/zero ages
 * appropriately.
 *
 * @see SocketHTTPClient_Cookie::expires absolute expiry time.
 * @see HTTPCLIENT_COOKIE_MAX_AGE_SIZE parsing buffer.
 * @see RFC 6265 section 5.3 expiry time calculation.
 * @see time_t for underlying time representation limits.
 */
#ifndef HTTPCLIENT_MAX_COOKIE_AGE_SEC
#define HTTPCLIENT_MAX_COOKIE_AGE_SEC (365LL * 24 * 3600 * 10)
#endif

/**
 * @brief Maximum allowed length of hash chains in cookie jar hash table.
 * @ingroup http_client
 * @ingroup http_client_cookie
 *
 * Exceeding this limit during insertion triggers eviction of oldest cookies
 * per bucket. Protects against hash collision DoS attacks where attacker
 * forces long chains degrading lookup to O(n). Value 100 balances security
 * (low collision risk) with memory efficiency (allows some chaining).
 *
 * Monitored during SocketHTTPClient_CookieJar_set() and related operations.
 *
 * @see @ref http_client_cookie "Cookie Configuration Constants"
 * @see SocketHTTPClient_CookieJar_set() insertion with collision handling.
 * @see HTTPCLIENT_COOKIE_HASH_SIZE table sizing impact.
 * @see socket_util_hash_djb2() hash function used for domain keys.
 */
#ifndef HTTPCLIENT_COOKIE_MAX_CHAIN_LEN
#define HTTPCLIENT_COOKIE_MAX_CHAIN_LEN 100
#endif

/** @} */ /* end of http_client_cookie group */

/**
 * @defgroup http_client_auth Authentication Buffer Constants
 * @brief Internal buffer sizes for HTTP authentication header generation and
 * computation.
 * @ingroup http_client
 *
 * Constants for Basic, Digest, and Bearer auth schemes. Sized conservatively
 * to handle long credentials, nonces, and params without overflows. Used in
 * temporary computations.
 *
 * @see SocketHTTPClient_Auth for credential configuration.
 * @see HTTP_AUTH_BASIC, HTTP_AUTH_DIGEST, HTTP_AUTH_BEARER enum.
 * @see RFC 7235 HTTP Authentication-Info and Authorization headers.
 * @{
 *
 * ============================================================================
 * Authentication Buffer Sizes
 *
 * These are internal buffer sizes for authentication header generation.
 * They are sized to handle typical use cases with some margin.
 * ============================================================================
 */

/**
 * @brief Buffer size for Basic auth credentials string (username:password, 512
 * bytes).
 * @ingroup http_client
 *
 * Temporary buffer for concatenating username:password before Base64 encoding
 * in Basic auth. 512 bytes accommodates long usernames/passwords with margin;
 * prevents overflows. Used in SocketHTTPClient_Auth for header generation.
 *
 * @see SocketHTTPClient_Auth::username and ::password fields.
 * @see HTTPCLIENT_AUTH_HEADER_SIZE encoded header buffer.
 * @see RFC 7617 Basic Authentication scheme.
 */
#ifndef HTTPCLIENT_AUTH_CREDENTIALS_SIZE
#define HTTPCLIENT_AUTH_CREDENTIALS_SIZE 512
#endif

/**
 * @brief Buffer size for Digest auth A1/A2 intermediate hashes (512 bytes).
 * @ingroup http_client
 *
 * Internal buffer for computing HA1 = MD5(username:realm:password) and
 * HA2 = MD5(method:digest-uri) used in Digest response calculation.
 * 512 bytes safe for hash outputs + temporary strings; prevents overflows in
 * crypto ops.
 *
 * @see HTTP_AUTH_DIGEST scheme requiring these intermediates.
 * @see HTTPCLIENT_DIGEST_RESPONSE_SIZE for final response.
 * @see RFC 7616 Digest Access Authentication.
 */
#ifndef HTTPCLIENT_DIGEST_A_BUFFER_SIZE
#define HTTPCLIENT_DIGEST_A_BUFFER_SIZE 512
#endif

/**
 * @brief Buffer size for Digest auth response value (256 bytes).
 * @ingroup http_client
 *
 * Holds final response-digest = KD(HA1, nonce:nonce-count:cnonce:qop:HA2)
 * or without qop. Sufficient for hex-encoded MD5 (32 chars) + params.
 * Used in Authorization header construction.
 *
 * @see HTTPCLIENT_DIGEST_A_BUFFER_SIZE intermediates.
 * @see HTTP_AUTH_DIGEST response calculation.
 * @see RFC 7616 section 3.4 response computation.
 */
#ifndef HTTPCLIENT_DIGEST_RESPONSE_SIZE
#define HTTPCLIENT_DIGEST_RESPONSE_SIZE 256
#endif

/**
 * @brief Size of client nonce (cnonce) in bytes for Digest auth (16 bytes
 * random).
 * @ingroup http_client
 *
 * Random data generated per request for replay protection in Digest auth.
 * 16 bytes (128 bits) provides sufficient entropy against guessing.
 * Hex-encoded to 32 chars in header.
 *
 * @see HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE encoded string size.
 * @see RFC 7616 section 3.2.1 client nonce requirement.
 * @see SocketCrypto for random generation (if available).
 */
#ifndef HTTPCLIENT_DIGEST_CNONCE_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_SIZE 16
#endif

/**
 * @brief Size of hex-encoded client nonce string for Digest auth headers (33
 * bytes).
 * @ingroup http_client
 *
 * Buffer for ASCII hex representation of cnonce (2 hex chars per byte + null
 * terminator). For 16-byte cnonce: 32 hex chars + NUL = 33 bytes. Included in
 * Authorization header as cnonce param.
 *
 * @see HTTPCLIENT_DIGEST_CNONCE_SIZE binary cnonce size.
 * @see RFC 7616 section 3.2.1 nonce format (hex lowercase recommended).
 * @see HTTPCLIENT_AUTH_HEADER_SIZE overall auth header buffer.
 */
#ifndef HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE
#define HTTPCLIENT_DIGEST_CNONCE_HEX_SIZE 33
#endif

/**
 * @brief Buffer size for Digest auth nonce-count (nc) hex string (16 bytes).
 * @ingroup http_client
 *
 * Holds 8-digit hex nonce count (00000001 to FFFFFFFF) + null terminator.
 * Incremented per request with same nonce for replay detection.
 * 16 bytes allows padding and future extensions.
 *
 * @see RFC 7616 section 3.2.2 nonce-count format (8 hex digits).
 * @see HTTPCLIENT_AUTH_HEADER_SIZE including nc in header.
 * @see Digest auth state management for rollover handling.
 */
#ifndef HTTPCLIENT_DIGEST_NC_SIZE
#define HTTPCLIENT_DIGEST_NC_SIZE 16
#endif

/** @} */ /* end of http_client_auth group */

/**
 * @defgroup http_client_buffers Request/Response Buffer Constants
 * @brief Buffer sizes for HTTP request serialization, response reading, and
 * headers.
 * @ingroup http_client
 *
 * Limits for temporary buffers during request building, body accumulation, and
 * header construction. Sized for efficiency and security (DoS prevention).
 *
 * @see SocketHTTPClient_Request for request building.
 * @see SocketHTTPClient_Response for response handling.
 * @see SocketHTTP1 for protocol-level buffering.
 * @{
 *
 * ============================================================================
 * Request/Response Buffer Limits
 * ============================================================================
 */

/**
 * @brief Buffer size for serializing HTTP request lines and headers (8192
 * bytes).
 * @ingroup http_client
 *
 * Temporary buffer for building complete request string before sending.
 * 8KB handles typical requests with many headers (e.g., cookies, auth).
 * Prevents reallocations during header accumulation.
 *
 * @see SocketHTTP1_serialize_request() underlying serialization.
 * @see HTTPCLIENT_AUTH_HEADER_SIZE for auth-specific buffers.
 * @see SocketHTTPClient_Request_header() adding custom headers.
 */
#ifndef HTTPCLIENT_REQUEST_BUFFER_SIZE
#define HTTPCLIENT_REQUEST_BUFFER_SIZE 8192
#endif

/**
 * @brief Chunk size for reading response bodies incrementally (4096 bytes).
 * @ingroup http_client
 *
 * Size of buffers used to read and accumulate response body data from socket.
 * 4KB balances I/O efficiency with memory usage during body parsing.
 * Used in chunked, content-length, or connection-close modes.
 *
 * Larger chunks reduce syscalls but increase latency for small responses.
 * Contributes to HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE limit checks.
 *
 * @see HTTPCLIENT_DEFAULT_MAX_RESPONSE_SIZE total body limit.
 * @see Socket_recvv() or similar for underlying I/O.
 * @see SocketHTTPClient_Response::body accumulated result.
 */
#ifndef HTTPCLIENT_BODY_CHUNK_SIZE
#define HTTPCLIENT_BODY_CHUNK_SIZE 4096
#endif

/**
 * @brief Buffer size for generating Host header (256 bytes).
 * @ingroup http_client
 *
 * Temporary buffer for "Host: hostname:port" construction per RFC 7230.
 * 256 bytes covers long FQDNs + port + optional userinfo.
 * Automatically included unless suppressed.
 *
 * @see SocketHTTP_URI for host/port extraction from URL.
 * @see SocketHTTP_Headers_add() header insertion.
 * @see RFC 7230 section 5.4 Host header requirements.
 */
#ifndef HTTPCLIENT_HOST_HEADER_SIZE
#define HTTPCLIENT_HOST_HEADER_SIZE 256
#endif

/**
 * @brief Buffer size for serializing Cookie header in outgoing requests (4096
 * bytes).
 * @ingroup http_client
 *
 * Accumulates "Cookie: name1=value1; name2=value2; ..." from jar matching
 * current request. 4KB handles sites with many cookies (analytics, session,
 * prefs). Truncates if exceeds (rare); logs warning.
 *
 * @see SocketHTTPClient_CookieJar for source jar.
 * @see SocketHTTPClient_set_cookie_jar() associating jar with client.
 * @see RFC 6265 section 5.4 Cookie header format.
 */
#ifndef HTTPCLIENT_COOKIE_HEADER_SIZE
#define HTTPCLIENT_COOKIE_HEADER_SIZE 4096
#endif

/**
 * @brief Buffer size for standard Authorization headers (Basic/Digest/Bearer,
 * 512 bytes).
 * @ingroup http_client
 *
 * For Basic: "Basic base64(creds)"; Digest: full params; Bearer: "Bearer
 * token". 512 bytes covers typical cases; see LARGE variant for complex
 * Digest.
 *
 * @see SocketHTTPClient_Auth for credential types.
 * @see HTTPCLIENT_AUTH_HEADER_LARGE_SIZE for extended Digest params.
 * @see RFC 7235 HTTP Authentication framework.
 */
#ifndef HTTPCLIENT_AUTH_HEADER_SIZE
#define HTTPCLIENT_AUTH_HEADER_SIZE 512
#endif

/**
 * @brief Larger buffer for complex Authorization headers, e.g., Digest with
 * long nonces (1024 bytes).
 * @ingroup http_client
 *
 * Extended size for cases where standard buffer insufficient, like verbose
 * Digest params or long bearer tokens. Fallback or realloc if needed. Used
 * when params exceed HTTPCLIENT_AUTH_HEADER_SIZE.
 *
 * @see HTTPCLIENT_AUTH_HEADER_SIZE standard size.
 * @see HTTP_AUTH_DIGEST full param list potential length.
 * @see RFC 7616 Digest auth header format.
 */
#ifndef HTTPCLIENT_AUTH_HEADER_LARGE_SIZE
#define HTTPCLIENT_AUTH_HEADER_LARGE_SIZE 1024
#endif

/**
 * @brief Buffer size for URI string in Digest auth calculations (512 bytes).
 * @ingroup http_client
 *
 * Holds normalized request-uri for HA2 hash (method:uri without query per
 * RFC). 512 bytes for long paths/queries; used in digest-uri param.
 *
 * @see SocketHTTP_URI for URI parsing/normalization.
 * @see HTTPCLIENT_DIGEST_A_BUFFER_SIZE including HA2 computation.
 * @see RFC 7616 section 3.4.2 digest-uri definition.
 */
#ifndef HTTPCLIENT_URI_BUFFER_SIZE
#define HTTPCLIENT_URI_BUFFER_SIZE 512
#endif

/**
 * @brief Maximum Set-Cookie headers processed per HTTP response (16).
 * @ingroup http_client
 *
 * Limits parsing of multiple Set-Cookie headers to prevent DoS from header
 * flooding. Servers rarely send >5-10; 16 provides margin for complex apps.
 * Excess ignored with warning log.
 *
 * @see SocketHTTP_Headers for header parsing.
 * @see SocketHTTPClient_CookieJar_set() per-cookie insertion.
 * @see HTTPCLIENT_MAX_COOKIES total jar limit.
 * @see RFC 6265 multiple Set-Cookie handling.
 */
#ifndef HTTPCLIENT_MAX_SET_COOKIES
#define HTTPCLIENT_MAX_SET_COOKIES 16
#endif

/**
 * @brief Buffer size for constructing Accept-Encoding request header (64
 * bytes).
 * @ingroup http_client
 *
 * Builds "Accept-Encoding: gzip, deflate, br" based on config flags.
 * Small size sufficient for standard encodings; extensible.
 *
 * @see @ref http_client_encoding "Content-Encoding Flags": GZIP, DEFLATE, BR.
 * @see SocketHTTPClient_Config::accept_encoding bitmask.
 * @see RFC 9110 Content-Encoding and Accept-Encoding.
 */
#ifndef HTTPCLIENT_ACCEPT_ENCODING_SIZE
#define HTTPCLIENT_ACCEPT_ENCODING_SIZE 64
#endif

/**
 * @brief Buffer size for Content-Length header value string (32 bytes).
 * @ingroup http_client
 *
 * Formats numeric body length up to ~10^18 bytes (far beyond practical
 * limits). 32 chars for digits + "Content-Length: " prefix space.
 *
 * @see RFC 7230 section 3.3.2 Content-Length.
 * @see SocketHTTPClient_Request_body() setting body length.
 * @see HTTPCLIENT_REQUEST_BUFFER_SIZE including this in request.
 */
#ifndef HTTPCLIENT_CONTENT_LENGTH_SIZE
#define HTTPCLIENT_CONTENT_LENGTH_SIZE 32
#endif

/**
 * @brief Default retry backoff parameters: jitter factor (0.25) and multiplier
 * (2.0).
 * @ingroup http_client
 *
 * Jitter: Random variation +/- jitter_factor * delay to prevent synchronized
 * retries (thundering herd) across clients. 25% provides good randomization
 * without excessive variance.
 *
 * Multiplier: Exponential backoff factor. delay_{n} = min(max_delay,
 * delay_{n-1} * multiplier). 2.0 standard for doubling delays (100ms -> 200 ->
 * 400 -> ... capped at max).
 *
 * Both used in retry logic when HTTPCLIENT_DEFAULT_ENABLE_RETRY active.
 * Not runtime configurable; compile-time constants.
 *
 * @see HTTPCLIENT_DEFAULT_RETRY_INITIAL_DELAY_MS starting delay.
 * @see HTTPCLIENT_DEFAULT_RETRY_MAX_DELAY_MS cap.
 * @see SocketHTTPClient_Config::enable_retry prerequisite.
 * @see Exponential backoff with jitter best practices.
 */
#ifndef HTTPCLIENT_RETRY_JITTER_FACTOR
#define HTTPCLIENT_RETRY_JITTER_FACTOR 0.25
#define HTTPCLIENT_RETRY_MULTIPLIER 2.0
#endif

/** @} */ /* end of http_client_buffers group */

/* ============================================================================
 * Default User-Agent
 * ============================================================================
 */

/**
 * @brief Default User-Agent header string sent in requests.
 * @ingroup http_client
 *
 * Simple identifier "SocketHTTPClient/1.0" for library requests.
 * Servers may use for rate limiting or logging; override for
 * application-specific ID. Includes version for compatibility tracking.
 * Configurable via SocketHTTPClient_Config.user_agent (NULL uses default).
 *
 * @see SocketHTTPClient_Config::user_agent runtime override.
 * @see RFC 7231 section 5.5.3 User-Agent header.
 * @see SocketHTTP_Headers_add() header insertion.
 */
#ifndef HTTPCLIENT_DEFAULT_USER_AGENT
#define HTTPCLIENT_DEFAULT_USER_AGENT "SocketHTTPClient/1.0"
#endif

/**
 * @defgroup http_client_encoding Content-Encoding Flags
 * @brief Bit flags indicating supported Content-Encoding methods for HTTP
 * client.
 * @ingroup http_client
 *
 * These flags are combined (bitwise OR) in
 * SocketHTTPClient_Config.accept_encoding to specify which encoding methods
 * the client supports in Accept-Encoding header and can decompress in
 * responses.
 *
 * Default: GZIP | DEFLATE (Brotli optional for smaller payloads).
 *
 * @see SocketHTTPClient_Config::accept_encoding
 * @see SocketHTTPClient_config_defaults()
 * @{
 */

/**
 * @brief Identity (no compression) encoding flag.
 * @ingroup http_client
 * @details Bit value 0x00. Represents uncompressed data transfer.
 * Used as base flag or when no encoding is applied.
 * @see @ref http_client_encoding "Content-Encoding Flags"
 */
#define HTTPCLIENT_ENCODING_IDENTITY 0x00
/**
 * @brief GZIP compression encoding flag.
 * @ingroup http_client
 * @details Bit value 0x01. Supports gzip compression (RFC 9110, formerly RFC
 * 7230). Advertises "gzip" in Accept-Encoding header. Client must decompress
 * gzip-encoded responses.
 * @see @ref http_client_encoding "Content-Encoding Flags"
 * @see SocketHTTPClient.c for header construction and decompression logic.
 */
#define HTTPCLIENT_ENCODING_GZIP 0x01
/**
 * @brief DEFLATE compression encoding flag.
 * @ingroup http_client
 * @details Bit value 0x02. Supports deflate compression (RFC 9110).
 * Advertises "deflate" in Accept-Encoding. Note: zlib wrapper often used; raw
 * deflate deprecated. Client handles decompression for responses with this
 * encoding.
 * @see @ref http_client_encoding "Content-Encoding Flags"
 * @see SocketHTTPClient.c line ~918 for Accept-Encoding handling.
 */
#define HTTPCLIENT_ENCODING_DEFLATE 0x02
/**
 * @brief Brotli compression encoding flag.
 * @ingroup http_client
 * @details Bit value 0x04. Supports Brotli compression (RFC 7932).
 * Advertises "br" in Accept-Encoding header. Modern, efficient for text;
 * requires Brotli library support. Client decompresses br-encoded responses if
 * enabled.
 * @see @ref http_client_encoding "Content-Encoding Flags"
 * @note Brotli support may require additional dependencies or conditional
 * compilation.
 */
#define HTTPCLIENT_ENCODING_BR 0x04

/** @} */ /* end of http_client_encoding group */

#endif /* SOCKETHTTPCLIENT_CONFIG_INCLUDED */
