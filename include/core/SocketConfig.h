#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/**
 * SocketConfig.h - Socket Library Configuration
 *
 * Part of the Socket Library
 *
 * This header provides compile-time configuration for the socket library
 * including all size limits, platform detection, and socket option mappings.
 */

/* Standard includes required for configuration macros */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Forward declaration */
extern const char *Socket_safe_strerror (int errnum);

/* ============================================================================
 * Library Version
 * ============================================================================ */

#define SOCKET_VERSION_MAJOR 0
#define SOCKET_VERSION_MINOR 1
#define SOCKET_VERSION_PATCH 0

#define SOCKET_VERSION_STRING "0.1.0"

/* Numeric version for compile-time comparisons: (MAJOR * 10000) + (MINOR * 100) + PATCH */
#define SOCKET_VERSION                                                        \
  ((SOCKET_VERSION_MAJOR * 10000) + (SOCKET_VERSION_MINOR * 100)              \
   + SOCKET_VERSION_PATCH)

/* ============================================================================
 * Size Limits and Capacity Configuration
 * ============================================================================
 *
 * CONFIGURABLE LIMITS SUMMARY
 *
 * All limits can be overridden at compile time with -D flags.
 *
 * CONNECTION LIMITS:
 *   SOCKET_MAX_CONNECTIONS - 10000 - Maximum connections in pool
 *   SOCKET_MAX_POLL_EVENTS - 1024 - Max events per poll iteration
 *
 * BUFFER LIMITS:
 *   SOCKET_MAX_BUFFER_SIZE - 1MB - Maximum buffer per connection
 *   SOCKET_MIN_BUFFER_SIZE - 512B - Minimum buffer size
 *
 * ARENA (MEMORY) LIMITS:
 *   ARENA_CHUNK_SIZE - 4KB - Default arena chunk size
 *   ARENA_MAX_ALLOC_SIZE - 100MB - Maximum single allocation
 *   ARENA_MAX_FREE_CHUNKS - 10 - Maximum cached free chunks
 *
 * RUNTIME GLOBAL MEMORY LIMIT:
 *   Use SocketConfig_set_max_memory() to set a global memory limit.
 *   Arena allocations will fail when the limit is exceeded.
 *   Query with SocketConfig_get_memory_used() / SocketConfig_get_max_memory().
 *
 * ENFORCEMENT:
 *   - All limits enforced at runtime with graceful failure
 *   - SOCKET_CTR_LIMIT_MEMORY_EXCEEDED incremented when global limit exceeded
 */

/* Maximum number of connections in pool (can be overridden at compile time) */
#ifndef SOCKET_MAX_CONNECTIONS
#define SOCKET_MAX_CONNECTIONS 10000UL
#endif

/* Maximum buffer size per connection (can be overridden at compile time) */
#ifndef SOCKET_MAX_BUFFER_SIZE
#define SOCKET_MAX_BUFFER_SIZE (1024 * 1024) /* 1MB */
#endif

/* Minimum buffer size per connection */
#ifndef SOCKET_MIN_BUFFER_SIZE
#define SOCKET_MIN_BUFFER_SIZE 512
#endif

/* UDP limits to avoid fragmentation and respect protocol max */
#ifndef UDP_MAX_PAYLOAD
#define UDP_MAX_PAYLOAD 65507UL /* IPv4/6 max UDP payload excluding headers */
#endif

#ifndef SAFE_UDP_SIZE
#define SAFE_UDP_SIZE 1472UL /* Safe for Ethernet MTU (1500 - IP/UDP ~28) */
#endif

#ifndef SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE
#define SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE 8192
#endif

#ifndef SOCKET_MAX_TTL
#define SOCKET_MAX_TTL 255 /* Standard IP TTL max */
#endif

#ifndef SOCKET_IPV6_MAX_PREFIX
#define SOCKET_IPV6_MAX_PREFIX 128 /* IPv6 address bits */
#endif

#ifndef SOCKET_IPV4_MAX_PREFIX
#define SOCKET_IPV4_MAX_PREFIX 32 /* IPv4 address bits */
#endif

#ifndef SOCKET_MAX_PORT
#define SOCKET_MAX_PORT 65535 /* Standard TCP/UDP port max */
#endif

/* Maximum events per poll */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
#endif

/* Maximum backlog for listen() */
#ifndef SOCKET_MAX_LISTEN_BACKLOG
#define SOCKET_MAX_LISTEN_BACKLOG 1024
#endif

/* Maximum file descriptors per SCM_RIGHTS message (FD passing) */
#ifndef SOCKET_MAX_FDS_PER_MSG
#define SOCKET_MAX_FDS_PER_MSG 253 /* SCM_MAX_FD on most POSIX systems */
#endif

/* Hash table size for socket data mapping - prime number */
#ifndef SOCKET_HASH_TABLE_SIZE
#define SOCKET_HASH_TABLE_SIZE 1021
#endif

/* ============================================================================
 * Arena Memory Configuration
 * ============================================================================ */

/* Arena chunk size */
#ifndef ARENA_CHUNK_SIZE
#define ARENA_CHUNK_SIZE (10 * 1024) /* 10KB */
#endif

/* Maximum allocation size for arena */
#ifndef ARENA_MAX_ALLOC_SIZE
#define ARENA_MAX_ALLOC_SIZE (100 * 1024 * 1024) /* 100MB */
#endif

/* Maximum number of free chunks to cache for reuse */
#ifndef ARENA_MAX_FREE_CHUNKS
#define ARENA_MAX_FREE_CHUNKS 10
#endif

/* Arena error buffer size for detailed error messages */
#ifndef ARENA_ERROR_BUFSIZE
#define ARENA_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Buffer Configuration
 * ============================================================================ */

/* Minimum capacity for circular buffers */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
#endif

/* Initial capacity when buffer reserve grows from zero */
#ifndef SOCKETBUF_INITIAL_CAPACITY
#define SOCKETBUF_INITIAL_CAPACITY 1024
#endif

/* Allocation overhead for arena bookkeeping during buffer resize */
#ifndef SOCKETBUF_ALLOC_OVERHEAD
#define SOCKETBUF_ALLOC_OVERHEAD 64
#endif

/**
 * SOCKETBUF_MAX_CAPACITY - Maximum buffer capacity (SIZE_MAX/2)
 *
 * Conservative limit providing guaranteed safety:
 * - 32-bit systems: max ~2GB (sufficient for network buffers)
 * - 64-bit systems: max ~9 exabytes (effectively unlimited)
 *
 * Prevents integer overflow when calculating buffer sizes.
 */
#ifndef SOCKETBUF_MAX_CAPACITY
#define SOCKETBUF_MAX_CAPACITY (SIZE_MAX / 2)
#endif

/* ============================================================================
 * DNS Configuration
 * ============================================================================ */

#ifndef SOCKET_DNS_THREAD_COUNT
#define SOCKET_DNS_THREAD_COUNT 4
#endif

#ifndef SOCKET_DNS_MAX_PENDING
#define SOCKET_DNS_MAX_PENDING 1000
#endif

#ifndef SOCKET_DNS_MAX_LABEL_LENGTH
#define SOCKET_DNS_MAX_LABEL_LENGTH 63
#endif

#ifndef SOCKET_DNS_WORKER_STACK_SIZE
#define SOCKET_DNS_WORKER_STACK_SIZE (128 * 1024)
#endif

/* DNS request hash table size - prime number */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/* Completion pipe read buffer size */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/* Completion signal byte value for DNS pipe signaling */
#ifndef SOCKET_DNS_COMPLETION_SIGNAL_BYTE
#define SOCKET_DNS_COMPLETION_SIGNAL_BYTE 1
#endif

/* Port number string buffer size */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/* Thread name buffer size (POSIX max 16 chars including null) */
#ifndef SOCKET_DNS_THREAD_NAME_SIZE
#define SOCKET_DNS_THREAD_NAME_SIZE 16
#endif

/* ============================================================================
 * Poll Backend Configuration
 * ============================================================================ */

#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/**
 * SOCKET_POLL_MAX_REGISTERED - Maximum sockets registered per poll instance
 *
 * Defense-in-depth limit to prevent resource exhaustion attacks.
 * Set to 0 to disable the limit (unlimited registrations).
 * Default: 0 (disabled) for backwards compatibility.
 *
 * Security note: In high-security deployments, consider setting this
 * to a reasonable limit based on expected workload to prevent DoS.
 */
#ifndef SOCKET_POLL_MAX_REGISTERED
#define SOCKET_POLL_MAX_REGISTERED 0
#endif

/* ============================================================================
 * Timer Subsystem Configuration
 * ============================================================================ */

/* Maximum timer timeout to prevent indefinite blocking (5 minutes) */
#ifndef SOCKET_MAX_TIMER_TIMEOUT_MS
#define SOCKET_MAX_TIMER_TIMEOUT_MS 300000
#endif

/* Maximum allowed delay or interval for individual timers (~1 year in ms)
 * Prevents resource exhaustion from extremely long timers and potential
 * int64_t overflow in expiry calculations after long uptime.
 * Can be overridden at compile time.
 */
#ifndef SOCKET_MAX_TIMER_DELAY_MS
#define SOCKET_MAX_TIMER_DELAY_MS (INT64_C(31536000000)) /* 365 days */
#endif

/* Timer error buffer size for detailed error messages */
#ifndef SOCKET_TIMER_ERROR_BUFSIZE
#define SOCKET_TIMER_ERROR_BUFSIZE 256
#endif

/* Initial capacity for timer heap array */
#ifndef SOCKET_TIMER_HEAP_INITIAL_CAPACITY
#define SOCKET_TIMER_HEAP_INITIAL_CAPACITY 16
#endif

/* Growth factor when resizing timer heap (must be > 1) */
#ifndef SOCKET_TIMER_HEAP_GROWTH_FACTOR
#define SOCKET_TIMER_HEAP_GROWTH_FACTOR 2
#endif

/* Maximum number of timers per heap to prevent resource exhaustion (default 100000) */
#ifndef SOCKET_MAX_TIMERS_PER_HEAP
#define SOCKET_MAX_TIMERS_PER_HEAP 100000
#endif

/* Minimum delay for one-shot timers (ms) */
#ifndef SOCKET_TIMER_MIN_DELAY_MS
#define SOCKET_TIMER_MIN_DELAY_MS 0
#endif

/* Minimum interval for repeating timers (ms) */
#ifndef SOCKET_TIMER_MIN_INTERVAL_MS
#define SOCKET_TIMER_MIN_INTERVAL_MS 1
#endif

/* Initial timer ID value (wraps at UINT_MAX) */
#ifndef SOCKET_TIMER_INITIAL_ID
#define SOCKET_TIMER_INITIAL_ID 1u
#endif

/* ============================================================================
 * Event Subsystem Configuration
 * ============================================================================ */

/* Maximum number of event handlers that can be registered */
#ifndef SOCKET_EVENT_MAX_HANDLERS
#define SOCKET_EVENT_MAX_HANDLERS 8
#endif

/* ============================================================================
 * Rate Limiting Configuration
 * ============================================================================ */

/* Default connection rate limit (new connections per second) */
#ifndef SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC
#define SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC 100
#endif

/* Default burst capacity for connection rate limiter */
#ifndef SOCKET_RATELIMIT_DEFAULT_BURST
#define SOCKET_RATELIMIT_DEFAULT_BURST 50
#endif

/* Default maximum connections per IP address (0 = unlimited) */
#ifndef SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP
#define SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP 10
#endif

/* Default bandwidth limit in bytes per second (0 = unlimited) */
#ifndef SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS
#define SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS 0
#endif

/* IP tracker hash table size - prime number for good distribution */
#ifndef SOCKET_IP_TRACKER_HASH_SIZE
#define SOCKET_IP_TRACKER_HASH_SIZE 1021
#endif

/* Maximum IP address string length (IPv6 with scope) */
#ifndef SOCKET_IP_MAX_LEN
#define SOCKET_IP_MAX_LEN 64
#endif

/* ============================================================================
 * SYN Flood Protection Configuration
 * ============================================================================ */

/* Sliding window duration for rate measurement (milliseconds) */
#ifndef SOCKET_SYN_DEFAULT_WINDOW_MS
#define SOCKET_SYN_DEFAULT_WINDOW_MS 10000
#endif

/* Maximum connection attempts per IP per window */
#ifndef SOCKET_SYN_DEFAULT_MAX_PER_WINDOW
#define SOCKET_SYN_DEFAULT_MAX_PER_WINDOW 50
#endif

/* Global connection rate limit (all IPs, per second) */
#ifndef SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC
#define SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC 1000
#endif

/* Minimum success/attempt ratio before IP becomes suspect */
#ifndef SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO
#define SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO 0.3f
#endif

/* Artificial delay for throttled connections (milliseconds) */
#ifndef SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS
#define SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS 100
#endif

/* Block duration for misbehaving IPs (milliseconds) */
#ifndef SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS
#define SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS 60000
#endif

/* TCP_DEFER_ACCEPT timeout for challenged connections (seconds) */
#ifndef SOCKET_SYN_DEFAULT_DEFER_SEC
#define SOCKET_SYN_DEFAULT_DEFER_SEC 5
#endif

/* Score threshold below which connections are throttled */
#ifndef SOCKET_SYN_DEFAULT_SCORE_THROTTLE
#define SOCKET_SYN_DEFAULT_SCORE_THROTTLE 0.7f
#endif

/* Score threshold below which connections are challenged */
#ifndef SOCKET_SYN_DEFAULT_SCORE_CHALLENGE
#define SOCKET_SYN_DEFAULT_SCORE_CHALLENGE 0.4f
#endif

/* Score threshold below which connections are blocked */
#ifndef SOCKET_SYN_DEFAULT_SCORE_BLOCK
#define SOCKET_SYN_DEFAULT_SCORE_BLOCK 0.2f
#endif

/* Score recovery rate per second (time-based decay) */
#ifndef SOCKET_SYN_DEFAULT_SCORE_DECAY
#define SOCKET_SYN_DEFAULT_SCORE_DECAY 0.01f
#endif

/* Score penalty per new connection attempt */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT
#define SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT 0.02f
#endif

/* Score penalty per connection failure */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_FAILURE
#define SOCKET_SYN_DEFAULT_PENALTY_FAILURE 0.05f
#endif

/* Score reward per successful connection */
#ifndef SOCKET_SYN_DEFAULT_REWARD_SUCCESS
#define SOCKET_SYN_DEFAULT_REWARD_SUCCESS 0.05f
#endif

/* Maximum unique IPs to track (LRU eviction when exceeded) */
#ifndef SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS
#define SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS 100000
#endif

/* Maximum whitelist entries */
#ifndef SOCKET_SYN_DEFAULT_MAX_WHITELIST
#define SOCKET_SYN_DEFAULT_MAX_WHITELIST 1000
#endif

/* Maximum blacklist entries */
#ifndef SOCKET_SYN_DEFAULT_MAX_BLACKLIST
#define SOCKET_SYN_DEFAULT_MAX_BLACKLIST 10000
#endif

/* Score threshold at or above which IP is considered trusted (for reputation) */
#ifndef SOCKET_SYN_TRUSTED_SCORE_THRESHOLD
#define SOCKET_SYN_TRUSTED_SCORE_THRESHOLD 0.9f
#endif

/* IPv6 address size in bytes (used for CIDR parsing) */
#ifndef SOCKET_IPV6_ADDR_BYTES
#define SOCKET_IPV6_ADDR_BYTES 16
#endif

/* IPv4 address size in bytes */
#ifndef SOCKET_IPV4_ADDR_BYTES
#define SOCKET_IPV4_ADDR_BYTES 4
#endif

/* Bits per byte (for CIDR prefix calculations) */
#ifndef SOCKET_BITS_PER_BYTE
#define SOCKET_BITS_PER_BYTE 8
#endif

/* ============================================================================
 * Logging Configuration
 * ============================================================================ */

/* Buffer size for formatted log messages */
#ifndef SOCKET_LOG_BUFFER_SIZE
#define SOCKET_LOG_BUFFER_SIZE 1024
#endif

/* Timestamp formatting constants */
#ifndef SOCKET_LOG_TIMESTAMP_BUFSIZE
#define SOCKET_LOG_TIMESTAMP_BUFSIZE 64
#endif

#ifndef SOCKET_LOG_TIMESTAMP_FORMAT
#define SOCKET_LOG_TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#endif

#ifndef SOCKET_LOG_DEFAULT_TIMESTAMP
#define SOCKET_LOG_DEFAULT_TIMESTAMP "1970-01-01 00:00:00"
#endif

#ifndef SOCKET_LOG_TRUNCATION_SUFFIX
#define SOCKET_LOG_TRUNCATION_SUFFIX "..."
#endif

#ifndef SOCKET_LOG_TRUNCATION_SUFFIX_LEN
#define SOCKET_LOG_TRUNCATION_SUFFIX_LEN (sizeof(SOCKET_LOG_TRUNCATION_SUFFIX) - 1)
#endif

/* ============================================================================
 * Error Handling Configuration
 * ============================================================================ */

/* Error buffer size */
#ifndef SOCKET_ERROR_BUFSIZE
#define SOCKET_ERROR_BUFSIZE 1024
#endif

/* Thread-safe strerror buffer size */
#ifndef SOCKET_STRERROR_BUFSIZE
#define SOCKET_STRERROR_BUFSIZE 128
#endif

/* Maximum field sizes for error messages */
#ifndef SOCKET_ERROR_MAX_HOSTNAME
#define SOCKET_ERROR_MAX_HOSTNAME 255
#endif

#ifndef SOCKET_ERROR_MAX_MESSAGE
#define SOCKET_ERROR_MAX_MESSAGE 512
#endif

/* Truncation marker for error messages */
#ifndef SOCKET_ERROR_TRUNCATION_MARKER
#define SOCKET_ERROR_TRUNCATION_MARKER "... (truncated)"
#endif

#ifndef SOCKET_ERROR_TRUNCATION_SIZE
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof (SOCKET_ERROR_TRUNCATION_MARKER))
#endif

/* Socket port string buffer size */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

/* ============================================================================
 * Platform Detection
 * ============================================================================ */

#ifdef __APPLE__
#define SOCKET_PLATFORM_MACOS 1
#else
#define SOCKET_PLATFORM_MACOS 0
#endif

/* ============================================================================
 * Feature Flags
 * ============================================================================
 *
 * Compile-time flags for optional features. Set to 0 to disable.
 * Can be overridden via CMake or compiler defines.
 */

#ifndef SOCKET_HAS_HTTP
#define SOCKET_HAS_HTTP 1  /**< HTTP/1.1, HTTP/2, HPACK, client/server support */
#endif

#ifndef SOCKET_HAS_WEBSOCKET
#define SOCKET_HAS_WEBSOCKET 1  /**< WebSocket RFC 6455 + permessage-deflate */
#endif

#ifndef SOCKET_HAS_TLS
#define SOCKET_HAS_TLS 0  /**< TLS 1.3 only (OpenSSL/LibreSSL) + DTLS - set by cmake */
#endif

/* IOV_MAX fallback if not defined */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/* sendmsg/recvmsg are standard POSIX - always available */
#define SOCKET_HAS_SENDMSG 1
#define SOCKET_HAS_RECVMSG 1

/* ============================================================================
 * Timeout Configuration
 * ============================================================================ */

#ifndef SOCKET_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_DEFAULT_CONNECT_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/* ============================================================================
 * Happy Eyeballs (RFC 8305) Configuration
 * ============================================================================ */

/**
 * SOCKET_CONNECT_HAPPY_EYEBALLS - Enable Happy Eyeballs for Socket_connect()
 *
 * When enabled (1), Socket_connect() will use the RFC 8305 Happy Eyeballs
 * algorithm for hostname connections, racing IPv6 and IPv4 connection
 * attempts for faster connection establishment.
 *
 * When disabled (0, default), Socket_connect() uses sequential connection
 * attempts for backwards compatibility.
 *
 * Can be overridden at compile time with -DSOCKET_CONNECT_HAPPY_EYEBALLS=1
 */
#ifndef SOCKET_CONNECT_HAPPY_EYEBALLS
#define SOCKET_CONNECT_HAPPY_EYEBALLS 0
#endif

#ifndef SOCKET_DEFAULT_DNS_TIMEOUT_MS
#define SOCKET_DEFAULT_DNS_TIMEOUT_MS 5000 /* 5 seconds */
#endif

#ifndef SOCKET_DEFAULT_OPERATION_TIMEOUT_MS
#define SOCKET_DEFAULT_OPERATION_TIMEOUT_MS 0 /* Infinite */
#endif

#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

#ifndef SOCKET_DEFAULT_POLL_TIMEOUT
#define SOCKET_DEFAULT_POLL_TIMEOUT 1000 /* 1 second */
#endif

/**
 * SocketTimeouts_T - Timeout configuration structure
 */
typedef struct SocketTimeouts
{
  int connect_timeout_ms;   /**< Connect timeout in ms (0 = infinite) */
  int dns_timeout_ms;       /**< DNS resolution timeout in ms (0 = infinite) */
  int operation_timeout_ms; /**< General operation timeout in ms (0 = infinite) */
} SocketTimeouts_T;

/**
 * SocketTimeouts_Extended_T - Extended per-phase timeout configuration
 *
 * Provides granular control over individual operation phases. This structure
 * allows fine-tuned timeout settings for production deployments where different
 * phases may have different latency characteristics.
 *
 * Timeout precedence (highest to lowest):
 * 1. Per-request timeout (if supported by API)
 * 2. Per-socket extended timeouts (this structure)
 * 3. Per-socket basic timeouts (SocketTimeouts_T)
 * 4. Global defaults (Socket_timeouts_setdefaults)
 *
 * A value of 0 means "use default from basic timeout structure".
 * A value of -1 means "no timeout (infinite)".
 */
typedef struct SocketTimeouts_Extended
{
  /* DNS resolution phase */
  int dns_timeout_ms;       /**< DNS resolution (0 = use basic, -1 = infinite) */

  /* Connection establishment phase */
  int connect_timeout_ms;   /**< TCP connect (0 = use basic, -1 = infinite) */

  /* TLS handshake phase */
  int tls_timeout_ms;       /**< TLS handshake (0 = use operation_timeout_ms) */

  /* Request/response cycle */
  int request_timeout_ms;   /**< Full request cycle (0 = use operation_timeout_ms) */

  /* Generic operation timeout (fallback for unspecified phases) */
  int operation_timeout_ms; /**< Default for other ops (0 = use basic, -1 = infinite) */
} SocketTimeouts_Extended_T;

/* Default values for extended timeouts (in milliseconds) */
#ifndef SOCKET_DEFAULT_TLS_TIMEOUT_MS
#define SOCKET_DEFAULT_TLS_TIMEOUT_MS 30000 /**< 30 seconds for TLS handshake */
#endif

#ifndef SOCKET_DEFAULT_REQUEST_TIMEOUT_MS
#define SOCKET_DEFAULT_REQUEST_TIMEOUT_MS 60000 /**< 60 seconds for request cycle */
#endif

/* ============================================================================
 * Pool Configuration
 * ============================================================================ */

#ifndef SOCKET_DEFAULT_POOL_SIZE
#define SOCKET_DEFAULT_POOL_SIZE 1000
#endif

#ifndef SOCKET_DEFAULT_POOL_BUFSIZE
#define SOCKET_DEFAULT_POOL_BUFSIZE 8192
#endif

#ifndef SOCKET_POOL_DEFAULT_PREWARM_PCT
#define SOCKET_POOL_DEFAULT_PREWARM_PCT 20
#endif

#ifndef SOCKET_POOL_MAX_BATCH_ACCEPTS
#define SOCKET_POOL_MAX_BATCH_ACCEPTS 1000
#endif

/**
 * Maximum number of pending async connect operations per pool.
 * Prevents resource exhaustion from excessive concurrent connect attempts.
 * Security: Limits memory consumption from async context allocations.
 */
#ifndef SOCKET_POOL_MAX_ASYNC_PENDING
#define SOCKET_POOL_MAX_ASYNC_PENDING 1000
#endif

#ifndef SOCKET_PERCENTAGE_DIVISOR
#define SOCKET_PERCENTAGE_DIVISOR 100
#endif

/* Default idle timeout for pool connections (seconds, 0 = disabled) */
#ifndef SOCKET_POOL_DEFAULT_IDLE_TIMEOUT
#define SOCKET_POOL_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

/* Interval between idle connection cleanup runs (milliseconds) */
#ifndef SOCKET_POOL_DEFAULT_CLEANUP_INTERVAL_MS
#define SOCKET_POOL_DEFAULT_CLEANUP_INTERVAL_MS 60000 /* 1 minute */
#endif

/* Time window for calculating pool churn rate statistics (seconds) */
#ifndef SOCKET_POOL_STATS_WINDOW_SEC
#define SOCKET_POOL_STATS_WINDOW_SEC 60
#endif

/* ============================================================================
 * Hash and Algorithm Constants
 * ============================================================================ */

/* Golden ratio constant for multiplicative hashing (2^32 * (sqrt(5)-1)/2) */
#ifndef HASH_GOLDEN_RATIO
#define HASH_GOLDEN_RATIO 2654435761u
#endif

/* ============================================================================
 * Arena Memory Alignment
 * ============================================================================ */

/* Alignment union - ensures proper alignment for all data types */
union align
{
  int i;
  long l;
  long *lp;
  void *p;
  void (*fp) (void);
  float f;
  double d;
  long double ld;
};

#ifndef ARENA_ALIGNMENT_SIZE
#define ARENA_ALIGNMENT_SIZE sizeof (union align)
#endif

/* Arena validation and return codes */
#ifndef ARENA_VALIDATION_SUCCESS
#define ARENA_VALIDATION_SUCCESS 1
#endif

#ifndef ARENA_VALIDATION_FAILURE
#define ARENA_VALIDATION_FAILURE 0
#endif

#ifndef ARENA_SUCCESS
#define ARENA_SUCCESS 0
#endif

#ifndef ARENA_FAILURE
#define ARENA_FAILURE (-1)
#endif

#ifndef ARENA_CHUNK_REUSED
#define ARENA_CHUNK_REUSED 1
#endif

#ifndef ARENA_CHUNK_NOT_REUSED
#define ARENA_CHUNK_NOT_REUSED 0
#endif

#ifndef ARENA_SIZE_VALID
#define ARENA_SIZE_VALID 1
#endif

#ifndef ARENA_SIZE_INVALID
#define ARENA_SIZE_INVALID 0
#endif

#ifndef ARENA_ENOMEM
#define ARENA_ENOMEM "Out of memory"
#endif

/* ============================================================================
 * Time Conversion Constants
 * ============================================================================ */

#define SOCKET_MS_PER_SECOND 1000
#define SOCKET_NS_PER_MS 1000000LL
#define SOCKET_NS_PER_SECOND 1000000000LL

/* ============================================================================
 * Async I/O Configuration
 * ============================================================================ */

#define SOCKET_DEFAULT_IO_URING_ENTRIES 1024
#define SOCKET_MAX_EVENT_BATCH 100

/* ============================================================================
 * String Conversion Macros
 * ============================================================================ */

#define SOCKET_STRINGIFY(x) #x
#define SOCKET_TO_STRING(x) SOCKET_STRINGIFY (x)

#define SOCKET_PORT_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_PORT)
#define SOCKET_TTL_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_TTL)
#define SOCKET_IPV4_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV4_MAX_PREFIX)
#define SOCKET_IPV6_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV6_MAX_PREFIX)

/* ============================================================================
 * Socket Type and Family Constants
 * ============================================================================ */

#define SOCKET_STREAM_TYPE SOCK_STREAM
#define SOCKET_DGRAM_TYPE SOCK_DGRAM

#define SOCKET_AF_UNSPEC AF_UNSPEC
#define SOCKET_AF_INET AF_INET
#define SOCKET_AF_INET6 AF_INET6
#define SOCKET_AF_UNIX AF_UNIX

#define SOCKET_IPPROTO_TCP IPPROTO_TCP
#define SOCKET_IPPROTO_UDP IPPROTO_UDP
#define SOCKET_IPPROTO_IP IPPROTO_IP
#define SOCKET_IPPROTO_IPV6 IPPROTO_IPV6

/* ============================================================================
 * Socket Options
 * ============================================================================ */

#define SOCKET_SOL_SOCKET SOL_SOCKET
#define SOCKET_SO_REUSEADDR SO_REUSEADDR

#ifdef SO_REUSEPORT
#define SOCKET_SO_REUSEPORT SO_REUSEPORT
#define SOCKET_HAS_SO_REUSEPORT 1
#else
#define SOCKET_SO_REUSEPORT 0
#define SOCKET_HAS_SO_REUSEPORT 0
#endif

#ifdef SOCK_CLOEXEC
#define SOCKET_SOCK_CLOEXEC SOCK_CLOEXEC
#define SOCKET_HAS_SOCK_CLOEXEC 1
#else
#define SOCKET_SOCK_CLOEXEC 0
#define SOCKET_HAS_SOCK_CLOEXEC 0
#endif

#ifdef __linux__
#define SOCKET_HAS_ACCEPT4 1
#define SOCKET_SO_DOMAIN SO_DOMAIN
#define SOCKET_HAS_SO_DOMAIN 1
#else
#define SOCKET_HAS_ACCEPT4 0
#define SOCKET_HAS_SO_DOMAIN 0
#endif

#define SOCKET_FD_CLOEXEC FD_CLOEXEC
#define SOCKET_SO_BROADCAST SO_BROADCAST
#define SOCKET_SO_KEEPALIVE SO_KEEPALIVE
#define SOCKET_SO_RCVTIMEO SO_RCVTIMEO
#define SOCKET_SO_SNDTIMEO SO_SNDTIMEO
#define SOCKET_SO_RCVBUF SO_RCVBUF
#define SOCKET_SO_SNDBUF SO_SNDBUF
#define SOCKET_SO_PEERCRED SO_PEERCRED

/* ============================================================================
 * TCP Options
 * ============================================================================ */

#define SOCKET_TCP_NODELAY TCP_NODELAY
#define SOCKET_TCP_KEEPIDLE TCP_KEEPIDLE
#define SOCKET_TCP_KEEPINTVL TCP_KEEPINTVL
#define SOCKET_TCP_KEEPCNT TCP_KEEPCNT

#ifdef TCP_CONGESTION
#define SOCKET_TCP_CONGESTION TCP_CONGESTION
#define SOCKET_HAS_TCP_CONGESTION 1
#else
#define SOCKET_HAS_TCP_CONGESTION 0
#endif

#ifdef TCP_FASTOPEN
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN
#define SOCKET_HAS_TCP_FASTOPEN 1
#elif defined(TCP_FASTOPEN_CONNECT)
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN_CONNECT
#define SOCKET_HAS_TCP_FASTOPEN 1
#else
#define SOCKET_HAS_TCP_FASTOPEN 0
#endif

#ifdef TCP_USER_TIMEOUT
#define SOCKET_TCP_USER_TIMEOUT TCP_USER_TIMEOUT
#define SOCKET_HAS_TCP_USER_TIMEOUT 1
#else
#define SOCKET_HAS_TCP_USER_TIMEOUT 0
#endif

/* TCP_DEFER_ACCEPT: Linux-specific option for SYN flood protection.
 * Delays accept() completion until client sends data.
 * On BSD/macOS, use SO_ACCEPTFILTER instead. */
#ifdef TCP_DEFER_ACCEPT
#define SOCKET_TCP_DEFER_ACCEPT TCP_DEFER_ACCEPT
#define SOCKET_HAS_TCP_DEFER_ACCEPT 1
#else
#define SOCKET_HAS_TCP_DEFER_ACCEPT 0
#endif

/* SO_ACCEPTFILTER: BSD/macOS equivalent of TCP_DEFER_ACCEPT.
 * Used with struct accept_filter_arg and filter name "dataready". */
#ifdef SO_ACCEPTFILTER
#define SOCKET_HAS_SO_ACCEPTFILTER 1
#else
#define SOCKET_HAS_SO_ACCEPTFILTER 0
#endif

/* ============================================================================
 * IPv6 Options
 * ============================================================================ */

#define SOCKET_IPV6_V6ONLY IPV6_V6ONLY

#ifdef IPV6_ADD_MEMBERSHIP
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_ADD_MEMBERSHIP
#elif defined(IPV6_JOIN_GROUP)
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#else
#error "IPv6 multicast add membership not supported on this platform"
#endif

#ifdef IPV6_DROP_MEMBERSHIP
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_DROP_MEMBERSHIP
#elif defined(IPV6_LEAVE_GROUP)
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#else
#error "IPv6 multicast drop membership not supported on this platform"
#endif

#define SOCKET_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS

/* ============================================================================
 * IP Options
 * ============================================================================ */

#define SOCKET_IP_TTL IP_TTL
#define SOCKET_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP
#define SOCKET_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP

/* ============================================================================
 * Address and Name Info Flags
 * ============================================================================ */

#define SOCKET_AI_PASSIVE AI_PASSIVE
#define SOCKET_AI_NUMERICHOST AI_NUMERICHOST
#define SOCKET_AI_NUMERICSERV AI_NUMERICSERV
#define SOCKET_NI_NUMERICHOST NI_NUMERICHOST
#define SOCKET_NI_NUMERICSERV NI_NUMERICSERV
#define SOCKET_NI_MAXHOST NI_MAXHOST
#define SOCKET_NI_MAXSERV NI_MAXSERV

/* ============================================================================
 * Shutdown and Message Flags
 * ============================================================================ */

#define SOCKET_SHUT_RD SHUT_RD
#define SOCKET_SHUT_WR SHUT_WR
#define SOCKET_SHUT_RDWR SHUT_RDWR

/* MSG_NOSIGNAL: Suppress SIGPIPE on send operations (Linux/FreeBSD).
 * On platforms without MSG_NOSIGNAL (macOS), we use SO_NOSIGPIPE instead
 * which is set at socket creation time. When MSG_NOSIGNAL is unavailable,
 * we define it as 0 so it can be safely OR'd into flags without effect. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define SOCKET_MSG_NOSIGNAL MSG_NOSIGNAL

/* SO_NOSIGPIPE: BSD/macOS socket option to suppress SIGPIPE.
 * This is set once at socket creation time as an alternative to MSG_NOSIGNAL.
 * On Linux, MSG_NOSIGNAL is preferred and this macro will be 0. */
#ifdef SO_NOSIGPIPE
#define SOCKET_HAS_SO_NOSIGPIPE 1
#else
#define SOCKET_HAS_SO_NOSIGPIPE 0
#endif

/* ============================================================================
 * Default Parameters
 * ============================================================================ */

#define SOCKET_DEFAULT_KEEPALIVE_IDLE 60
#define SOCKET_DEFAULT_KEEPALIVE_INTERVAL 10
#define SOCKET_DEFAULT_KEEPALIVE_COUNT 3
#define SOCKET_DEFAULT_DATAGRAM_TTL 64
#define SOCKET_MULTICAST_DEFAULT_INTERFACE 0

/* ============================================================================
 * Global Memory Limit Configuration
 * ============================================================================
 *
 * These functions control the global memory limit for Arena allocations.
 * When a limit is set, Arena_alloc will return NULL if the allocation
 * would exceed the configured limit.
 *
 * Thread-safe: Yes (uses atomic operations)
 */

/**
 * SocketConfig_set_max_memory - Set global memory limit for Arena allocations
 * @max_bytes: Maximum total bytes (0 = unlimited, default)
 *
 * Thread-safe: Yes (atomic store)
 */
extern void SocketConfig_set_max_memory (size_t max_bytes);

/**
 * SocketConfig_get_max_memory - Get current global memory limit
 *
 * Returns: Maximum bytes configured (0 = unlimited)
 * Thread-safe: Yes (atomic load)
 */
extern size_t SocketConfig_get_max_memory (void);

/**
 * SocketConfig_get_memory_used - Get current total memory usage
 *
 * Returns: Total bytes currently allocated via Arena
 * Thread-safe: Yes (atomic load)
 */
extern size_t SocketConfig_get_memory_used (void);

/* Validation macros */
#define SOCKET_VALID_PORT(p) ((int)(p) >= 0 && (int)(p) <= 65535)
#define SOCKET_VALID_BUFFER_SIZE(s)                                           \
  ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)
#define SOCKET_VALID_CONNECTION_COUNT(c)                                      \
  ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)
#define SOCKET_VALID_POLL_EVENTS(e)                                           \
  ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)
#define SOCKET_VALID_IP_STRING(ip) ((ip) != NULL && (ip)[0] != '\0')

/* SAFE_CLOSE - Close fd with POSIX.1-2008 EINTR handling (no retry) */
#define SAFE_CLOSE(fd)                                                        \
  do                                                                          \
    {                                                                         \
      if ((fd) >= 0)                                                          \
        {                                                                     \
          int _r = close (fd);                                                \
          if (_r < 0 && errno != EINTR)                                       \
            fprintf (stderr, "close failed: %s\n", Socket_safe_strerror (errno)); \
        }                                                                     \
    }                                                                         \
  while (0)

#endif /* SOCKETCONFIG_INCLUDED */
