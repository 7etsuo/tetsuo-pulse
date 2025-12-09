#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/**
 * @file SocketConfig.h
 * @ingroup foundation
 * @brief Compile-time configuration and platform detection for the socket library.
 *
 * This header provides compile-time configuration for the socket library
 * including all size limits, platform detection, and socket option mappings.
 * All configuration values can be overridden at compile time using -D flags.
 *
 * @see SocketUtil.h for runtime utilities that use these configurations.
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

/**
 * @brief Thread-safe and bounds-checked strerror implementation.
 * @ingroup foundation
 * @param errnum Error number to convert to string.
 * @return Human-readable error string or static fallback on failure.
 *
 * Provides a safe alternative to strerror() that avoids buffer overflows
 * and thread-safety issues with errno. Returns a static buffer with error
 * description, or "Unknown error" on failure.
 *
 * @note Thread-safe: Yes - uses internal static buffer or strerror_r().
 * @see Socket_GetLastError() for formatted error strings with context.
 * @see Socket_geterrorcode() for error categorization.
 * @see @ref foundation for error handling utilities.
 */
extern const char *Socket_safe_strerror (int errnum);

/* ============================================================================
 * Library Version
 * ============================================================================
 */

/**
 * @brief Major version number.
 * @ingroup foundation
 */
#define SOCKET_VERSION_MAJOR 0

/**
 * @brief Minor version number.
 * @ingroup foundation
 */
#define SOCKET_VERSION_MINOR 1

/**
 * @brief Patch version number.
 * @ingroup foundation
 */
#define SOCKET_VERSION_PATCH 0

/**
 * @brief Version string for human-readable output.
 * @ingroup foundation
 */
#define SOCKET_VERSION_STRING "0.1.0"

/**
 * @brief Numeric version for compile-time comparisons.
 *
 * Calculated as: (MAJOR * 10000) + (MINOR * 100) + PATCH
 *
 * @ingroup foundation
 * @see SOCKET_VERSION_MAJOR, SOCKET_VERSION_MINOR, SOCKET_VERSION_PATCH
 */
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

/**
 * @brief Maximum number of connections in pool.
 *
 * Can be overridden at compile time with -DSOCKET_MAX_CONNECTIONS=value.
 *
 * @ingroup foundation
 * @see SocketPool_T for connection pool implementation.
 */
#ifndef SOCKET_MAX_CONNECTIONS
#define SOCKET_MAX_CONNECTIONS 10000UL
#endif

/**
 * @brief Maximum buffer size per connection.
 *
 * Can be overridden at compile time with -DSOCKET_MAX_BUFFER_SIZE=value.
 *
 * @ingroup foundation
 * @see SocketBuf_T for buffer implementation.
 */
#ifndef SOCKET_MAX_BUFFER_SIZE
#define SOCKET_MAX_BUFFER_SIZE (1024 * 1024) /* 1MB */
#endif

/**
 * @brief Minimum buffer size per connection.
 *
 * @ingroup foundation
 * @see SOCKET_MAX_BUFFER_SIZE for upper limit.
 */
#ifndef SOCKET_MIN_BUFFER_SIZE
#define SOCKET_MIN_BUFFER_SIZE 512
#endif

/**
 * @brief Maximum UDP payload size excluding headers.
 *
 * Respects IPv4/IPv6 protocol maximums to avoid fragmentation.
 *
 * @ingroup core_io
 * @see SAFE_UDP_SIZE for MTU-safe size.
 */
#ifndef UDP_MAX_PAYLOAD
#define UDP_MAX_PAYLOAD 65507UL /* IPv4/6 max UDP payload excluding headers   \
                                 */
#endif

/**
 * @brief Safe UDP payload size for Ethernet MTU.
 *
 * Ensures packets fit within standard 1500-byte Ethernet MTU
 * after IP/UDP headers (~28 bytes).
 *
 * @ingroup core_io
 * @see UDP_MAX_PAYLOAD for protocol maximum.
 */
#ifndef SAFE_UDP_SIZE
#define SAFE_UDP_SIZE 1472UL /* Safe for Ethernet MTU (1500 - IP/UDP ~28) */
#endif

/**
 * @brief Fallback buffer size for sendfile operations.
 *
 * Used when sendfile() is not available or fails.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE
#define SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE 8192
#endif

/**
 * @brief Maximum IP TTL (Time To Live) value.
 *
 * Standard maximum for IP packets.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_MAX_TTL
#define SOCKET_MAX_TTL 255 /* Standard IP TTL max */
#endif

/**
 * @brief Maximum IPv6 prefix length in bits.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_IPV6_MAX_PREFIX
#define SOCKET_IPV6_MAX_PREFIX 128 /* IPv6 address bits */
#endif

/**
 * @brief Maximum IPv4 prefix length in bits.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_IPV4_MAX_PREFIX
#define SOCKET_IPV4_MAX_PREFIX 32 /* IPv4 address bits */
#endif

/**
 * @brief Maximum TCP/UDP port number.
 *
 * Standard maximum for port numbers.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_MAX_PORT
#define SOCKET_MAX_PORT 65535 /* Standard TCP/UDP port max */
#endif

/**
 * @brief Maximum events per poll iteration.
 *
 * Can be overridden at compile time with -DSOCKET_MAX_POLL_EVENTS=value.
 *
 * @ingroup event_system
 * @see SocketPoll_T for event polling implementation.
 */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
#endif

/**
 * @brief Maximum backlog for listen() system call.
 *
 * @ingroup core_io
 * @see Socket_listen() for server socket setup.
 */
#ifndef SOCKET_MAX_LISTEN_BACKLOG
#define SOCKET_MAX_LISTEN_BACKLOG 1024
#endif

/**
 * @brief Maximum file descriptors per SCM_RIGHTS message.
 *
 * Unix domain socket file descriptor passing limit.
 *
 * @ingroup core_io
 * @see Socket_sendfds() for FD passing implementation.
 */
#ifndef SOCKET_MAX_FDS_PER_MSG
#define SOCKET_MAX_FDS_PER_MSG 253 /* SCM_MAX_FD on most POSIX systems */
#endif

/**
 * @brief Hash table size for socket data mapping.
 *
 * Prime number for optimal hash distribution.
 *
 * @ingroup foundation
 * @see HASH_GOLDEN_RATIO for hash function constant.
 */
#ifndef SOCKET_HASH_TABLE_SIZE
#define SOCKET_HASH_TABLE_SIZE 1021
#endif

/* ============================================================================
 * Arena Memory Configuration
 * ============================================================================
 */

/**
 * @brief Default arena chunk size.
 *
 * Memory blocks are allocated in chunks of this size.
 *
 * @ingroup foundation
 * @see Arena_T for arena memory management.
 */
#ifndef ARENA_CHUNK_SIZE
#define ARENA_CHUNK_SIZE (10 * 1024) /* 10KB */
#endif

/**
 * @brief Maximum allocation size for arena.
 *
 * Matches centralized security limit to prevent overflow attacks.
 *
 * @ingroup foundation
 * @see SOCKET_MAX_BUFFER_SIZE for buffer size limits.
 */
#ifndef ARENA_MAX_ALLOC_SIZE
#define ARENA_MAX_ALLOC_SIZE                                                  \
  SOCKET_SECURITY_MAX_ALLOCATION /* Matches centralized limit */
#endif

/**
 * @brief Maximum number of free chunks to cache for reuse.
 *
 * Prevents excessive memory retention while enabling allocation reuse.
 *
 * @ingroup foundation
 * @see Arena_T for arena implementation.
 */
#ifndef ARENA_MAX_FREE_CHUNKS
#define ARENA_MAX_FREE_CHUNKS 10
#endif

/**
 * @brief Buffer size for arena error messages.
 *
 * @ingroup foundation
 */
#ifndef ARENA_ERROR_BUFSIZE
#define ARENA_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Buffer Configuration
 * ============================================================================
 */

/**
 * @brief Minimum capacity for circular buffers.
 *
 * @ingroup core_io
 * @see SocketBuf_T for buffer implementation.
 */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
#endif

/**
 * @brief Initial capacity when buffer reserve grows from zero.
 *
 * @ingroup core_io
 * @see SocketBuf_T for buffer implementation.
 */
#ifndef SOCKETBUF_INITIAL_CAPACITY
#define SOCKETBUF_INITIAL_CAPACITY 1024
#endif

/**
 * @brief Allocation overhead for arena bookkeeping during buffer resize.
 *
 * @ingroup core_io
 * @see SocketBuf_T for buffer implementation.
 */
#ifndef SOCKETBUF_ALLOC_OVERHEAD
#define SOCKETBUF_ALLOC_OVERHEAD 64
#endif

/**
 * @brief SOCKETBUF_MAX_CAPACITY - Maximum buffer capacity (SIZE_MAX/2)
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
 * ============================================================================
 */

/**
 * @brief Number of DNS worker threads.
 *
 * @ingroup core_io
 * @see SocketDNS_T for async DNS resolution.
 */
#ifndef SOCKET_DNS_THREAD_COUNT
#define SOCKET_DNS_THREAD_COUNT 4
#endif

/**
 * @brief Maximum pending DNS requests.
 *
 * @ingroup core_io
 * @see SocketDNS_T for DNS implementation.
 */
#ifndef SOCKET_DNS_MAX_PENDING
#define SOCKET_DNS_MAX_PENDING 1000
#endif

/**
 * @brief Maximum DNS label length.
 *
 * Per RFC 1035, DNS labels are limited to 63 characters.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_MAX_LABEL_LENGTH
#define SOCKET_DNS_MAX_LABEL_LENGTH 63
#endif

/**
 * @brief DNS worker thread stack size.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_WORKER_STACK_SIZE
#define SOCKET_DNS_WORKER_STACK_SIZE (128 * 1024)
#endif

/**
 * @brief DNS request hash table size.
 *
 * Prime number for optimal hash distribution.
 *
 * @ingroup core_io
 * @see SOCKET_DNS_MAX_PENDING for request limits.
 */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/**
 * @brief Completion pipe read buffer size.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/**
 * @brief Completion signal byte value for DNS pipe signaling.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_COMPLETION_SIGNAL_BYTE
#define SOCKET_DNS_COMPLETION_SIGNAL_BYTE 1
#endif

/**
 * @brief Port number string buffer size.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/**
 * @brief Thread name buffer size.
 *
 * POSIX maximum 16 characters including null terminator.
 *
 * @ingroup core_io
 */
#ifndef SOCKET_DNS_THREAD_NAME_SIZE
#define SOCKET_DNS_THREAD_NAME_SIZE 16
#endif

/* ============================================================================
 * Poll Backend Configuration
 * ============================================================================
 */

/**
 * @brief Initial file descriptor capacity for poll backend.
 *
 * @ingroup event_system
 * @see SocketPoll_T for event polling implementation.
 */
#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

/**
 * @brief Initial file descriptor map size.
 *
 * @ingroup event_system
 * @see SocketPoll_T for event polling implementation.
 */
#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

/**
 * @brief File descriptor map expansion increment.
 *
 * @ingroup event_system
 * @see SocketPoll_T for event polling implementation.
 */
#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/**
 * @brief SOCKET_POLL_MAX_REGISTERED - Maximum sockets registered per poll instance
 *
 * @brief Defense-in-depth limit to prevent resource exhaustion attacks.
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
 * ============================================================================
 */

/**
 * @brief Maximum timer timeout to prevent indefinite blocking.
 *
 * 5 minutes maximum to prevent resource exhaustion.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_MAX_TIMER_TIMEOUT_MS
#define SOCKET_MAX_TIMER_TIMEOUT_MS 300000
#endif

/**
 * @brief Maximum allowed delay or interval for individual timers.
 *
 * Prevents resource exhaustion and int64_t overflow (~1 year in ms).
 * Can be overridden at compile time with -DSOCKET_MAX_TIMER_DELAY_MS=value.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_MAX_TIMER_DELAY_MS
#define SOCKET_MAX_TIMER_DELAY_MS (INT64_C (31536000000)) /* 365 days */
#endif

/**
 * @brief Timer error buffer size for detailed error messages.
 *
 * @ingroup event_system
 */
#ifndef SOCKET_TIMER_ERROR_BUFSIZE
#define SOCKET_TIMER_ERROR_BUFSIZE 256
#endif

/**
 * @brief Initial capacity for timer heap array.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer heap implementation.
 */
#ifndef SOCKET_TIMER_HEAP_INITIAL_CAPACITY
#define SOCKET_TIMER_HEAP_INITIAL_CAPACITY 16
#endif

/**
 * @brief Growth factor when resizing timer heap.
 *
 * Must be greater than 1.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer heap implementation.
 */
#ifndef SOCKET_TIMER_HEAP_GROWTH_FACTOR
#define SOCKET_TIMER_HEAP_GROWTH_FACTOR 2
#endif

/**
 * @brief Maximum number of timers per heap.
 *
 * Prevents resource exhaustion.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_MAX_TIMERS_PER_HEAP
#define SOCKET_MAX_TIMERS_PER_HEAP 100000
#endif

/**
 * @brief Minimum delay for one-shot timers.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_TIMER_MIN_DELAY_MS
#define SOCKET_TIMER_MIN_DELAY_MS 0
#endif

/**
 * @brief Minimum interval for repeating timers.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_TIMER_MIN_INTERVAL_MS
#define SOCKET_TIMER_MIN_INTERVAL_MS 1
#endif

/**
 * @brief Initial timer ID value.
 *
 * Wraps at UINT64_MAX.
 *
 * @ingroup event_system
 * @see SocketTimer_T for timer implementation.
 */
#ifndef SOCKET_TIMER_INITIAL_ID
#define SOCKET_TIMER_INITIAL_ID 1ULL
#endif

/* ============================================================================
 * Event Subsystem Configuration
 * ============================================================================
 */

/**
 * @brief Maximum number of event handlers that can be registered.
 *
 * @ingroup event_system
 * @see SocketAsync_T for async I/O events.
 */
#ifndef SOCKET_EVENT_MAX_HANDLERS
#define SOCKET_EVENT_MAX_HANDLERS 8
#endif

/* ============================================================================
 * Rate Limiting Configuration
 * ============================================================================
 */

/**
 * @brief Default connection rate limit.
 *
 * New connections per second.
 *
 * @ingroup utilities
 * @see SocketRateLimit_T for rate limiting implementation.
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC
#define SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC 100
#endif

/**
 * @brief Default burst capacity for connection rate limiter.
 *
 * @ingroup utilities
 * @see SocketRateLimit_T for rate limiting implementation.
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_BURST
#define SOCKET_RATELIMIT_DEFAULT_BURST 50
#endif

/**
 * @brief Default maximum connections per IP address.
 *
 * 0 = unlimited.
 *
 * @ingroup utilities
 * @see SocketPool_T for connection pool rate limiting.
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP
#define SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP 10
#endif

/**
 * @brief Default bandwidth limit in bytes per second.
 *
 * 0 = unlimited.
 *
 * @ingroup utilities
 * @see SocketRateLimit_T for bandwidth limiting.
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS
#define SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS 0
#endif

/**
 * @brief IP tracker hash table size.
 *
 * Prime number for good distribution.
 *
 * @ingroup utilities
 * @see SocketPool_T for IP tracking implementation.
 */
#ifndef SOCKET_IP_TRACKER_HASH_SIZE
#define SOCKET_IP_TRACKER_HASH_SIZE 1021
#endif

/**
 * @brief Maximum IP address string length.
 *
 * IPv6 with scope ID.
 *
 * @ingroup utilities
 */
#ifndef SOCKET_IP_MAX_LEN
#define SOCKET_IP_MAX_LEN 64
#endif

/* ============================================================================
 * SYN Flood Protection Configuration
 * ============================================================================
 */

/**
 * @brief Sliding window duration for rate measurement.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_WINDOW_MS
#define SOCKET_SYN_DEFAULT_WINDOW_MS 10000
#endif

/**
 * @brief Maximum connection attempts per IP per window.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_PER_WINDOW
#define SOCKET_SYN_DEFAULT_MAX_PER_WINDOW 50
#endif

/**
 * @brief Global connection rate limit.
 *
 * All IPs, per second.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC
#define SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC 1000
#endif

/**
 * @brief Minimum success/attempt ratio before IP becomes suspect.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO
#define SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO 0.3f
#endif

/**
 * @brief Artificial delay for throttled connections.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS
#define SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS 100
#endif

/**
 * @brief Block duration for misbehaving IPs.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS
#define SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS 60000
#endif

/**
 * @brief TCP_DEFER_ACCEPT timeout for challenged connections.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_DEFER_SEC
#define SOCKET_SYN_DEFAULT_DEFER_SEC 5
#endif

/**
 * @brief Score threshold below which connections are throttled.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_THROTTLE
#define SOCKET_SYN_DEFAULT_SCORE_THROTTLE 0.7f
#endif

/**
 * @brief Score threshold below which connections are challenged.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_CHALLENGE
#define SOCKET_SYN_DEFAULT_SCORE_CHALLENGE 0.4f
#endif

/**
 * @brief Score threshold below which connections are blocked.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_BLOCK
#define SOCKET_SYN_DEFAULT_SCORE_BLOCK 0.2f
#endif

/**
 * @brief Score recovery rate per second.
 *
 * Time-based decay.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_DECAY
#define SOCKET_SYN_DEFAULT_SCORE_DECAY 0.01f
#endif

/**
 * @brief Score penalty per new connection attempt.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT
#define SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT 0.02f
#endif

/**
 * @brief Score penalty per connection failure.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_FAILURE
#define SOCKET_SYN_DEFAULT_PENALTY_FAILURE 0.05f
#endif

/**
 * @brief Score reward per successful connection.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_REWARD_SUCCESS
#define SOCKET_SYN_DEFAULT_REWARD_SUCCESS 0.05f
#endif

/**
 * @brief Maximum unique IPs to track.
 *
 * LRU eviction when exceeded.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS
#define SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS 100000
#endif

/**
 * @brief Maximum whitelist entries.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_WHITELIST
#define SOCKET_SYN_DEFAULT_MAX_WHITELIST 1000
#endif

/**
 * @brief Maximum blacklist entries.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_BLACKLIST
#define SOCKET_SYN_DEFAULT_MAX_BLACKLIST 10000
#endif

/**
 * @brief Score threshold at or above which IP is considered trusted.
 *
 * For reputation tracking.
 *
 * @ingroup security
 * @see SocketSYNProtect_T for SYN flood protection.
 */
#ifndef SOCKET_SYN_TRUSTED_SCORE_THRESHOLD
#define SOCKET_SYN_TRUSTED_SCORE_THRESHOLD 0.9f
#endif

/**
 * @brief IPv6 address size in bytes.
 *
 * Used for CIDR parsing.
 *
 * @ingroup security
 */
#ifndef SOCKET_IPV6_ADDR_BYTES
#define SOCKET_IPV6_ADDR_BYTES 16
#endif

/**
 * @brief IPv4 address size in bytes.
 *
 * @ingroup security
 */
#ifndef SOCKET_IPV4_ADDR_BYTES
#define SOCKET_IPV4_ADDR_BYTES 4
#endif

/**
 * @brief Bits per byte.
 *
 * For CIDR prefix calculations.
 *
 * @ingroup security
 */
#ifndef SOCKET_BITS_PER_BYTE
#define SOCKET_BITS_PER_BYTE 8
#endif

/* ============================================================================
 * Logging Configuration
 * ============================================================================
 */

/**
 * @brief Buffer size for formatted log messages.
 *
 * @ingroup utilities
 * @see SocketLog_emit() for logging functions.
 */
#ifndef SOCKET_LOG_BUFFER_SIZE
#define SOCKET_LOG_BUFFER_SIZE 1024
#endif

/**
 * @brief Timestamp formatting buffer size.
 *
 * @ingroup utilities
 * @see SocketLog_emit() for logging functions.
 */
#ifndef SOCKET_LOG_TIMESTAMP_BUFSIZE
#define SOCKET_LOG_TIMESTAMP_BUFSIZE 64
#endif

/**
 * @brief Timestamp format string.
 *
 * @ingroup utilities
 * @see SocketLog_emit() for logging functions.
 */
#ifndef SOCKET_LOG_TIMESTAMP_FORMAT
#define SOCKET_LOG_TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#endif

/**
 * @brief Default timestamp for formatting errors.
 *
 * @ingroup utilities
 * @see SocketLog_emit() for logging functions.
 */
#ifndef SOCKET_LOG_DEFAULT_TIMESTAMP
#define SOCKET_LOG_DEFAULT_TIMESTAMP "1970-01-01 00:00:00"
#endif

/**
 * @brief Log truncation suffix.
 *
 * @ingroup utilities
 * @see SocketLog_emit() for logging functions.
 */
#ifndef SOCKET_LOG_TRUNCATION_SUFFIX
#define SOCKET_LOG_TRUNCATION_SUFFIX "..."
#endif

/**
 * @brief Length of log truncation suffix.
 *
 * @ingroup utilities
 * @see SOCKET_LOG_TRUNCATION_SUFFIX
 */
#ifndef SOCKET_LOG_TRUNCATION_SUFFIX_LEN
#define SOCKET_LOG_TRUNCATION_SUFFIX_LEN                                      \
  (sizeof (SOCKET_LOG_TRUNCATION_SUFFIX) - 1)
#endif

/* ============================================================================
 * Error Handling Configuration
 * ============================================================================
 */

/**
 * @brief Error buffer size.
 *
 * @ingroup foundation
 * @see SOCKET_ERROR_FMT for error formatting.
 */
#ifndef SOCKET_ERROR_BUFSIZE
#define SOCKET_ERROR_BUFSIZE 1024
#endif

/**
 * @brief Thread-safe strerror buffer size.
 *
 * @ingroup foundation
 * @see Socket_safe_strerror() for thread-safe error strings.
 */
#ifndef SOCKET_STRERROR_BUFSIZE
#define SOCKET_STRERROR_BUFSIZE 128
#endif

/**
 * @brief Maximum hostname length in error messages.
 *
 * @ingroup foundation
 */
#ifndef SOCKET_ERROR_MAX_HOSTNAME
#define SOCKET_ERROR_MAX_HOSTNAME 255
#endif

/**
 * @brief Maximum error message length.
 *
 * @ingroup foundation
 */
#ifndef SOCKET_ERROR_MAX_MESSAGE
#define SOCKET_ERROR_MAX_MESSAGE 512
#endif

/**
 * @brief Truncation marker for error messages.
 *
 * @ingroup foundation
 */
#ifndef SOCKET_ERROR_TRUNCATION_MARKER
#define SOCKET_ERROR_TRUNCATION_MARKER "... (truncated)"
#endif

/**
 * @brief Size of truncation marker.
 *
 * @ingroup foundation
 * @see SOCKET_ERROR_TRUNCATION_MARKER
 */
#ifndef SOCKET_ERROR_TRUNCATION_SIZE
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof (SOCKET_ERROR_TRUNCATION_MARKER))
#endif

/**
 * @brief Socket port string buffer size.
 *
 * @ingroup foundation
 */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

/* ============================================================================
 * Platform Detection
 * ============================================================================
 */

/**
 * @brief Platform detection flag for macOS/Apple systems.
 * @ingroup foundation
 *
 * Set to 1 when compiled under __APPLE__ macro (macOS, iOS), enabling
 * platform-specific features such as kqueue event polling backend,
 * SO_NOSIGPIPE socket option, and Darwin-specific workarounds.
 *
 * Used internally to select optimal I/O primitives and handle platform
 * differences in socket options and system calls.
 *
 * @see @ref event_system for platform backend selection (epoll vs kqueue).
 * @see SocketPoll_backend.h for backend implementations.
 * @see SOCKET_HAS_SO_NOSIGPIPE for SIGPIPE suppression on macOS.
 */
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
/**
 * @brief HTTP protocol support flag.
 * @ingroup http
 *
 * Includes full HTTP/1.1 and HTTP/2 implementation with HPACK header compression,
 * client (SocketHTTPClient) and server (SocketHTTPServer) APIs, WebSocket support.
 *
 * Set to 1 to enable HTTP features (default), 0 to disable for reduced footprint.
 * Controlled by CMake -DENABLE_HTTP=ON/OFF.
 *
 * @see include/http/ for HTTP module headers.
 * @see SocketHTTPClient_T for high-level HTTP client.
 * @see SocketHTTPServer_T for HTTP server.
 * @see SocketWS_T for WebSocket over HTTP.
 */
#ifndef SOCKET_HAS_HTTP
#define SOCKET_HAS_HTTP 1
#endif
/**
 * @brief WebSocket protocol support flag.
 * @ingroup http
 *
 * Enables WebSocket RFC 6455 implementation with permessage-deflate extension support.
 * Builds on HTTP module for handshake and framing.
 *
 * Set to 1 to enable WebSocket features (default), 0 to disable.
 * Requires SOCKET_HAS_HTTP=1.
 *
 * @see SocketWS_T for WebSocket API.
 * @see SocketWS_client_connect() for client connections.
 * @see SocketWS_server_accept() for server upgrades.
 * @see docs/WEBSOCKET.md for usage guide.
 */
#ifndef SOCKET_HAS_WEBSOCKET
#define SOCKET_HAS_WEBSOCKET 1
#endif
/**
 * @brief TLS/SSL support flag.
 * @ingroup security
 *
 * Enables TLS 1.3 (only, no legacy versions) and DTLS support using OpenSSL or LibreSSL.
 * Includes client/server certificate management, session resumption, ALPN negotiation.
 *
 * Set to 1 to enable TLS features, 0 to disable (default for minimal builds).
 * Controlled by CMake -DENABLE_TLS=ON/OFF, auto-detects crypto library.
 *
 * Security notes:
 * - TLS 1.3 only - no support for vulnerable protocols (SSLv*, TLS 1.0/1.1)
 * - Hardened defaults: Secure ciphers, forward secrecy, no weak curves
 * - Certificate validation with OCSP stapling support
 *
 * @see include/tls/ for TLS module headers.
 * @see SocketTLS_enable() to enable TLS on a socket.
 * @see SocketTLSContext_new() for context configuration.
 * @see SocketDTLS_T for DTLS (UDP) support.
 * @see docs/SECURITY.md for security hardening details.
 */
#ifndef SOCKET_HAS_TLS
#define SOCKET_HAS_TLS 0
#endif

/**
 * @brief Fallback definition for IOV_MAX if not provided by system headers.
 *
 * Maximum number of I/O vectors supported for scatter/gather operations (readv/writev, sendmsg/recvmsg).
 * This limit prevents excessive memory use in vectorized I/O operations and aligns with POSIX standards.
 *
 * @see struct iovec (sys/uio.h) for I/O vector structure.
 * @see Socket_sendv(), Socket_recvv() for vectorized send/receive operations.
 * @see SocketConfig.h for other configuration constants.
 */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/**
 * @brief sendmsg() support flag.
 *
 * Standard POSIX - always available.
 *
 * @ingroup core_io
 */
#define SOCKET_HAS_SENDMSG 1

/**
 * @brief recvmsg() support flag.
 *
 * Standard POSIX - always available.
 *
 * @ingroup core_io
 */
#define SOCKET_HAS_RECVMSG 1

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

/**
 * @brief Default connect timeout.
 *
 * @ingroup foundation
 * @see SocketTimeouts_T for timeout configuration.
 */
#ifndef SOCKET_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_DEFAULT_CONNECT_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/* ============================================================================
 * Happy Eyeballs (RFC 8305) Configuration
 * ============================================================================
 */

/**
 * @brief SOCKET_CONNECT_HAPPY_EYEBALLS - Enable Happy Eyeballs for Socket_connect()
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

/**
 * @brief Default DNS resolution timeout.
 *
 * @ingroup core_io
 * @see SocketHappyEyeballs_T for Happy Eyeballs implementation.
 */
#ifndef SOCKET_DEFAULT_DNS_TIMEOUT_MS
#define SOCKET_DEFAULT_DNS_TIMEOUT_MS 5000 /* 5 seconds */
#endif

/**
 * @brief Default operation timeout.
 *
 * 0 = infinite.
 *
 * @ingroup foundation
 * @see SocketTimeouts_T for timeout configuration.
 */
#ifndef SOCKET_DEFAULT_OPERATION_TIMEOUT_MS
#define SOCKET_DEFAULT_OPERATION_TIMEOUT_MS 0 /* Infinite */
#endif

/**
 * @brief Default idle timeout.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pool timeouts.
 */
#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

/**
 * @brief Default poll timeout.
 *
 * @ingroup event_system
 * @see SocketPoll_T for event polling.
 */
#ifndef SOCKET_DEFAULT_POLL_TIMEOUT
#define SOCKET_DEFAULT_POLL_TIMEOUT 1000 /* 1 second */
#endif

/**
 * @brief Timeout configuration structure for socket operations.
 * @ingroup foundation
 *
 * Basic timeout settings for connection establishment, DNS resolution, and general operations.
 * Values of 0 indicate infinite timeout (blocking until completion or error).
 *
 * @see SocketConfig.h for default values like SOCKET_DEFAULT_CONNECT_TIMEOUT_MS.
 * @see SocketTimeouts_Extended_T for per-phase extended timeouts.
 * @see Socket_connect() for connect timeout usage.
 */
typedef struct SocketTimeouts
{
  int connect_timeout_ms;   /**< Connect timeout in ms (0 = infinite) */
  int dns_timeout_ms;       /**< DNS resolution timeout in ms (0 = infinite) */
  int operation_timeout_ms; /**< General operation timeout in ms (0 = infinite)
                             */
} SocketTimeouts_T;

/**
 * @brief Extended per-phase timeout configuration structure.
 * @ingroup foundation
 *
 * Provides granular control over timeouts for specific operation phases like DNS, connect, TLS handshake, and requests.
 * Allows fine-tuning for production environments with varying latency characteristics per phase.
 *
 * Precedence (highest to lowest):
 * 1. Per-request timeouts (API-specific)
 * 2. Per-socket extended timeouts (this structure)
 * 3. Per-socket basic timeouts (SocketTimeouts_T)
 * 4. Global defaults
 *
 * Value meanings:
 * - 0: Use value from basic SocketTimeouts_T
 * - -1: Infinite timeout (no limit)
 * - Positive: Specific timeout in ms
 *
 * @see SocketTimeouts_T for basic timeouts.
 * @see SocketConfig.h constants like SOCKET_DEFAULT_TLS_TIMEOUT_MS for defaults.
 * @see SocketTLS_handshake() for TLS phase timeout usage.
 */
typedef struct SocketTimeouts_Extended
{
  /* DNS resolution phase */
  int dns_timeout_ms; /**< DNS resolution (0 = use basic, -1 = infinite) */

  /* Connection establishment phase */
  int connect_timeout_ms; /**< TCP connect (0 = use basic, -1 = infinite) */

  /* TLS handshake phase */
  int tls_timeout_ms; /**< TLS handshake (0 = use operation_timeout_ms) */

  /* Request/response cycle */
  int request_timeout_ms; /**< Full request cycle (0 = use
                             operation_timeout_ms) */

  /* Generic operation timeout (fallback for unspecified phases) */
  int operation_timeout_ms; /**< Default for other ops (0 = use basic, -1 =
                               infinite) */
} SocketTimeouts_Extended_T;

/**
 * @brief Default TLS handshake timeout.
 *
 * @ingroup foundation
 * @see SocketTimeouts_Extended_T
 */
#ifndef SOCKET_DEFAULT_TLS_TIMEOUT_MS
#define SOCKET_DEFAULT_TLS_TIMEOUT_MS                                         \
  30000 /**< 30 seconds for TLS handshake */
#endif

/**
 * @brief Default request cycle timeout.
 *
 * @ingroup foundation
 * @see SocketTimeouts_Extended_T
 */
#ifndef SOCKET_DEFAULT_REQUEST_TIMEOUT_MS
#define SOCKET_DEFAULT_REQUEST_TIMEOUT_MS                                     \
  60000 /**< 60 seconds for request cycle */
#endif

/* ============================================================================
 * Pool Configuration
 * ============================================================================
 */

/**
 * @brief Default connection pool size.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_DEFAULT_POOL_SIZE
#define SOCKET_DEFAULT_POOL_SIZE 1000
#endif

/**
 * @brief Default pool buffer size.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_DEFAULT_POOL_BUFSIZE
#define SOCKET_DEFAULT_POOL_BUFSIZE 8192
#endif

/**
 * @brief Default pool prewarm percentage.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_POOL_DEFAULT_PREWARM_PCT
#define SOCKET_POOL_DEFAULT_PREWARM_PCT 20
#endif

/**
 * @brief Maximum batch accepts per iteration.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_POOL_MAX_BATCH_ACCEPTS
#define SOCKET_POOL_MAX_BATCH_ACCEPTS 1000
#endif

/**
 * @brief Maximum pending async connect operations per pool.
 *
 * Prevents resource exhaustion from excessive concurrent connect attempts.
 * Security: Limits memory consumption from async context allocations.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_POOL_MAX_ASYNC_PENDING
#define SOCKET_POOL_MAX_ASYNC_PENDING 1000
#endif

/**
 * @brief Percentage divisor for calculations.
 *
 * @ingroup connection_mgmt
 */
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

/**
 * @brief Time window for pool statistics calculation.
 *
 * @ingroup connection_mgmt
 * @see SocketPool_T for connection pooling.
 */
#ifndef SOCKET_POOL_STATS_WINDOW_SEC
#define SOCKET_POOL_STATS_WINDOW_SEC 60
#endif

/* ============================================================================
 * Hash and Algorithm Constants
 * ============================================================================
 */

/**
 * @brief Golden ratio constant for multiplicative hashing.
 *
 * Calculated as 2^32 * (sqrt(5)-1)/2.
 * Used for optimal hash distribution in hash tables.
 *
 * @ingroup foundation
 * @see socket_util_hash_fd() for hash function usage.
 */
#ifndef HASH_GOLDEN_RATIO
#define HASH_GOLDEN_RATIO 2654435761u
#endif

/* ============================================================================
 * Arena Memory Alignment
 * ============================================================================
 */

/**
 * @brief Alignment union for arena memory management.
 *
 * Ensures proper alignment for all data types to prevent alignment issues.
 * Used to determine the maximum alignment requirement for arena allocations.
 *
 * @ingroup foundation
 * @see Arena_T for arena memory management.
 */
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

/**
 * @brief Arena alignment size.
 *
 * Size of the alignment union, ensuring proper alignment for all data types.
 *
 * @ingroup foundation
 * @see union align
 */
#ifndef ARENA_ALIGNMENT_SIZE
#define ARENA_ALIGNMENT_SIZE sizeof (union align)
#endif

/**
 * @brief Arena validation success code.
 *
 * @ingroup foundation
 */
#ifndef ARENA_VALIDATION_SUCCESS
#define ARENA_VALIDATION_SUCCESS 1
#endif

/**
 * @brief Arena validation failure code.
 *
 * @ingroup foundation
 */
#ifndef ARENA_VALIDATION_FAILURE
#define ARENA_VALIDATION_FAILURE 0
#endif

/**
 * @brief Arena operation success code.
 *
 * @ingroup foundation
 */
#ifndef ARENA_SUCCESS
#define ARENA_SUCCESS 0
#endif

/**
 * @brief Arena operation failure code.
 *
 * @ingroup foundation
 */
#ifndef ARENA_FAILURE
#define ARENA_FAILURE (-1)
#endif

/**
 * @brief Arena chunk reused indicator.
 *
 * @ingroup foundation
 */
#ifndef ARENA_CHUNK_REUSED
#define ARENA_CHUNK_REUSED 1
#endif

/**
 * @brief Arena chunk not reused indicator.
 *
 * @ingroup foundation
 */
#ifndef ARENA_CHUNK_NOT_REUSED
#define ARENA_CHUNK_NOT_REUSED 0
#endif

/**
 * @brief Arena size validation success.
 *
 * @ingroup foundation
 */
#ifndef ARENA_SIZE_VALID
#define ARENA_SIZE_VALID 1
#endif

/**
 * @brief Arena size validation failure.
 *
 * @ingroup foundation
 */
#ifndef ARENA_SIZE_INVALID
#define ARENA_SIZE_INVALID 0
#endif

/**
 * @brief Arena out of memory error message.
 *
 * @ingroup foundation
 */
#ifndef ARENA_ENOMEM
#define ARENA_ENOMEM "Out of memory"
#endif

/* ============================================================================
 * Time Conversion Constants
 * ============================================================================
 */

/**
 * @brief Milliseconds per second.
 *
 * @ingroup foundation
 */
#define SOCKET_MS_PER_SECOND 1000

/**
 * @brief Nanoseconds per millisecond.
 *
 * @ingroup foundation
 */
#define SOCKET_NS_PER_MS 1000000LL

/**
 * @brief Nanoseconds per second.
 *
 * @ingroup foundation
 */
#define SOCKET_NS_PER_SECOND 1000000000LL

/* ============================================================================
 * Async I/O Configuration
 * ============================================================================
 */

/**
 * @brief Default number of io_uring entries.
 *
 * @ingroup async_io
 */
#define SOCKET_DEFAULT_IO_URING_ENTRIES 1024

/**
 * @brief Maximum number of events per batch.
 *
 * @ingroup async_io
 */
#define SOCKET_MAX_EVENT_BATCH 100

/* ============================================================================
 * String Conversion Macros
 * ============================================================================
 */

/**
 * @brief Stringify macro for compile-time string conversion.
 *
 * @ingroup foundation
 */
#define SOCKET_STRINGIFY(x) #x

/**
 * @brief Convert macro argument to string.
 *
 * @ingroup foundation
 * @see SOCKET_STRINGIFY
 */
#define SOCKET_TO_STRING(x) SOCKET_STRINGIFY (x)

/**
 * @brief Valid port range string for error messages.
 *
 * @ingroup foundation
 * @see SOCKET_MAX_PORT
 */
#define SOCKET_PORT_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_PORT)

/**
 * @brief Valid TTL range string for error messages.
 *
 * @ingroup foundation
 * @see SOCKET_MAX_TTL
 */
#define SOCKET_TTL_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_TTL)

/**
 * @brief Valid IPv4 prefix range string for error messages.
 *
 * @ingroup foundation
 * @see SOCKET_IPV4_MAX_PREFIX
 */
#define SOCKET_IPV4_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV4_MAX_PREFIX)

/**
 * @brief Valid IPv6 prefix range string for error messages.
 *
 * @ingroup foundation
 * @see SOCKET_IPV6_MAX_PREFIX
 */
#define SOCKET_IPV6_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV6_MAX_PREFIX)

/* ============================================================================
 * Socket Type and Family Constants
 * ============================================================================
 */

/**
 * @brief TCP stream socket type.
 *
 * @ingroup core_io
 * @see SOCK_STREAM
 */
#define SOCKET_STREAM_TYPE SOCK_STREAM

/**
 * @brief UDP datagram socket type.
 *
 * @ingroup core_io
 * @see SOCK_DGRAM
 */
#define SOCKET_DGRAM_TYPE SOCK_DGRAM

/**
 * @brief Unspecified address family.
 *
 * @ingroup core_io
 * @see AF_UNSPEC
 */
#define SOCKET_AF_UNSPEC AF_UNSPEC

/**
 * @brief IPv4 address family.
 *
 * @ingroup core_io
 * @see AF_INET
 */
#define SOCKET_AF_INET AF_INET

/**
 * @brief IPv6 address family.
 *
 * @ingroup core_io
 * @see AF_INET6
 */
#define SOCKET_AF_INET6 AF_INET6

/**
 * @brief Unix domain socket address family.
 *
 * @ingroup core_io
 * @see AF_UNIX
 */
#define SOCKET_AF_UNIX AF_UNIX

/**
 * @brief TCP protocol number.
 *
 * @ingroup core_io
 * @see IPPROTO_TCP
 */
#define SOCKET_IPPROTO_TCP IPPROTO_TCP

/**
 * @brief UDP protocol number.
 *
 * @ingroup core_io
 * @see IPPROTO_UDP
 */
#define SOCKET_IPPROTO_UDP IPPROTO_UDP

/**
 * @brief IP protocol number.
 *
 * @ingroup core_io
 * @see IPPROTO_IP
 */
#define SOCKET_IPPROTO_IP IPPROTO_IP

/**
 * @brief IPv6 protocol number.
 *
 * @ingroup core_io
 * @see IPPROTO_IPV6
 */
#define SOCKET_IPPROTO_IPV6 IPPROTO_IPV6

/* ============================================================================
 * Socket Options
 * ============================================================================
 */

/**
 * @brief Socket options level.
 *
 * @ingroup core_io
 * @see SOL_SOCKET
 */
#define SOCKET_SOL_SOCKET SOL_SOCKET

/**
 * @brief Allow reuse of local addresses.
 *
 * @ingroup core_io
 * @see SO_REUSEADDR
 */
#define SOCKET_SO_REUSEADDR SO_REUSEADDR

/**
 * @brief Allow reuse of local ports (if available).
 *
 * @ingroup core_io
 * @see SO_REUSEPORT
 */
#ifdef SO_REUSEPORT
#define SOCKET_SO_REUSEPORT SO_REUSEPORT
#define SOCKET_HAS_SO_REUSEPORT 1
#else
#define SOCKET_SO_REUSEPORT 0
#define SOCKET_HAS_SO_REUSEPORT 0
#endif

/**
 * @brief SOCK_CLOEXEC flag for socket creation (if available).
 *
 * @ingroup core_io
 * @see SOCK_CLOEXEC
 */
#ifdef SOCK_CLOEXEC
#define SOCKET_SOCK_CLOEXEC SOCK_CLOEXEC
#define SOCKET_HAS_SOCK_CLOEXEC 1
#else
#define SOCKET_SOCK_CLOEXEC 0
#define SOCKET_HAS_SOCK_CLOEXEC 0
#endif

/**
 * @brief Linux-specific accept4() support flag.
 *
 * @ingroup core_io
 */
/**
 * @brief Linux-specific features detection.
 * @ingroup core_io
 *
 * Detects Linux platform (__linux__) to enable Linux-only optimizations and options:
 * - accept4(): Atomic accept with non-blocking and CLOEXEC flags.
 * - SO_DOMAIN: Socket option to query address family (AF_INET, etc.).
 *
 * On non-Linux platforms, these fall back to standard accept() + fcntl() and
 * no SO_DOMAIN support.
 *
 * @see accept4(2) Linux man page for accept4 details.
 * @see Socket_accept() portable wrapper.
 * @see getsockopt(2) for SO_DOMAIN usage.
 */
#ifdef __linux__
#define SOCKET_HAS_ACCEPT4 1
#define SOCKET_SO_DOMAIN SO_DOMAIN
#define SOCKET_HAS_SO_DOMAIN 1
#else
#define SOCKET_HAS_ACCEPT4 0
#define SOCKET_HAS_SO_DOMAIN 0
#endif

/**
 * @brief File descriptor close-on-exec flag.
 *
 * @ingroup core_io
 * @see FD_CLOEXEC
 */
#define SOCKET_FD_CLOEXEC FD_CLOEXEC

/**
 * @brief Enable broadcast transmission.
 *
 * @ingroup core_io
 * @see SO_BROADCAST
 */
#define SOCKET_SO_BROADCAST SO_BROADCAST

/**
 * @brief Enable keep-alive packets.
 *
 * @ingroup core_io
 * @see SO_KEEPALIVE
 */
#define SOCKET_SO_KEEPALIVE SO_KEEPALIVE

/**
 * @brief Receive timeout.
 *
 * @ingroup core_io
 * @see SO_RCVTIMEO
 */
#define SOCKET_SO_RCVTIMEO SO_RCVTIMEO

/**
 * @brief Send timeout.
 *
 * @ingroup core_io
 * @see SO_SNDTIMEO
 */
#define SOCKET_SO_SNDTIMEO SO_SNDTIMEO

/**
 * @brief Receive buffer size.
 *
 * @ingroup core_io
 * @see SO_RCVBUF
 */
#define SOCKET_SO_RCVBUF SO_RCVBUF

/**
 * @brief Send buffer size.
 *
 * @ingroup core_io
 * @see SO_SNDBUF
 */
#define SOCKET_SO_SNDBUF SO_SNDBUF

/**
 * @brief Peer credentials.
 *
 * @ingroup core_io
 * @see SO_PEERCRED
 */
#define SOCKET_SO_PEERCRED SO_PEERCRED

/* ============================================================================
 * TCP Options
 * ============================================================================
 */

/**
 * @brief Disable Nagle's algorithm.
 *
 * @ingroup core_io
 * @see TCP_NODELAY
 */
#define SOCKET_TCP_NODELAY TCP_NODELAY

/**
 * @brief Keep-alive idle time.
 *
 * @ingroup core_io
 * @see TCP_KEEPIDLE
 */
#define SOCKET_TCP_KEEPIDLE TCP_KEEPIDLE

/**
 * @brief Keep-alive interval.
 *
 * @ingroup core_io
 * @see TCP_KEEPINTVL
 */
#define SOCKET_TCP_KEEPINTVL TCP_KEEPINTVL

/**
 * @brief Keep-alive probe count.
 *
 * @ingroup core_io
 * @see TCP_KEEPCNT
 */
#define SOCKET_TCP_KEEPCNT TCP_KEEPCNT

/**
 * @brief TCP congestion control algorithm (if available).
 *
 * @ingroup core_io
 * @see TCP_CONGESTION
 */
#ifdef TCP_CONGESTION
#define SOCKET_TCP_CONGESTION TCP_CONGESTION
#define SOCKET_HAS_TCP_CONGESTION 1
#else
#define SOCKET_HAS_TCP_CONGESTION 0
#endif

/**
 * @brief TCP Fast Open support (if available).
 *
 * @ingroup core_io
 * @see TCP_FASTOPEN
 */
#ifdef TCP_FASTOPEN
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN
#define SOCKET_HAS_TCP_FASTOPEN 1
#elif defined(TCP_FASTOPEN_CONNECT)
#define SOCKET_TCP_FASTOPEN TCP_FASTOPEN_CONNECT
#define SOCKET_HAS_TCP_FASTOPEN 1
#else
#define SOCKET_HAS_TCP_FASTOPEN 0
#endif

/**
 * @brief TCP user timeout support (if available).
 *
 * @ingroup core_io
 * @see TCP_USER_TIMEOUT
 */
#ifdef TCP_USER_TIMEOUT
#define SOCKET_TCP_USER_TIMEOUT TCP_USER_TIMEOUT
#define SOCKET_HAS_TCP_USER_TIMEOUT 1
#else
#define SOCKET_HAS_TCP_USER_TIMEOUT 0
#endif

/**
 * @brief TCP_DEFER_ACCEPT option for SYN flood protection.
 *
 * Linux-specific option that delays accept() completion until client sends data.
 * On BSD/macOS, use SO_ACCEPTFILTER instead.
 *
 * @ingroup security
 * @see TCP_DEFER_ACCEPT
 */
#ifdef TCP_DEFER_ACCEPT
#define SOCKET_TCP_DEFER_ACCEPT TCP_DEFER_ACCEPT
#define SOCKET_HAS_TCP_DEFER_ACCEPT 1
#else
#define SOCKET_HAS_TCP_DEFER_ACCEPT 0
#endif

/**
 * @brief SO_ACCEPTFILTER support flag.
 *
 * BSD/macOS equivalent of TCP_DEFER_ACCEPT. Used with struct accept_filter_arg
 * and filter name "dataready".
 *
 * @ingroup security
 * @see SO_ACCEPTFILTER
 */
#ifdef SO_ACCEPTFILTER
#define SOCKET_HAS_SO_ACCEPTFILTER 1
#else
#define SOCKET_HAS_SO_ACCEPTFILTER 0
#endif

/* ============================================================================
 * IPv6 Options
 * ============================================================================
 */

/**
 * @brief IPv6 only flag.
 *
 * Restricts socket to IPv6 only (no IPv4-mapped IPv6 addresses).
 *
 * @ingroup core_io
 * @see IPV6_V6ONLY
 */
#define SOCKET_IPV6_V6ONLY IPV6_V6ONLY

/**
 * @brief IPv6 multicast add membership.
 *
 * @ingroup core_io
 * @see IPV6_ADD_MEMBERSHIP, IPV6_JOIN_GROUP
 */
#ifdef IPV6_ADD_MEMBERSHIP
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_ADD_MEMBERSHIP
#elif defined(IPV6_JOIN_GROUP)
#define SOCKET_IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#else
#error "IPv6 multicast add membership not supported on this platform"
#endif

/**
 * @brief IPv6 multicast drop membership.
 *
 * @ingroup core_io
 * @see IPV6_DROP_MEMBERSHIP, IPV6_LEAVE_GROUP
 */
#ifdef IPV6_DROP_MEMBERSHIP
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_DROP_MEMBERSHIP
#elif defined(IPV6_LEAVE_GROUP)
#define SOCKET_IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#else
#error "IPv6 multicast drop membership not supported on this platform"
#endif

/**
 * @brief IPv6 unicast hop limit.
 *
 * @ingroup core_io
 * @see IPV6_UNICAST_HOPS
 */
#define SOCKET_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS

/* ============================================================================
 * IP Options
 * ============================================================================
 */

/**
 * @brief IP time to live.
 *
 * @ingroup core_io
 * @see IP_TTL
 */
#define SOCKET_IP_TTL IP_TTL

/**
 * @brief IP multicast add membership.
 *
 * @ingroup core_io
 * @see IP_ADD_MEMBERSHIP
 */
#define SOCKET_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP

/**
 * @brief IP multicast drop membership.
 *
 * @ingroup core_io
 * @see IP_DROP_MEMBERSHIP
 */
#define SOCKET_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP

/* ============================================================================
 * Address and Name Info Flags
 * ============================================================================
 */

/**
 * @brief Passive socket flag for getaddrinfo().
 *
 * @ingroup core_io
 * @see AI_PASSIVE
 */
#define SOCKET_AI_PASSIVE AI_PASSIVE

/**
 * @brief Numeric host address flag for getaddrinfo().
 *
 * @ingroup core_io
 * @see AI_NUMERICHOST
 */
#define SOCKET_AI_NUMERICHOST AI_NUMERICHOST

/**
 * @brief Numeric service port flag for getaddrinfo().
 *
 * @ingroup core_io
 * @see AI_NUMERICSERV
 */
#define SOCKET_AI_NUMERICSERV AI_NUMERICSERV

/**
 * @brief Numeric host address flag for getnameinfo().
 *
 * @ingroup core_io
 * @see NI_NUMERICHOST
 */
#define SOCKET_NI_NUMERICHOST NI_NUMERICHOST

/**
 * @brief Numeric service port flag for getnameinfo().
 *
 * @ingroup core_io
 * @see NI_NUMERICSERV
 */
#define SOCKET_NI_NUMERICSERV NI_NUMERICSERV

/**
 * @brief Maximum host name length for getnameinfo().
 *
 * @ingroup core_io
 * @see NI_MAXHOST
 */
#define SOCKET_NI_MAXHOST NI_MAXHOST

/**
 * @brief Maximum service name length for getnameinfo().
 *
 * @ingroup core_io
 * @see NI_MAXSERV
 */
#define SOCKET_NI_MAXSERV NI_MAXSERV

/* ============================================================================
 * Shutdown and Message Flags
 * ============================================================================
 */

/**
 * @brief Shutdown read direction.
 *
 * @ingroup core_io
 * @see SHUT_RD
 */
#define SOCKET_SHUT_RD SHUT_RD

/**
 * @brief Shutdown write direction.
 *
 * @ingroup core_io
 * @see SHUT_WR
 */
#define SOCKET_SHUT_WR SHUT_WR

/**
 * @brief Shutdown both read and write directions.
 *
 * @ingroup core_io
 * @see SHUT_RDWR
 */
#define SOCKET_SHUT_RDWR SHUT_RDWR

/**
 * @brief MSG_NOSIGNAL fallback for platforms without it.
 *
 * Suppress SIGPIPE on send operations (Linux/FreeBSD).
 * On platforms without MSG_NOSIGNAL (macOS), we use SO_NOSIGPIPE instead
 * which is set at socket creation time. When MSG_NOSIGNAL is unavailable,
 * we define it as 0 so it can be safely OR'd into flags without effect.
 *
 * @ingroup core_io
 * @see MSG_NOSIGNAL
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/**
 * @brief Suppress SIGPIPE on send operations.
 *
 * @ingroup core_io
 * @see MSG_NOSIGNAL
 */
#define SOCKET_MSG_NOSIGNAL MSG_NOSIGNAL

/**
 * @brief SO_NOSIGPIPE support flag.
 *
 * BSD/macOS socket option to suppress SIGPIPE.
 * This is set once at socket creation time as an alternative to MSG_NOSIGNAL.
 * On Linux, MSG_NOSIGNAL is preferred and this macro will be 0.
 *
 * @ingroup core_io
 * @see SO_NOSIGPIPE
 */
#ifdef SO_NOSIGPIPE
#define SOCKET_HAS_SO_NOSIGPIPE 1
#else
#define SOCKET_HAS_SO_NOSIGPIPE 0
#endif

/* ============================================================================
 * Default Parameters
 * ============================================================================
 */

/**
 * @brief Default TCP keep-alive idle time (seconds).
 *
 * @ingroup core_io
 */
#define SOCKET_DEFAULT_KEEPALIVE_IDLE 60

/**
 * @brief Default TCP keep-alive interval (seconds).
 *
 * @ingroup core_io
 */
#define SOCKET_DEFAULT_KEEPALIVE_INTERVAL 10

/**
 * @brief Default TCP keep-alive probe count.
 *
 * @ingroup core_io
 */
#define SOCKET_DEFAULT_KEEPALIVE_COUNT 3

/**
 * @brief Default datagram TTL value.
 *
 * @ingroup core_io
 */
#define SOCKET_DEFAULT_DATAGRAM_TTL 64

/**
 * @brief Default multicast interface index.
 *
 * @ingroup core_io
 */
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
 * @brief Set global memory limit for Arena allocations.
 * @ingroup foundation
 * @param max_bytes Maximum total bytes (0 = unlimited, default).
 * @threadsafe Yes (atomic store)
 * @see SocketConfig_get_max_memory() to query the current limit.
 * @see SocketConfig_get_memory_used() to see current usage.
 * @see Arena_T for memory allocation that respects this limit.
 */
extern void SocketConfig_set_max_memory (size_t max_bytes);

/**
 * @brief Get current global memory limit.
 * @ingroup foundation
 * @return Maximum bytes configured (0 = unlimited).
 * @threadsafe Yes (atomic load)
 * @see SocketConfig_set_max_memory() to set the limit.
 * @see SocketConfig_get_memory_used() to see current usage.
 */
extern size_t SocketConfig_get_max_memory (void);

/**
 * @brief Get current total memory usage.
 * @ingroup foundation
 * @return Total bytes currently allocated via Arena.
 * @threadsafe Yes (atomic load)
 * @see SocketConfig_set_max_memory() to set the limit that this usage is checked against.
 * @see Arena_T for the allocator that tracks this usage.
 */
extern size_t SocketConfig_get_memory_used (void);

/**
 * @brief Port number validation macro.
 *
 * @param p Port number to validate.
 * @return Non-zero if port is valid (0-65535).
 * @ingroup foundation
 */
#define SOCKET_VALID_PORT(p) ((int)(p) >= 0 && (int)(p) <= 65535)

/**
 * @brief Buffer size validation macro.
 *
 * @param s Buffer size to validate.
 * @return Non-zero if buffer size is valid.
 * @ingroup foundation
 * @see SOCKET_MIN_BUFFER_SIZE, SOCKET_MAX_BUFFER_SIZE
 */
#define SOCKET_VALID_BUFFER_SIZE(s)                                           \
  ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE                                      \
   && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)

/**
 * @brief Connection count validation macro.
 *
 * @param c Connection count to validate.
 * @return Non-zero if connection count is valid.
 * @ingroup foundation
 * @see SOCKET_MAX_CONNECTIONS
 */
#define SOCKET_VALID_CONNECTION_COUNT(c)                                      \
  ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)

/**
 * @brief Poll events validation macro.
 *
 * @param e Number of poll events to validate.
 * @return Non-zero if poll events count is valid.
 * @ingroup foundation
 * @see SOCKET_MAX_POLL_EVENTS
 */
#define SOCKET_VALID_POLL_EVENTS(e)                                           \
  ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)

/**
 * @brief IP string validation macro.
 *
 * @param ip IP string to validate.
 * @return Non-zero if IP string is valid (non-null, non-empty).
 * @ingroup foundation
 */
#define SOCKET_VALID_IP_STRING(ip) ((ip) != NULL && (ip)[0] != '\0')

/**
 * @brief Safe file descriptor close macro.
 *
 * Closes file descriptor with proper POSIX.1-2008 EINTR handling.
 * Per POSIX spec, do NOT retry close() on EINTR as the file descriptor
 * state is unspecified. EINTR is treated as success since the FD is
 * likely closed anyway.
 *
 * @param fd File descriptor to close (ignored if negative).
 * @ingroup foundation
 * @see close(2) for system call documentation.
 */
#define SAFE_CLOSE(fd)                                                        \
  do                                                                          \
    {                                                                         \
      if ((fd) >= 0)                                                          \
        {                                                                     \
          int _r = close (fd);                                                \
          if (_r < 0 && errno != EINTR)                                       \
            fprintf (stderr, "close failed: %s\n",                            \
                     Socket_safe_strerror (errno));                           \
        }                                                                     \
    }                                                                         \
  while (0)

#endif /* SOCKETCONFIG_INCLUDED */
