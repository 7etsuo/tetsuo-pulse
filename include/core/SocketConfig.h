/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETCONFIG_INCLUDED
#define SOCKETCONFIG_INCLUDED

/**
 * @file SocketConfig.h
 * @brief Compile-time and runtime configuration constants, limits, and
 * platform adaptations.
 *
 * Central hub for all library configuration: version info, size limits, buffer
 * capacities, timeout defaults, feature flags (HTTP, TLS, WebSocket),
 * platform-specific options (epoll/kqueue, SO_REUSEPORT), and socket option
 * mappings. Enables customizable builds via CMake flags (-DENABLE_TLS=ON,
 * -DSOCKET_MAX_CONNECTIONS=5000) and runtime tuning via functions like
 * SocketConfig_set_max_memory().
 *
 * ## Key Configuration Areas
 *
 * ### Size and Capacity Limits
 * - Connection pools: SOCKET_MAX_CONNECTIONS (default 10k)
 * - Buffers: SOCKET_MAX_BUFFER_SIZE (1MB), UDP_MAX_PAYLOAD (65k)
 * - Arenas: ARENA_CHUNK_SIZE (10k), global limit via set_max_memory()
 *
 * ### Feature Flags
 * - SOCKET_HAS_TLS: TLS 1.3 support (OpenSSL/LibreSSL)
 * - SOCKET_HAS_HTTP: HTTP/1.1 + HTTP/2 with HPACK
 * - SOCKET_HAS_WEBSOCKET: RFC 6455 WebSocket
 *
 * ### Platform Detection and Backends
 * - Linux: epoll, accept4(), TCP_DEFER_ACCEPT
 * - BSD/macOS: kqueue, SO_NOSIGPIPE, SO_ACCEPTFILTER
 * - Universal: poll() fallback, MSG_NOSIGNAL handling
 *
 * ### Runtime Config
 * - Global memory limit enforcement for arenas
 * - Validation macros (SOCKET_VALID_PORT, etc.)
 * - Timeout structs (SocketTimeouts_T, SocketTimeouts_Extended_T)
 *
 * All constants can be overridden at compile-time with -D flags. Runtime
 * functions provide dynamic control where applicable. Thread-safe where noted.
 *
 * ## Overriding Defaults
 *
 * ### CMake Build Flags
 * | Flag | Default | Purpose |
 * |------|---------|---------|
 * | -DENABLE_TLS=ON | Enabled | TLS/DTLS support |
 * | -DENABLE_HTTP=ON | Enabled | HTTP protocols |
 * | -DSOCKET_MAX_CONNECTIONS=10000 | 10k | Pool size limit |
 *
 * ### Runtime Functions
 * - SocketConfig_set_max_memory(bytes) - Global arena limit
 * - SocketConfig_get_memory_used() - Current usage query
 *
 * ## Platform Requirements
 *
 * - POSIX.1-2008 compliant system (Linux, BSD, macOS)
 * - C11 compiler with stdatomic.h support for thread safety
 * - Optional: OpenSSL/LibreSSL for TLS, CMake 3.10+ for builds
 *
 * ## Validation and Safety
 *
 * - All limits enforced at runtime with NULL returns or exceptions
 * - Macros like SAFE_CLOSE handle EINTR safely
 * - Atomic operations for shared config state
 *
 * @note Many values are #ifndef guarded for easy overrides.
 * @warning Overly low limits may cause premature failures; test thoroughly.
 * @warning Feature flags affect ABI; rebuild dependent code when changed.
 *
 * @see SocketUtil.h - Runtime utilities leveraging these configs.
 * @see Arena.h - Memory allocation respecting global limits.
 * @see Socket.h - Socket creation using validated params.
 * @see @ref foundation - Base module group.
 * @see docs/CONFIGURATION.md - Detailed build and runtime config guide.
 * @see CMakeLists.txt - Build system integration.
 */

/* Standard includes required for configuration macros */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * @brief Thread-safe wrapper for strerror() with fallback handling.
 *
 * Converts error numbers to human-readable strings using thread-local storage.
 * Supports both GNU and POSIX strerror_r() variants. Returns "Unknown error #N"
 * for invalid codes.
 *
 * @param[in] errnum Error number (e.g., errno value).
 * @return Null-terminated error string (valid until next call in same thread).
 * @threadsafe Yes - uses per-thread buffers.
 */
extern const char *Socket_safe_strerror (int errnum);

/* ============================================================================
 * Library Version
 * ============================================================================
 */

/**
 * @brief Major version number.
 */
#define SOCKET_VERSION_MAJOR 0

/**
 * @brief Minor version number.
 */
#define SOCKET_VERSION_MINOR 1

/**
 * @brief Patch version number.
 */
#define SOCKET_VERSION_PATCH 0

/**
 * @brief Version string for human-readable output.
 */
#define SOCKET_VERSION_STRING "0.1.0"

/**
 * @brief Numeric version for compile-time comparisons.
 *
 * Calculated as: (MAJOR * 10000) + (MINOR * 100) + PATCH
 *
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
 */
#ifndef SOCKET_MAX_CONNECTIONS
#define SOCKET_MAX_CONNECTIONS 10000UL
#endif

/**
 * @brief Maximum buffer size per connection.
 *
 * Can be overridden at compile time with -DSOCKET_MAX_BUFFER_SIZE=value.
 *
 */
#ifndef SOCKET_MAX_BUFFER_SIZE
#define SOCKET_MAX_BUFFER_SIZE (1024 * 1024) /* 1MB */
#endif

/**
 * @brief Minimum buffer size per connection.
 *
 */
#ifndef SOCKET_MIN_BUFFER_SIZE
#define SOCKET_MIN_BUFFER_SIZE 512
#endif

/**
 * @brief Initial capacity for SocketBuf when doubling from zero.
 *
 * Used by SocketBuf_reserve() when calculating new capacity.
 *
 */
#ifndef SOCKETBUF_INITIAL_CAPACITY
#define SOCKETBUF_INITIAL_CAPACITY 4096
#endif

/**
 * @brief Allocation overhead for SocketBuf capacity calculations.
 *
 * Safety margin to account for arena alignment and metadata.
 *
 */
#ifndef SOCKETBUF_ALLOC_OVERHEAD
#define SOCKETBUF_ALLOC_OVERHEAD 64
#endif

/**
 * @brief Maximum capacity for readline temporary buffer.
 *
 * Limits stack allocation in SocketBuf_readline() for safety.
 *
 */
#ifndef SOCKETBUF_MAX_LINE_LENGTH
#define SOCKETBUF_MAX_LINE_LENGTH 8192
#endif

/**
 * @brief Maximum UDP payload size excluding headers.
 *
 * Respects IPv4/IPv6 protocol maximums to avoid fragmentation.
 *
 */
#ifndef UDP_MAX_PAYLOAD
#define UDP_MAX_PAYLOAD                                                       \
  65507UL /* IPv4/6 max UDP payload excluding headers                         \
           */
#endif

/**
 * @brief Safe UDP payload size for Ethernet MTU.
 *
 * Ensures packets fit within standard 1500-byte Ethernet MTU
 * after IP/UDP headers (~28 bytes).
 *
 */
#ifndef SAFE_UDP_SIZE
#define SAFE_UDP_SIZE 1472UL /* Safe for Ethernet MTU (1500 - IP/UDP ~28) */
#endif

/**
 * @brief Fallback buffer size for sendfile operations.
 *
 * Used when kernel sendfile() is unavailable (TLS connections, unsupported
 * platforms) or fails. The buffer mediates read/write loops in
 * socket_sendfile_fallback().
 *
 * ## Rationale for 8192 Bytes
 *
 * - **Page alignment**: 8KB = 2 pages on most systems (4KB page size),
 *   optimizing kernel buffer cache utilization and reducing TLB misses.
 * - **Network efficiency**: Fits within typical socket buffer chunks and
 *   allows efficient pipelining of read→send cycles without excessive
 *   context switches.
 * - **Stack safety**: Small enough for stack allocation (used in
 *   sendfile_transfer_loop) without risking stack overflow.
 * - **Performance trade-offs**: Larger buffers (64KB+) improve throughput
 *   for bulk transfers but waste memory for small files and increase
 *   latency for concurrent connections. 8KB balances throughput with
 *   responsiveness.
 *
 * Can be overridden at compile time with
 * -DSOCKET_SENDFILE_FALLBACK_BUFFER_SIZE=value.
 *
 * @note Kernel sendfile() bypasses this buffer entirely via zero-copy DMA.
 * @see Socket_sendfile() in src/socket/Socket-iov.c
 * @see sendfile_transfer_loop() for buffer usage pattern
 */
#ifndef SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE
#define SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE 8192
#endif

/**
 * @brief Maximum IP TTL (Time To Live) value.
 *
 * Standard maximum for IP packets.
 *
 */
#ifndef SOCKET_MAX_TTL
#define SOCKET_MAX_TTL 255 /* Standard IP TTL max */
#endif

/**
 * @brief Maximum IPv6 prefix length in bits.
 *
 */
#ifndef SOCKET_IPV6_MAX_PREFIX
#define SOCKET_IPV6_MAX_PREFIX 128 /* IPv6 address bits */
#endif

/**
 * @brief Maximum IPv4 prefix length in bits.
 *
 */
#ifndef SOCKET_IPV4_MAX_PREFIX
#define SOCKET_IPV4_MAX_PREFIX 32 /* IPv4 address bits */
#endif

/**
 * @brief Maximum TCP/UDP port number.
 *
 * Standard maximum for port numbers.
 *
 */
#ifndef SOCKET_MAX_PORT
#define SOCKET_MAX_PORT 65535 /* Standard TCP/UDP port max */
#endif

/**
 * @brief Maximum events per poll iteration.
 *
 * Can be overridden at compile time with -DSOCKET_MAX_POLL_EVENTS=value.
 *
 */
#ifndef SOCKET_MAX_POLL_EVENTS
#define SOCKET_MAX_POLL_EVENTS 10000
#endif

/**
 * @brief Maximum backlog for listen() system call.
 *
 */
#ifndef SOCKET_MAX_LISTEN_BACKLOG
#define SOCKET_MAX_LISTEN_BACKLOG 1024
#endif

/**
 * @brief Maximum file descriptors per SCM_RIGHTS message.
 *
 * Unix domain socket file descriptor passing limit.
 *
 */
#ifndef SOCKET_MAX_FDS_PER_MSG
#define SOCKET_MAX_FDS_PER_MSG 253 /* SCM_MAX_FD on most POSIX systems */
#endif

/**
 * @brief Hash table size for socket data mapping.
 *
 * Prime number for optimal hash distribution.
 *
 */
#ifndef SOCKET_HASH_TABLE_SIZE
#define SOCKET_HASH_TABLE_SIZE 1021
#endif

/**
 * @brief Maximum hash chain length before rejecting insertion.
 *
 * Defense-in-depth against algorithmic complexity attacks where an attacker
 * could craft inputs that cause hash collisions, degrading O(1) lookups to O(n).
 * When a hash bucket exceeds this chain length, new registrations are rejected.
 *
 * Set to 0 to disable chain length checking (not recommended).
 *
 */
#ifndef SOCKET_MAX_HASH_CHAIN_LENGTH
#define SOCKET_MAX_HASH_CHAIN_LENGTH 16
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
 */
#ifndef ARENA_CHUNK_SIZE
#define ARENA_CHUNK_SIZE (10 * 1024) /* 10KB */
#endif

/**
 * @brief Maximum allocation size for arena.
 *
 * Matches centralized security limit to prevent overflow attacks.
 *
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
 */
#ifndef ARENA_MAX_FREE_CHUNKS
#define ARENA_MAX_FREE_CHUNKS 10
#endif

/**
 * @brief Buffer size for arena error messages.
 *
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
 */
#ifndef SOCKETBUF_MIN_CAPACITY
#define SOCKETBUF_MIN_CAPACITY 512
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

/**
 * @brief Standard 16KB buffer size for WebSocket and HTTP/2 streams.
 *
 * Optimized for HTTP/2 multiplexing scenarios where many concurrent streams
 * may exist on a single connection. Smaller than standard WebSocket buffers
 * (64KB) to reduce memory footprint while maintaining good performance.
 *
 * Used by:
 * - WebSocket-over-HTTP/2 (RFC 8441)
 * - HTTP/2 stream buffers
 */
#ifndef SOCKET_BUFFER_SIZE_16KB
#define SOCKET_BUFFER_SIZE_16KB (16 * 1024)
#endif

/* ============================================================================
 * DNS Configuration
 * ============================================================================
 */

/**
 * @brief Number of DNS worker threads.
 *
 */
#ifndef SOCKET_DNS_THREAD_COUNT
#define SOCKET_DNS_THREAD_COUNT 4
#endif

/**
 * @brief Maximum pending DNS requests.
 *
 */
#ifndef SOCKET_DNS_MAX_PENDING
#define SOCKET_DNS_MAX_PENDING 1000
#endif

/**
 * @brief Maximum DNS label length.
 *
 * Per RFC 1035, DNS labels are limited to 63 characters.
 *
 */
#ifndef SOCKET_DNS_MAX_LABEL_LENGTH
#define SOCKET_DNS_MAX_LABEL_LENGTH 63
#endif

/**
 * @brief DNS worker thread stack size.
 *
 */
#ifndef SOCKET_DNS_WORKER_STACK_SIZE
#define SOCKET_DNS_WORKER_STACK_SIZE (128 * 1024)
#endif

/**
 * @brief DNS request hash table size.
 *
 * Prime number for optimal hash distribution.
 *
 */
#ifndef SOCKET_DNS_REQUEST_HASH_SIZE
#define SOCKET_DNS_REQUEST_HASH_SIZE 1021
#endif

/**
 * @brief Completion pipe read buffer size.
 *
 */
#ifndef SOCKET_DNS_PIPE_BUFFER_SIZE
#define SOCKET_DNS_PIPE_BUFFER_SIZE 256
#endif

/**
 * @brief Completion signal byte value for DNS pipe signaling.
 *
 */
#ifndef SOCKET_DNS_COMPLETION_SIGNAL_BYTE
#define SOCKET_DNS_COMPLETION_SIGNAL_BYTE 1
#endif

/**
 * @brief Port number string buffer size.
 *
 */
#ifndef SOCKET_DNS_PORT_STR_SIZE
#define SOCKET_DNS_PORT_STR_SIZE 16
#endif

/**
 * @brief Thread name buffer size.
 *
 * POSIX maximum 16 characters including null terminator.
 *
 */
#ifndef SOCKET_DNS_THREAD_NAME_SIZE
#define SOCKET_DNS_THREAD_NAME_SIZE 16
#endif

/**
 * @brief Default DNS cache TTL in seconds.
 *
 * Controls how long DNS resolution results are cached before being
 * considered stale. Default 5 minutes balances freshness with performance.
 *
 */
#ifndef SOCKET_DNS_DEFAULT_CACHE_TTL_SECONDS
#define SOCKET_DNS_DEFAULT_CACHE_TTL_SECONDS 300
#endif

/**
 * @brief Default maximum DNS cache entries.
 *
 * Limits memory usage by capping cached DNS results.
 * When exceeded, oldest entries are evicted (LRU).
 *
 */
#ifndef SOCKET_DNS_DEFAULT_CACHE_MAX_ENTRIES
#define SOCKET_DNS_DEFAULT_CACHE_MAX_ENTRIES 1000
#endif

/**
 * @brief DNS cache hash table size.
 *
 * Prime number for optimal hash distribution in cache lookups.
 *
 */
#ifndef SOCKET_DNS_CACHE_HASH_SIZE
#define SOCKET_DNS_CACHE_HASH_SIZE 1021
#endif

/* ============================================================================
 * Poll Backend Configuration
 * ============================================================================
 */

/**
 * @brief Initial file descriptor capacity for poll backend.
 *
 */
#ifndef POLL_INITIAL_FDS
#define POLL_INITIAL_FDS 64
#endif

/**
 * @brief Initial file descriptor map size.
 *
 */
#ifndef POLL_INITIAL_FD_MAP_SIZE
#define POLL_INITIAL_FD_MAP_SIZE 1024
#endif

/**
 * @brief File descriptor map expansion increment.
 *
 */
#ifndef POLL_FD_MAP_EXPAND_INCREMENT
#define POLL_FD_MAP_EXPAND_INCREMENT 1024
#endif

/**
 * @brief SOCKET_POLL_MAX_REGISTERED - Maximum sockets registered per poll
 * instance
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
 */
#ifndef SOCKET_MAX_TIMER_DELAY_MS
#define SOCKET_MAX_TIMER_DELAY_MS (INT64_C (31536000000)) /* 365 days */
#endif

/**
 * @brief Timer error buffer size for detailed error messages.
 *
 */
#ifndef SOCKET_TIMER_ERROR_BUFSIZE
#define SOCKET_TIMER_ERROR_BUFSIZE 256
#endif

/**
 * @brief Initial capacity for timer heap array.
 *
 */
#ifndef SOCKET_TIMER_HEAP_INITIAL_CAPACITY
#define SOCKET_TIMER_HEAP_INITIAL_CAPACITY 16
#endif

/**
 * @brief Growth factor when resizing timer heap.
 *
 * Must be greater than 1.
 *
 */
#ifndef SOCKET_TIMER_HEAP_GROWTH_FACTOR
#define SOCKET_TIMER_HEAP_GROWTH_FACTOR 2
#endif

/**
 * @brief Maximum number of timers per heap.
 *
 * Prevents resource exhaustion.
 *
 */
#ifndef SOCKET_MAX_TIMERS_PER_HEAP
#define SOCKET_MAX_TIMERS_PER_HEAP 100000
#endif

/**
 * @brief Minimum delay for one-shot timers.
 *
 */
#ifndef SOCKET_TIMER_MIN_DELAY_MS
#define SOCKET_TIMER_MIN_DELAY_MS 0
#endif

/**
 * @brief Minimum interval for repeating timers.
 *
 */
#ifndef SOCKET_TIMER_MIN_INTERVAL_MS
#define SOCKET_TIMER_MIN_INTERVAL_MS 1
#endif

/**
 * @brief Initial timer ID value.
 *
 * Wraps at UINT64_MAX.
 *
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
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC
#define SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC 100
#endif

/**
 * @brief Default burst capacity for connection rate limiter.
 *
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_BURST
#define SOCKET_RATELIMIT_DEFAULT_BURST 50
#endif

/**
 * @brief Default maximum connections per IP address.
 *
 * 0 = unlimited.
 *
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP
#define SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP 10
#endif

/**
 * @brief Default bandwidth limit in bytes per second.
 *
 * 0 = unlimited.
 *
 */
#ifndef SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS
#define SOCKET_RATELIMIT_DEFAULT_BANDWIDTH_BPS 0
#endif

/**
 * @brief IP tracker hash table size.
 *
 * Prime number for good distribution.
 *
 */
#ifndef SOCKET_IP_TRACKER_HASH_SIZE
#define SOCKET_IP_TRACKER_HASH_SIZE 1021
#endif

/**
 * @brief Maximum IP address string length.
 *
 * IPv6 with scope ID.
 *
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
 */
#ifndef SOCKET_SYN_DEFAULT_WINDOW_MS
#define SOCKET_SYN_DEFAULT_WINDOW_MS 10000
#endif

/**
 * @brief Maximum connection attempts per IP per window.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_PER_WINDOW
#define SOCKET_SYN_DEFAULT_MAX_PER_WINDOW 50
#endif

/**
 * @brief Global connection rate limit.
 *
 * All IPs, per second.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC
#define SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC 1000
#endif

/**
 * @brief Minimum success/attempt ratio before IP becomes suspect.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO
#define SOCKET_SYN_DEFAULT_MIN_SUCCESS_RATIO 0.3f
#endif

/**
 * @brief Artificial delay for throttled connections.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS
#define SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS 100
#endif

/**
 * @brief Block duration for misbehaving IPs.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS
#define SOCKET_SYN_DEFAULT_BLOCK_DURATION_MS 60000
#endif

/**
 * @brief TCP_DEFER_ACCEPT timeout for challenged connections.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_DEFER_SEC
#define SOCKET_SYN_DEFAULT_DEFER_SEC 5
#endif

/**
 * @brief Score threshold below which connections are throttled.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_THROTTLE
#define SOCKET_SYN_DEFAULT_SCORE_THROTTLE 0.7f
#endif

/**
 * @brief Score threshold below which connections are challenged.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_CHALLENGE
#define SOCKET_SYN_DEFAULT_SCORE_CHALLENGE 0.4f
#endif

/**
 * @brief Score threshold below which connections are blocked.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_BLOCK
#define SOCKET_SYN_DEFAULT_SCORE_BLOCK 0.2f
#endif

/**
 * @brief Score recovery rate per second.
 *
 * Time-based decay.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_SCORE_DECAY
#define SOCKET_SYN_DEFAULT_SCORE_DECAY 0.01f
#endif

/**
 * @brief Score penalty per new connection attempt.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT
#define SOCKET_SYN_DEFAULT_PENALTY_ATTEMPT 0.02f
#endif

/**
 * @brief Score penalty per connection failure.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_PENALTY_FAILURE
#define SOCKET_SYN_DEFAULT_PENALTY_FAILURE 0.05f
#endif

/**
 * @brief Score reward per successful connection.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_REWARD_SUCCESS
#define SOCKET_SYN_DEFAULT_REWARD_SUCCESS 0.05f
#endif

/**
 * @brief Maximum unique IPs to track.
 *
 * LRU eviction when exceeded.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS
#define SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS 100000
#endif

/**
 * @brief Maximum whitelist entries.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_WHITELIST
#define SOCKET_SYN_DEFAULT_MAX_WHITELIST 1000
#endif

/**
 * @brief Maximum blacklist entries.
 *
 */
#ifndef SOCKET_SYN_DEFAULT_MAX_BLACKLIST
#define SOCKET_SYN_DEFAULT_MAX_BLACKLIST 10000
#endif

/**
 * @brief Score threshold at or above which IP is considered trusted.
 *
 * For reputation tracking.
 *
 */
#ifndef SOCKET_SYN_TRUSTED_SCORE_THRESHOLD
#define SOCKET_SYN_TRUSTED_SCORE_THRESHOLD 0.9f
#endif

/**
 * @brief IPv6 address size in bytes.
 *
 * Used for CIDR parsing.
 *
 */
#ifndef SOCKET_IPV6_ADDR_BYTES
#define SOCKET_IPV6_ADDR_BYTES 16
#endif

/**
 * @brief IPv4 address size in bytes.
 *
 */
#ifndef SOCKET_IPV4_ADDR_BYTES
#define SOCKET_IPV4_ADDR_BYTES 4
#endif

/**
 * @brief Bits per byte.
 *
 * For CIDR prefix calculations.
 *
 */
#ifndef SOCKET_BITS_PER_BYTE
#define SOCKET_BITS_PER_BYTE 8
#endif

/**
 * @brief Minimum duration for TimeWindow to prevent division by zero.
 *
 * Enforces a minimum window duration of 1ms in TimeWindow_init.
 * This prevents division by zero in rate calculations.
 *
 */
#ifndef TIMEWINDOW_MIN_DURATION_MS
#define TIMEWINDOW_MIN_DURATION_MS 1
#endif

/**
 * @brief Maximum allowed window duration for SYN protection.
 *
 * Caps config.window_duration_ms to prevent excessive memory usage.
 * Security limit: 60 seconds maximum.
 *
 */
#ifndef SOCKET_SYN_MAX_WINDOW_MS
#define SOCKET_SYN_MAX_WINDOW_MS 60000
#endif

/**
 * @brief Maximum allowed attempts per window for SYN protection.
 *
 * Caps config.max_attempts_per_window to prevent abuse.
 *
 */
#ifndef SOCKET_SYN_MAX_ATTEMPTS_CAP
#define SOCKET_SYN_MAX_ATTEMPTS_CAP 1000
#endif

/**
 * @brief Maximum allowed global connections per second.
 *
 * Caps config.max_global_per_second to prevent resource exhaustion.
 *
 */
#ifndef SOCKET_SYN_MAX_GLOBAL_PER_SEC_CAP
#define SOCKET_SYN_MAX_GLOBAL_PER_SEC_CAP 10000
#endif

/**
 * @brief Score adjustment factor for challenge threshold.
 *
 * Used when score_challenge > score_throttle to auto-correct.
 *
 */
#ifndef SOCKET_SYN_CHALLENGE_ADJUST_FACTOR
#define SOCKET_SYN_CHALLENGE_ADJUST_FACTOR 0.8f
#endif

/**
 * @brief Score adjustment factor for block threshold.
 *
 * Used when score_block > score_challenge to auto-correct.
 *
 */
#ifndef SOCKET_SYN_BLOCK_ADJUST_FACTOR
#define SOCKET_SYN_BLOCK_ADJUST_FACTOR 0.5f
#endif

/**
 * @brief Maximum tracked IPs cap for SYN protection.
 *
 * Prevents OOM from excessive tracked IP allocations.
 * Security limit: 1 million IPs maximum.
 *
 */
#ifndef SOCKET_SYN_MAX_TRACKED_IPS_CAP
#define SOCKET_SYN_MAX_TRACKED_IPS_CAP 1000000
#endif

/**
 * @brief Maximum whitelist/blacklist entries cap.
 *
 * Prevents OOM from excessive list allocations.
 *
 */
#ifndef SOCKET_SYN_MAX_LIST_CAP
#define SOCKET_SYN_MAX_LIST_CAP 10000
#endif

/**
 * @brief Fallback hash seed when cryptographic random fails.
 *
 * MurmurHash2 mixing constant; ensures deterministic fallback behavior
 * while still providing reasonable hash distribution.
 */
#ifndef SOCKET_SYN_FALLBACK_SEED
#define SOCKET_SYN_FALLBACK_SEED 0x5bd1e995U
#endif

/* ============================================================================
 * Pool Health Check Configuration
 * ============================================================================
 */

/**
 * @brief Hash table size for per-host circuit breaker entries.
 *
 * Prime number for good hash distribution.
 *
 */
#ifndef SOCKET_HEALTH_HASH_SIZE
#define SOCKET_HEALTH_HASH_SIZE 257
#endif

/**
 * @brief Consecutive failures to open circuit breaker.
 *
 * When a host reaches this many consecutive failures, the circuit
 * opens and new connections to that host are blocked.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_FAILURE_THRESHOLD
#define SOCKET_HEALTH_DEFAULT_FAILURE_THRESHOLD 5
#endif

/**
 * @brief Time in OPEN state before transitioning to HALF_OPEN.
 *
 * After this timeout, the circuit breaker allows a probe attempt.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_RESET_TIMEOUT_MS
#define SOCKET_HEALTH_DEFAULT_RESET_TIMEOUT_MS 30000
#endif

/**
 * @brief Maximum probe attempts in HALF_OPEN state.
 *
 * If all probes fail, circuit returns to OPEN for another reset_timeout.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_HALF_OPEN_MAX_PROBES
#define SOCKET_HEALTH_DEFAULT_HALF_OPEN_MAX_PROBES 3
#endif

/**
 * @brief Interval between health probe cycles.
 *
 * Background thread wakes at this interval to probe connections.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_PROBE_INTERVAL_MS
#define SOCKET_HEALTH_DEFAULT_PROBE_INTERVAL_MS 10000
#endif

/**
 * @brief Timeout for individual health probe operations.
 *
 * Each probe callback should complete within this time.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_PROBE_TIMEOUT_MS
#define SOCKET_HEALTH_DEFAULT_PROBE_TIMEOUT_MS 5000
#endif

/**
 * @brief Maximum connections to probe per cycle.
 *
 * Limits CPU usage per probe cycle.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_PROBES_PER_CYCLE
#define SOCKET_HEALTH_DEFAULT_PROBES_PER_CYCLE 10
#endif

/**
 * @brief Maximum number of circuit breaker entries.
 *
 * Limits memory usage from unbounded circuit entry creation.
 * When limit is reached, new hosts use a shared "overflow" entry.
 *
 */
#ifndef SOCKET_HEALTH_DEFAULT_MAX_CIRCUITS
#define SOCKET_HEALTH_DEFAULT_MAX_CIRCUITS 10000
#endif

/**
 * @brief Maximum length of "host:port" key string.
 *
 */
#ifndef SOCKET_HEALTH_MAX_HOST_KEY_LEN
#define SOCKET_HEALTH_MAX_HOST_KEY_LEN 256
#endif

/**
 * @brief Health check worker thread stack size.
 *
 */
#ifndef SOCKET_HEALTH_WORKER_STACK_SIZE
#define SOCKET_HEALTH_WORKER_STACK_SIZE (128 * 1024)
#endif

/* ============================================================================
 * Logging Configuration
 * ============================================================================
 */

/**
 * @brief Buffer size for formatted log messages.
 *
 */
#ifndef SOCKET_LOG_BUFFER_SIZE
#define SOCKET_LOG_BUFFER_SIZE 1024
#endif

/**
 * @brief Timestamp formatting buffer size.
 *
 */
#ifndef SOCKET_LOG_TIMESTAMP_BUFSIZE
#define SOCKET_LOG_TIMESTAMP_BUFSIZE 64
#endif

/**
 * @brief Timestamp format string.
 *
 */
#ifndef SOCKET_LOG_TIMESTAMP_FORMAT
#define SOCKET_LOG_TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#endif

/**
 * @brief Default timestamp for formatting errors.
 *
 */
#ifndef SOCKET_LOG_DEFAULT_TIMESTAMP
#define SOCKET_LOG_DEFAULT_TIMESTAMP "1970-01-01 00:00:00"
#endif

/**
 * @brief Log truncation suffix.
 *
 */
#ifndef SOCKET_LOG_TRUNCATION_SUFFIX
#define SOCKET_LOG_TRUNCATION_SUFFIX "..."
#endif

/**
 * @brief Length of log truncation suffix.
 *
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
 */
#ifndef SOCKET_ERROR_BUFSIZE
#define SOCKET_ERROR_BUFSIZE 1024
#endif

/**
 * @brief Thread-safe strerror buffer size.
 *
 */
#ifndef SOCKET_STRERROR_BUFSIZE
#define SOCKET_STRERROR_BUFSIZE 128
#endif

/**
 * @brief Maximum hostname length in error messages.
 *
 */
#ifndef SOCKET_ERROR_MAX_HOSTNAME
#define SOCKET_ERROR_MAX_HOSTNAME 255
#endif

/**
 * @brief Maximum error message length.
 *
 */
#ifndef SOCKET_ERROR_MAX_MESSAGE
#define SOCKET_ERROR_MAX_MESSAGE 512
#endif

/**
 * @brief Truncation marker for error messages.
 *
 */
#ifndef SOCKET_ERROR_TRUNCATION_MARKER
#define SOCKET_ERROR_TRUNCATION_MARKER "... (truncated)"
#endif

/**
 * @brief Size of truncation marker.
 *
 */
#ifndef SOCKET_ERROR_TRUNCATION_SIZE
#define SOCKET_ERROR_TRUNCATION_SIZE (sizeof (SOCKET_ERROR_TRUNCATION_MARKER))
#endif

/**
 * @brief Socket port string buffer size.
 *
 */
#ifndef SOCKET_PORT_STR_BUFSIZE
#define SOCKET_PORT_STR_BUFSIZE 16
#endif

/**
 * @brief Maximum extra characters for CIDR notation suffix.
 *
 * Accounts for "/" plus up to 3 digits for prefix length (e.g., "/128").
 */
#ifndef SOCKET_CIDR_SUFFIX_MAX_LEN
#define SOCKET_CIDR_SUFFIX_MAX_LEN 10
#endif

/**
 * @brief Maximum poll timeout value to prevent overflow.
 *
 * Some poll() implementations may have issues with very large values.
 * Cap at INT_MAX/2 to provide safety margin.
 */
#ifndef SOCKET_POLL_TIMEOUT_MAX
#define SOCKET_POLL_TIMEOUT_MAX (INT_MAX / 2)
#endif

/* ============================================================================
 * Platform Detection
 * ============================================================================
 */

/**
 * @brief Platform detection flag for macOS/Apple systems.
 *
 * Set to 1 when compiled under __APPLE__ macro (macOS, iOS), enabling
 * platform-specific features such as kqueue event polling backend,
 * SO_NOSIGPIPE socket option, and Darwin-specific workarounds.
 *
 * Used internally to select optimal I/O primitives and handle platform
 * differences in socket options and system calls.
 *
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
 *
 * Includes full HTTP/1.1 and HTTP/2 implementation with HPACK header
 * compression, client (SocketHTTPClient) and server (SocketHTTPServer) APIs,
 * WebSocket support.
 *
 * Set to 1 to enable HTTP features (default), 0 to disable for reduced
 * footprint. Controlled by CMake -DENABLE_HTTP=ON/OFF.
 *
 */
#ifndef SOCKET_HAS_HTTP
#define SOCKET_HAS_HTTP 1
#endif
/**
 * @brief WebSocket protocol support flag.
 *
 * Enables WebSocket RFC 6455 implementation with permessage-deflate extension
 * support. Builds on HTTP module for handshake and framing.
 *
 * Set to 1 to enable WebSocket features (default), 0 to disable.
 * Requires SOCKET_HAS_HTTP=1.
 *
 */
#ifndef SOCKET_HAS_WEBSOCKET
#define SOCKET_HAS_WEBSOCKET 1
#endif
/**
 * @brief TLS/SSL support flag.
 *
 * Enables TLS 1.3 (only, no legacy versions) and DTLS support using OpenSSL or
 * LibreSSL. Includes client/server certificate management, session resumption,
 * ALPN negotiation.
 *
 * Set to 1 to enable TLS features, 0 to disable (default for minimal builds).
 * Controlled by CMake -DENABLE_TLS=ON/OFF, auto-detects crypto library.
 *
 * Security notes:
 * - TLS 1.3 only - no support for vulnerable protocols (SSLv*, TLS 1.0/1.1)
 * - Hardened defaults: Secure ciphers, forward secrecy, no weak curves
 * - Certificate validation with OCSP stapling support
 *
 */
#ifndef SOCKET_HAS_TLS
#define SOCKET_HAS_TLS 0
#endif

/**
 * @brief io_uring async I/O support flag (Linux only).
 *
 * Enables high-performance asynchronous I/O using Linux io_uring interface.
 * Requires kernel 5.1+ (5.6+ for full features like multi-shot operations).
 * When disabled, falls back to epoll-based async I/O.
 *
 * Set to 1 by CMake -DENABLE_IO_URING=ON when liburing is available.
 * Default 0 (disabled) for compatibility.
 *
 * Runtime check: Use SocketAsync_io_uring_available() to verify kernel support.
 *
 */
#ifndef SOCKET_HAS_IO_URING
#define SOCKET_HAS_IO_URING 0
#endif

/**
 * @brief Fallback definition for IOV_MAX if not provided by system headers.
 *
 * Maximum number of I/O vectors supported for scatter/gather operations
 * (readv/writev, sendmsg/recvmsg). This limit prevents excessive memory use in
 * vectorized I/O operations and aligns with POSIX standards.
 *
 */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

/**
 * @brief sendmsg() support flag.
 *
 * Standard POSIX - always available.
 *
 */
#define SOCKET_HAS_SENDMSG 1

/**
 * @brief recvmsg() support flag.
 *
 * Standard POSIX - always available.
 *
 */
#define SOCKET_HAS_RECVMSG 1

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

/**
 * @brief Default connect timeout.
 *
 */
#ifndef SOCKET_DEFAULT_CONNECT_TIMEOUT_MS
#define SOCKET_DEFAULT_CONNECT_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/* ============================================================================
 * Happy Eyeballs (RFC 8305) Configuration
 * ============================================================================
 */

/**
 * @brief SOCKET_CONNECT_HAPPY_EYEBALLS - Enable Happy Eyeballs for
 * Socket_connect()
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
 */
#ifndef SOCKET_DEFAULT_DNS_TIMEOUT_MS
#define SOCKET_DEFAULT_DNS_TIMEOUT_MS 5000 /* 5 seconds */
#endif

/**
 * @brief Default operation timeout.
 *
 * 0 = infinite.
 *
 */
#ifndef SOCKET_DEFAULT_OPERATION_TIMEOUT_MS
#define SOCKET_DEFAULT_OPERATION_TIMEOUT_MS 0 /* Infinite */
#endif

/**
 * @brief Default idle timeout.
 *
 */
#ifndef SOCKET_DEFAULT_IDLE_TIMEOUT
#define SOCKET_DEFAULT_IDLE_TIMEOUT 300 /* 5 minutes */
#endif

/**
 * @brief Default poll timeout.
 *
 */
#ifndef SOCKET_DEFAULT_POLL_TIMEOUT
#define SOCKET_DEFAULT_POLL_TIMEOUT 1000 /* 1 second */
#endif

/**
 * @brief Basic timeout configuration structure for socket operations.
 *
 * Defines timeout parameters for core socket operations: connection
 * establishment, DNS resolution, and general read/write operations. This
 * structure provides a simple way to configure blocking vs non-blocking
 * behavior across library APIs.
 *
 * All fields are in milliseconds. A value of 0 means infinite timeout (block
 * until completion, error, or interrupt). Negative values are invalid and may
 * trigger assertions or defaults.
 *
 * Lifecycle: Stack-allocated or embedded in larger configs; no allocation/free
 * needed. Thread safety: Read-only after initialization; safe to share const
 * instances. Used by high-level APIs like Socket_connect(), SocketHTTPClient,
 * etc., for consistent timeout behavior.
 *
 * Defaults: See constants like SOCKET_DEFAULT_CONNECT_TIMEOUT_MS (30s).
 *
 * ## Fields
 *
 * | Field | Default | Description |
 * |----------------|----------------|---------------------------------------------|
 * | connect_timeout_ms | 30000 | TCP connect timeout (ms, 0=infinite) |
 * | dns_timeout_ms | 5000 | DNS resolution timeout (ms, 0=infinite) |
 * | operation_timeout_ms | 0 | General I/O timeout (ms, 0=infinite) |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketTimeouts_T timeouts = {
 *     .connect_timeout_ms = 5000,  // 5s connect
 *     .dns_timeout_ms = 2000,     // 2s DNS
 *     .operation_timeout_ms = 10000 // 10s I/O
 * };
 *
 * // Pass to API functions
 * // e.g., Socket_connect_with_timeout(host, port, &timeouts); (hypothetical)
 * @endcode
 *
 * @note These timeouts apply unless overridden by extended structs or
 * per-function params.
 * @note Infinite timeouts (0) suitable for trusted clients; use finite in
 * untrusted scenarios.
 * @warning Very short values may cause unnecessary failures on slow networks.
 *
 * @see SocketTimeouts_Extended_T - Granular per-phase timeouts.
 * @see SOCKET_DEFAULT_CONNECT_TIMEOUT_MS - Compile-time defaults.
 * @see Socket_connect() - Applies connect_timeout_ms.
 * @see SocketDNS_T - Uses dns_timeout_ms for resolutions.
 * @see @ref core_io - Related socket operations.
 * @see docs/TIMEOUTS.md - Timeout best practices and tuning.
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
 *
 * Provides granular control over timeouts for specific operation phases like
 * DNS, connect, TLS handshake, and requests. Allows fine-tuning for production
 * environments with varying latency characteristics per phase.
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
 * @see SocketConfig.h constants like SOCKET_DEFAULT_TLS_TIMEOUT_MS for
 * defaults.
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
 */
#ifndef SOCKET_DEFAULT_TLS_TIMEOUT_MS
#define SOCKET_DEFAULT_TLS_TIMEOUT_MS                                         \
  30000 /**< 30 seconds for TLS handshake */
#endif

/**
 * @brief Default request cycle timeout.
 *
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
 */
#ifndef SOCKET_DEFAULT_POOL_SIZE
#define SOCKET_DEFAULT_POOL_SIZE 1000
#endif

/**
 * @brief Default pool buffer size.
 *
 */
#ifndef SOCKET_DEFAULT_POOL_BUFSIZE
#define SOCKET_DEFAULT_POOL_BUFSIZE 8192
#endif

/**
 * @brief Default pool prewarm percentage.
 *
 */
#ifndef SOCKET_POOL_DEFAULT_PREWARM_PCT
#define SOCKET_POOL_DEFAULT_PREWARM_PCT 20
#endif

/**
 * @brief Maximum batch accepts per iteration.
 *
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
 */
#ifndef SOCKET_POOL_MAX_ASYNC_PENDING
#define SOCKET_POOL_MAX_ASYNC_PENDING 1000
#endif

/**
 * @brief Percentage divisor for calculations.
 *
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
 */
#ifndef SOCKET_POOL_STATS_WINDOW_SEC
#define SOCKET_POOL_STATS_WINDOW_SEC 60
#endif

/**
 * @brief Maximum rate limit value (connections per second).
 *
 * Security limit to prevent resource exhaustion from overly permissive
 * rate configurations. Practical upper bound for most servers.
 *
 */
#ifndef SOCKET_POOL_MAX_RATE_PER_SEC
#define SOCKET_POOL_MAX_RATE_PER_SEC 1000000
#endif

/**
 * @brief Maximum burst multiplier relative to rate.
 *
 * Limits burst size to prevent memory exhaustion in rate limiter.
 * Burst capacity = rate * multiplier.
 *
 */
#ifndef SOCKET_POOL_MAX_BURST_MULTIPLIER
#define SOCKET_POOL_MAX_BURST_MULTIPLIER 100
#endif

/**
 * @brief Maximum connections allowed per IP address.
 *
 * Security limit to prevent single-source attacks via per-IP limiting.
 * Generous default allows legitimate load balancers while limiting abuse.
 *
 */
#ifndef SOCKET_POOL_MAX_CONNECTIONS_PER_IP
#define SOCKET_POOL_MAX_CONNECTIONS_PER_IP 10000
#endif

/**
 * @brief Tokens consumed per connection accept.
 *
 * Number of rate limit tokens consumed per successful connection accept.
 * Typically 1 for simple connection counting.
 *
 */
#ifndef SOCKET_POOL_TOKENS_PER_ACCEPT
#define SOCKET_POOL_TOKENS_PER_ACCEPT 1
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
 */
#ifndef ARENA_ALIGNMENT_SIZE
#define ARENA_ALIGNMENT_SIZE sizeof (union align)
#endif

/**
 * @brief Arena validation success code.
 *
 */
#ifndef ARENA_VALIDATION_SUCCESS
#define ARENA_VALIDATION_SUCCESS 1
#endif

/**
 * @brief Arena validation failure code.
 *
 */
#ifndef ARENA_VALIDATION_FAILURE
#define ARENA_VALIDATION_FAILURE 0
#endif

/**
 * @brief Arena operation success code.
 *
 */
#ifndef ARENA_SUCCESS
#define ARENA_SUCCESS 0
#endif

/**
 * @brief Arena operation failure code.
 *
 */
#ifndef ARENA_FAILURE
#define ARENA_FAILURE (-1)
#endif

/**
 * @brief Arena chunk reused indicator.
 *
 */
#ifndef ARENA_CHUNK_REUSED
#define ARENA_CHUNK_REUSED 1
#endif

/**
 * @brief Arena chunk not reused indicator.
 *
 */
#ifndef ARENA_CHUNK_NOT_REUSED
#define ARENA_CHUNK_NOT_REUSED 0
#endif

/**
 * @brief Arena size validation success.
 *
 */
#ifndef ARENA_SIZE_VALID
#define ARENA_SIZE_VALID 1
#endif

/**
 * @brief Arena size validation failure.
 *
 */
#ifndef ARENA_SIZE_INVALID
#define ARENA_SIZE_INVALID 0
#endif

/**
 * @brief Arena out of memory error message.
 *
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
 */
#define SOCKET_MS_PER_SECOND 1000

/**
 * @brief Nanoseconds per millisecond.
 *
 */
#define SOCKET_NS_PER_MS 1000000LL

/**
 * @brief Nanoseconds per second.
 *
 */
#define SOCKET_NS_PER_SECOND 1000000000LL

/* ============================================================================
 * Async I/O Configuration
 * ============================================================================
 */

/**
 * @brief Default number of io_uring entries.
 *
 */
#define SOCKET_DEFAULT_IO_URING_ENTRIES 1024

/**
 * @brief Maximum number of events per batch.
 *
 */
#define SOCKET_MAX_EVENT_BATCH 100

/* ============================================================================
 * String Conversion Macros
 * ============================================================================
 */

/**
 * @brief Stringify macro for compile-time string conversion.
 *
 */
#define SOCKET_STRINGIFY(x) #x

/**
 * @brief Convert macro argument to string.
 *
 */
#define SOCKET_TO_STRING(x) SOCKET_STRINGIFY (x)

/**
 * @brief Valid port range string for error messages.
 *
 */
#define SOCKET_PORT_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_PORT)

/**
 * @brief Valid TTL range string for error messages.
 *
 */
#define SOCKET_TTL_VALID_RANGE "1-" SOCKET_TO_STRING (SOCKET_MAX_TTL)

/**
 * @brief Valid IPv4 prefix range string for error messages.
 *
 */
#define SOCKET_IPV4_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV4_MAX_PREFIX)

/**
 * @brief Valid IPv6 prefix range string for error messages.
 *
 */
#define SOCKET_IPV6_PREFIX_RANGE "0-" SOCKET_TO_STRING (SOCKET_IPV6_MAX_PREFIX)

/* ============================================================================
 * Socket Type and Family Constants
 * ============================================================================
 */

/**
 * @brief TCP stream socket type.
 *
 */
#define SOCKET_STREAM_TYPE SOCK_STREAM

/**
 * @brief UDP datagram socket type.
 *
 */
#define SOCKET_DGRAM_TYPE SOCK_DGRAM

/**
 * @brief Unspecified address family.
 *
 */
#define SOCKET_AF_UNSPEC AF_UNSPEC

/**
 * @brief IPv4 address family.
 *
 */
#define SOCKET_AF_INET AF_INET

/**
 * @brief IPv6 address family.
 *
 */
#define SOCKET_AF_INET6 AF_INET6

/**
 * @brief Unix domain socket address family.
 *
 */
#define SOCKET_AF_UNIX AF_UNIX

/**
 * @brief TCP protocol number.
 *
 */
#define SOCKET_IPPROTO_TCP IPPROTO_TCP

/**
 * @brief UDP protocol number.
 *
 */
#define SOCKET_IPPROTO_UDP IPPROTO_UDP

/**
 * @brief IP protocol number.
 *
 */
#define SOCKET_IPPROTO_IP IPPROTO_IP

/**
 * @brief IPv6 protocol number.
 *
 */
#define SOCKET_IPPROTO_IPV6 IPPROTO_IPV6

/* ============================================================================
 * Socket Options
 * ============================================================================
 */

/**
 * @brief Socket options level.
 *
 */
#define SOCKET_SOL_SOCKET SOL_SOCKET

/**
 * @brief Allow reuse of local addresses.
 *
 */
#define SOCKET_SO_REUSEADDR SO_REUSEADDR

/**
 * @brief Allow reuse of local ports (if available).
 *
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
 */
/**
 * @brief Linux-specific features detection.
 *
 * Detects Linux platform (__linux__) to enable Linux-only optimizations and
 * options:
 * - accept4(): Atomic accept with non-blocking and CLOEXEC flags.
 * - SO_DOMAIN: Socket option to query address family (AF_INET, etc.).
 *
 * On non-Linux platforms, these fall back to standard accept() + fcntl() and
 * no SO_DOMAIN support.
 *
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
 */
#define SOCKET_FD_CLOEXEC FD_CLOEXEC

/**
 * @brief Enable broadcast transmission.
 *
 */
#define SOCKET_SO_BROADCAST SO_BROADCAST

/**
 * @brief Enable keep-alive packets.
 *
 */
#define SOCKET_SO_KEEPALIVE SO_KEEPALIVE

/**
 * @brief Receive timeout.
 *
 */
#define SOCKET_SO_RCVTIMEO SO_RCVTIMEO

/**
 * @brief Send timeout.
 *
 */
#define SOCKET_SO_SNDTIMEO SO_SNDTIMEO

/**
 * @brief Receive buffer size.
 *
 */
#define SOCKET_SO_RCVBUF SO_RCVBUF

/**
 * @brief Send buffer size.
 *
 */
#define SOCKET_SO_SNDBUF SO_SNDBUF

/**
 * @brief Peer credentials.
 *
 */
#define SOCKET_SO_PEERCRED SO_PEERCRED

/* ============================================================================
 * TCP Options
 * ============================================================================
 */

/**
 * @brief Disable Nagle's algorithm.
 *
 */
#define SOCKET_TCP_NODELAY TCP_NODELAY

/**
 * @brief Keep-alive idle time.
 *
 */
#define SOCKET_TCP_KEEPIDLE TCP_KEEPIDLE

/**
 * @brief Keep-alive interval.
 *
 */
#define SOCKET_TCP_KEEPINTVL TCP_KEEPINTVL

/**
 * @brief Keep-alive probe count.
 *
 */
#define SOCKET_TCP_KEEPCNT TCP_KEEPCNT

/**
 * @brief TCP congestion control algorithm (if available).
 *
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
 * Linux-specific option that delays accept() completion until client sends
 * data. On BSD/macOS, use SO_ACCEPTFILTER instead.
 *
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
 */
#define SOCKET_IPV6_V6ONLY IPV6_V6ONLY

/**
 * @brief IPv6 multicast add membership.
 *
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
 */
#define SOCKET_IPV6_UNICAST_HOPS IPV6_UNICAST_HOPS

/* ============================================================================
 * IP Options
 * ============================================================================
 */

/**
 * @brief IP time to live.
 *
 */
#define SOCKET_IP_TTL IP_TTL

/**
 * @brief IP multicast add membership.
 *
 */
#define SOCKET_IP_ADD_MEMBERSHIP IP_ADD_MEMBERSHIP

/**
 * @brief IP multicast drop membership.
 *
 */
#define SOCKET_IP_DROP_MEMBERSHIP IP_DROP_MEMBERSHIP

/* ============================================================================
 * Address and Name Info Flags
 * ============================================================================
 */

/**
 * @brief Passive socket flag for getaddrinfo().
 *
 */
#define SOCKET_AI_PASSIVE AI_PASSIVE

/**
 * @brief Numeric host address flag for getaddrinfo().
 *
 */
#define SOCKET_AI_NUMERICHOST AI_NUMERICHOST

/**
 * @brief Numeric service port flag for getaddrinfo().
 *
 */
#define SOCKET_AI_NUMERICSERV AI_NUMERICSERV

/**
 * @brief Numeric host address flag for getnameinfo().
 *
 */
#define SOCKET_NI_NUMERICHOST NI_NUMERICHOST

/**
 * @brief Numeric service port flag for getnameinfo().
 *
 */
#define SOCKET_NI_NUMERICSERV NI_NUMERICSERV

/**
 * @brief Maximum host name length for getnameinfo().
 *
 */
#define SOCKET_NI_MAXHOST NI_MAXHOST

/**
 * @brief Maximum service name length for getnameinfo().
 *
 */
#define SOCKET_NI_MAXSERV NI_MAXSERV

/* ============================================================================
 * Shutdown and Message Flags
 * ============================================================================
 */

/**
 * @brief Shutdown read direction.
 *
 */
#define SOCKET_SHUT_RD SHUT_RD

/**
 * @brief Shutdown write direction.
 *
 */
#define SOCKET_SHUT_WR SHUT_WR

/**
 * @brief Shutdown both read and write directions.
 *
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
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/**
 * @brief Suppress SIGPIPE on send operations.
 *
 */
#define SOCKET_MSG_NOSIGNAL MSG_NOSIGNAL

/**
 * @brief SO_NOSIGPIPE support flag.
 *
 * BSD/macOS socket option to suppress SIGPIPE.
 * This is set once at socket creation time as an alternative to MSG_NOSIGNAL.
 * On Linux, MSG_NOSIGNAL is preferred and this macro will be 0.
 *
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
 */
#define SOCKET_DEFAULT_KEEPALIVE_IDLE 60

/**
 * @brief Default TCP keep-alive interval (seconds).
 *
 */
#define SOCKET_DEFAULT_KEEPALIVE_INTERVAL 10

/**
 * @brief Default TCP keep-alive probe count.
 *
 */
#define SOCKET_DEFAULT_KEEPALIVE_COUNT 3

/**
 * @brief Maximum TCP keep-alive idle time (seconds).
 *
 * Limits the idle time before first probe to 1 year.
 */
#ifndef SOCKET_KEEPALIVE_MAX_IDLE
#define SOCKET_KEEPALIVE_MAX_IDLE (86400 * 365) /* 1 year in seconds */
#endif

/**
 * @brief Maximum TCP keep-alive interval (seconds).
 *
 * Limits the interval between probes to 1 hour.
 */
#ifndef SOCKET_KEEPALIVE_MAX_INTERVAL
#define SOCKET_KEEPALIVE_MAX_INTERVAL 3600 /* 1 hour */
#endif

/**
 * @brief Maximum TCP keep-alive probe count.
 *
 * Limits the number of failed probes before disconnect.
 */
#ifndef SOCKET_KEEPALIVE_MAX_COUNT
#define SOCKET_KEEPALIVE_MAX_COUNT 32
#endif

/**
 * @brief Maximum TCP defer accept timeout (seconds).
 *
 * Limits TCP_DEFER_ACCEPT/SO_ACCEPTFILTER timeout to 1 hour.
 */
#ifndef SOCKET_MAX_DEFER_ACCEPT_SEC
#define SOCKET_MAX_DEFER_ACCEPT_SEC 3600 /* 1 hour */
#endif

/**
 * @brief Maximum congestion control algorithm name length.
 *
 * Maximum length of TCP_CONGESTION algorithm name string (excluding null).
 */
#ifndef SOCKET_MAX_CONGESTION_ALGO_LEN
#define SOCKET_MAX_CONGESTION_ALGO_LEN 63
#endif

/**
 * @brief Default datagram TTL value.
 *
 */
#define SOCKET_DEFAULT_DATAGRAM_TTL 64

/**
 * @brief Default multicast interface index.
 *
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
 * @brief Sets the global memory limit enforced by all Arena allocators.
 *
 * Configures a hard limit on total memory usage across all arenas. When reached,
 * Arena_alloc() calls return NULL, triggering Arena_Failed exceptions. Setting to
 * 0 disables the limit (unlimited). Changes take effect immediately for new
 * allocations.
 *
 * @param[in] max_bytes The new global limit in bytes (0 = unlimited).
 * @return None.
 * @threadsafe Yes - uses atomic operations.
 */
extern void SocketConfig_set_max_memory (size_t max_bytes);

/**
 * @brief Retrieves the currently configured global memory limit.
 *
 * Returns the maximum allowed total memory for all Arena allocations. A value of
 * 0 indicates unlimited.
 *
 * @return Current global memory limit in bytes (0 = unlimited).
 * @threadsafe Yes - atomic load operation.
 */
extern size_t SocketConfig_get_max_memory (void);

/**
 * @brief Retrieves the total current memory allocated via Arenas.
 *
 * Returns aggregate bytes currently allocated across all arenas in the process.
 * Excludes freed chunks that may be cached for reuse. Value increases on
 * alloc/calloc, decreases on arena clear/dispose. Useful for monitoring memory
 * footprint and detecting leaks.
 *
 * @return Total bytes currently in use by all arenas (0 if none allocated).
 * @threadsafe Yes - atomic load with memory barriers.
 */
extern size_t SocketConfig_get_memory_used (void);

/**
 * @brief Port number validation macro.
 *
 * @param p Port number to validate.
 * @return Non-zero if port is valid (0-65535).
 */
#define SOCKET_VALID_PORT(p) ((int)(p) >= 0 && (int)(p) <= 65535)

/**
 * @brief Buffer size validation macro.
 *
 * @param s Buffer size to validate.
 * @return Non-zero if buffer size is valid.
 */
#define SOCKET_VALID_BUFFER_SIZE(s)                                           \
  ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE                                      \
   && (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)

/**
 * @brief Connection count validation macro.
 *
 * @param c Connection count to validate.
 * @return Non-zero if connection count is valid.
 */
#define SOCKET_VALID_CONNECTION_COUNT(c)                                      \
  ((size_t)(c) > 0 && (size_t)(c) <= SOCKET_MAX_CONNECTIONS)

/**
 * @brief Poll events validation macro.
 *
 * @param e Number of poll events to validate.
 * @return Non-zero if poll events count is valid.
 */
#define SOCKET_VALID_POLL_EVENTS(e)                                           \
  ((int)(e) > 0 && (int)(e) <= SOCKET_MAX_POLL_EVENTS)

/**
 * @brief IP string validation macro.
 *
 * @param ip IP string to validate.
 * @return Non-zero if IP string is valid (non-null, non-empty).
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
