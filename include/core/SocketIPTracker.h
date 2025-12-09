#ifndef SOCKETIPTRACKER_INCLUDED
#define SOCKETIPTRACKER_INCLUDED

/**
 * @defgroup ip_tracker IP Connection Tracking
 * @brief Per-IP connection tracking for rate limiting and DoS protection.
 * @ingroup security
 *
 * Comprehensive module for tracking concurrent connections per IP address to
 * prevent single-source DoS attacks by enforcing configurable limits.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────────────┐
 * │     Application Layer       │
 * │   SocketPool, HTTPServer    │
 * └─────────────┬───────────────┘
 *               │ Integrates with
 * ┌─────────────▼───────────────┐
 * │   SocketIPTracker           │
 * │   - DJB2 hash (salted)      │
 * │   - Mutex protected         │
 * │   - Arena or malloc         │
 * │   - IPv4/IPv6 validation    │
 * └─────────────┬───────────────┘
 *               │ Depends on
 * ┌─────────────▼───────────────┐
 * │     Foundation Layer        │
 * │   Arena, Except, Util, Crypto│
 * └─────────────────────────────┘
 * ```
 *
 * ## Key Features
 *
 * | Feature              | Description                          |
 * |----------------------|--------------------------------------|
 * | Thread-Safe          | Internal mutex for all operations    |
 * | Efficient Lookups    | O(1) average via hash table          |
 * | Flexible Allocation  | Supports Arena_T or standard malloc  |
 * | DoS Resistance       | Random hash seed from crypto         |
 * | IP Validation        | Validates IPv4/IPv6 with inet_pton   |
 * | Configurable Limits  | Per-IP and max unique IPs            |
 * | Auto Cleanup         | Removes zero-count entries           |
 *
 * ## Default Configuration
 *
 * | Parameter         | Default Value              | Notes |
 * |-------------------|----------------------------|-------|
 * | max_per_ip        | Passed to new() (0=unlimited) | Clamped >=0 |
 * | max_unique_ips    | SOCKET_MAX_CONNECTIONS     | Prevents OOM |
 * | bucket_count      | SOCKET_IP_TRACKER_HASH_SIZE| Hash table size |
 * | hash_seed         | Random bytes or fallback   | DoS protection |
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref foundation (Arena, Except, SocketUtil, SocketCrypto
 * for seed gen)
 * - **Used by**: @ref connection_mgmt (SocketPool integrates for per-IP
 * limits)
 * - **Complements**: SocketSYNProtect for multi-layered security
 *
 * ## Usage Patterns
 *
 * ### Standalone Usage
 *
 * @code{.c}
 * #include "core/SocketIPTracker.h"
 * #include "core/Arena.h"
 *
 * Arena_T arena = Arena_new();
 * TRY {
 *   SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10); // Max 10 per
 * IP
 *
 *   const char *client_ip = "192.168.1.1"; // From Socket_getpeeraddr()
 *   if (SocketIPTracker_track(tracker, client_ip)) {
 *       // Connection allowed
 *       printf("Tracked IP %s, total conns: %zu\n", client_ip,
 * SocketIPTracker_total(tracker)); } else {
 *       // Reject connection
 *       fprintf(stderr, "IP %s exceeded limit\n", client_ip);
 *   }
 *
 *   // Later, on disconnect:
 *   SocketIPTracker_release(tracker, client_ip);
 *
 *   SocketIPTracker_free(&tracker);
 * } EXCEPT(SocketIPTracker_Failed) {
 *   fprintf(stderr, "Tracker init failed: %s\n", Except_message(Exception));
 * } FINALLY {
 *   // Arena_dispose(&arena); // Called outside TRY if needed
 * } END_TRY;
 * @endcode
 *
 * ### With SocketPool Integration
 *
 * @code{.c}
 * SocketPool_T pool = SocketPool_new(arena, 1000, 4096);
 * SocketPool_setmaxperip(pool, 5); // Enables internal IP tracking
 *
 * // Pool automatically tracks/releases on accept/close
 * Connection_T conn = SocketPool_accept_limited(pool, server_sock);
 * if (conn) {
 *     // Handle connection
 *     const char *ip = Socket_getpeeraddr(Connection_socket(conn));
 *     int count = SocketPool_ip_count(pool, ip); // Query if needed
 * }
 * @endcode
 *
 * @note
 * - Invalid IPs (non IPv4/IPv6) are rejected for track(), no-op for
 * release/count=0.
 * - Unlimited mode (max_per_ip=0) always allows tracking without limit checks.
 * - Hash collisions handled by chaining; average chain length low.
 * - For production, monitor SocketIPTracker_unique_ips() and total() for
 * capacity.
 *
 * @warning
 * - Do not call free() concurrently with other operations; use graceful
 * shutdown.
 * - Arena-allocated trackers cleaned via Arena_dispose(); free() just NULLs
 * ptr.
 * - Max unique limit prevents OOM but may reject legit clients under load.
 *
 * @complexity
 * - track(), release(), count(): O(1) average (hash + short chain traversal)
 * - O(n) worst-case if severe hash collisions (unlikely with random seed)
 *
 * @see SocketPool_setmaxperip() Pool integration
 * @see SocketRateLimit_T Complementary bandwidth limiting
 * @see Socket_getpeeraddr() IP extraction
 * @see docs/SECURITY.md DoS protection guide
 * @see docs/PROXY.md If using behind proxy (use X-Forwarded-For)
 *
 * @{
 *
 * @file SocketIPTracker.h
 * @brief Header for IP connection tracker module.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX system with pthreads
 * - arpa/inet.h for IP validation
 *
 * @see SocketIPTracker_new()
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>

/**
 * @brief Opaque type for IP connection tracker instance.
 * @ingroup security
 *
 * Manages concurrent connection counts per IP address using a thread-safe
 * hash table. Enforces per-IP limits to mitigate DoS attacks from single
 * sources. Supports IPv4 and IPv6 with automatic validation and efficient O(1)
 * average operations. Configurable for memory usage and integrates with Arena
 * allocator.
 *
 * ## Key Characteristics
 *
 * - **Opaque**: Internal struct hidden; use provided API only
 * - **Hash-based**: DJB2 algorithm with random seed for collision resistance
 * - **Limits**: Enforceable max per IP and total unique IPs to prevent
 * abuse/OOM
 * - **Cleanup**: Auto-removes zero-count entries; manual clear() available
 *
 * ## Lifecycle
 *
 * 1. Create: SocketIPTracker_new(arena, max_per_ip)
 * 2. Configure: Optional setmax(), setmaxunique()
 * 3. Use: track() on accept, release() on close, query count/total
 * 4. Destroy: SocketIPTracker_free() or via Arena_dispose()
 *
 * ## Thread Safety
 *
 * @threadsafe Yes - All public functions acquire internal mutex.
 * Concurrent track/release/count from multiple threads safe without external
 * sync. Avoid free() during active operations; prefer coordinated shutdown.
 *
 * ## Edge Cases Handled
 *
 * - Invalid IPs (non IPv4/6): Rejected for track(), no-op others
 * - Unlimited mode (max_per_ip <=0): Always allows without checks
 * - Alloc failures: Graceful fallback in unlimited mode
 * - Count overflow: Logs error, rejects increment
 *
 * @note
 * - IP strings must be null-terminated, length < SOCKET_IP_MAX_LEN
 * - Uses SocketCrypto_random_bytes for hash seed; falls back to time/PID if
 * unavailable
 * - For load-balanced/proxied setups, extract real client IP from headers
 *
 * @warning
 * - Hitting max_unique_ips silently rejects new IPs (log warned)
 * - Long chains possible under hash attack, but salted seed mitigates
 * - Arena users: free() only NULLs; actual cleanup on Arena_dispose()
 *
 * @complexity Operations: O(1) average, O(unique_ips / buckets) worst chain
 * length
 *
 * @see SocketIPTracker_new() for instantiation
 * @see SocketIPTracker_track() primary usage entrypoint
 * @see @ref foundation Required base modules
 * @see docs/SECURITY.md Production deployment guide
 */
#define T SocketIPTracker_T
typedef struct T *T;

/**
 * @brief Base exception for IP tracker module failures.
 * @ingroup security
 *
 * Raised when operations fail due to allocation errors, mutex issues,
 * or internal state corruption. Specific causes logged via SocketLog.
 *
 * ## Common Causes
 *
 * | Scenario | Details |
 * |----------|---------|
 * | Alloc Fail | Arena or malloc failure for buckets/entries |
 * | Mutex Fail | pthread_mutex_init/destroy error |
 * | Config Error | Overflow in bucket calculation |
 *
 * @note Use TRY/EXCEPT(SocketIPTracker_Failed) around new() and critical ops.
 * @see Except.h For exception handling macros (TRY, RAISE, etc.)
 * @see SocketIPTracker_new() Main allocation point
 */
extern const Except_T SocketIPTracker_Failed;

/**
 * @brief Create and initialize a new IP connection tracker instance.
 * @ingroup security
 *
 * Constructs a thread-safe hash table-based tracker for per-IP connection
 * counting. Supports configurable limits, IPv4/IPv6 validation, and flexible
 * memory management. Automatically generates a random hash seed for DoS
 * resistance.
 *
 * Detailed behavior:
 * - Clamps max_per_ip < 0 to 0 (unlimited)
 * - Initializes fixed-size hash table (SOCKET_IP_TRACKER_HASH_SIZE buckets)
 * - Sets default max_unique_ips to SOCKET_MAX_CONNECTIONS for memory safety
 * - Validates platform support (pthreads, arpa/inet.h)
 *
 * @param[in] arena Arena_T for all internal allocations (NULL = use
 * malloc/free)
 * @param[in] max_per_ip Maximum allowed concurrent connections per IP (>=0,
 * 0=unlimited)
 *
 * @return Validated tracker instance ready for use
 *
 * @throws SocketIPTracker_Failed Allocation or system call failures:
 * - Arena_alloc/malloc for struct or buckets array
 * - pthread_mutex_init for internal locking
 * - Rare arithmetic overflow in bucket sizing
 *
 * @threadsafe Yes - Single-threaded construction; instance safe for
 * multi-thread share
 *
 * ## Basic Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketIPTracker_T tracker;
 * TRY {
 *   tracker = SocketIPTracker_new(arena, 50); // Limit 50 conns/IP
 *   SocketIPTracker_setmaxunique(tracker, 10000); // Custom unique limit
 *   // Integrate with server loop...
 * } EXCEPT(SocketIPTracker_Failed) {
 *   SOCKET_LOG_ERROR_MSG("Failed to create IP tracker: %s",
 * Except_message(Exception));
 *   // Handle gracefully, e.g. fallback to no limiting
 * } END_TRY;
 * // free/cleanup in FINALLY or after use
 * @endcode
 *
 * ## Heap Allocation Example
 *
 * @code{.c}
 * SocketIPTracker_T tracker = SocketIPTracker_new(NULL, 100);
 * if (tracker) {
 *   // Use tracker
 *   SocketIPTracker_free(&tracker);
 * } // Auto-cleanup on exception via TRY if wrapped
 * @endcode
 *
 * @note
 * - Arena usage recommended for batch resource management with other objects
 * - Hash seed generated via SocketCrypto_random_bytes; logs fallback if crypto
 * unavailable
 * - Unlimited mode still tracks counts for monitoring but never rejects
 *
 * @warning
 * - Ensure sufficient memory for expected unique_ips * sizeof(IPEntry) ~20
 * bytes/IP
 * - On failure, partial allocations cleaned (heap freed, arena untouched)
 * - Not movable: don't memcpy tracker instances
 *
 * @complexity O(1) - Constant-time initialization independent of usage scale
 *
 * @see SocketIPTracker_free() for destruction and resource release
 * @see SocketIPTracker_setmax() runtime limit adjustment
 * @see SocketIPTracker_track() core tracking operation
 * @see Arena_T @ref foundation for memory management
 * @see docs/ERROR_HANDLING.md Exception best practices
 */
extern T SocketIPTracker_new (Arena_T arena, int max_per_ip);

/**
 * @brief Dispose of IP tracker instance and release resources.
 * @ingroup security
 *
 * Cleans up internal state: destroys mutex, frees heap-allocated
 * buckets/entries, and nullifies the pointer. For arena-allocated trackers,
 * only nullifies pointer as actual memory freed collectively by
 * Arena_dispose().
 *
 * Behavior details:
 * - Idempotent: Safe to call multiple times or on NULL/ already-freed
 * - Thread-safe via mutex for destroy (but avoid concurrent ops during free)
 * - Logs errors if mutex_destroy fails (rare)
 * - Resets internal counters to 0 before cleanup
 *
 * @param[in,out] tracker Pointer to tracker instance (set to NULL on success)
 *
 * @threadsafe Partial - Acquires mutex internally, but concurrent
 * track/release during free may deadlock or corrupt. Coordinate shutdown
 * before calling.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Arena case: free() nulls, dispose arena for full cleanup
 * SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10);
 * // ... use ...
 * SocketIPTracker_free(&tracker); // tracker = NULL
 * Arena_dispose(&arena); // Frees tracker memory
 *
 * // Heap case: free() releases everything
 * SocketIPTracker_T tracker = SocketIPTracker_new(NULL, 10);
 * // ... use ...
 * SocketIPTracker_free(&tracker); // All resources freed, tracker=NULL
 * @endcode
 *
 * ## With Exception Safety
 *
 * @code{.c}
 * TRY {
 *   SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10);
 *   // Operations...
 *   RETURN tracker; // Transfers ownership
 * } EXCEPT(SocketIPTracker_Failed) {
 *   // No cleanup needed; exception unwinds
 * } FINALLY {
 *   SocketIPTracker_free(&tracker); // Safe even if NULL
 * } END_TRY;
 * @endcode
 *
 * @note
 * - Call after all operations complete; prefer in FINALLY block
 * - For pools/servers, integrate with graceful drain sequences
 * - No data loss: all tracked IPs cleared before free
 *
 * @warning
 * - Concurrent modifications during free undefined; use
 * SocketIPTracker_clear() first if needed
 * - Mutex destroy may fail if locked elsewhere (logs EPERM)
 * - Arena users must dispose arena separately to avoid leaks
 *
 * @complexity O(unique_ips) - Traverses and frees all bucket chains
 *
 * @see SocketIPTracker_new() Creation counterpart
 * @see SocketIPTracker_clear() Alternative for reset without destroy
 * @see Arena_dispose() For arena-managed cleanup
 * @see docs/SIGNALS.md Graceful shutdown integration
 */
extern void SocketIPTracker_free (T *tracker);

/**
 * @brief Increment connection count for specified IP; enforce limit if set.
 * @ingroup security
 *
 * Core operation to track a new connection from a client IP. Performs IP
 * validation, hash lookup, and conditional increment based on current limit.
 * Creates new entry if IP not previously tracked.
 *
 * Edge cases:
 * - Invalid format (non IPv4/6 or too long): Returns 0 (reject), logs warning
 * - Unlimited mode: Always succeeds, increments count
 * - Max unique reached: Rejects new unique IP (logs warning)
 * - Alloc fail for new entry: Succeeds in unlimited, fails limited
 * - NULL/empty ip: Returns 1, no tracking (safe default)
 *
 * Updates internal total_conns and unique_ips counters atomically.
 *
 * @param[in] tracker Active tracker instance
 * @param[in] ip Null-terminated IP string (e.g. "192.0.2.1" or
 * "[2001:db8::1]")
 *
 * @return 1 if connection allowed and tracked, 0 if rejected (limit or error)
 *
 * @threadsafe Yes - Mutex protects entire operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * // In server accept loop
 * Socket_T client_sock = Socket_accept(server_sock);
 * if (client_sock) {
 *   const char *client_ip = Socket_getpeeraddr(client_sock);
 *   if (SocketIPTracker_track(tracker, client_ip)) {
 *       // Proceed with connection setup
 *       Connection_T conn = SocketPool_add(pool, client_sock);
 *       // Associate conn with IP if needed
 *   } else {
 *       // Reject: too many from this IP
 *       SOCKET_LOG_WARN_MSG("Rejecting connection from %s: limit exceeded",
 * client_ip); Socket_free(&client_sock);
 *   }
 * }
 * @endcode
 *
 * ## Advanced: With Metrics
 *
 * @code{.c}
 * if (SocketIPTracker_track(tracker, ip)) {
 *     size_t total = SocketIPTracker_total(tracker);
 *     size_t uniques = SocketIPTracker_unique_ips(tracker);
 *     SOCKET_LOG_INFO_MSG("New conn from %s; total=%zu, uniques=%zu", ip,
 * total, uniques); SocketMetrics_increment(CONNECTION_ACCEPTED, 1); } else {
 *     SocketMetrics_increment(CONNECTION_REJECTED_RATE_LIMIT, 1);
 * }
 * @endcode
 *
 * @note
 * - Call on every accept/handshake completion, before full connection setup
 * - IP must be canonical (no ports, resolved from getpeername or headers)
 * - Performance: Fast hash lookup; chain traversal avg ~1
 *
 * @warning
 * - Rejecting invalid IPs prevents spoofing but may block malformed proxies
 * - Under high load, monitor for alloc failures in limited mode
 * - Pair with SocketSYNProtect for layered SYN flood + conn limit defense
 *
 * @complexity O(1) average - Hash computation + chain search (short avg)
 * @complexity O(buckets load) worst - Linear chain if collisions
 *
 * @see SocketIPTracker_release() Balance with disconnect
 * @see SocketIPTracker_count() Query current count for IP
 * @see validate_ip_format() Internal check (IPv4/6 via inet_pton)
 * @see SocketPool_track_ip() If using pool-managed tracking
 * @see docs/SECURITY.md Rate limiting strategies
 */
extern int SocketIPTracker_track (T tracker, const char *ip);

/**
 * @brief Decrement connection count for IP; auto-remove if zero.
 * @ingroup security
 *
 * Balances SocketIPTracker_track() by reducing count for a disconnecting
 * client. Performs IP validation and efficient hash lookup. Removes entry from
 * table when count hits 0 to conserve memory. No-op for untracked or invalid
 * IPs.
 *
 * Edge cases:
 * - Untracked IP: No-op, returns immediately
 * - Invalid IP: Logs warning, no-op
 * - Count underflow prevention: Ignores if already 0
 * - Concurrent increments: Atomic update via mutex
 *
 * Updates total_conns and unique_ips atomically on removal.
 *
 * @param[in] tracker Active tracker
 * @param[in] ip IP string of disconnecting client
 *
 * @threadsafe Yes - Full mutex protection
 *
 * ## Usage Example
 *
 * @code{.c}
 * // On connection close/disconnect
 * void on_disconnect(Connection_T conn) {
 *   const char *ip = get_client_ip(conn); // Extract from conn or socket
 *   SocketIPTracker_release(tracker, ip);
 *   // Optional: log if count now 0
 *   if (SocketIPTracker_count(tracker, ip) == 0) {
 *       SOCKET_LOG_DEBUG_MSG("IP %s fully disconnected", ip);
 *   }
 *   // Proceed with cleanup
 * }
 * @endcode
 *
 * ## In Server Loop Context
 *
 * @code{.c}
 * // Graceful close handling
 * TRY {
 *   Socket_shutdown(conn_sock, SHUT_RDWR);
 *   const char *ip = Socket_getpeeraddr(conn_sock);
 *   SocketIPTracker_release(tracker, ip);
 *   Socket_free(&conn_sock);
 * } EXCEPT(Socket_Closed) {
 *   // Peer closed; still release IP count
 *   SocketIPTracker_release(tracker, ip);
 * } END_TRY;
 * @endcode
 *
 * @note
 * - Always call on logical disconnect, even if socket error
 * - Pairs with track() to maintain accurate counts
 * - O(1) unlink using prev pointer tracking in impl
 *
 * @warning
 * - Forgetting release leads to "ghost" counts and premature rejections
 * - In pooled connections, ensure release on every reuse/timeout
 * - Invalid IPs logged but not tracked to avoid DoS via bad data
 *
 * @complexity O(1) average - Symmetric to track(): hash + chain search
 *
 * @see SocketIPTracker_track() Increment counterpart
 * @see SocketIPTracker_clear() Bulk reset all counts
 * @see SocketPool_release_ip() Pool variant
 * @see docs/HTTP-REFACTOR.md Connection lifecycle in HTTP servers
 */
extern void SocketIPTracker_release (T tracker, const char *ip);

/**
 * @brief Get current connection count for an IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param ip IP address string (IPv4 or IPv6).
 *
 * @return Current connection count (0 if not tracked).
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_track() for incrementing.
 * @see SocketIPTracker_release() for decrementing.
 */
extern int SocketIPTracker_count (T tracker, const char *ip);

/**
 * @brief Set maximum connections per IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param max_per_ip New maximum (0 = unlimited).
 *
 * Note: Does not affect existing connections over the new limit.
 * New connections will be rejected until count drops below limit.
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_getmax() to retrieve current limit.
 * @see SocketPool_setmaxperip() for pool equivalent configuration.
 */
extern void SocketIPTracker_setmax (T tracker, int max_per_ip);

/**
 * @brief Get maximum connections per IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Maximum connections per IP (0 = unlimited).
 * @threadsafe Yes.
 * @see SocketIPTracker_setmax() to change the limit.
 */
extern int SocketIPTracker_getmax (T tracker);

/**
 * @brief Set maximum unique IPs to track.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param max_unique New maximum (0 = unlimited).
 *
 * Limits memory usage by rejecting new unique IPs when limit reached.
 * Does not evict existing entries.
 *
 * @threadsafe Yes.
 * @see SocketIPTracker_getmaxunique() to retrieve current limit.
 */
extern void SocketIPTracker_setmaxunique (T tracker, size_t max_unique);

/**
 * @brief Get maximum unique IPs limit.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Current maximum unique IPs (0 = unlimited).
 * @threadsafe Yes.
 * @see SocketIPTracker_setmaxunique() to change the limit.
 */
extern size_t SocketIPTracker_getmaxunique (T tracker);

/**
 * @brief Get total tracked connections across all IPs.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Total number of tracked connections across all IPs.
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_unique_ips() for unique IP count.
 */
extern size_t SocketIPTracker_total (T tracker);

/**
 * @brief Get number of unique IPs being tracked.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Number of unique IP addresses with at least one connection.
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_total() for total connection count.
 */
extern size_t SocketIPTracker_unique_ips (T tracker);

/**
 * @brief Clear all tracked connections.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_free() for complete cleanup.
 *
 * Removes all entries from the tracker.
 * Useful for testing or administrative reset.
 */
extern void SocketIPTracker_clear (T tracker);

/**
 * @} */   /* End ip_tracker group */

/** @} */ /* End security group if nested */

#undef T
#endif /* SOCKETIPTRACKER_INCLUDED */
