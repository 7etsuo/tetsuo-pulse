#ifndef SOCKET_PRIVATE_H_INCLUDED
#define SOCKET_PRIVATE_H_INCLUDED

/**
 * @file Socket-private.h
 * @brief Private implementation details for Socket module: internal structure
 * and shared utilities.
 * @private Internal use only - included by Socket_*.c implementation files.
 * @ingroup core_io
 *
 * This header provides:
 * - Complete `struct Socket_T` definition extending `SocketBase_T`
 * - Thread-safe live socket counting utilities for leak detection
 * - TLS field initialization (conditional on SOCKET_HAS_TLS)
 * - Shared functions across Socket implementation files
 *
 *  Architecture Overview
 *
 * ```
 * +---------------------+     +---------------------+
 * | Socket.h (Public)   |     | Socket-private.h    |
 * | - Opaque Socket_T   |<--->| - struct Socket_T   |
 * | - Public functions  |     | - Private utilities |
 * +----------+----------+     +----------+----------+
 *            |                           |
 *            | includes                   | includes
 *            v                           v
 * +----------+----------+     +----------+----------+
 * | Application Code     |     | Implementation:    |
 * | - Socket_new()       |     | - Socket.c         |
 * | - Socket_connect()   |     | - Socket-*.c       |
 * +----------------------+     +---------------------+
 * ```
 *
 *  Module Relationships
 * - **Depends on**: core/Arena.h (memory), core/SocketConfig.h (config),
 * socket/SocketCommon-private.h (base)
 * - **Used internally by**: All socket implementation files (*.c)
 * - **Integrates with**: core/SocketRateLimit.h (throttling), tls/SocketTLS.h
 * (secure transport when enabled)
 * - **Public counterpart**: socket/Socket.h (opaque type and API)
 *
 *  Key Features
 * - **Live Count Tracking**: Atomic counters for debugging and tests
 * (Socket_debug_live_count())
 * - **Bandwidth Limiting**: Per-socket SocketRateLimit_T integration
 * - **TLS Support** (conditional): State and buffers for non-blocking TLS I/O
 * - **Double-Free Protection**: Atomic 'freed' sentinel
 *
 *  Conditional Compilation
 * - Use `#if SOCKET_HAS_TLS` to guard TLS-related code (checks value 0/1, not
 * just definition)
 * - TLS fields add ~100 bytes to struct size when enabled
 *
 *  Thread Safety
 * - Utilities: Fully thread-safe (atomics/mutexes)
 * - Struct fields: Varies - atomics for simple state, mutexes for complex ops
 * - Direct access: Requires external synchronization by caller
 *
 *  Usage Guidelines
 * - Include only from <code>socket/&#42;.c</code> implementation files
 * - Never include in application or public headers
 * - For ABI stability, avoid direct field manipulation - use accessor
 * functions
 *
 *  Testing Integration
 * - Tests MUST verify `Socket_debug_live_count() == 0` after teardown
 * - Sanitizers (ASan/UBSan) required for all paths
 *
 * @warning Direct struct field access breaks encapsulation and may change ABI
 * @note Memory for dynamic fields from embedded arena (lifecycle tied to
 * socket)
 * @complexity Most operations O(1), with locking for shared state
 *
 * @see socket/Socket.h for public opaque API
 * @see socket/SocketCommon-private.h for SocketBase_T details
 * @see core/SocketRateLimit.h for bandwidth limiting
 * @see tls/SocketTLS.h for TLS integration (#if SOCKET_HAS_TLS)
 * @see docs/MEMORY_MANAGEMENT.md for arena guidelines
 * @see docs/SECURITY.md for TLS hardening and rate limiting
 * @see docs/ERROR_HANDLING.md for exception patterns in socket ops
 * @see docs/TESTING.md for live count verification in tests
 */

#include "core/Arena.h" /**< Arena-based memory management for socket allocations. @ingroup foundation */

#include "core/SocketConfig.h" /**< Global socket configuration and default timeouts. @ingroup core_io */

#include "core/SocketRateLimit.h" /**< Rate limiting for socket bandwidth control. @ingroup utilities */

#include "socket/Socket.h" /**< Public interface for Socket_T operations. @ingroup core_io */

#include "socket/SocketCommon-private.h" /**< Shared private base for socket implementations. @ingroup core_io */

#include <stdatomic.h> /**< C11 atomic operations for thread-safe state management (e.g., free flag). */

/**
 * @defgroup socket_live_utils Live Socket Counting Utilities
 * @brief Thread-safe global counter for tracking active Socket_T instances.
 * @private
 * @ingroup core_io
 *
 * These utilities maintain a global, thread-safe count of live sockets for
 * debugging, leak detection, and resource monitoring. The counter is
 * incremented on successful allocation (Socket_new, Socket_new_from_fd,
 * Socket_accept) and decremented on free (Socket_free).
 *
 *  Purpose and Usage
 * - **Leak Detection**: Tests verify count == 0 after teardown
 * - **Resource Tracking**: Monitor open sockets in long-running apps
 * - **Debugging**: Identify memory leaks or unclosed sockets
 *
 *  Implementation
 * - Atomic operations or mutex-protected counter in SocketCommon-private.h
 * - Public query via Socket_debug_live_count() (test/debug only)
 * - No exceptions raised - simple counter ops
 *
 *  Thread Safety
 * All functions are fully thread-safe for concurrent allocation/free.
 *
 *  Testing Requirements
 * - All unit tests MUST end with `assert(Socket_debug_live_count() == 0)`
 * - Valgrind/ASan to confirm no leaks
 * - Multi-threaded tests to verify atomic correctness
 *
 * @warning Counter overflow theoretically possible (UINT_MAX sockets), but
 * unlikely
 * @note Exposed publicly for tests via Socket.h, but primarily internal
 * @complexity All operations O(1)
 *
 * @see Socket_debug_live_count() for querying count
 * @see docs/TESTING.md for integration in test suites
 * @see core/SocketCommon-private.h for implementation details
 * @{
 */

/**
 * @brief Increment the global live socket counter atomically.
 * @private
 * @ingroup socket_live_utils
 *
 * Increases the thread-safe counter tracking active Socket_T instances.
 * Automatically invoked by Socket_new(), Socket_new_from_fd(), and
 * Socket_accept() after successful allocation and initialization.
 *
 *  Behavior
 * - Performs atomic increment (or mutex-protected if atomic unavailable)
 * - No error conditions - always succeeds
 * - Used for leak detection and resource monitoring
 *
 *  Internal Usage Pattern
 *
 * @code{.c}
 * // In Socket_new() or similar:
 * struct Socket_T *sock = Arena_alloc(arena, sizeof(struct Socket_T),
 * __FILE__, __LINE__);
 * // ... initialize fields ...
 * socket_live_increment();  // Track new live instance
 * return (Socket_T)sock;
 * @endcode
 *
 *  Balancing
 * Always paired with socket_live_decrement() in Socket_free().
 *
 * @threadsafe Yes - atomic operation or internal locking ensures
 * multi-threaded safety
 *
 * @complexity O(1) - single atomic increment
 *
 * @note Implementation delegates to SocketLiveCount_increment() in
 * SocketCommon-private.h
 *
 * @see @ref socket_live_utils for related utilities
 * @see socket_live_decrement() for decrement counterpart
 * @see Socket_debug_live_count() for querying total count
 * @see core/SocketCommon-private.h for underlying counter mechanism
 * @see docs/TESTING.md#leak-detection for test verification patterns
 */
extern void socket_live_increment (void);

/**
 * @brief Decrement the global live socket counter atomically.
 * @private
 * @ingroup socket_live_utils
 *
 * Decreases the thread-safe counter tracking active Socket_T instances.
 * Automatically invoked by Socket_free() before deallocating resources and
 * closing fd.
 *
 *  Behavior
 * - Performs atomic decrement (or mutex-protected)
 * - Includes assertions in debug builds if count underflow
 * - Signals potential double-free if invoked on already-freed socket
 *
 *  Internal Usage Pattern
 *
 * @code{.c}
 * // In Socket_free():
 * if (atomic_load(&sock->freed)) return;  // Double-free guard
 * atomic_store(&sock->freed, 1);
 * // ... cleanup resources, close fd ...
 * socket_live_decrement();  // Untrack freed instance
 * Arena_free(sock->base.arena, sock);  // Or dispose
 * @endcode
 *
 *  Balancing
 * Paired with socket_live_increment() during allocation.
 *
 * @threadsafe Yes - atomic operation ensures safety in concurrent frees
 *
 * @complexity O(1) - single atomic decrement
 *
 * @warning Must not be called on invalid/freed sockets - use atomic 'freed'
 * guard
 * @note Debug builds may assert(count > 0) to catch underflow
 *
 * @see @ref socket_live_utils for related utilities
 * @see socket_live_increment() for increment counterpart
 * @see Socket_debug_live_count() for querying total count
 * @see core/SocketCommon-private.h for underlying mechanism
 * @see docs/TESTING.md#leak-detection for verification
 */
extern void socket_live_decrement (void);

/**
 * @brief Query current number of active Socket_T instances (public for tests).
 * @ingroup socket_live_utils
 *
 * Returns the global count of currently allocated and live Socket_T objects.
 * Exposed publicly in Socket.h for unit testing and debugging purposes.
 *
 *  Usage in Tests
 *
 * @code{.c}
 * // At end of test case:
 * assert(Socket_debug_live_count() == 0 && "Socket leak detected!");
 *
 * // During test setup/teardown verification:
 * int before = Socket_debug_live_count();
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * assert(Socket_debug_live_count() == before + 1);
 * Socket_free(&sock);
 * assert(Socket_debug_live_count() == before);
 * @endcode
 *
 *  Behavior
 * - Returns instantaneous snapshot of live count
 * - Thread-safe read operation
 * - No side effects or exceptions
 *
 * @return Current live socket count (>= 0)
 *
 * @threadsafe Yes - atomic read or mutex-protected query
 *
 * @complexity O(1) - simple counter read
 *
 *  Public vs Private
 * - Declared in Socket.h for test access
 * - Implementation details in Socket-private.h and SocketCommon-private.h
 * - Tests should use this to verify no leaks
 *
 * @warning Non-zero count at test end indicates memory leak or unclosed
 * sockets
 * @note Counter wraps around at UINT_MAX (unlikely in practice)
 *
 * @see @ref socket_live_utils for counter management functions
 * @see socket_live_increment() and socket_live_decrement() for updates
 * @see core/SocketCommon-private.h for implementation
 * @see docs/TESTING.md#resource-leak-detection for best practices
 * @see Socket.h for public declaration
 */
extern int Socket_debug_live_count (void);

/** @} */ /* End socket_live_utils group */

#if SOCKET_HAS_TLS
/**
 * @defgroup socket_tls_utils Internal TLS Field Utilities
 * @brief Utilities for initializing and managing TLS state in Socket_T.
 * @private
 * @ingroup core_io
 *
 * These functions handle TLS-specific initialization and cleanup within
 * the Socket_T structure. Only compiled and available when SOCKET_HAS_TLS
 * == 1.
 *
 *  Purpose
 * - Zero-initialize TLS fields to prevent use of uninitialized state
 * - Called during socket creation paths to ensure safe defaults
 * - Supports conditional compilation for non-TLS builds
 *
 *  TLS Integration Flow
 *
 * 1. Socket_new() or Socket_accept() calls socket_init_tls_fields()
 * 2. SocketTLS_enable() populates tls_ssl, tls_ctx from shared context
 * 3. Handshake via SocketTLS_handshake() updates state and buffers
 * 4. Socket_free() or shutdown cleans up and secure-clears buffers
 *
 * @note Use `#if SOCKET_HAS_TLS` guards (value check, not #ifdef)
 * @warning Sensitive data (keys, buffers) securely erased on cleanup
 * @threadsafe Partial - initialization is single-threaded; runtime ops locked
 *
 * @see tls/SocketTLS.h for public TLS API
 * @see docs/SECURITY.md#tls-hardening for configuration
 * @see docs/TIMEOUTS.md for TLS-specific timeouts
 * @{
 */

/**
 * @brief Initialize all TLS fields in Socket_T to safe defaults.
 * @private
 * @ingroup socket_tls_utils
 * @param[in,out] sock Socket instance to initialize TLS fields for
 *
 * Zero-initializes or NULLs all TLS-related fields in the Socket_T structure.
 * Called from all socket creation paths: Socket_new(), Socket_new_from_fd(),
 * Socket_accept(), etc., to ensure clean state before any TLS operations.
 *
 *  What Gets Initialized
 * | Field | Initial Value | Purpose |
 * |-------|---------------|---------|
 * | tls_ctx | NULL | No shared TLS context yet |
 * | tls_ssl | NULL | No per-socket SSL session |
 * | tls_enabled | 0 | TLS not activated |
 * | tls_handshake_done | 0 | No handshake completed |
 * | tls_shutdown_done | 0 | No shutdown performed |
 * | tls_*_buf | NULL/0 | No pending encrypted/decrypted data |
 * | tls_sni_hostname | NULL | No SNI set |
 * | tls_timeouts | Defaults | Inherit from SocketConfig |
 *
 *  Usage Pattern
 *
 * @code{.c}
 * // In Socket_new():
 * struct Socket_T *sock = ALLOC(arena, sizeof(struct Socket_T), ...);
 * // ... init base fields ...
 * #if SOCKET_HAS_TLS
 *   socket_init_tls_fields(sock);  // Zero TLS fields
 * #endif
 * @endcode
 *
 *  Error Handling
 * - No exceptions raised - simple assignments
 * - Allocation failures handled at higher levels (Arena_alloc)
 *
 * @threadsafe No - direct field writes; call during construction before
 * multi-thread access
 *
 * @complexity O(1) - fixed number of field assignments
 *
 * @note Only compiled when CMake sets SOCKET_HAS_TLS=1 (OpenSSL/LibreSSL
 * detected)
 * @warning Fields must be re-initialized after deserialization or memcpy (if
 * ever used)
 *
 * @see SocketTLS_enable() for activating TLS after init
 * @see Socket_free() for cleanup counterpart
 * @see @ref socket_tls_utils for related TLS utilities
 * @see tls/SocketTLS.h for handshake and I/O functions
 * @see docs/SECURITY.md for TLS best practices
 * @see core/SocketConfig.h for default timeouts
 */
/** @} */ /* End socket_tls_utils group */
extern void socket_init_tls_fields (Socket_T sock);
#endif

/**
 * @brief Internal structure for Socket_T - extends SocketBase_T with
 * TCP-specific features.
 * @private
 * @ingroup core_io
 *
 * Full implementation of the opaque Socket_T type, providing the complete
 * state for TCP/IP and Unix domain sockets. Embeds SocketBase_T for common
 * fields and adds protocol-specific elements like bandwidth throttling and
 * conditional TLS state.
 *
 *  Structure Hierarchy
 * - **Base**: SocketBase_T (fd, arena, endpoints, timeouts, metrics, flags)
 * - **TCP Extensions**: bandwidth_limiter, freed atomic
 * - **TLS Extensions** (SOCKET_HAS_TLS): tls_* fields for secure transport
 *
 *  Memory Management
 * - All dynamic allocations (strings, buffers) from base.arena
 * - Arena lifetime tied to socket - cleared on free
 * - Sensitive data (TLS buffers, keys) securely zeroed
 *
 *  Key Features
 * | Feature | Description | Fields Involved |
 * |---------|-------------|-----------------|
 * | Bandwidth Limiting | Token bucket throttling for sends | bandwidth_limiter
 * | | Double-Free Guard | Atomic sentinel prevents races | freed | | TLS State
 * | Non-blocking TLS 1.3+ support | tls_* (conditional) | | Endpoint Tracking
 * | Local/peer addresses and ports | base endpoints |
 *
 *  Thread Safety
 * - **Atomic Fields** (freed): Fully safe for concurrent access
 * - **Limiter**: Internal mutex in SocketRateLimit_T
 * - **TLS Fields**: Protected by SocketTLS module locking
 * - **Base Fields**: Varies - use public functions for safe access
 * - **Overall**: Public API thread-safe; direct access requires locks
 *
 *  Conditional Compilation Impact
 * - Without TLS: Smaller struct, no tls_* fields or init function
 * - With TLS: Additional ~100 bytes, buffers for pending I/O data
 * - Always use #if SOCKET_HAS_TLS for code guards
 *
 *  Lifecycle
 * 1. Allocation: Arena_alloc(sizeof(Socket_T)), init fields,
 * socket_live_increment()
 * 2. Usage: Public functions access/manipulate fields safely
 * 3. Cleanup: socket_live_decrement(), close fd, secure clear, Arena_free()
 *
 * @warning Direct field modification breaks invariants, thread safety, and ABI
 * @note sizeof(Socket_T) not guaranteed stable - compile-time dependent
 * @complexity Field access O(1); operations may acquire locks O(1) avg
 *
 *  Field Documentation
 * See individual field comments for details on usage, safety, and integration.
 *
 * @see socket/Socket.h for public opaque typedef and API
 * @see socket/SocketCommon-private.h for embedded SocketBase_T details
 * @see core/SocketRateLimit.h for bandwidth_limiter integration
 * @see tls/SocketTLS.h for TLS fields and functions (#if SOCKET_HAS_TLS)
 * @see docs/MEMORY_MANAGEMENT.md for arena patterns
 * @see docs/SECURITY.md for TLS hardening and throttling
 * @see docs/TIMEOUTS.md for timeout configuration
 * @see docs/ERROR_HANDLING.md for exception safety in ops
 * @see @ref socket_live_utils for live counting integration
 */
struct Socket_T
{
  SocketBase_T
      base; /**< @brief Core base structure shared across all socket types
             * (TCP, UDP, etc.).
             *
             * Embeds fundamental elements:
             * - fd: Underlying file descriptor
             * - arena: Memory arena for dynamic allocations
             * - endpoints: Local/peer addresses, ports, resolution state
             * - timeouts: Basic and extended timeout config
             * - metrics: Send/recv bytes, errors, etc.
             * - flags/state: Connected, bound, listening, closed, etc.
             *
             * @private
             * @details All socket implementations inherit/extend this base for
             * consistency. Thread safety varies: atomics for flags, mutexes
             * for metrics/timeouts.
             *
             * @warning Do not access directly - use public getters/setters
             * (e.g., Socket_fd(), Socket_timeouts_get())
             * @threadsafe Partial - public API provides safe access
             *
             * @see socket/SocketCommon-private.h for full base definition and
             * fields
             * @see docs/MEMORY_MANAGEMENT.md for arena details
             * @see docs/METRICS.md for metrics tracking
             * @see docs/TIMEOUTS.md for timeout handling */

  /**
   * @brief Optional bandwidth rate limiter for throttling send operations.
   * @private
   * @details Token bucket algorithm to enforce bytes-per-second limits.
   * NULL if Socket_setbandwidth() not called or unlimited.
   * Integrated into send/sendv paths for enforcement.
   */
  SocketRateLimit_T
      bandwidth_limiter; /**< Pointer to rate limit instance (or NULL).
                          * @see Socket_setbandwidth() public setter.
                          * @see core/SocketRateLimit.h
                          */

  _Atomic int
      freed; /**< @brief Atomic sentinel for double-free protection.
              * 0 = socket in use, 1 = free operation in progress.
              * Accessed via atomic_exchange with memory_order_acq_rel
              * to ensure visibility in multi-threaded close scenarios.
              * @private
              * @note Prevents use-after-free in concurrent environments.
              */

#if SOCKET_HAS_TLS
  /**
   * @brief TLS/SSL state and buffers for secure transport layer integration.
   * @private
   * @details Compiled only when SOCKET_HAS_TLS=1. Provides full support for
   * TLS 1.2+ (1.3 preferred) with non-blocking handshake, record I/O, and
   * buffering. Handles pending encrypted/decrypted data during async
   * operations. Opaque pointers (SSL_CTX*, SSL*) hide backend details
   * (OpenSSL/LibreSSL).
   *
   *  TLS Fields Overview
   * | Field | Type | Purpose | Thread Safety |
   * |-------|------|---------|---------------|
   * | tls_ctx | void* (SSL_CTX*) | Shared context with certs/protocols |
   * Read-only after init | | tls_ssl | void* (SSL*) | Per-socket
   * session/crypto state | Locked by SocketTLS_* | | tls_enabled | int flag |
   * TLS activation status | Atomic | | tls_handshake_done | int flag |
   * Handshake completion | Atomic | | tls_shutdown_done | int flag | Shutdown
   * status | Atomic | | tls_last_handshake_state | int | Debug/resume info |
   * Read-only | | tls_sni_hostname | char* | SNI for virtual hosting |
   * Arena-allocated | | tls_read_buf / tls_write_buf | void* | Pending I/O
   * buffers | Locked during I/O | | tls_*_buf_len | size_t | Buffer data
   * lengths | Locked during I/O | | tls_timeouts | SocketTimeouts_T |
   * TLS-specific timeouts | Copied on set |
   *
   *  Initialization and Lifecycle
   * - **Init**: socket_init_tls_fields() zeros all fields on creation
   * - **Enable**: SocketTLS_enable() sets tls_ssl/tls_ctx/enabled
   * - **Handshake**: SocketTLS_handshake() updates state/buffers
   * - **I/O**: SocketTLS_send/recv manage buffers and flow control
   * - **Cleanup**: SocketTLS_shutdown() or Socket_free() frees and
   * secure-clears
   *
   *  Security Considerations
   * - Buffers use secure zeroing for sensitive crypto data
   * - SNI hostname validated and arena-allocated
   * - Timeouts prevent indefinite blocking in handshakes
   * - Supports session resumption for performance
   *
   *  Non-Blocking Support
   * - Buffers handle partial reads/writes during handshake and records
   * - State flags track progress for poll/event integration
   * - Integrates with SocketPoll via underlying fd events
   *
   * @warning Never access directly - use SocketTLS_* public API for safety
   * @note Fields padded/aligned for performance; size impacts memory usage
   * @threadsafe Partial - flags atomic, but buffers/state require locking
   *
   * @see socket_init_tls_fields() for initialization
   * @see @ref socket_tls_utils for related utilities
   * @see tls/SocketTLS.h for public functions (enable, handshake, send/recv)
   * @see docs/SECURITY.md#tls-hardening for cipher suites and config
   * @see docs/ASYNC_IO.md for non-blocking TLS patterns
   * @see docs/TIMEOUTS.md for tls_timeouts details
   * @see core/SocketConfig.h for base timeout inheritance
   */
  void *tls_ctx; /**< Opaque pointer to SSL_CTX: shared TLS context (certs,
                  * keys, protocols, ciphers). Set by SocketTLS_enable();
                  * shared across sockets from same context.
                  * @private @note Reference-counted; freed on context destroy.
                  */
  void *tls_ssl; /**< Opaque pointer to SSL: per-socket TLS session and crypto
                  * state. Manages handshake, records, alerts, and resumption.
                  * @private @warning Never NULL after enable without proper
                  * cleanup. */
  int tls_enabled; /**< Flag indicating TLS is enabled/activated (1=yes, 0=no).
                    * Set by SocketTLS_enable(); checked before TLS operations.
                    * @private @threadsafe Atomic access recommended. */
  int tls_handshake_done; /**< Flag: successful TLS handshake completed
                           * (1=yes). Updated by SocketTLS_handshake*();
                           * enables full duplex I/O.
                           * @private @note Reset on renegotiation if
                           * supported. */
  int tls_shutdown_done;  /**< Flag: clean TLS shutdown performed (close_notify
                           * exchanged).  Set after bidirectional shutdown;
                           * prevents further I/O.
                           * @private @see SocketTLS_shutdown() for triggering.
                           */
  int tls_last_handshake_state; /**< Retained state from most recent handshake
                                 * attempt. For debugging, resumption, or error
                                 * recovery. Values from TLSHandshakeState
                                 * enum.
                                 * @private @note Helps diagnose partial
                                 * handshakes in non-blocking mode. */
  char *
      tls_sni_hostname; /**< Arena-allocated SNI hostname string for
                         * server-side virtual hosting. Set via
                         * SocketTLS_set_hostname(); used in client hello.
                         * @private @note Validated UTF-8; freed with arena. */
  void *
      tls_read_buf; /**< Buffer holding decrypted inbound TLS data or pending
                     * reads. Managed during recv to handle partial records.
                     * @private @warning Secure-clear on free; size dynamic. */
  void *tls_write_buf;     /**< Buffer holding encrypted outbound TLS data or
                            * pending writes.     Managed during send for partial
                            * records/handshakes.
                            * @private @warning Secure-clear on free; size dynamic.
                            */
  size_t tls_read_buf_len; /**< Length of usable data in tls_read_buf.
                            * Updated after decryption; consumed by app recv.
                            * @private @note 0 when empty/full processed. */
  size_t
      tls_write_buf_len; /**< Length of data waiting in tls_write_buf.
                          * Bytes to flush during next write event.
                          * @private @note Managed by SocketTLS_send/flush. */
  SocketTimeouts_T
      tls_timeouts; /**< TLS-specific timeout overrides (handshake, idle,
                     * etc.). Supplements base.timeouts; 0=inherited,
                     * -1=infinite.
                     * @private @see Socket_timeouts_set_extended() for config
                     * @see core/SocketConfig.h for defaults and structure. */
  int tls_renegotiation_count; /**< Counter for TLS renegotiation events on
                                * this socket. Used for DoS protection - reject
                                * if exceeds SOCKET_TLS_MAX_RENEGOTIATIONS.
                                * Reset on disable. TLS 1.3 always 0 (no reneg).
                                * @private @see SocketTLS_check_renegotiation()
                                */

  /**
   * @brief kTLS (Kernel TLS) offload state fields.
   * @private
   * @details Tracks kTLS activation and offload status for TX/RX paths.
   * kTLS offloads TLS record encryption/decryption to the Linux kernel,
   * reducing context switches and improving performance. Requires:
   * - Linux 4.13+ kernel with CONFIG_TLS=y
   * - OpenSSL 3.0+ compiled with enable-ktls
   * - Compatible cipher (AES-GCM-128/256, ChaCha20-Poly1305)
   *
   * When kTLS is active, SSL_write/SSL_read continue to work normally -
   * OpenSSL handles the kernel offload internally through its BIO layer.
   *
   * @see SocketTLS_enable_ktls() for activation
   * @see SocketTLS_is_ktls_tx_active() / SocketTLS_is_ktls_rx_active() for status
   */
  int tls_ktls_enabled; /**< kTLS offload requested by user (1=yes, 0=no).
                         * Set by SocketTLS_enable_ktls(); actual activation
                         * depends on kernel/OpenSSL support and cipher.
                         * @private */
  int tls_ktls_tx_active; /**< kTLS TX (transmit) offload currently active.
                           * Set after successful handshake if kTLS enabled
                           * and kernel accepted TX offload.
                           * Check with BIO_get_ktls_send().
                           * @private */
  int tls_ktls_rx_active; /**< kTLS RX (receive) offload currently active.
                           * Set after successful handshake if kTLS enabled
                           * and kernel accepted RX offload.
                           * Check with BIO_get_ktls_recv().
                           * @private */
#endif
};

#endif /* SOCKET_PRIVATE_H_INCLUDED */
