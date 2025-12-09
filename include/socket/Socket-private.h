#ifndef SOCKET_PRIVATE_H_INCLUDED
#define SOCKET_PRIVATE_H_INCLUDED

/**
 * @file Socket-private.h
 * @brief Private implementation details for the Socket module, including internal structure definition.
 * @private Internal use only; do not include directly in application code.
 * @ingroup core_io
 *
 * This header defines the opaque Socket_T structure for internal manipulation
 * and provides utility functions shared across socket implementation files.
 * It includes conditional TLS fields when SOCKET_HAS_TLS is enabled.
 *
 * @see socket/Socket.h for the public socket API.
 * @see socket/SocketCommon-private.h for shared base structure.
 * @see core/SocketRateLimit.h for bandwidth limiting integration.
 * @see docs/ERROR_HANDLING.md for exception handling in socket operations.
 */

#include "core/Arena.h"           /**< Arena-based memory management for socket allocations. @see core/Arena.h @ingroup foundation */

#include "core/SocketConfig.h"       /**< Global socket configuration and default timeouts. @see core/SocketConfig.h @ingroup core_io */

#include "core/SocketRateLimit.h"    /**< Token bucket rate limiter for bandwidth control. @see core/SocketRateLimit.h @ingroup utilities */ */

#include "socket/Socket.h"           /**< Public opaque Socket_T declaration and API. */ */

#include "socket/SocketCommon-private.h" /**< Shared SocketBase_T structure for all socket types. @see socket/SocketCommon-private.h @private */ */

#include <stdatomic.h>               /**< C11 atomic operations for thread-safe state management (e.g., free flag). */

/**
 * @brief Utility functions for managing global live socket count across modules.
 * @private
 * @ingroup core_io
 * @details These functions maintain a thread-safe counter of active Socket instances
 * for debugging, leak detection, and resource tracking. Called during alloc/free.
 * Tests must verify socket_debug_live_count() == 0 after teardown.
 * @see Socket.h for public debugging if exposed.
 * @note Atomic operations ensure correctness in multi-threaded environments.
 */
 
/**
 * @brief Atomically increment the global live socket counter.
 * @private
 * @ingroup core_io
 * @details Invoked on successful Socket_T allocation (e.g., Socket_new).
 * @see socket_live_decrement() for balancing decrement.
 */
extern void socket_live_increment(void);

/**
 * @brief Atomically decrement the global live socket counter.
 * @private
 * @ingroup core_io
 * @details Invoked on Socket_T deallocation (e.g., Socket_free).
 * @see socket_live_increment() for balancing increment.
 */
extern void socket_live_decrement(void);

/**
 * @brief Query the current number of live Socket instances.
 * @private
 * @ingroup core_io
 * @return int The current count of allocated Socket_T objects.
 * @details Primarily for unit tests and debug builds to detect leaks.
 * Public equivalent may exist as Socket_debug_live_count() in Socket.h.
 */
extern int socket_debug_live_count(void);

#if SOCKET_HAS_TLS
/**
 * @brief Initialize all TLS-related fields in a newly created or accepted Socket_T.
 * @private
 * @ingroup core_io
 * @param sock The Socket_T instance to initialize.
 * @details Shared utility called from Socket_new(), Socket_accept(), or TLS enable paths.
 * Allocates internal buffers from sock->base.arena and sets up opaque TLS pointers.
 * Prepares for TLS handshake by configuring SNI if provided.
 * @note Only compiled and called when SOCKET_HAS_TLS == 1.
 * @throws Arena_Failed if buffer allocation fails.
 * @throws SocketTLS_Failed if underlying TLS context creation fails.
 * @see tls/SocketTLS.h for public TLS handshake and I/O functions.
 * @see SocketTLS_enable() which may invoke this internally.
 * @see docs/SECURITY.md for TLS best practices and configuration.
 */
extern void socket_init_tls_fields(Socket_T sock);
#endif

/**
 * @brief Opaque Socket_T structure definition for internal use.
 * @private
 * @ingroup core_io
 * @details Complete internal representation of a socket instance, extending SocketBase_T
 * with protocol-specific features like bandwidth limiting and TLS state.
 * 
 * Memory for fields like buffers and strings is allocated from the embedded arena.
 * Thread-safety varies by field; atomic for shared state, mutex-protected for complex ops.
 * Conditional compilation for TLS fields via #if SOCKET_HAS_TLS.
 * 
 * @warning Direct field access is unsupported and may break ABI. Use public functions.
 * @see socket/Socket.h for opaque type and public methods.
 * @see socket/SocketCommon-private.h for base fields documentation.
 * @see core/SocketRateLimit.h for limiter details.
 * @see tls/SocketTLS.h for TLS integration (when enabled).
 * @see docs/MEMORY_MANAGEMENT.md for arena usage guidelines.
 * @see docs/SECURITY.md for TLS and rate-limiting security considerations.
 */
struct Socket_T
{
  SocketBase_T base; /**< @brief Embedded base structure shared with other socket types.
                          * Contains core elements: fd, arena, endpoints (local/peer),
                          * timeouts, metrics, and common flags/state.
                          * @private
                          * @see SocketCommon-private.h
                          */

  /**
   * @brief Optional bandwidth rate limiter for throttling send operations.
   * @private
   * @details Token bucket algorithm to enforce bytes-per-second limits.
   * NULL if Socket_setbandwidth() not called or unlimited.
   * Integrated into send/sendv paths for enforcement.
   */
  SocketRateLimit_T bandwidth_limiter; /**< Pointer to rate limit instance (or NULL). 
                                            * @see Socket_setbandwidth() public setter.
                                            * @see core/SocketRateLimit.h
                                            */

  _Atomic int freed; /**< @brief Atomic sentinel for double-free protection.
                          * 0 = socket in use, 1 = free operation in progress.
                          * Accessed via atomic_exchange with memory_order_acq_rel
                          * to ensure visibility in multi-threaded close scenarios.
                          * @private
                          * @note Prevents use-after-free in concurrent environments.
                          */

#if SOCKET_HAS_TLS
  /**
   * @brief TLS/SSL-specific state and buffers for secure transport.
   * @private
   * @details Enabled only when SOCKET_HAS_TLS=1 (OpenSSL/LibreSSL detected).
   * Supports TLS 1.2+ with 1.3 preferred; handles handshakes, records, and buffering.
   * Buffers manage pending encrypted/decrypted data during non-blocking I/O.
   * Opaque pointers hide implementation details.
   * 
   * @note Fields zeroed or freed during Socket_free() or TLS shutdown.
   * @warning Sensitive data in buffers cleared with secure erase.
   * @see SocketTLS.h for public TLS enable/handshake/shutdown.
   * @see docs/SECURITY.md#tls-hardening for configuration and cipher suites.
   * @see docs/TIMEOUTS.md for TLS timeout handling.
   */
  void *tls_ctx;                  /**< Opaque SSL_CTX* : Global TLS context with certs, keys, protocols. */
  void *tls_ssl;                  /**< Opaque SSL* : Per-socket TLS session and crypto state. */
  int tls_enabled;                /**< Flag: 1 if TLS activated via SocketTLS_enable(). */
  int tls_handshake_done;         /**< Flag: 1 after successful TLS handshake completion. */
  int tls_shutdown_done;          /**< Flag: 1 after clean TLS shutdown (close_notify sent/received). */
  int tls_last_handshake_state;   /**< Retained state from last handshake for debugging/resumption. */
  char *tls_sni_hostname;         /**< Arena-allocated SNI string for server-side virtual hosting. */
  void *tls_read_buf;             /**< Buffer for decrypted inbound TLS data or pending reads. */
  void *tls_write_buf;            /**< Buffer for encrypted outbound TLS data or pending writes. */
  size_t tls_read_buf_len;        /**< Usable data length in tls_read_buf. */
  size_t tls_write_buf_len;       /**< Usable data length in tls_write_buf. */
  SocketTimeouts_T tls_timeouts;  /**< Overrides for TLS ops (handshake, idle); supplements base.timeouts.
                                       * @see core/SocketConfig.h
                                       */
#endif
};

#endif /* SOCKET_PRIVATE_H_INCLUDED */
