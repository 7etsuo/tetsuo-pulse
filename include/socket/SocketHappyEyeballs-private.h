#ifndef SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED
#define SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED

/**
 * @file SocketHappyEyeballs-private.h
 * @brief Internal structures and state for Happy Eyeballs connection racing (RFC 8305).
 * @ingroup core_io
 *
 * Part of the Socket Library.
 *
 * This header contains internal implementation details for the Happy Eyeballs module.
 * Not for public use - structures and functions may change without notice.
 *
 * The Happy Eyeballs algorithm races IPv6 and IPv4 connection attempts to minimize
 * connection latency on dual-stack hosts.
 *
 * @see SocketHappyEyeballs.h for the public API.
 * @see @ref async_io "Async I/O module" for integration with event loops.
 * @see SocketDNS.h for asynchronous DNS resolution used in racing.
 */

#include "core/Arena.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"

#include <netdb.h>
#include <stdint.h>
#include <time.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/**
 * @brief Maximum number of simultaneous connection attempts allowed.
 * @ingroup core_io
 * @note Default 8, as recommended by RFC 8305 for balancing performance and resources.
 * @see SocketHE_T::attempt_count for runtime tracking.
 */
#ifndef SOCKET_HE_MAX_ATTEMPTS
#define SOCKET_HE_MAX_ATTEMPTS 8
#endif

/**
 * @brief Size of internal error message buffer in bytes.
 * @ingroup core_io
 * @note Sufficient for typical errno/strerror messages plus context.
 */
#ifndef SOCKET_HE_ERROR_BUFSIZE
#define SOCKET_HE_ERROR_BUFSIZE 256
#endif

/* ============================================================================
 * Connection Attempt State
 * ============================================================================
 */

/**
 * @brief State of an individual Happy Eyeballs connection attempt.
 * @ingroup core_io
 *
 * Tracks progression: IDLE → CONNECTING (on connect(2)) → CONNECTED (success)
 * or FAILED (error/timeout).
 *
 * @see SocketHE_Attempt_T::state field usage.
 * @see SocketHE_T::attempts list of active attempts.
 */
typedef enum SocketHE_AttemptState
{
  HE_ATTEMPT_IDLE = 0,       /**< Attempt not yet started. */
  HE_ATTEMPT_CONNECTING,     /**< Non-blocking connect(2) in progress. */
  HE_ATTEMPT_CONNECTED,      /**< Connection successfully established. */
  HE_ATTEMPT_FAILED          /**< Connection attempt failed (error or timeout). */
} SocketHE_AttemptState;

/* ============================================================================
 * Connection Attempt Structure
 * ============================================================================
 */

/**
 * @brief Single connection attempt structure in Happy Eyeballs racing.
 * @ingroup core_io
 *
 * Represents one parallel connection try to a resolved address.
 * Multiple instances run concurrently for IPv4/IPv6 racing.
 * Allocated from SocketHE_T::arena; linked via ::next for list management.
 *
 * @see SocketHE_AttemptState for state transitions.
 * @see SocketHE_T::attempts head of attempt list.
 * @see SocketHappyEyeballs.h for public connection interface.
 */
typedef struct SocketHE_Attempt
{
  Socket_T socket;                  /**< Socket instance (NULL if failed or completed). */
  struct addrinfo *addr;            /**< Target address (borrowed reference from DNS results). */
  SocketHE_AttemptState state;      /**< Current state of the attempt. */
  int error;                        /**< Saved errno on failure (0 if not failed). */
  int64_t start_time_ms;            /**< Monotonic timestamp when connect() started (ms). */
  struct SocketHE_Attempt *next;    /**< Next attempt in singly-linked list. */
} SocketHE_Attempt_T;

/* ============================================================================
 * Sorted Address List
 * ============================================================================
 */

/**
 * @brief Wrapper for resolved addresses in Happy Eyeballs address ordering.
 * @ingroup core_io
 *
 * Per RFC 8305 §4.2, sorts and interleaves IPv6/IPv4 addresses preferring
 * the configured family, with tracking for which have been attempted.
 * Wraps struct addrinfo for easy iteration and management.
 *
 * @see SocketHE_T::addresses head of sorted list.
 * @see SocketHE_T::next_ipv6 and ::next_ipv4 for interleaving pointers.
 * @see SocketDNS.h for address resolution source.
 */
typedef struct SocketHE_AddressEntry
{
  struct addrinfo *addr;                /**< Borrowed pointer to resolved address info. */
  int family;                           /**< Address family: AF_INET or AF_INET6. */
  int tried;                            /**< Flag: 1 if connection attempt started for this address. */
  struct SocketHE_AddressEntry *next;   /**< Next entry in preference-sorted list. */
} SocketHE_AddressEntry_T;

/* ============================================================================
 * Main Context Structure
 * ============================================================================
 */

/**
 * @brief Main context structure for Happy Eyeballs (RFC 8305) connection racing.
 * @ingroup core_io
 *
 * Orchestrates DNS resolution, address sorting, parallel connection attempts,
 * winner selection, and cleanup. Supports both synchronous and asynchronous modes
 * via optional SocketDNS_T and SocketPoll_T integration.
 *
 * Memory policy:
 * - Context allocated via malloc() in public API.
 * - Internal structures (attempts, addresses) from ::arena.
 * - Owns ::resolved addresses (caller must not freeaddrinfo).
 * - Borrows ::dns and ::poll references; frees if ::owns_* flags set.
 *
 * Threading: Not thread-safe; single-threaded event loop usage assumed.
 *
 * @see SocketHappyEyeballs.h::SocketHE_new() for creation.
 * @see SocketHE_Attempt_T for individual attempts.
 * @see SocketHE_AddressEntry_T for address management.
 * @see Arena_T for allocation details.
 * @see Socket_get_monotonic_ms() for timing source.
 */
struct SocketHE_T
{
  /* === Configuration === */
  SocketHE_Config_T config;             /**< User-provided configuration options. */

  char *host;                           /**< Copy of target hostname (allocated from ::arena). */
  int port;                             /**< Target service port number. */

  /* === External Dependencies (Borrowed) === */
  SocketDNS_T dns;                      /**< Optional DNS resolver for async resolution (NULL=blocking). */
  SocketPoll_T poll;                    /**< Optional event poll for async progress (NULL=sync). */

  /* === Owned Resources === */
  Arena_T arena;                        /**< Arena for all internal allocations. */
  int owns_dns;                         /**< Flag: 1 if this context created and owns ::dns. */
  int owns_poll;                        /**< Flag: 1 if this context created and owns ::poll. */

  /* === DNS State === */
  Request_T dns_request;                /**< Active asynchronous DNS request handle (SocketDNS_Request_T *). */
  struct addrinfo *resolved;            /**< Owned list of resolved addresses (freeaddrinfo on cleanup). */
  int dns_complete;                     /**< Flag: 1 if DNS resolution succeeded or failed. */
  int dns_error;                        /**< SocketDNS error code if resolution failed. */

  /* === Address Management === */
  SocketHE_AddressEntry_T *addresses;   /**< Head of preference-sorted address list (arena-allocated). */
  SocketHE_AddressEntry_T *next_ipv6;   /**< Pointer to next untried IPv6 address for interleaving. */
  SocketHE_AddressEntry_T *next_ipv4;   /**< Pointer to next untried IPv4 address for interleaving. */
  int interleave_prefer_ipv6;           /**< Interleave state: 1=prefer IPv6 next, 0=prefer IPv4. */

  /* === Connection Attempts === */
  SocketHE_Attempt_T *attempts;         /**< Singly-linked list of attempt structures (head). */
  int attempt_count;                    /**< Count of started attempts (limited by SOCKET_HE_MAX_ATTEMPTS). */
  Socket_T winner;                      /**< Winning connected socket (transferred to caller on success). */

  /* === Timing (Monotonic ms) === */
  int64_t start_time_ms;                /**< Timestamp when Happy Eyeballs operation began. */
  int64_t first_attempt_time_ms;        /**< Timestamp of first connect() call. */
  int fallback_timer_armed;             /**< Flag: 1 if fallback delay timer is active. */

  /* === State Tracking === */
  SocketHE_State state;                 /**< Overall state machine state (e.g., RESOLVING, CONNECTING). */
  char error_buf[SOCKET_HE_ERROR_BUFSIZE]; /**< Buffer for formatted error messages. */
};

/**
 * @brief Safe iteration macro over linked list of connection attempts.
 * @ingroup core_io
 * @param he Pointer to SocketHE_T context containing the attempts list.
 * @param iter Name of the loop variable (type: SocketHE_Attempt_T *).
 * @internal
 *
 * Provides a do-while(0) for loop idiom to iterate attempts without duplication.
 * Safe for removal/modification during iteration if care is taken.
 *
 * @see SocketHE_T::attempts for the list head.
 * @see SocketHE_Attempt_T::next for linking.
 */
#define HE_FOREACH_ATTEMPT(he, iter)                                          \
  for (SocketHE_Attempt_T *iter = (he)->attempts; iter; iter = iter->next)

/* ============================================================================
 * Implementation Notes
 * ============================================================================
 */

/**
 * @note Timing and Monotonic Clocks
 * @ingroup core_io
 *
 * All internal timing uses Socket_get_monotonic_ms() for reliable, non-decreasing
 * timestamps (CLOCK_MONOTONIC). This avoids issues with system clock adjustments
 * or suspend/resume.
 *
 * Standard elapsed time pattern in implementation:
 * @code
 * int64_t now = Socket_get_monotonic_ms();
 * int64_t elapsed = (now > start_ms) ? (now - start_ms) : 0;
 * @endcode
 *
 * @see core/SocketUtil.h for Socket_get_monotonic_ms() and related utilities.
 * @see SocketHE_T timing fields (::start_time_ms, etc.) for usage.
 * @see @ref foundation "Foundation module" for core timing primitives.
 */

#endif /* SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED */
