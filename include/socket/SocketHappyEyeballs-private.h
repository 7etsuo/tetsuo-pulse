/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED
#define SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED

/**
 * @file SocketHappyEyeballs-private.h
 * @brief Internal structures and state for Happy Eyeballs connection racing
 * (RFC 8305).
 * @ingroup async_io
 *
 * Part of the Socket Library.
 *
 * This header contains internal implementation details for the Happy Eyeballs
 * module. Not for public use - structures and functions may change without
 * notice.
 *
 * The Happy Eyeballs algorithm races IPv6 and IPv4 connection attempts to
 * minimize connection latency on dual-stack hosts.
 *
 * @see SocketHappyEyeballs.h for the public API.
 * @see @ref async_io "Async I/O module" for integration with event loops.
 * @see SocketDNS.h for asynchronous DNS resolution used in racing.
 */

#include "core/Arena.h"
#include "dns/SocketDNSResolver.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"

#include <netdb.h>
#include <stdint.h>
#include <time.h>

/**
 * @brief Maximum number of simultaneous connection attempts allowed.
 * @ingroup async_io
 * @note Default 8, as recommended by RFC 8305 for balancing performance and
 * resources.
 * @see SocketHE_T::attempt_count for runtime tracking.
 */
#ifndef SOCKET_HE_MAX_ATTEMPTS
#define SOCKET_HE_MAX_ATTEMPTS 8
#endif

/**
 * @brief Size of internal error message buffer in bytes.
 * @ingroup async_io
 * @note Sufficient for typical errno/strerror messages plus context.
 */
#ifndef SOCKET_HE_ERROR_BUFSIZE
#define SOCKET_HE_ERROR_BUFSIZE 256
#endif

/**
 * @brief Size of thread-local error buffer for SocketHappyEyeballs_connect().
 * @ingroup async_io
 * @note Used to preserve error messages across SocketHappyEyeballs_free() in
 * synchronous blocking mode. Must be large enough to accommodate detailed
 * multi-attempt failure messages. Value of 512 chosen to balance memory usage
 * (per-thread stack) with comprehensive error reporting for connection races.
 * @see SocketHappyEyeballs_connect() for usage context.
 */
#ifndef SOCKET_HE_CONNECT_ERROR_BUFSIZE
#define SOCKET_HE_CONNECT_ERROR_BUFSIZE 512
#endif

/**
 * @brief State enumeration for individual Happy Eyeballs connection attempts.
 * @ingroup async_io
 *
 * Defines discrete states tracking the lifecycle of a single parallel
 * connect(2) attempt within the RFC 8305 racing algorithm. Used to determine
 * readiness for I/O, winner selection, or cleanup. Transitions occur during
 * SocketHappyEyeballs_process() based on poll events, timeouts, and system
 * call results.
 *
 * State Progression:
 * - HE_ATTEMPT_IDLE: Initial state; attempt allocated but connect(2) not yet
 * called.
 * - HE_ATTEMPT_CONNECTING: Non-blocking connect(2) initiated; pending
 * completion signal.
 * - HE_ATTEMPT_CONNECTED: connect(2) succeeded (no error); socket ready for
 * use.
 * - HE_ATTEMPT_FAILED: Attempt aborted due to error, timeout, or cancellation.
 *
 * Transitions:
 * - IDLE → CONNECTING: When address selected and socket created/connect
 * started.
 * - CONNECTING → CONNECTED: Poll detects writability without error or
 * getsockopt(SO_ERROR)==0.
 * - CONNECTING → FAILED: Poll error, timeout expiry, or connect errno !=
 * EINPROGRESS.
 * - CONNECTED/FAILED → IDLE or destroyed: After winner selection or cleanup
 * phase.
 *
 * @note Only one transition per process() cycle per attempt for determinism.
 * @note FAILED state preserves specific errno in attempt::error for root cause
 * analysis.
 * @note No "PARTIAL" or TLS-specific states; focused on TCP connect phase
 * only.
 * @warning State races undefined if accessed concurrently outside owning
 * thread.
 *
 * @see SocketHE_Attempt_T::state for per-attempt storage and updates.
 * @see SocketHE_T::attempts for list of attempts sharing this enum.
 * @see SocketHappyEyeballs_process() for advancement logic.
 * @see SocketHE_State for higher-level operation states.
 * @see docs/ASYNC_IO.md#connection-attempt-states for visual state diagram.
 * @see Socket_get_monotonic_ms() for timeout calculations involving states.
 */
typedef enum SocketHE_AttemptState
{
  HE_ATTEMPT_IDLE = 0,   /**< Attempt not yet started. */
  HE_ATTEMPT_CONNECTING, /**< Non-blocking connect(2) in progress. */
  HE_ATTEMPT_CONNECTED,  /**< Connection successfully established. */
  HE_ATTEMPT_FAILED      /**< Connection attempt failed (error or timeout). */
} SocketHE_AttemptState;

/**
 * @brief Single connection attempt structure in Happy Eyeballs racing.
 * @ingroup async_io
 *
 * Represents one parallel connection try to a resolved address in the
 * IPv4/IPv6 racing algorithm (RFC 8305). Multiple instances are created and
 * managed concurrently to minimize connection latency. Allocated from the
 * owning SocketHE_T::arena for efficient, bulk memory management; linked via
 * ::next in a singly-linked list for O(1) append/removal.
 *
 * Lifecycle Management:
 * - Created internally by SocketHE_T when initiating connect(2) to a specific
 * address.
 * - Progress tracked via ::state transitions during
 * SocketHappyEyeballs_process().
 * - On success: ::socket may become the winner (transferred to caller) or
 * closed on loss.
 * - On failure/timeout: ::socket closed, ::error set, state to FAILED.
 * - Destroyed automatically via Arena_clear/dispose in owning context.
 *
 * Thread Safety Characteristics:
 * - No - internal opaque structure; concurrent access from multiple threads
 * leads to undefined behavior.
 * - All modifications protected by owning SocketHE_T's internal
 * synchronization (if implemented).
 *
 * Related Types and Functions:
 * - Integrated with SocketHE_T::attempts list and SocketHE_AddressEntry_T for
 * address selection.
 * - State machine driven by internal connection polling logic.
 * - Error reporting via ::error for post-mortem analysis.
 *
 * @note Fields are private implementation details; direct manipulation
 * corrupts the state machine.
 * @note ::addr borrows reference from ::resolved in SocketHE_T; lifetime tied
 * to context.
 * @note ::error captures exact errno from connect(2), sendmmsg(2), or poll(2)
 * failures.
 * @note ::start_time_ms uses Socket_get_monotonic_ms() for accurate elapsed
 * time calculations.
 * @warning External closure of ::socket invalidates attempt state; avoid
 * concurrent I/O.
 * @warning Reuse of freed attempts undefined; rely on arena management.
 *
 * @complexity O(1) access and update - direct field access, no lookups.
 *
 * @see SocketHE_AttemptState for detailed state transitions.
 * @see SocketHE_T::attempts for list integration and iteration.
 * @see SocketHappyEyeballs.h for public-facing connection API.
 * @see Socket_T for underlying socket operations and ownership rules.
 * @see Socket_get_monotonic_ms() for timing source.
 * @see docs/ASYNC_IO.md#happy-eyeballs-connection-racing for algorithm
 * context.
 */
typedef struct SocketHE_AddressEntry
{
  Socket_T socket; /**< Socket instance (NULL if failed or completed). */
  struct addrinfo
      *addr;  /**< Target address (borrowed reference from DNS results). */
  int family; /**< Address family (AF_INET or AF_INET6 from
                 addrinfo.ai_family). */
  int tried;  /**< 0 if not attempted, 1 if connect() called (success or fail).
               */
  SocketHE_AttemptState state; /**< Current state of the attempt. */
  int error;                   /**< Saved errno on failure (0 if not failed). */
  int64_t
      start_time_ms; /**< Monotonic timestamp when connect() started (ms). */
  struct SocketHE_AddressEntry
      *next; /**< Next entry in preference-sorted list. */
} SocketHE_AddressEntry_T;
typedef struct SocketHE_Attempt
{
  Socket_T socket; /**< Socket instance (NULL if failed or completed). */
  struct addrinfo
      *addr; /**< Target address (borrowed reference from DNS results). */
  SocketHE_AttemptState state; /**< Current state of the attempt. */
  int error;                   /**< Saved errno on failure (0 if not failed). */
  int64_t
      start_time_ms; /**< Monotonic timestamp when connect() started (ms). */
  struct SocketHE_Attempt *next; /**< Next attempt in singly-linked list. */
} SocketHE_Attempt_T;

/**
 * @brief Wrapper structure for resolved addresses in Happy Eyeballs address
 * preference ordering.
 * @ingroup async_io
 *
 * Implements RFC 8305 §4.2 address sorting and interleaving logic: prefers
 * configured family (IPv6 default), tracks attempted addresses to avoid
 * duplicates, wraps struct addrinfo for simplified list management and
 * iteration. Used internally to select next address for connection attempts
 * during racing phase.
 *
 * Lifecycle Management:
 * - Created from SocketDNS results during resolution phase in SocketHE_T.
 * - Sorted by family preference and address order (stable sort preserves DNS
 * order).
 * - ::tried flag updated when attempt starts for that address.
 * - List persists until operation completes or context freed; addresses freed
 * via freeaddrinfo() on ::resolved.
 *
 * Thread Safety Characteristics:
 * - No - internal structure; access serialized by owning SocketHE_T thread.
 * - List modifications (if any) protected internally.
 *
 * Related Types and Functions:
 * - Derived from struct addrinfo * in SocketHE_T::resolved.
 * - Used to populate SocketHE_Attempt_T::addr during racing.
 * - Interleaved via SocketHE_T::next_ipv6 / ::next_ipv4 pointers for
 * dual-stack racing.
 *
 * @note ::addr is borrowed from global resolved list; do not free
 * individually.
 * @note Sorting prefers IPv6 (default) but configurable via
 * SocketHE_Config_T::prefer_ipv6.
 * @note ::family extracted for quick filtering; matches ::addr->ai_family.
 * @note ::tried prevents re-attempting failed addresses in same operation.
 * @warning Modifying ::tried externally may cause duplicate attempts or skips.
 *
 * @complexity O(n log n) initial sort - stable sort by family and address;
 * O(1) iteration.
 *
 * @see SocketHE_T::addresses for sorted list head.
 * @see SocketHE_T::next_ipv6 and ::next_ipv4 for race interleaving logic.
 * @see SocketDNS.h and SocketDNS_resolve() for address resolution source.
 * @see struct addrinfo for wrapped address details.
 * @see SocketHE_Config_T::prefer_ipv6 for preference configuration.
 * @see docs/ASYNC_IO.md#address-selection for RFC 8305 details.
 */

/**
 * @brief Main opaque context for Happy Eyeballs (RFC 8305) dual-stack
 * connection racing.
 * @ingroup async_io
 *
 * Central orchestrator for the entire Happy Eyeballs algorithm: performs
 * asynchronous DNS resolution, sorts and interleaves resolved addresses per
 * family preference, launches parallel non-blocking connect(2) attempts,
 * monitors progress via poll integration, selects first successful connection
 * as winner, cancels/closes losers, and provides cleanup. Supports both
 * blocking synchronous mode (internal polling loop) and non-blocking
 * asynchronous mode with external event loop.
 *
 * What the Type Represents:
 * - State machine managing phases: IDLE → RESOLVING → (CONNECTING | FAILED |
 * CANCELLED) → CONNECTED.
 * - Resource owner for arenas, lists, sockets, timers during operation
 * lifetime.
 * - Integration point for SocketDNS_T (async DNS) and SocketPoll_T (event
 * multiplexing).
 *
 * Lifecycle Management:
 * - Created via SocketHappyEyeballs_start() (async) or internally in
 * SocketHappyEyeballs_connect() (sync).
 * - Advanced via SocketHappyEyeballs_process() calls in async mode or internal
 * loop in sync mode.
 * - Completed when SocketHappyEyeballs_poll() returns true (CONNECTED, FAILED,
 * or CANCELLED).
 * - Resources released via SocketHappyEyeballs_free() which cancels
 * in-progress ops if needed.
 * - Public API allocates via malloc(); internals use ::arena for zero-overhead
 * allocations.
 *
 * Thread Safety Characteristics:
 * - No - explicitly not thread-safe; all operations must occur from a single
 * thread (typically event loop thread).
 * - No internal locking; assumes exclusive access by caller.
 * - Multiple independent SocketHE_T instances may be used concurrently from
 * different threads.
 * - DNS callbacks execute in SocketDNS worker threads but synchronize back to
 * main thread via pollfd.
 *
 * Related Types and Functions:
 * - Configured via SocketHE_Config_T passed at creation.
 * - Manages lists of SocketHE_Attempt_T and SocketHE_AddressEntry_T.
 * - Integrates with Socket_T for connection primitives, SocketDNS_T for
 * resolution, SocketPoll_T for events.
 * - Error reporting via SocketHappyEyeballs_error() and SocketHE_Failed
 * exception.
 * - Timing via monotonic clocks; see SocketHE_T timing fields for details.
 *
 * @note Memory: Caller frees context via SocketHappyEyeballs_free(); owns
 * resulting socket from ::winner.
 * @note ::resolved owned; call freeaddrinfo() internally on cleanup - do not
 * access externally.
 * @note ::dns and ::poll borrowed unless ::owns_dns/::owns_poll set
 * (auto-create case).
 * @note State transitions atomic within process() but check
 * SocketHappyEyeballs_state() for current.
 * @note Error buffer ::error_buf formatted for SocketHappyEyeballs_error();
 * capacity SOCKET_HE_ERROR_BUFSIZE.
 * @warning Cancelling mid-operation closes sockets and aborts DNS; resources
 * reclaimed on free().
 * @warning Exceeding ::config.total_timeout_ms triggers FAILED state with
 * timeout error.
 * @warning In sync mode, blocks up to total_timeout_ms; use async for
 * responsive apps.
 *
 * @complexity Varies by phase:
 * - Init/resolution: O(n log n) for address sort where n=resolved addresses.
 * - Connecting: O(m) where m=attempts, each poll O(1) average.
 * - Overall: Efficient for small n/m (typical <10); scales with
 * config.max_attempts.
 *
 *  Internal Architecture Diagram
 *
 * ```
 * +-------------------+     +-------------------+
 * | SocketHE_T        |<--->| SocketDNS_T       |  (async resolution)
 * | - config          |     +-------------------+
 * | - host/port       |           ^
 * | - arena           |           | owns/borrows
 * | - dns/poll        |     +-------------------+
 * | - resolved/addrs  |<--->| SocketPoll_T      |  (event integration)
 * | - attempts/winner |     +-------------------+
 * | - state/timers    |           ^
 * +-------------------+           |
 *         |                       |
 *         v                       v
 * +-------------------+     +-------------------+
 * | SocketHE_Attempt  |     | SocketHE_Address  |
 * | - socket/addr     |     | - addr/family     |
 * | - state/error     |     | - tried/next      |
 * | - time/next       |     +-------------------+
 * +-------------------+               ^
 *         ^                           |
 *         | borrows                   | wraps
 * +-------------------+     +-------------------+
 * |   struct          |     |   struct          |
 * |   addrinfo        |     |   addrinfo        |
 * +-------------------+     +-------------------+
 * ```
 *
 * @see SocketHappyEyeballs_start() and SocketHappyEyeballs_connect() for
 * public creation APIs.
 * @see SocketHE_Attempt_T for per-attempt state tracking.
 * @see SocketHE_AddressEntry_T for address selection logic.
 * @see Arena_T for internal allocation policy.
 * @see Socket_get_monotonic_ms() for all timing fields (::start_time_ms,
 * etc.).
 * @see SocketHE_State for overall operation states.
 * @see SocketHE_Config_T for tunable parameters.
 * @see docs/ASYNC_IO.md for integration guides and RFC 8305 compliance
 * details.
 * @see docs/ERROR_HANDLING.md for exception and error handling.
 */
struct SocketHE_T
{
  /* === Configuration === */
  SocketHE_Config_T config; /**< User-provided configuration options. */

  char *host; /**< Copy of target hostname (allocated from ::arena). */
  int port;   /**< Target service port number. */

  /* === External Dependencies (Borrowed) === */
  SocketDNSResolver_T resolver; /**< Async DNS resolver for resolution
                                   (NULL=create internal). */
  SocketPoll_T poll; /**< Optional event poll for async progress (NULL=sync). */

  /* === Owned Resources === */
  Arena_T arena; /**< Arena for all internal allocations. */
  Arena_T
      resolver_arena; /**< Arena for resolver (only when owns_resolver=1). */
  int owns_resolver;  /**< Flag: 1 if this context created and owns ::resolver.
                       */
  int owns_poll;      /**< Flag: 1 if this context created and owns ::poll. */

  /* === DNS State === */
  SocketDNSResolver_Query_T
      dns_query;             /**< Active asynchronous DNS query handle. */
  struct addrinfo *resolved; /**< Owned list of resolved addresses
                                (freeaddrinfo on cleanup). */
  volatile int
      dns_complete; /**< Flag: 1 if DNS resolution succeeded or failed. */
  int dns_error;    /**< Resolver error code if resolution failed. */
  volatile int dns_callback_pending; /**< Flag: 1 if callback has fired, result
                                        pending. */

  /* === Address Management === */
  SocketHE_AddressEntry_T *addresses; /**< Head of preference-sorted address
                                         list (arena-allocated). */
  SocketHE_AddressEntry_T
      *next_ipv6; /**< Pointer to next untried IPv6 address for interleaving. */
  SocketHE_AddressEntry_T
      *next_ipv4; /**< Pointer to next untried IPv4 address for interleaving. */
  int interleave_prefer_ipv6; /**< Interleave state: 1=prefer IPv6 next,
                                 0=prefer IPv4. */

  /* === Connection Attempts === */
  SocketHE_Attempt_T
      *attempts;     /**< Singly-linked list of attempt structures (head). */
  int attempt_count; /**< Count of started attempts (limited by
                        SOCKET_HE_MAX_ATTEMPTS). */
  Socket_T winner;   /**< Winning connected socket (transferred to caller on
                        success). */

  /* === Timing (Monotonic ms) === */
  int64_t start_time_ms; /**< Timestamp when Happy Eyeballs operation began. */
  int64_t first_attempt_time_ms; /**< Timestamp of first connect() call. */
  int fallback_timer_armed; /**< Flag: 1 if fallback delay timer is active. */

  /* === State Tracking === */
  SocketHE_State
      state; /**< Overall state machine state (e.g., RESOLVING, CONNECTING). */
  char error_buf[SOCKET_HE_ERROR_BUFSIZE]; /**< Buffer for formatted error
                                              messages. */
};

/**
 * @brief Safe iteration macro over linked list of connection attempts.
 * @ingroup async_io
 * @param[in] he Pointer to SocketHE_T context containing the attempts list.
 * @param[in] iter Name of the loop variable (type: SocketHE_Attempt_T *).
 * @internal
 *
 * Provides a do-while(0) for loop idiom to iterate attempts without
 * duplication. Safe for removal/modification during iteration if care is taken
 * (save iter->next before structural changes).
 *
 *  Usage Example
 *
 * @code{.c}
 * HE_FOREACH_ATTEMPT(he, attempt) {
 *   if (attempt->state == HE_ATTEMPT_CONNECTED) {
 *     // Process successful connection
 *     winner_socket = attempt->socket;
 *     break;  // Or continue to check others
 *   } else if (attempt->state == HE_ATTEMPT_FAILED) {
 *     // Log failure: attempt->error
 *   }
 * }
 * @endcode
 *
 * @note When removing attempts during iteration, manually unlink and save next
 * pointer to avoid skipping elements.
 * @warning Iteration is not reentrant; do not nest HE_FOREACH_ATTEMPT calls on
 * the same list.
 *
 * @see SocketHE_T::attempts for the list head.
 * @see SocketHE_Attempt_T::next for linking.
 * @see SocketHE_AttemptState for attempt states.
 */
#define HE_FOREACH_ATTEMPT(he, iter) \
  for (SocketHE_Attempt_T *iter = (he)->attempts; iter; iter = iter->next)

/**
 * @note Timing and Monotonic Clocks
 * @ingroup async_io
 *
 * All internal timing uses Socket_get_monotonic_ms() for reliable,
 * non-decreasing timestamps (CLOCK_MONOTONIC). This avoids issues with system
 * clock adjustments or suspend/resume.
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
