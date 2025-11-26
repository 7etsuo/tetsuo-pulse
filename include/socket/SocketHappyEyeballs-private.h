#ifndef SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED
#define SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED

/**
 * SocketHappyEyeballs-private.h - Internal structures for Happy Eyeballs
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header contains internal implementation details for the Happy Eyeballs
 * module. Not for public use - structures may change without notice.
 *
 * The Happy Eyeballs algorithm (RFC 8305) races IPv6 and IPv4 connection
 * attempts to minimize connection latency on dual-stack systems.
 */

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"

#include <netdb.h>
#include <stdint.h>
#include <time.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/** Maximum number of simultaneous connection attempts */
#ifndef SOCKET_HE_MAX_ATTEMPTS
#define SOCKET_HE_MAX_ATTEMPTS 8
#endif

/** Error buffer size for storing error messages */
#ifndef SOCKET_HE_ERROR_BUFSIZE
#define SOCKET_HE_ERROR_BUFSIZE 256
#endif

/** Milliseconds per second for time conversion */
#define SOCKET_HE_MS_PER_SEC 1000

/** Nanoseconds per millisecond for time conversion */
#define SOCKET_HE_NS_PER_MS 1000000LL

/* ============================================================================
 * Connection Attempt State
 * ============================================================================ */

/**
 * SocketHE_AttemptState - State of individual connection attempt
 *
 * Each connection attempt progresses through these states:
 * - IDLE -> CONNECTING (when connect() is called)
 * - CONNECTING -> CONNECTED (on success) or FAILED (on error/timeout)
 */
typedef enum
{
  HE_ATTEMPT_IDLE = 0,   /**< Not started */
  HE_ATTEMPT_CONNECTING, /**< Non-blocking connect in progress */
  HE_ATTEMPT_CONNECTED,  /**< Successfully connected */
  HE_ATTEMPT_FAILED      /**< Connection failed */
} SocketHE_AttemptState;

/* ============================================================================
 * Connection Attempt Structure
 * ============================================================================ */

/**
 * SocketHE_Attempt - Single connection attempt
 *
 * Tracks one address being tried for connection. Multiple attempts
 * may be active simultaneously (one per address family typically).
 * Memory is arena-allocated from the parent context's arena.
 */
typedef struct SocketHE_Attempt
{
  Socket_T socket;               /**< Socket for this attempt (NULL if failed) */
  struct addrinfo *addr;         /**< Address being tried (borrowed from DNS) */
  SocketHE_AttemptState state;   /**< Current attempt state */
  int error;                     /**< errno if failed, 0 otherwise */
  int64_t start_time_ms;         /**< When attempt started (for timeout) */
  struct SocketHE_Attempt *next; /**< Next attempt in linked list */
} SocketHE_Attempt_T;

/* ============================================================================
 * Sorted Address List
 * ============================================================================ */

/**
 * SocketHE_AddressEntry - Entry in sorted address list
 *
 * Per RFC 8305, addresses are sorted with the preferred family first,
 * then interleaved for resilience. This structure wraps addrinfo
 * for sorted iteration.
 */
typedef struct SocketHE_AddressEntry
{
  struct addrinfo *addr;              /**< Address info (borrowed from DNS) */
  int family;                         /**< AF_INET or AF_INET6 */
  int tried;                          /**< 1 if attempt already started */
  struct SocketHE_AddressEntry *next; /**< Next in sorted list */
} SocketHE_AddressEntry_T;

/* ============================================================================
 * Main Context Structure
 * ============================================================================ */

/**
 * SocketHE_T - Happy Eyeballs connection context
 *
 * Manages the full Happy Eyeballs connection process including:
 * - DNS resolution (async or blocking)
 * - Address sorting per RFC 8305
 * - Connection racing with configurable delays
 * - Winner selection and loser cleanup
 * - Result tracking and error reporting
 *
 * Memory management:
 * - Context itself is malloc'd
 * - All sub-structures use arena allocation
 * - DNS result (resolved) is owned and must be freeaddrinfo'd
 */
struct SocketHE_T
{
  /* Configuration */
  SocketHE_Config_T config; /**< User configuration */
  char *host;               /**< Target hostname (arena-allocated copy) */
  int port;                 /**< Target port number */

  /* External resources (borrowed references, not owned) */
  SocketDNS_T dns;   /**< DNS resolver (NULL for sync API) */
  SocketPoll_T poll; /**< Event poll (NULL for sync API) */

  /* Internal resources (owned by this context) */
  Arena_T arena;  /**< Memory arena for all allocations */
  int owns_dns;   /**< 1 if we created dns, must free */
  int owns_poll;  /**< 1 if we created poll, must free */

  /* DNS resolution state */
  SocketDNS_Request_T dns_request; /**< Active async DNS request */
  struct addrinfo *resolved;       /**< Resolved addresses (owned, freeaddrinfo) */
  int dns_complete;                /**< 1 when DNS resolution finished */
  int dns_error;                   /**< DNS error code if failed */

  /* Sorted address list (arena-allocated) */
  SocketHE_AddressEntry_T *addresses;   /**< Head of sorted address list */
  SocketHE_AddressEntry_T *next_ipv6;   /**< Next IPv6 address to try */
  SocketHE_AddressEntry_T *next_ipv4;   /**< Next IPv4 address to try */
  int interleave_prefer_ipv6;           /**< 1 to try IPv6 next, 0 for IPv4 */

  /* Connection attempts (arena-allocated linked list) */
  SocketHE_Attempt_T *attempts; /**< List of active/completed attempts */
  int attempt_count;            /**< Number of attempts started */
  Socket_T winner;              /**< Winning socket (transferred to caller) */

  /* Timing (monotonic clock milliseconds) */
  int64_t start_time_ms;         /**< When operation started */
  int64_t first_attempt_time_ms; /**< When first attempt started */
  int fallback_timer_armed;      /**< 1 if waiting for fallback delay */

  /* Operation state */
  SocketHE_State state;                    /**< Current state machine state */
  char error_buf[SOCKET_HE_ERROR_BUFSIZE]; /**< Error message buffer */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * sockethe_get_time_ms - Get monotonic time in milliseconds
 *
 * Uses CLOCK_MONOTONIC for reliable elapsed time measurement that is
 * not affected by system clock adjustments (NTP, manual changes, etc).
 *
 * Returns: Current monotonic time in milliseconds, or 0 on error
 * Thread-safe: Yes
 */
static inline int64_t
sockethe_get_time_ms (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    return 0;

  return (int64_t)ts.tv_sec * SOCKET_HE_MS_PER_SEC
         + (int64_t)ts.tv_nsec / SOCKET_HE_NS_PER_MS;
}

/**
 * sockethe_elapsed_ms - Calculate elapsed time in milliseconds
 * @start_ms: Start time from sockethe_get_time_ms()
 *
 * Returns: Elapsed milliseconds since start_ms (always non-negative)
 * Thread-safe: Yes
 *
 * If the clock wraps or returns an error, returns 0 to avoid
 * spurious timeout triggers.
 */
static inline int64_t
sockethe_elapsed_ms (const int64_t start_ms)
{
  int64_t elapsed = sockethe_get_time_ms () - start_ms;

  return (elapsed < 0) ? 0 : elapsed;
}

#endif /* SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED */
