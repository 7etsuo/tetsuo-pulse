#ifndef SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED
#define SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED

/**
 * SocketHappyEyeballs-private.h - Internal structures for Happy Eyeballs
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header contains internal implementation details for the Happy Eyeballs
 * module. Not for public use.
 */

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"

#include <netdb.h>
#include <stdint.h>
#include <sys/time.h>

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

/** Microseconds per millisecond for time conversion */
#define SOCKET_HE_USEC_PER_MS 1000

/** Milliseconds per second for time conversion */
#define SOCKET_HE_MS_PER_SEC 1000

/* ============================================================================
 * Connection Attempt Structure
 * ============================================================================ */

/**
 * SocketHE_AttemptState - State of individual connection attempt
 */
typedef enum
{
  HE_ATTEMPT_IDLE = 0,   /**< Not started */
  HE_ATTEMPT_CONNECTING, /**< Non-blocking connect in progress */
  HE_ATTEMPT_CONNECTED,  /**< Successfully connected */
  HE_ATTEMPT_FAILED      /**< Connection failed */
} SocketHE_AttemptState;

/**
 * SocketHE_Attempt - Single connection attempt
 *
 * Tracks one address being tried for connection.
 */
typedef struct SocketHE_Attempt
{
  Socket_T socket;               /**< Socket for this attempt (NULL if failed) */
  struct addrinfo *addr;         /**< Address being tried (borrowed) */
  SocketHE_AttemptState state;   /**< Current attempt state */
  int error;                     /**< errno if failed */
  int64_t start_time_ms;         /**< When attempt started (for timeout) */
  struct SocketHE_Attempt *next; /**< Next attempt in list */
} SocketHE_Attempt_T;

/* ============================================================================
 * Sorted Address List
 * ============================================================================ */

/**
 * SocketHE_AddressEntry - Entry in sorted address list
 *
 * Addresses are sorted IPv6-first, IPv4-second per RFC 8305, then
 * interleaved for resilience.
 */
typedef struct SocketHE_AddressEntry
{
  struct addrinfo *addr;              /**< Address info (borrowed) */
  int family;                         /**< AF_INET or AF_INET6 */
  int tried;                          /**< Already started attempt */
  struct SocketHE_AddressEntry *next; /**< Next in sorted list */
} SocketHE_AddressEntry_T;

/* ============================================================================
 * Main Context Structure
 * ============================================================================ */

/**
 * SocketHE_T - Happy Eyeballs connection context
 *
 * Manages the full Happy Eyeballs connection process including DNS
 * resolution, connection racing, and result tracking.
 */
struct SocketHE_T
{
  /* Configuration */
  SocketHE_Config_T config; /**< User configuration */
  char *host;               /**< Target hostname (copied) */
  int port;                 /**< Target port */

  /* External resources (borrowed, not owned) */
  SocketDNS_T dns;   /**< DNS resolver */
  SocketPoll_T poll; /**< Event poll */

  /* Internal resources (owned) */
  Arena_T arena;  /**< Memory arena for allocations */
  int owns_dns;   /**< 1 if we created dns */
  int owns_poll;  /**< 1 if we created poll */

  /* DNS resolution state */
  SocketDNS_Request_T dns_request; /**< Active DNS request */
  struct addrinfo *resolved;       /**< Resolved addresses (owned) */
  int dns_complete;                /**< DNS resolution finished */
  int dns_error;                   /**< DNS error code if failed */

  /* Sorted address list */
  SocketHE_AddressEntry_T *addresses;   /**< Sorted address list */
  SocketHE_AddressEntry_T *next_ipv6;   /**< Next IPv6 to try */
  SocketHE_AddressEntry_T *next_ipv4;   /**< Next IPv4 to try */
  int interleave_prefer_ipv6;           /**< Next family to try */

  /* Connection attempts */
  SocketHE_Attempt_T *attempts; /**< List of active attempts */
  int attempt_count;            /**< Number of active attempts */
  Socket_T winner;              /**< Winning socket (if any) */

  /* Timing */
  int64_t start_time_ms;         /**< Overall start time */
  int64_t first_attempt_time_ms; /**< When first attempt started */
  int fallback_timer_armed;      /**< 1 if waiting for fallback delay */

  /* State */
  SocketHE_State state;                        /**< Current operation state */
  char error_buf[SOCKET_HE_ERROR_BUFSIZE];     /**< Error message */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * sockethe_get_time_ms - Get current time in milliseconds
 *
 * Returns: Current time in milliseconds since epoch
 */
static inline int64_t
sockethe_get_time_ms (void)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  return (int64_t)tv.tv_sec * SOCKET_HE_MS_PER_SEC
         + (int64_t)tv.tv_usec / SOCKET_HE_USEC_PER_MS;
}

/**
 * sockethe_elapsed_ms - Calculate elapsed time in milliseconds
 * @start_ms: Start time from sockethe_get_time_ms()
 *
 * Returns: Elapsed milliseconds
 */
static inline int64_t
sockethe_elapsed_ms (int64_t start_ms)
{
  return sockethe_get_time_ms () - start_ms;
}

#endif /* SOCKETHAPPYEYEBALLS_PRIVATE_INCLUDED */
