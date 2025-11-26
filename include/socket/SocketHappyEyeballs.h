#ifndef SOCKETHAPPYEYEBALLS_INCLUDED
#define SOCKETHAPPYEYEBALLS_INCLUDED

/**
 * SocketHappyEyeballs.h - Happy Eyeballs (RFC 8305) Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements the Happy Eyeballs algorithm for fast dual-stack connection
 * establishment. This algorithm races IPv6 and IPv4 connection attempts
 * to minimize connection delay when one address family is slower or
 * unavailable.
 *
 * RFC 8305 Algorithm:
 * 1. Start DNS queries for A and AAAA records in parallel
 * 2. Sort results by address family preference (IPv6 first per RFC)
 * 3. Start first connection attempt (IPv6)
 * 4. After 250ms delay, start second attempt (IPv4) if first hasn't succeeded
 * 5. First successful connection wins; cancel and close others
 * 6. Return winning socket to caller
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - Non-blocking socket support
 * - SocketDNS for async DNS resolution
 * - SocketPoll for connection monitoring
 *
 * Features:
 * - RFC 8305 compliant connection racing
 * - Configurable attempt delay and timeouts
 * - Both synchronous and asynchronous APIs
 * - Proper cleanup of losing connections
 * - IPv6 preference with fallback
 *
 * Thread Safety:
 * - SocketHE_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Synchronous API is thread-safe (uses internal resources)
 *
 * Usage (Synchronous):
 *   Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, NULL);
 *   // sock is connected via fastest address family
 *
 * Usage (Asynchronous):
 *   SocketHE_T he = SocketHappyEyeballs_start(dns, poll, "example.com", 443,
 *                                              NULL);
 *   while (!SocketHappyEyeballs_poll(he)) {
 *       SocketPoll_wait(poll, &events, timeout);
 *       SocketHappyEyeballs_process(he);
 *   }
 *   Socket_T sock = SocketHappyEyeballs_result(he);
 *   SocketHappyEyeballs_free(&he);
 */

#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

#define T SocketHE_T
typedef struct T *T;

/* Exception for Happy Eyeballs failures */
extern const Except_T SocketHE_Failed;

/* ============================================================================
 * Connection Attempt State
 * ============================================================================ */

/**
 * SocketHE_State - State of Happy Eyeballs operation
 */
typedef enum
{
  HE_STATE_IDLE = 0,   /**< Not started */
  HE_STATE_RESOLVING,  /**< DNS resolution in progress */
  HE_STATE_CONNECTING, /**< Connection attempts in progress */
  HE_STATE_CONNECTED,  /**< Successfully connected */
  HE_STATE_FAILED,     /**< All attempts failed */
  HE_STATE_CANCELLED   /**< Operation cancelled */
} SocketHE_State;

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * SocketHE_Config_T - Happy Eyeballs configuration
 *
 * All time values are in milliseconds. Use 0 for defaults.
 */
typedef struct SocketHE_Config
{
  int first_attempt_delay_ms; /**< Delay before starting second family */
  int attempt_timeout_ms;     /**< Per-attempt connection timeout */
  int total_timeout_ms;       /**< Overall operation timeout */
  int prefer_ipv6;            /**< 1 = IPv6 first (default), 0 = IPv4 first */
  int max_attempts;           /**< Maximum simultaneous attempts */
} SocketHE_Config_T;

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/* RFC 8305 recommends 250ms delay before starting fallback family */
#ifndef SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS
#define SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS 250
#endif

/* Per-attempt timeout for individual connection attempts */
#ifndef SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS 5000
#endif

/* Total operation timeout including DNS and all attempts */
#ifndef SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS 30000
#endif

/* Maximum simultaneous connection attempts */
#ifndef SOCKET_HE_DEFAULT_MAX_ATTEMPTS
#define SOCKET_HE_DEFAULT_MAX_ATTEMPTS 2
#endif

/* Poll interval for synchronous connection loop */
#ifndef SOCKET_HE_SYNC_POLL_INTERVAL_MS
#define SOCKET_HE_SYNC_POLL_INTERVAL_MS 50
#endif

/* Port string buffer size (max 5 digits + null) */
#ifndef SOCKET_HE_PORT_STR_SIZE
#define SOCKET_HE_PORT_STR_SIZE 8
#endif

/* ============================================================================
 * Synchronous API (Simple Usage)
 * ============================================================================ */

/**
 * SocketHappyEyeballs_connect - Connect using Happy Eyeballs (blocking)
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: Connected socket
 * Raises: SocketHE_Failed on connection failure or timeout
 * Thread-safe: Yes (uses internal DNS resolver and poll)
 *
 * Performs RFC 8305 Happy Eyeballs connection. Blocks until connected
 * or all attempts fail.
 */
extern Socket_T SocketHappyEyeballs_connect (const char *host, int port,
                                             const SocketHE_Config_T *config);

/* ============================================================================
 * Asynchronous API (Event-Driven Usage)
 * ============================================================================ */

/**
 * SocketHappyEyeballs_start - Start async Happy Eyeballs connection
 * @dns: DNS resolver instance (caller-owned)
 * @poll: Poll instance for connection monitoring (caller-owned)
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: Happy Eyeballs context handle
 * Raises: SocketHE_Failed on initialization failure
 * Thread-safe: No (operate from single thread)
 */
extern T SocketHappyEyeballs_start (SocketDNS_T dns, SocketPoll_T poll,
                                    const char *host, int port,
                                    const SocketHE_Config_T *config);

/**
 * SocketHappyEyeballs_poll - Check if operation is complete
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if complete (success or failure), 0 if still in progress
 * Thread-safe: No
 */
extern int SocketHappyEyeballs_poll (T he);

/**
 * SocketHappyEyeballs_process - Process events and advance state machine
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 *
 * Call after SocketPoll_wait() returns events.
 */
extern void SocketHappyEyeballs_process (T he);

/**
 * SocketHappyEyeballs_result - Get connected socket from completed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Connected socket, or NULL if failed/cancelled/pending
 * Thread-safe: No
 *
 * Transfers ownership to caller - caller must Socket_free() when done.
 */
extern Socket_T SocketHappyEyeballs_result (T he);

/**
 * SocketHappyEyeballs_cancel - Cancel in-progress operation
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 */
extern void SocketHappyEyeballs_cancel (T he);

/**
 * SocketHappyEyeballs_free - Free Happy Eyeballs context
 * @he: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHappyEyeballs_free (T *he);

/* ============================================================================
 * State Query
 * ============================================================================ */

/**
 * SocketHappyEyeballs_state - Get current operation state
 * @he: Happy Eyeballs context
 *
 * Returns: Current state
 * Thread-safe: No
 */
extern SocketHE_State SocketHappyEyeballs_state (T he);

/**
 * SocketHappyEyeballs_error - Get error message for failed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Error message string, or NULL if no error
 * Thread-safe: No
 */
extern const char *SocketHappyEyeballs_error (T he);

/* ============================================================================
 * Configuration Helpers
 * ============================================================================ */

/**
 * SocketHappyEyeballs_config_defaults - Initialize config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes
 */
extern void SocketHappyEyeballs_config_defaults (SocketHE_Config_T *config);

/* ============================================================================
 * Timer Integration
 * ============================================================================ */

/**
 * SocketHappyEyeballs_next_timeout_ms - Get time until next timer expiry
 * @he: Happy Eyeballs context
 *
 * Returns: Milliseconds until next timeout, or -1 if no pending timers
 * Thread-safe: No
 */
extern int SocketHappyEyeballs_next_timeout_ms (T he);

#undef T
#endif /* SOCKETHAPPYEYEBALLS_INCLUDED */
