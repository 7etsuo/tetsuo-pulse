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
 * RFC 8305 Algorithm Summary:
 * 1. Start DNS queries for A and AAAA records (parallel or sequential)
 * 2. Sort results by address family preference (IPv6 first per RFC)
 * 3. Start first connection attempt (preferred family)
 * 4. After 250ms delay, start second attempt (fallback family)
 * 5. First successful connection wins; cancel and close others
 * 6. Return winning socket to caller
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - Non-blocking socket support (O_NONBLOCK)
 * - CLOCK_MONOTONIC for reliable timing
 * - SocketDNS module for async DNS resolution
 * - SocketPoll module for connection monitoring
 *
 * Features:
 * - RFC 8305 compliant connection racing
 * - Configurable attempt delay and timeouts
 * - Both synchronous and asynchronous APIs
 * - Proper cleanup of losing connections
 * - IPv6 preference with fallback (configurable)
 * - Per-attempt and total timeout support
 *
 * Thread Safety:
 * - SocketHE_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Synchronous API is thread-safe (uses internal resources)
 *
 * Memory Management:
 * - Context is malloc'd, internal structures use Arena
 * - Caller must call SocketHappyEyeballs_free() to release
 * - Result socket ownership transfers to caller
 *
 * Usage (Synchronous - Simple):
 *   Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, NULL);
 *   // sock is connected via fastest address family
 *   // Use sock normally, then Socket_free(&sock)
 *
 * Usage (Asynchronous - Event-Driven):
 *   SocketHE_T he = SocketHappyEyeballs_start(dns, poll, "example.com", 443,
 *                                              NULL);
 *   while (!SocketHappyEyeballs_poll(he)) {
 *       int timeout = SocketHappyEyeballs_next_timeout_ms(he);
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

/** Exception for Happy Eyeballs failures */
extern const Except_T SocketHE_Failed;

/* ============================================================================
 * Connection State
 * ============================================================================ */

/**
 * SocketHE_State - State of Happy Eyeballs operation
 *
 * State machine transitions:
 *   IDLE -> RESOLVING -> CONNECTING -> CONNECTED (success)
 *                                  \-> FAILED (all attempts failed)
 *   Any state -> CANCELLED (explicit cancel)
 */
typedef enum
{
  HE_STATE_IDLE = 0,   /**< Not started, waiting for process() */
  HE_STATE_RESOLVING,  /**< DNS resolution in progress */
  HE_STATE_CONNECTING, /**< Connection attempts in progress */
  HE_STATE_CONNECTED,  /**< Successfully connected (call result()) */
  HE_STATE_FAILED,     /**< All attempts failed (call error()) */
  HE_STATE_CANCELLED   /**< Operation cancelled by user */
} SocketHE_State;

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * SocketHE_Config_T - Happy Eyeballs configuration
 *
 * All time values are in milliseconds. Use 0 for defaults.
 * Call SocketHappyEyeballs_config_defaults() to initialize.
 */
typedef struct SocketHE_Config
{
  int first_attempt_delay_ms; /**< Delay before starting second family (250ms) */
  int attempt_timeout_ms;     /**< Per-attempt connection timeout (5000ms) */
  int total_timeout_ms;       /**< Overall operation timeout (30000ms) */
  int prefer_ipv6;            /**< 1 = IPv6 first (default), 0 = IPv4 first */
  int max_attempts;           /**< Maximum simultaneous attempts (2) */
} SocketHE_Config_T;

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** RFC 8305 recommends 250ms delay before starting fallback family */
#ifndef SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS
#define SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS 250
#endif

/** Per-attempt timeout for individual connection attempts */
#ifndef SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS 5000
#endif

/** Total operation timeout including DNS and all connection attempts */
#ifndef SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS 30000
#endif

/** Maximum simultaneous connection attempts (per RFC 8305 recommendation) */
#ifndef SOCKET_HE_DEFAULT_MAX_ATTEMPTS
#define SOCKET_HE_DEFAULT_MAX_ATTEMPTS 2
#endif

/** Poll interval for synchronous connection loop */
#ifndef SOCKET_HE_SYNC_POLL_INTERVAL_MS
#define SOCKET_HE_SYNC_POLL_INTERVAL_MS 50
#endif

/** Port string buffer size (max "65535" + null terminator) */
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
 * Returns: Connected socket (caller must Socket_free())
 * Raises: SocketHE_Failed on connection failure or timeout
 * Thread-safe: Yes (uses internal DNS resolver and poll)
 *
 * Performs RFC 8305 Happy Eyeballs connection. Blocks until connected
 * or all attempts fail. The returned socket is in blocking mode.
 *
 * WARNING: This function may block for up to total_timeout_ms (default 30s)
 * during DNS resolution and connection attempts. For non-blocking operation,
 * use the asynchronous API instead.
 */
extern Socket_T SocketHappyEyeballs_connect (const char *host, int port,
                                             const SocketHE_Config_T *config);

/* ============================================================================
 * Asynchronous API (Event-Driven Usage)
 * ============================================================================ */

/**
 * SocketHappyEyeballs_start - Start async Happy Eyeballs connection
 * @dns: DNS resolver instance (caller-owned, must outlive operation)
 * @poll: Poll instance for connection monitoring (caller-owned)
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @config: Configuration options (NULL for defaults)
 *
 * Returns: Happy Eyeballs context handle
 * Raises: SocketHE_Failed on initialization failure
 * Thread-safe: No (operate from single thread)
 *
 * Starts asynchronous Happy Eyeballs connection. Caller must:
 * 1. Call SocketHappyEyeballs_process() after each poll wait
 * 2. Check SocketHappyEyeballs_poll() for completion
 * 3. Call SocketHappyEyeballs_result() to get socket
 * 4. Call SocketHappyEyeballs_free() to release context
 */
extern T SocketHappyEyeballs_start (SocketDNS_T dns, SocketPoll_T poll,
                                    const char *host, int port,
                                    const SocketHE_Config_T *config);

/**
 * SocketHappyEyeballs_poll - Check if operation is complete
 * @he: Happy Eyeballs context
 *
 * Returns: 1 if complete (success, failure, or cancelled), 0 if in progress
 * Thread-safe: No
 *
 * Non-blocking check for completion. After this returns 1, call
 * SocketHappyEyeballs_state() to determine success or failure.
 */
extern int SocketHappyEyeballs_poll (T he);

/**
 * SocketHappyEyeballs_process - Process events and advance state machine
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 *
 * Call after SocketPoll_wait() returns. This function:
 * - Checks DNS completion and processes results
 * - Checks connection attempt completion
 * - Starts fallback attempts after delay
 * - Handles timeouts
 */
extern void SocketHappyEyeballs_process (T he);

/**
 * SocketHappyEyeballs_result - Get connected socket from completed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Connected socket, or NULL if failed/cancelled/pending
 * Thread-safe: No
 *
 * Transfers socket ownership to caller. Caller must Socket_free() when done.
 * The returned socket is in blocking mode. Can only be called once per
 * successful connection - subsequent calls return NULL.
 */
extern Socket_T SocketHappyEyeballs_result (T he);

/**
 * SocketHappyEyeballs_cancel - Cancel in-progress operation
 * @he: Happy Eyeballs context
 *
 * Thread-safe: No
 *
 * Cancels DNS requests and closes all pending connection attempts.
 * After cancel, state becomes HE_STATE_CANCELLED.
 */
extern void SocketHappyEyeballs_cancel (T he);

/**
 * SocketHappyEyeballs_free - Free Happy Eyeballs context
 * @he: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 *
 * Releases all resources. If operation is still in progress, it will
 * be cancelled first. Safe to call with NULL or *he == NULL.
 */
extern void SocketHappyEyeballs_free (T *he);

/* ============================================================================
 * State Query
 * ============================================================================ */

/**
 * SocketHappyEyeballs_state - Get current operation state
 * @he: Happy Eyeballs context
 *
 * Returns: Current state (SocketHE_State enum)
 * Thread-safe: No
 */
extern SocketHE_State SocketHappyEyeballs_state (T he);

/**
 * SocketHappyEyeballs_error - Get error message for failed operation
 * @he: Happy Eyeballs context
 *
 * Returns: Error message string, or NULL if not in FAILED state
 * Thread-safe: No
 *
 * The returned string is valid until SocketHappyEyeballs_free() is called.
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
 *
 * Sets all fields to their default values as per RFC 8305 recommendations.
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
 *
 * Use this as the timeout argument to SocketPoll_wait() for efficient
 * event loop integration. Returns the minimum of:
 * - Time until total timeout expires
 * - Time until fallback timer fires
 */
extern int SocketHappyEyeballs_next_timeout_ms (T he);

#undef T
#endif /* SOCKETHAPPYEYEBALLS_INCLUDED */
