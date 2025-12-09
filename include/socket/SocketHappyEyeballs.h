#ifndef SOCKETHAPPYEYEBALLS_INCLUDED
#define SOCKETHAPPYEYEBALLS_INCLUDED

/**
 * @file SocketHappyEyeballs.h
 * @ingroup async_io
 * @brief Happy Eyeballs (RFC 8305) implementation for fast dual-stack
 * connections.
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
 * Platform Requirements:
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
 *
 * @see SocketHappyEyeballs_connect() for synchronous connection.
 * @see SocketHappyEyeballs_start() for asynchronous connection setup.
 * @see @ref SocketDNS_T for DNS resolver integration.
 * @see @ref SocketPoll_T for event loop integration.
 * @see @ref SocketHTTPClient_T for HTTP client integration.
 * @see @ref SocketProxy_T for proxy connection integration.
 */

#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/**
 * @brief Opaque Happy Eyeballs context handle.
 * @ingroup async_io
 *
 * Represents an ongoing Happy Eyeballs connection attempt. Not thread-safe.
 * Created by SocketHappyEyeballs_start() or internally in sync version.
 *
 * @see SocketHappyEyeballs_start()
 * @see SocketHappyEyeballs_free()
 * @see SocketHappyEyeballs_poll()
 */
#define T SocketHE_T
typedef struct T *T;

/**
 * @brief Exception raised on Happy Eyeballs failures.
 * @ingroup async_io
 *
 * Thrown by SocketHappyEyeballs_connect() and SocketHappyEyeballs_start() on
 * initialization or operation failures such as DNS errors, timeouts, etc.
 *
 * @see SocketHappyEyeballs_error() for detailed error message on failure.
 * @see docs/ERROR_HANDLING.md for exception handling.
 */
extern const Except_T SocketHE_Failed;

/* ============================================================================
 * Connection State
 * ============================================================================
 */

/**
 * @brief State enumeration for Happy Eyeballs connection progress.
 * @ingroup async_io
 *
 * State machine transitions:
 *   IDLE -> RESOLVING -> CONNECTING -> CONNECTED (success)
 *                         \-> FAILED (all attempts failed)
 *   Any state -> CANCELLED (explicit cancel)
 *
 * @see SocketHappyEyeballs_state() to query current state.
 * @see SocketHappyEyeballs_start(), SocketHappyEyeballs_poll() for state changes.
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
 * ============================================================================
 */

/**
 * @brief Happy Eyeballs configuration structure.
 * @ingroup async_io
 *
 * All time values are in milliseconds. Use 0 for defaults.
 * Call SocketHappyEyeballs_config_defaults() to initialize.
 *
 * @var SocketHE_Config_T::first_attempt_delay_ms Delay before starting second family (250ms default).
 * @var SocketHE_Config_T::attempt_timeout_ms Per-attempt connection timeout (5000ms default).
 * @var SocketHE_Config_T::total_timeout_ms Overall operation timeout (30000ms default).
 * @var SocketHE_Config_T::dns_timeout_ms DNS resolution timeout (5000ms default, 0=use total).
 * @var SocketHE_Config_T::prefer_ipv6 1=IPv6 first (default), 0=IPv4 first.
 * @var SocketHE_Config_T::max_attempts Maximum simultaneous attempts (2 default).
 *
 * @see SocketHappyEyeballs_config_defaults() to set defaults.
 * @see SocketHappyEyeballs_connect(), SocketHappyEyeballs_start() for usage.
 * @see docs/ASYNC_IO.md for configuration tuning.
 */
typedef struct SocketHE_Config
{
  int first_attempt_delay_ms; /**< Delay before starting second family (250ms)
                               */
  int attempt_timeout_ms;     /**< Per-attempt connection timeout (5000ms) */
  int total_timeout_ms;       /**< Overall operation timeout (30000ms) */
  int dns_timeout_ms; /**< DNS resolution timeout (5000ms, 0=use total) */
  int prefer_ipv6;    /**< 1 = IPv6 first (default), 0 = IPv4 first */
  int max_attempts;   /**< Maximum simultaneous attempts (2) */
} SocketHE_Config_T;

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 */

/**
 * @brief RFC 8305 recommended delay before starting fallback address family (250 ms).
 * @ingroup async_io
 * @{
 */
#ifndef SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS
#define SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS 250
#endif

/**
 * @brief Default per-attempt connection timeout (5000 ms).
 * @ingroup async_io
 */
#ifndef SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS 5000
#endif

/**
 * @brief Default total operation timeout including DNS and connections (30000 ms).
 * @ingroup async_io
 */
#ifndef SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS 30000
#endif

/**
 * @brief Default DNS resolution timeout (5000 ms, 0=use total timeout).
 * @ingroup async_io
 */
#ifndef SOCKET_HE_DEFAULT_DNS_TIMEOUT_MS
#define SOCKET_HE_DEFAULT_DNS_TIMEOUT_MS 5000
#endif

/**
 * @brief Default maximum simultaneous connection attempts (2 per RFC 8305).
 * @ingroup async_io
 */
#ifndef SOCKET_HE_DEFAULT_MAX_ATTEMPTS
#define SOCKET_HE_DEFAULT_MAX_ATTEMPTS 2
#endif

/**
 * @brief Poll interval for synchronous connection loop (50 ms).
 * @ingroup async_io
 */
#ifndef SOCKET_HE_SYNC_POLL_INTERVAL_MS
#define SOCKET_HE_SYNC_POLL_INTERVAL_MS 50
#endif

/**
 * @brief Buffer size for port string conversion (8 bytes for "65535\0").
 * @ingroup async_io
 */
#ifndef SOCKET_HE_PORT_STR_SIZE
#define SOCKET_HE_PORT_STR_SIZE 8
#endif

/**
 * @brief Happy Eyeballs default configuration constants.
 * @ingroup async_io
 * @}
 */

/* ============================================================================
 * Synchronous API (Simple Usage)
 * ============================================================================
 */

/**
 * @brief Perform synchronous Happy Eyeballs connection to host (RFC 8305 compliant).
 * @ingroup async_io
 * @param host Hostname or IP address to connect to.
 * @param port Port number (1-65535).
 * @param config Configuration options (NULL for defaults).
 * @return Connected Socket_T on success (caller owns, must Socket_free()).
 * @throws SocketHE_Failed on DNS failure, connection timeout, or all attempts fail.
 * @threadsafe Yes - creates internal resources, safe from any thread.
 *
 * Implements blocking Happy Eyeballs algorithm: resolves DNS, races IPv6/IPv4
 * connections, returns first successful socket. Socket is in blocking mode.
 *
 * Blocks up to total_timeout_ms (default 30s). For non-blocking, use
 * SocketHappyEyeballs_start() with event loop.
 *
 * @warning Long-blocking call; unsuitable for event loops without timeouts.
 * @see SocketHappyEyeballs_start() for asynchronous version.
 * @see SocketHappyEyeballs_config_defaults() for config setup.
 * @see @ref SocketDNS_T for underlying DNS resolution.
 * @see docs/ASYNC_IO.md "Happy Eyeballs" section for details.
 */
extern Socket_T SocketHappyEyeballs_connect (const char *host, int port,
                                             const SocketHE_Config_T *config);

/* ============================================================================
 * Asynchronous API (Event-Driven Usage)
 * ============================================================================
 */

/**
 * @brief Start asynchronous Happy Eyeballs connection.
 * @ingroup async_io
 * @param dns DNS resolver instance (caller-owned, must outlive operation).
 * @param poll Poll instance for connection monitoring (caller-owned).
 * @param host Hostname or IP address to connect to.
 * @param port Port number (1-65535).
 * @param config Configuration options (NULL for defaults).
 * @return Happy Eyeballs context handle.
 * @throws SocketHE_Failed on initialization failure.
 * @threadsafe No - operate from single thread.
 *
 * Starts asynchronous Happy Eyeballs connection. Caller must:
 * 1. Call SocketHappyEyeballs_process() after each poll wait
 * 2. Check SocketHappyEyeballs_poll() for completion
 * 3. Call SocketHappyEyeballs_result() to get socket
 * 4. Call SocketHappyEyeballs_free() to release context
 *
 * @see SocketHappyEyeballs_connect() for synchronous version.
 * @see SocketHappyEyeballs_config_defaults() for config setup.
 * @see @ref SocketDNS_T "SocketDNS" for DNS integration.
 * @see @ref SocketPoll_T "SocketPoll" for event loop integration.
 */
extern T SocketHappyEyeballs_start (SocketDNS_T dns, SocketPoll_T poll,
                                    const char *host, int port,
                                    const SocketHE_Config_T *config);

/**
 * @brief Check if Happy Eyeballs operation is complete.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @return 1 if complete (success, failure, or cancelled), 0 if in progress.
 * @threadsafe No.
 *
 * Non-blocking check for completion. After this returns 1, call
 * SocketHappyEyeballs_state() to determine success or failure.
 *
 * @see SocketHappyEyeballs_state() to check outcome.
 * @see SocketHappyEyeballs_process() which must be called regularly.
 * @see SocketHappyEyeballs_start() for initiating the operation.
 */
extern int SocketHappyEyeballs_poll (T he);

/**
 * @brief Process events and advance the Happy Eyeballs state machine.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @threadsafe No.
 *
 * Call after SocketPoll_wait() returns. This function:
 * - Checks DNS completion and processes results
 * - Checks connection attempt completion
 * - Starts fallback attempts after delay
 * - Handles timeouts
 *
 * @see SocketHappyEyeballs_poll() to check for completion.
 * @see SocketPoll_wait() for event waiting.
 * @see SocketHappyEyeballs_start() for setup.
 */
extern void SocketHappyEyeballs_process (T he);

/**
 * @brief Get the connected socket from a completed Happy Eyeballs operation.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @return Connected socket, or NULL if failed/cancelled/pending.
 * @threadsafe No.
 *
 * Transfers socket ownership to caller. Caller must Socket_free() when done.
 * The returned socket is in blocking mode. Can only be called once per
 * successful connection - subsequent calls return NULL.
 *
 * @see SocketHappyEyeballs_state() to verify success.
 * @see Socket_free() for cleanup.
 * @see SocketHappyEyeballs_connect() synchronous equivalent.
 */
extern Socket_T SocketHappyEyeballs_result (T he);

/**
 * @brief Cancel an in-progress Happy Eyeballs operation.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @threadsafe No.
 *
 * Cancels DNS requests and closes all pending connection attempts.
 * After cancel, state becomes HE_STATE_CANCELLED.
 *
 * @see SocketHappyEyeballs_state() to confirm cancellation.
 * @see SocketHappyEyeballs_free() to clean up resources.
 */
extern void SocketHappyEyeballs_cancel (T he);

/**
 * @brief Free the Happy Eyeballs context and release resources.
 * @ingroup async_io
 * @param he Pointer to context (set to NULL on success).
 * @threadsafe No.
 *
 * Releases all resources. If operation is still in progress, it will
 * be cancelled first. Safe to call with NULL or *he == NULL.
 *
 * @see SocketHappyEyeballs_start() for creation.
 * @see SocketHappyEyeballs_cancel() for explicit cancellation.
 */
extern void SocketHappyEyeballs_free (T *he);

/* ============================================================================
 * State Query
 * ============================================================================
 */

/**
 * @brief Get the current state of the Happy Eyeballs operation.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @return Current state (SocketHE_State enum).
 * @threadsafe No.
 *
 * @see SocketHE_State for possible values.
 * @see SocketHappyEyeballs_poll() to wait for completion.
 */
extern SocketHE_State SocketHappyEyeballs_state (T he);

/**
 * @brief Get the error message for a failed Happy Eyeballs operation.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @return Error message string, or NULL if not in FAILED state.
 * @threadsafe No.
 *
 * The returned string is valid until SocketHappyEyeballs_free() is called.
 *
 * @see SocketHappyEyeballs_state() to check if FAILED.
 * @see SocketHE_Failed for general exception.
 */
extern const char *SocketHappyEyeballs_error (T he);

/* ============================================================================
 * Configuration Helpers
 * ============================================================================
 */

/**
 * @brief Initialize Happy Eyeballs configuration with default values.
 * @ingroup async_io
 * @param config Configuration structure to initialize.
 * @threadsafe Yes.
 *
 * Sets all fields to their default values as per RFC 8305 recommendations.
 *
 * @see SocketHE_Config_T for structure details.
 * @see SocketHappyEyeballs_connect(), SocketHappyEyeballs_start() for usage.
 * @see docs/ASYNC_IO.md for RFC 8305 details.
 */
extern void SocketHappyEyeballs_config_defaults (SocketHE_Config_T *config);

/* ============================================================================
 * Timer Integration
 * ============================================================================
 */

/**
 * @brief Get milliseconds until the next Happy Eyeballs timer expiry.
 * @ingroup async_io
 * @param he Happy Eyeballs context.
 * @return Milliseconds until next timeout, or -1 if no pending timers.
 * @threadsafe No.
 *
 * Use this as the timeout argument to SocketPoll_wait() for efficient
 * event loop integration. Returns the minimum of:
 * - Time until total timeout expires
 * - Time until fallback timer fires
 *
 * @see SocketPoll_wait() for usage in event loops.
 * @see SocketHappyEyeballs_process() for timer handling.
 */
extern int SocketHappyEyeballs_next_timeout_ms (T he);

#undef T
#endif /* SOCKETHAPPYEYEBALLS_INCLUDED */
