/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETRECONNECT_PRIVATE_INCLUDED
#define SOCKETRECONNECT_PRIVATE_INCLUDED

/**
 * @defgroup reconnect_private SocketReconnect Private Implementation Details
 * @ingroup connection_mgmt
 * @internal
 * @brief Internal structures and utilities for reconnection logic.
 *
 * Contains opaque type definitions, internal enums, and utility functions
 * used exclusively by the SocketReconnect implementation.
 *
 *  Internal Architecture Overview
 *
 * The private API supports the public reconnection framework through:
 *
 * - State tracking in SocketReconnect_T (timers, counters, error state)
 * - Circuit breaker logic with internal states (CLOSED, OPEN, HALF_OPEN)
 * - Time utilities using monotonic clocks
 * - Jitter calculation for backoff variability
 *
 * ```
 * Public API (SocketReconnect.h)
 *           |
 *           | uses
 *           v
 * +-------------------------+
 * | SocketReconnect-private.h|
 * +-------------------------+
 * | - SocketReconnect_T     |
 * | - CircuitState enum     |
 * | - time/random helpers   |
 * +-------------------------+
 *           |
 *           | implements
 *           v
 * SocketReconnect.c (internal functions)
 * ```
 *
 *  Module Relationships
 *
 * - **Depends on**: Foundation (Arena, Except, SocketUtil, SocketCrypto)
 * - **Used by**: SocketReconnect.c implementation only
 * - **Exposes**: No public symbols; internal use only
 *
 *  Key Internal Components
 *
 * | Component | Purpose | Thread Safety |
 * |-----------|---------|---------------|
 * | SocketReconnect_T | State and config storage | No (single-threaded access)
 * | | CircuitState | Internal circuit breaker FSM | Internal only | |
 * socketreconnect_* helpers | Time, random, elapsed calcs | Yes
 * (reentrant/static) |
 *
 *  Platform Requirements
 *
 * - POSIX with CLOCK_MONOTONIC for reliable timing
 * - Thread-local storage support (__thread or TLS)
 * - Optional: Cryptographic RNG for jitter (fallback to PRNG)
 *
 * @see SocketReconnect.h for public interface
 * @see @ref connection_mgmt for related modules
 * @{
 */

/**
 * @file SocketReconnect-private.h
 * @ingroup connection_mgmt
 * @internal
 * @brief Private header for SocketReconnect module internals.
 *
 * Defines internal data structures and utility functions not exposed publicly.
 * Use only within SocketReconnect.c implementation.
 *
 *  Features
 *
 * - Opaque context structure for all reconnection state
 * - Internal circuit breaker state machine
 * - Monotonic time helpers for accurate timing
 * - Secure random jitter for backoff (with fallback)
 *
 *  Usage Notes
 *
 * - All functions and types marked @internal
 * - No direct inclusion from application code
 * - Thread safety varies; check individual docs
 *
 *  Compilation
 *
 * - Included automatically via SocketReconnect.h when building libsocket
 * - Requires C11 with _GNU_SOURCE for system features
 *
 * @warning Modifying internals may break public API guarantees
 * @note For debugging, use SOCKET_LOG_COMPONENT "Reconnect"
 *
 * @see SocketReconnect_T for main internal type
 * @see socketreconnect_get_time_ms() for time utilities
 */

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"
#include <stdint.h>

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

/**
 * @brief Maximum buffer capacity for internal error message strings.
 * @internal
 * @ingroup connection_mgmt
 *
 * Defines the fixed size (including null terminator) for error_buf in
 * SocketReconnect_T. Selected to fit detailed messages: errno description +
 * connection context (host, port, attempt #).
 *
 * Example capacity usage: "connection attempt 5 to host:port failed: [errno
 * str] (err=123)"
 *
 * @note Avoids dynamic allocations in hot error paths; snprintf-safe size
 * @warning Messages truncated if exceeding limit; prioritize essential info
 *
 * @see SocketReconnect_T::error_buf field
 * @see socketreconnect_error_fmt() internal formatting (in .c)
 * @see strerror() or Socket_safe_strerror() sources
 */
#ifndef SOCKET_RECONNECT_ERROR_BUFSIZE
#define SOCKET_RECONNECT_ERROR_BUFSIZE 256
#endif

/**
 * @brief Maximum length for target hostname/IP strings (excluding null
 * terminator).
 * @internal
 * @ingroup connection_mgmt
 *
 * Limits size of host field in SocketReconnect_T. Aligns with DNS max label
 * length and accommodates IPv6 literals (e.g., "[2001:db8::1]"), Unix paths if
 * extended.
 *
 * Validation occurs at SocketReconnect_new(): truncates or raises exception if
 * exceeded.
 *
 * @note 255 chars +1 for null = 256 bytes allocated from arena
 * @note Excludes port; full URI not supported here
 * @warning Longer hosts rejected to prevent buffer issues or DoS via oversized
 * alloc
 *
 * @see SocketReconnect_T::host field storage
 * @see SocketReconnect_new() validation and copying
 * @see getaddrinfo() compatibility for resolution
 */
#ifndef SOCKET_RECONNECT_MAX_HOST_LEN
#define SOCKET_RECONNECT_MAX_HOST_LEN 255
#endif

/**
 * @brief Internal circuit breaker states for reconnection resilience.
 * @ingroup connection_mgmt
 * @internal
 *
 * Manages the circuit breaker pattern to prevent connection storms and
 * cascading failures during service outages. Provides three internal states
 * that map to public SocketReconnect_State behaviors but allow precise control
 * over transitions.
 *
 *  State Descriptions
 *
 * | State | Description | Behavior |
 * |-------|-------------|----------|
 * | CIRCUIT_CLOSED | Normal operation | Allows all connection attempts;
 * failures increment counters | | CIRCUIT_OPEN | Protection mode | Blocks
 * attempts after failure threshold; waits for reset timeout | |
 * CIRCUIT_HALF_OPEN | Probe mode | Permits one probe connection; success
 * closes circuit, failure re-opens |
 *
 *  Transitions
 *
 * - CLOSED → OPEN: Consecutive failures reach policy.circuit_failure_threshold
 * - OPEN → HALF_OPEN: Timeout expires (policy.circuit_reset_timeout_ms)
 * - HALF_OPEN → CLOSED: Probe connection succeeds
 * - HALF_OPEN → OPEN: Probe fails
 * - CLOSED → CLOSED: Successful connections reset failure counters
 *
 * Transitions are atomic and handled internally by the state machine.
 *
 *  Usage
 *
 * Accessed only via SocketReconnect_T::circuit_state. Never set directly from
 * outside the module. Public API reflects these states through
 * SocketReconnect_State.
 *
 * @complexity O(1) for state checks and transitions
 * @threadsafe Internal - modifications protected by reconnect instance logic
 *
 * @note Resets to CLOSED on SocketReconnect_reset()
 * @warning Manipulating directly may cause inconsistent state or infinite
 * loops
 *
 * @see SocketReconnect_State for public state view
 * @see SocketReconnect_T::circuit_state for storage
 * @see SocketReconnect_Policy_T::circuit_failure_threshold configuration
 */
typedef enum
{
  CIRCUIT_CLOSED
  = 0,          /**< Normal operation: connections allowed, failures tracked */
  CIRCUIT_OPEN, /**< Blocked: too many consecutive failures, waiting timeout */
  CIRCUIT_HALF_OPEN /**< Probe allowed: single connection attempt to test
                       recovery */
} SocketReconnect_CircuitState;

/**
 * @brief Opaque internal context for reconnecting socket management.
 * @ingroup connection_mgmt
 * @internal
 *
 * Core data structure holding all configuration, state, timers, and resources
 * for a single reconnection instance. Supports exponential backoff with
 * jitter, circuit breaker pattern, periodic health checks, and automatic I/O
 * recovery.
 *
 *  Key Responsibilities
 *
 * - State machine transitions (connect, backoff, circuit states)
 * - Timer management (backoff delays, health intervals, circuit timeouts)
 * - Failure counting and retry limits
 * - Error logging and last-error tracking
 * - Resource ownership (arena, socket, callbacks)
 *
 *  Field Groups Overview
 *
 * | Group | Fields | Purpose |
 * |-------|--------|---------|
 * | Configuration | policy, host, port | Backoff policy and target endpoint |
 * | Resources | arena, socket | Memory and current connection handle |
 * | Callbacks | callback, health_check, userdata | Event notifications and
 * custom checks | | State | state, circuit_state | Current FSM and breaker
 * status | | Tracking | attempt_*, failures, successes | Metrics for retries
 * and reliability | | Timing | *_time_ms, backoff_until_ms, etc. | Monotonic
 * timestamps for scheduling | | Connection | connect_in_progress | Async
 * connect flags | | Errors | error_buf, last_error | Diagnostic information |
 *
 *  Lifecycle
 *
 * 1. **Creation**: SocketReconnect_new() allocates via arena, initializes
 * policy, copies host/port
 * 2. **Operation**: Public functions update fields atomically (e.g., connect
 * starts async, updates timers)
 * 3. **Destruction**: SocketReconnect_free() closes socket, disposes arena,
 * clears pointers
 *
 * Invariants:
 * - arena always valid until free
 * - socket NULL when not CONNECTED
 * - Timestamps use monotonic ms (non-decreasing)
 * - error_buf null-terminated, sized to SOCKET_RECONNECT_ERROR_BUFSIZE
 *
 *  Thread Safety
 *
 * @threadsafe No - Designed for single-threaded access from event loop
 * - All modifications via public API calls
 * - Internal helpers (time, random) are thread-safe
 * - Callbacks invoked from caller's thread context
 *
 *  Performance Notes
 *
 * - O(1) most operations (state checks, timer updates)
 * - Minimal allocations (arena-backed)
 * - Low memory footprint (~200-300 bytes + socket/arena)
 *
 * @complexity Varies by operation; generally O(1)
 * @note Host string copied to arena for lifetime management
 * @warning Direct field access undefined; use accessors where public
 * @note For leak detection, arena tracks all sub-allocs
 *
 * @see SocketReconnect_new() creation
 * @see SocketReconnect_free() destruction
 * @see SocketReconnect_Policy_T embedded policy
 * @see socketreconnect_get_time_ms() for timing helpers
 */
struct SocketReconnect_T
{
  /* Configuration - Policy and endpoint details */
  SocketReconnect_Policy_T policy; /**< Embedded backoff, circuit, and health
                                      policy; copied from input or defaults */

  /** Target hostname/IP; null-terminated string allocated from arena;
   *  Length limited to SOCKET_RECONNECT_MAX_HOST_LEN (255 chars) */
  char *host;

  /** Target TCP/UDP port (1-65535); validated at creation */
  int port;

  /* Internal resources - Owned objects for lifecycle management */
  Arena_T arena; /**< Memory arena owning host string, error_buf contents, and
                  * any sub-allocs; Disposed on free(); all pointers
                  * invalidated after */

  /** Current underlying socket; NULL when disconnected or connecting;
   *  Owned until closed on error/disconnect; do not free externally */
  Socket_T socket;

  /* Callbacks - User-provided hooks for events and checks */
  SocketReconnect_Callback
      callback; /**< Optional state transition notifier (old->new state);
                 *  Invoked synchronously from public API calls */

  /** Optional custom health check; if NULL, uses default poll-based check;
   *  Must respect timeout_ms param to avoid blocking */
  SocketReconnect_HealthCheck health_check;

  /** Opaque user data forwarded to callbacks; stored as-is, no ownership */
  void *userdata;

  /* State machine - Current status and internal breakers */
  SocketReconnect_State
      state; /**< Public-facing state; updated on transitions */

  /** Internal circuit breaker state; drives protection logic beyond public
   * view */
  SocketReconnect_CircuitState circuit_state;

  /* Connection tracking - Metrics for retries, success/failure rates */
  int attempt_count; /**< Attempts since last success or reset; resets on
                        connect success */

  /** Consecutive failures; triggers circuit open at threshold */
  int consecutive_failures;

  /** Lifetime total connection attempts; for long-term metrics */
  int total_attempts;

  /** Lifetime successful connections; for reliability stats */
  int total_successes;

  /* Timing - Monotonic timestamps (ms) for scheduling and delays */
  int64_t state_start_time_ms; /**< Timestamp when current state entered */

  int64_t last_attempt_time_ms; /**< Timestamp of most recent connect attempt */

  int64_t last_success_time_ms; /**< Timestamp of last successful connection */

  /** Absolute time when current backoff period expires; used for
   * next_timeout_ms */
  int64_t backoff_until_ms;

  /** Timestamp when circuit opened; used for half-open transition */
  int64_t circuit_open_time_ms;

  /** Timestamp of last health check invocation */
  int64_t last_health_check_ms;

  /** Currently computed backoff delay (with jitter applied); for
   * logging/metrics */
  int current_backoff_delay_ms;

  /* Connection state - Flags for async operations */
  int connect_in_progress; /**< Flag: non-zero if non-blocking connect pending;
                              cleared on completion/error */

  /* Error tracking - Diagnostics for failures */
  /** Fixed-size buffer for formatted last error (e.g., "connect failed:
   * Connection refused"); Null-terminated; overwritten on new errors */
  char error_buf[SOCKET_RECONNECT_ERROR_BUFSIZE];

  /** Cached errno from last failure; 0 if no error */
  int last_error;

#if SOCKET_HAS_TLS
  /* TLS Configuration - Optional secure connection support */

  /** TLS context for secure connections; NULL if TLS not configured.
   *  NOT owned by SocketReconnect - caller must ensure ctx outlives conn.
   *  Applied via SocketTLS_enable() after each successful TCP connect. */
  SocketTLSContext_T tls_ctx;

  /** SNI hostname for TLS certificate verification; arena-allocated.
   *  Used for SSL_set_tlsext_host_name() and X509 hostname check.
   *  NULL if TLS not configured. */
  char *tls_hostname;

  /** Current TLS handshake state; tracks progress during async handshake.
   *  Reset to TLS_HANDSHAKE_NOT_STARTED on each new connection attempt. */
  TLSHandshakeState tls_handshake_state;

  /** Flag: TLS handshake has been initiated for current connection.
   *  Set after SocketTLS_enable(); cleared on disconnect/error. */
  int tls_handshake_started;

  /** Flag: Enable session resumption for faster reconnects.
   *  When enabled, saves session after handshake and restores on reconnect. */
  int tls_session_resumption_enabled;

  /** Saved TLS session data for resumption; arena-allocated.
   *  Populated after successful handshake if resumption enabled. */
  unsigned char *tls_session_data;

  /** Length of saved TLS session data in bytes. */
  size_t tls_session_data_len;
#endif /* SOCKET_HAS_TLS */
};

/**
 * @brief Retrieve current monotonic time in milliseconds for internal timing.
 * @internal
 * @ingroup connection_mgmt
 *
 * Provides a consistent, non-decreasing timestamp resistant to system clock
 * changes (e.g., NTP adjustments). Used for all backoff, timeout, and health
 * check calculations.
 *
 * @return int64_t milliseconds since arbitrary fixed epoch (monotonic).
 *
 *  Usage Example
 *
 * @code{.c}
 * int64_t now = socketreconnect_get_time_ms();
 * if (socketreconnect_elapsed_ms(start) > timeout_ms) {
 *     // Handle timeout
 * }
 * @endcode
 *
 * Always prefer this over system time for scheduling to avoid jumps
 * backward/forward.
 *
 * @complexity O(1) - thin wrapper over system clock query
 * @threadsafe Yes - reentrant with no shared mutable state
 *
 * @note Backed by CLOCK_MONOTONIC or platform equivalent
 * @warning Value wraps after ~292 years; handle int64_t overflow in
 * long-running apps
 *
 * @see Socket_get_monotonic_ms() core implementation
 * @see socketreconnect_elapsed_ms() for computing durations
 */

static int64_t
socketreconnect_now_ms (void)
{
  return Socket_get_monotonic_ms ();
}

/**
 * @brief Compute elapsed monotonic time since provided start timestamp.
 * @internal
 * @ingroup connection_mgmt
 *
 * Calculates duration between start_ms and current time, clamping to 0 if
 * anomalous (e.g., clock adjustment). Essential for timeout checks and delay
 * validation.
 *
 * @param[in] start_ms Starting timestamp from socketreconnect_get_time_ms()
 *
 * @return Non-negative int64_t milliseconds elapsed; 0 if start_ms >= now
 *
 *  Usage Example
 *
 * @code{.c}
 * int64_t start = socketreconnect_get_time_ms();
 * // ... some operation ...
 * int64_t elapsed = socketreconnect_elapsed_ms(start);
 * if (elapsed > policy.max_delay_ms) {
 *     // Timeout handling
 * }
 * @endcode
 *
 * Guarantees non-negative result for safe comparisons.
 *
 * @complexity O(1) - arithmetic only (calls get_time_ms inline)
 * @threadsafe Yes - pure function, no side effects
 *
 * @note Clamps to 0 on underflow to handle rare clock issues
 * @warning Input must be valid monotonic timestamp; invalid values may yield
 * large positives
 *
 * @see socketreconnect_get_time_ms() to obtain start_ms
 * @see Socket_get_monotonic_ms() underlying time source
 */

static int64_t
socketreconnect_elapsed_ms (int64_t start_ms)
{
  int64_t now = socketreconnect_now_ms ();
  int64_t delta = now - start_ms;
  return delta > 0 ? delta : 0;
}

/**
 * @brief Generate uniform random double in [0.0, 1.0) for jitter in backoff
 * calculations.
 * @internal
 * @ingroup connection_mgmt
 *
 * Produces randomness for exponential backoff jitter to avoid thundering herd
 * (synchronized retries). Prioritizes secure crypto RNG, falls back to fast
 * thread-local PRNG for performance.
 *
 * @return double uniformly distributed in [0.0, 1.0)
 *
 *  Usage in Backoff
 *
 * Jitter applied as: delay *= (1.0 + jitter_factor * (2*rand - 1))
 * Where jitter_factor from policy (0.0-1.0).
 *
 * @code{.c}
 * double r = socketreconnect_random_double();
 * int64_t jittered_delay = base_delay * (1.0 + policy.jitter * (2*r - 1.0));
 * @endcode
 *
 *  Implementation Details
 *
 * 1. **Primary**: SocketCrypto_random_bytes() for 32-bit uint → normalized
 * double
 * 2. **Fallback**: Thread-local xorshift32 PRNG, seeded once by monotonic time
 *    - xorshift: seed ^= seed <<13; ^= >>17; ^= <<5
 *    - Period: 2^32 -1; good for non-crypto use
 *
 * Secure source preferred but not required; fallback ensures availability.
 *
 * @complexity O(1) amortized - crypto may block briefly, PRNG instant
 * @threadsafe Yes - crypto reentrant, PRNG per-thread (__thread static)
 *
 * @note Fallback seeded lazily on first call per thread
 * @warning NON-CRYPTO: Do not use for keys, nonces, or security decisions
 * @note If crypto fails (e.g., /dev/urandom unavailable), logs warning
 * internally
 *
 * @see SocketCrypto_random_bytes() primary secure source
 * @see SocketReconnect_Policy_T::jitter usage context
 * @see xorshift algorithm for PRNG details
 */

static double
reconnect_jitter (void)
{
  unsigned int value;
  if (SocketCrypto_random_bytes (&value, sizeof (value)) == 0)
    {
      return (double)value / (double)0xFFFFFFFFU;
    }
  else
    {
      /* Fallback to time-based PRNG */
#ifdef _WIN32
      static __declspec (thread) unsigned int seed = 0;
#else
      static __thread unsigned int seed = 0;
#endif
      if (seed == 0)
        {
          seed = (unsigned int)Socket_get_monotonic_ms ();
        }
      /* xorshift32 */
      seed ^= seed << 13;
      seed ^= seed >> 17;
      seed ^= seed << 5;
      return (double)seed / (double)0xFFFFFFFFU;
    }
}

/**
 * @} -- reconnect_private
 */

#endif /* SOCKETRECONNECT_PRIVATE_INCLUDED */
