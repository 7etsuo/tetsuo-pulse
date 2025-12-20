/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketReconnect.c - Automatic Reconnection Framework Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements automatic reconnection with exponential backoff, circuit breaker
 * pattern, and health monitoring.
 *
 * Backoff Algorithm:
 *   delay = min(initial_delay * multiplier^attempt, max_delay)
 *   jittered_delay = delay * (1.0 + jitter * (2*random - 1))
 *
 * Circuit Breaker:
 *   CLOSED -> OPEN: After circuit_failure_threshold consecutive failures
 *   OPEN -> HALF_OPEN: After circuit_reset_timeout_ms
 *   HALF_OPEN -> CLOSED: On successful connection
 *   HALF_OPEN -> OPEN: On failed probe
 */

/* System headers first (alphabetical order) */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Project headers */
#include "socket/SocketReconnect-private.h"
#include "socket/SocketReconnect.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#define T SocketReconnect_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Reconnect"

/* Exception definition */
const Except_T SocketReconnect_Failed
    = { &SocketReconnect_Failed, "Reconnection operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketReconnect);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketReconnect, e)

#define RAISE_RECONNECT_ERROR_MSG(exception, fmt, ...)                        \
  SOCKET_RAISE_FMT (SocketReconnect, exception, fmt, ##__VA_ARGS__)

/**
 * @brief Minimum poll timeout for health check when user specifies 0 or
 * negative.
 *
 * A minimum timeout ensures we don't spin too fast when checking socket health.
 */
#ifndef SOCKET_RECONNECT_MIN_HEALTH_POLL_MS
#define SOCKET_RECONNECT_MIN_HEALTH_POLL_MS 100
#endif

/* ============================================================================
 * State Names
 * ============================================================================
 */

static const char *state_names[]
    = { "DISCONNECTED", "CONNECTING", "CONNECTED", "BACKOFF", "CIRCUIT_OPEN" };

const char *
SocketReconnect_state_name (SocketReconnect_State state)
{
  if (state >= 0 && state <= RECONNECT_CIRCUIT_OPEN)
    return state_names[state];
  return "UNKNOWN";
}

static void
reconnect_set_socket_error (T conn, const char *operation, int err)
{
  conn->last_error = err;
  snprintf (conn->error_buf, sizeof (conn->error_buf),
            "%s: %s", operation, Socket_safe_strerror (err));
}

static void
restore_socket_blocking (Socket_T socket)
{
  if (!socket)
    return;
  int fd = Socket_fd (socket);
  if (fd < 0)
    return;
  int flags = fcntl (fd, F_GETFL);
  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

#if SOCKET_HAS_TLS
static void
reconnect_set_tls_error (T conn, const char *operation)
{
  conn->last_error = errno;
  snprintf (conn->error_buf, sizeof (conn->error_buf),
            "%s: %s", operation, Socket_GetLastError ());
}
#endif

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 *
 * Note: socketreconnect_now_ms(), socketreconnect_elapsed_ms(), and
 * reconnect_jitter() are defined in SocketReconnect-private.h as static
 * inline functions for use across split files if needed.
 */

/* ============================================================================
 * Policy Defaults
 * ============================================================================
 */

void
SocketReconnect_policy_defaults (SocketReconnect_Policy_T *policy)
{
  assert (policy);
  policy->initial_delay_ms = SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS;
  policy->max_delay_ms = SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS;
  policy->multiplier = SOCKET_RECONNECT_DEFAULT_MULTIPLIER;
  policy->jitter = SOCKET_RECONNECT_DEFAULT_JITTER;
  policy->max_attempts = SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS;
  policy->circuit_failure_threshold
      = SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD;
  policy->circuit_reset_timeout_ms = SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS;
  policy->health_check_interval_ms
      = SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS;
  policy->health_check_timeout_ms = SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS;
}

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

static void handle_connect_failure (T conn);

#if SOCKET_HAS_TLS
static void save_tls_session (T conn);
static int restore_tls_session (T conn);
#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Internal State Machine Helpers
 * ============================================================================
 */

/**
 * transition_state - Transition to new state with callback
 * @conn: Reconnection context
 * @new_state: Target state
 */
static void
transition_state (T conn, SocketReconnect_State new_state)
{
  SocketReconnect_State old_state = conn->state;

  if (old_state == new_state)
    return;

  conn->state = new_state;
  conn->state_start_time_ms = socketreconnect_now_ms ();

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d state transition: %s -> %s", conn->host, conn->port,
                   SocketReconnect_state_name (old_state),
                   SocketReconnect_state_name (new_state));

  if (conn->callback)
    {
      conn->callback (conn, old_state, new_state, conn->userdata);
    }
}

/**
 * calculate_backoff_delay - Calculate next backoff delay with jitter
 * @conn: Reconnection context
 *
 * Returns: Delay in milliseconds
 */
static int
calculate_backoff_delay (T conn)
{
  /* Exponential backoff: initial * multiplier^attempt */
  double delay = (double)conn->policy.initial_delay_ms
                 * pow (conn->policy.multiplier, (double)conn->attempt_count);

  /* Cap at max delay, handle nan/inf */
  if (isnan (delay) || isinf (delay)
      || delay > (double)conn->policy.max_delay_ms)
    delay = (double)conn->policy.max_delay_ms;

  /* Add jitter: delay * (1 + jitter * (2*random - 1)) */
  if (conn->policy.jitter > 0.0)
    {
      double jitter_range = delay * conn->policy.jitter;
      double jitter_offset
          = jitter_range * (2.0 * reconnect_jitter () - 1.0);
      delay += jitter_offset;
    }

  /* Ensure minimum 1ms */
  if (delay < 1.0)
    delay = 1.0;

  return (int)delay;
}

/**
 * update_circuit_breaker - Update circuit breaker state based on result
 * @conn: Reconnection context
 * @success: 1 if connection succeeded, 0 if failed
 */
static void
update_circuit_breaker (T conn, int success)
{
  if (success)
    {
      conn->consecutive_failures = 0;
      if (conn->circuit_state != CIRCUIT_CLOSED)
        {
          SocketLog_emitf (
              SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
              "%s:%d circuit breaker closed after successful connection",
              conn->host, conn->port);
          conn->circuit_state = CIRCUIT_CLOSED;
        }
    }
  else
    {
      conn->consecutive_failures++;

      if (conn->circuit_state == CIRCUIT_HALF_OPEN)
        {
          /* Probe failed, reopen circuit */
          conn->circuit_state = CIRCUIT_OPEN;
          conn->circuit_open_time_ms = socketreconnect_now_ms ();
          SocketLog_emitf (
              SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
              "%s:%d circuit breaker reopened after probe failure", conn->host,
              conn->port);
        }
      else if (conn->consecutive_failures
                   >= conn->policy.circuit_failure_threshold
               && conn->circuit_state == CIRCUIT_CLOSED)
        {
          /* Too many failures, open circuit */
          conn->circuit_state = CIRCUIT_OPEN;
          conn->circuit_open_time_ms = socketreconnect_now_ms ();
          SocketLog_emitf (
              SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
              "%s:%d circuit breaker opened after %d consecutive failures",
              conn->host, conn->port, conn->consecutive_failures);
        }
    }
}

/**
 * circuit_allows_attempt - Check if circuit breaker allows connection attempt
 * @conn: Reconnection context
 *
 * Returns: 1 if attempt allowed, 0 if blocked
 */
static int
circuit_allows_attempt (T conn)
{
  if (conn->circuit_state == CIRCUIT_CLOSED)
    return 1;

  if (conn->circuit_state == CIRCUIT_OPEN)
    {
      int64_t elapsed
          = socketreconnect_elapsed_ms (conn->circuit_open_time_ms);
      if (elapsed >= conn->policy.circuit_reset_timeout_ms)
        {
          /* Allow probe attempt */
          conn->circuit_state = CIRCUIT_HALF_OPEN;
          SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                           "%s:%d circuit breaker half-open, allowing probe",
                           conn->host, conn->port);
          return 1;
        }
      return 0;
    }

  /* HALF_OPEN - allow one probe */
  return 1;
}

/**
 * close_socket - Close and free current socket
 * @conn: Reconnection context
 *
 * Performs graceful TLS shutdown if TLS was enabled before closing
 * the underlying socket. Ignores errors during shutdown to ensure
 * cleanup always succeeds.
 */
static void
close_socket (T conn)
{
  if (conn->socket)
    {
#if SOCKET_HAS_TLS
      /* Perform TLS shutdown if handshake completed */
      if (conn->tls_ctx && conn->tls_handshake_started
          && conn->tls_handshake_state == TLS_HANDSHAKE_COMPLETE)
        {
          /* Best-effort TLS shutdown - ignore errors */
          TRY { SocketTLS_shutdown_send (conn->socket); }
          EXCEPT (SocketTLS_ShutdownFailed)
          {
            /* Ignore - peer may have already closed */
            SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                             "%s:%d TLS shutdown failed (ignored)", conn->host,
                             conn->port);
          }
          EXCEPT (SocketTLS_Failed)
          {
            /* Ignore - TLS may be in bad state */
          }
          EXCEPT (Socket_Closed)
          {
            /* Ignore - socket already closed */
          }
          END_TRY;
        }

      /* Reset TLS state for next connection attempt */
      conn->tls_handshake_started = 0;
      conn->tls_handshake_state = TLS_HANDSHAKE_NOT_STARTED;
#endif /* SOCKET_HAS_TLS */

      Socket_free (&conn->socket);
      conn->socket = NULL;
    }
  conn->connect_in_progress = 0;
}

/* ============================================================================
 * Connection Handling
 * ============================================================================
 */

/**
 * start_connect - Initiate connection attempt
 * @conn: Reconnection context
 *
 * Returns: 1 if connection started/completed, 0 if failed
 */
static int
start_connect (T conn)
{
  int fd, flags;

  /* Check max attempts */
  if (conn->policy.max_attempts > 0
      && conn->attempt_count >= conn->policy.max_attempts)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Maximum reconnection attempts (%d) reached",
                conn->policy.max_attempts);
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT, "%s:%d %s",
                       conn->host, conn->port, conn->error_buf);
      return 0;
    }

  /* Check circuit breaker */
  if (!circuit_allows_attempt (conn))
    {
      transition_state (conn, RECONNECT_CIRCUIT_OPEN);
      return 0;
    }

  /* Clean up any existing socket */
  close_socket (conn);

  /* Create new socket - use AF_INET for IPv4, resolve actual address family
   * later */
  TRY { conn->socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    reconnect_set_socket_error (conn, "Failed to create socket", err);
    return 0;
  }
  END_TRY;

  if (!conn->socket)
    return 0;

  /* Set non-blocking for async connect */
  TRY
  {
    Socket_setnonblocking (conn->socket);
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    reconnect_set_socket_error (conn, "Failed to set non-blocking mode", err);
    close_socket (conn);
    return 0;
  }
  END_TRY;

  /* Update attempt tracking */
  conn->attempt_count++;
  conn->total_attempts++;
  conn->last_attempt_time_ms = socketreconnect_now_ms ();

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d starting connection attempt %d", conn->host,
                   conn->port, conn->attempt_count);

  /* Start connect - use Socket_connect which handles DNS */
  TRY
  {
    Socket_connect (conn->socket, conn->host, conn->port);
    /* Immediate success (rare, usually localhost) */
    conn->connect_in_progress = 0;
    RETURN 1;
  }
  EXCEPT (Socket_Failed)
  {
    /* Check if it's EINPROGRESS (non-blocking connect started) */
    int err = Socket_geterrno ();
    /* LCOV_EXCL_START - requires non-routable address for async connect */
    if (err == EINPROGRESS || err == EINTR)
      {
        conn->connect_in_progress = 1;
        return 1;
      }
    /* LCOV_EXCL_STOP */

    /* Real failure */
    reconnect_set_socket_error (conn, "Connect failed", err);
    close_socket (conn);
    return 0;
  }
  END_TRY;

  return 1;
}

/**
 * check_connect_completion - Check if async connect has completed
 * @conn: Reconnection context
 *
 * Returns: 1 if connected, 0 if still pending, -1 if failed
 *
 * LCOV_EXCL_START - requires non-routable address to trigger EINPROGRESS
 */
static int
check_connect_completion (T conn)
{
  int fd, error;
  socklen_t len;
  struct pollfd pfd;
  int result;

  if (!conn->socket || !conn->connect_in_progress)
    return -1;

  fd = Socket_fd (conn->socket);

  /* Poll for write readiness */
  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;

  result = poll (&pfd, 1, 0);
  if (result < 0)
    {
      if (errno == EINTR)
        return 0;
      reconnect_set_socket_error (conn, "Connect poll failed", errno);
      return -1;
    }

  if (result == 0)
    return 0; /* Still connecting */

  /* Check for errors */
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      error = 0;
      len = sizeof (error);
      getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len);
      int connect_err = error ? error : ECONNREFUSED;
      reconnect_set_socket_error (conn, "Connect poll error", connect_err);
      return -1;
    }

  /* Check SO_ERROR */
  error = 0;
  len = sizeof (error);
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
      reconnect_set_socket_error (conn, "Connect check getsockopt failed", errno);
      return -1;
    }

  if (error != 0)
    {
      reconnect_set_socket_error (conn, "Connect check failed", error);
      return -1;
    }

  /* Success! Restore blocking mode */
  restore_socket_blocking (conn->socket);

  conn->connect_in_progress = 0;
  return 1;
}
/* LCOV_EXCL_STOP */

#if SOCKET_HAS_TLS
/**
 * start_tls_handshake - Initialize TLS on connected socket
 * @conn: Reconnection context with TCP connection established
 *
 * Returns: 1 if TLS started successfully, 0 on error
 *
 * Called after TCP connect succeeds when TLS is configured.
 * Enables TLS, sets hostname, restores session, and initiates handshake.
 */
static int
start_tls_handshake (T conn)
{
  assert (conn->tls_ctx);
  assert (conn->tls_hostname);
  assert (conn->socket);

  TRY
  {
    /* Enable TLS on the socket */
    SocketTLS_enable (conn->socket, conn->tls_ctx);

    /* Set SNI hostname for certificate verification */
    SocketTLS_set_hostname (conn->socket, conn->tls_hostname);

    /* Attempt session resumption if we have saved session data */
    restore_tls_session (conn);

    conn->tls_handshake_started = 1;
    conn->tls_handshake_state = TLS_HANDSHAKE_NOT_STARTED;

    SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                     "%s:%d TLS enabled, starting handshake", conn->host,
                     conn->port);
    return 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    reconnect_set_tls_error (conn, "TLS enable failed");
    return 0;
  }
  END_TRY;

  return 1;
}

/**
 * perform_tls_handshake_step - Execute one step of TLS handshake
 * @conn: Reconnection context with TLS handshake in progress
 *
 * Returns: 1 if handshake complete, 0 if in progress, -1 on error
 *
 * Drives the TLS handshake state machine. Should be called from process()
 * when socket events indicate readiness.
 */
static int
perform_tls_handshake_step (T conn)
{
  volatile TLSHandshakeState state = TLS_HANDSHAKE_NOT_STARTED;

  TRY { state = SocketTLS_handshake (conn->socket); }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    reconnect_set_tls_error (conn, "TLS handshake failed");
    conn->tls_handshake_state = TLS_HANDSHAKE_ERROR;
    return -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    reconnect_set_tls_error (conn, "TLS certificate verification failed");
    conn->tls_handshake_state = TLS_HANDSHAKE_ERROR;
    return -1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    reconnect_set_tls_error (conn, "TLS error");
    conn->tls_handshake_state = TLS_HANDSHAKE_ERROR;
    return -1;
  }
  END_TRY;

  conn->tls_handshake_state = state;

  switch (state)
    {
    case TLS_HANDSHAKE_COMPLETE:
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d TLS handshake complete (cipher: %s)", conn->host,
                       conn->port, SocketTLS_get_cipher (conn->socket));

      /* Save session for future resumption */
      save_tls_session (conn);
      return 1;

    case TLS_HANDSHAKE_WANT_READ:
    case TLS_HANDSHAKE_WANT_WRITE:
    case TLS_HANDSHAKE_IN_PROGRESS:
      /* Continue handshake on next event */
      return 0;

    case TLS_HANDSHAKE_ERROR:
      if (conn->error_buf[0] == '\0')
        {
          reconnect_set_tls_error (conn, "TLS handshake error");
        }
      return -1;

    default:
      return 0;
    }
}

/**
 * complete_tls_connection - Finalize connection after TLS handshake success
 * @conn: Reconnection context
 */
static void
complete_tls_connection (T conn)
{
  conn->consecutive_failures = 0;
  conn->attempt_count = 0;
  conn->total_successes++;
  conn->last_success_time_ms = socketreconnect_now_ms ();
  conn->last_health_check_ms = conn->last_success_time_ms;

  conn->error_buf[0] = '\0';
  conn->last_error = 0;

  update_circuit_breaker (conn, 1);
  transition_state (conn, RECONNECT_CONNECTED);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "%s:%d TLS connection established successfully", conn->host,
                   conn->port);
}
#endif /* SOCKET_HAS_TLS */

/**
 * handle_connect_success - Process successful TCP connection
 * @conn: Reconnection context
 *
 * For plain TCP: Transitions to CONNECTED immediately.
 * For TLS: Initiates TLS handshake; CONNECTED transition deferred.
 */
static void
handle_connect_success (T conn)
{
#if SOCKET_HAS_TLS
  if (conn->tls_ctx)
    {
      /* TLS enabled - start handshake instead of completing connection */
      if (!start_tls_handshake (conn))
        {
          /* TLS setup failed - treat as connection failure */
          handle_connect_failure (conn);
          return;
        }

      /* Stay in CONNECTING state while TLS handshake proceeds */
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d TCP connected, TLS handshake pending",
                       conn->host, conn->port);

      /* Immediately try first handshake step */
      int hs_result = perform_tls_handshake_step (conn);
      if (hs_result == 1)
        {
          /* Handshake completed immediately (unlikely but possible) */
          complete_tls_connection (conn);
        }
      else if (hs_result < 0)
        {
          /* Handshake failed */
          handle_connect_failure (conn);
        }
      /* hs_result == 0: handshake in progress, wait for events */
      return;
    }
#endif /* SOCKET_HAS_TLS */

  /* Plain TCP connection success */
  conn->consecutive_failures = 0;
  conn->attempt_count = 0;
  conn->total_successes++;
  conn->last_success_time_ms = socketreconnect_now_ms ();
  conn->last_health_check_ms = conn->last_success_time_ms;

  /* Clear error buffer on success to prevent stale error messages */
  conn->error_buf[0] = '\0';
  conn->last_error = 0;

  update_circuit_breaker (conn, 1);
  transition_state (conn, RECONNECT_CONNECTED);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "%s:%d connected successfully", conn->host, conn->port);
}

/**
 * handle_connect_failure - Process connection failure
 * @conn: Reconnection context
 */
static void
handle_connect_failure (T conn)
{
  close_socket (conn);
  update_circuit_breaker (conn, 0);

  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                   "%s:%d connection attempt %d failed: %s", conn->host,
                   conn->port, conn->attempt_count, conn->error_buf);

  /* Check if circuit breaker tripped */
  if (conn->circuit_state == CIRCUIT_OPEN)
    {
      transition_state (conn, RECONNECT_CIRCUIT_OPEN);
      return;
    }

  /* Check max attempts */
  if (conn->policy.max_attempts > 0
      && conn->attempt_count >= conn->policy.max_attempts)
    {
      transition_state (conn, RECONNECT_DISCONNECTED);
      return;
    }

  /* Enter backoff */
  conn->current_backoff_delay_ms = calculate_backoff_delay (conn);
  conn->backoff_until_ms
      = socketreconnect_now_ms () + conn->current_backoff_delay_ms;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d backing off for %d ms", conn->host, conn->port,
                   conn->current_backoff_delay_ms);

  transition_state (conn, RECONNECT_BACKOFF);
}

/* ============================================================================
 * Health Check
 * ============================================================================
 */

/**
 * default_health_check - Default health check implementation
 * @conn: Reconnection context
 * @socket: Connected socket
 * @userdata: User data (unused)
 *
 * Returns: 1 if healthy, 0 if unhealthy
 *
 * Checks if socket is still connected by polling for read with timeout.
 * EOF (0 bytes readable) indicates disconnection.
 */
static int
default_health_check (const T conn, const Socket_T socket, int timeout_ms,
                      void *userdata)
{
  struct pollfd pfd;
  int fd, result;
  char buf;
  int poll_timeout
      = (timeout_ms > 0) ? timeout_ms : SOCKET_RECONNECT_MIN_HEALTH_POLL_MS;

  (void)conn;
  (void)userdata;

  if (!socket)
    return 0;

  fd = Socket_fd (socket);
  pfd.fd = fd;
  pfd.events = POLLIN | POLLERR | POLLHUP;
  pfd.revents = 0;

  result = poll (&pfd, 1, poll_timeout);
  if (result < 0)
    return errno == EINTR ? 1 : 0;

  if (result == 0)
    return 1; /* Timeout, assume healthy */

  /* Error or hangup */
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return 0;

  /* If readable, peek to check for EOF */
  if (pfd.revents & POLLIN)
    {
      char dummy;
      volatile ssize_t peek_res = 0;
      TRY
      {
        peek_res = socket_recv_internal (socket, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);
      }
      EXCEPT (Socket_Failed)
      {
        return 0;
      }
      EXCEPT (Socket_Closed)
      {
        return 0;
      }
#if SOCKET_HAS_TLS
      EXCEPT (SocketTLS_Failed)
      {
        return 0;
      }
#endif
      END_TRY;
      if (peek_res == 0)
        return 0; /* EOF or would block */
    }

  return 1;
}

/**
 * perform_health_check - Run health check and handle result
 * @conn: Reconnection context
 */
static void
perform_health_check (T conn)
{
  int healthy;
  SocketReconnect_HealthCheck check;

  if (!conn->socket || conn->state != RECONNECT_CONNECTED)
    return;

  check = conn->health_check ? conn->health_check : default_health_check;
  healthy = check (conn, conn->socket, conn->policy.health_check_timeout_ms,
                   conn->userdata);

  conn->last_health_check_ms = socketreconnect_now_ms ();

  if (!healthy)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "%s:%d health check failed, reconnecting", conn->host,
                       conn->port);
      close_socket (conn);
      handle_connect_failure (conn);
    }
}

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

T
SocketReconnect_new (const char *host, int port,
                     const SocketReconnect_Policy_T *policy,
                     SocketReconnect_Callback callback, void *userdata)
{
  T conn;
  size_t host_len;

  if (!host)
    {
      SOCKET_ERROR_MSG ("Host cannot be NULL");
      RAISE_MODULE_ERROR (SocketReconnect_Failed);
    }
  if (!(port > 0 && port <= 65535))
    {
      SOCKET_ERROR_FMT ("Invalid port %d (must be 1-65535)", port);
      RAISE_MODULE_ERROR (SocketReconnect_Failed);
    }

  conn = calloc (1, sizeof (*conn));
  if (!conn)
    {
      SOCKET_ERROR_MSG (
          "Failed to allocate reconnection context"); /* LCOV_EXCL_LINE */
      RAISE_MODULE_ERROR (SocketReconnect_Failed);    /* LCOV_EXCL_LINE */
    }

  conn->arena = Arena_new ();
  if (!conn->arena)
    {
      free (conn); /* LCOV_EXCL_LINE */
      SOCKET_ERROR_MSG (
          "Failed to create arena for reconnection context"); /* LCOV_EXCL_LINE
                                                               */
      RAISE_MODULE_ERROR (SocketReconnect_Failed); /* LCOV_EXCL_LINE */
    }

  /* Copy configuration */
  if (policy)
    conn->policy = *policy;
  else
    SocketReconnect_policy_defaults (&conn->policy);

  /* Validate policy parameters */
  if (conn->policy.initial_delay_ms < 1)
    conn->policy.initial_delay_ms = SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS;
  if (conn->policy.max_delay_ms < conn->policy.initial_delay_ms)
    conn->policy.max_delay_ms = SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS;
  if (conn->policy.multiplier < 1.0)
    conn->policy.multiplier = SOCKET_RECONNECT_DEFAULT_MULTIPLIER;
  if (conn->policy.jitter < 0.0 || conn->policy.jitter > 1.0)
    conn->policy.jitter = SOCKET_RECONNECT_DEFAULT_JITTER;
  if (conn->policy.max_attempts < 0)
    conn->policy.max_attempts = SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS;
  if (conn->policy.circuit_failure_threshold < 1)
    conn->policy.circuit_failure_threshold
        = SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD;
  if (conn->policy.circuit_reset_timeout_ms < 1000)
    conn->policy.circuit_reset_timeout_ms
        = SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS;
  if (conn->policy.health_check_interval_ms < 0)
    conn->policy.health_check_interval_ms
        = SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS;
  if (conn->policy.health_check_timeout_ms < 100)
    conn->policy.health_check_timeout_ms
        = SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS;

  /* Copy hostname with length validation */
  host_len = strlen (host) + 1;
  if (!SocketSecurity_check_size (host_len))
    {
      RAISE_RECONNECT_ERROR_MSG (SocketReconnect_Failed,
                                 "Hostname too long for allocation");
    }
  if (host_len > SOCKET_ERROR_MAX_HOSTNAME + 1)
    {
      Arena_dispose (&conn->arena);
      free (conn);
      SOCKET_ERROR_FMT ("Hostname too long (%zu > %d max)", host_len - 1,
                        SOCKET_ERROR_MAX_HOSTNAME);
      RAISE_MODULE_ERROR (SocketReconnect_Failed);
    }

  conn->host = Arena_alloc (conn->arena, host_len, __FILE__, __LINE__);
  if (!conn->host)
    {
      Arena_dispose (&conn->arena);                     /* LCOV_EXCL_LINE */
      free (conn);                                      /* LCOV_EXCL_LINE */
      SOCKET_ERROR_MSG ("Failed to allocate hostname"); /* LCOV_EXCL_LINE */
      RAISE_MODULE_ERROR (SocketReconnect_Failed);      /* LCOV_EXCL_LINE */
    }
  memcpy (conn->host, host, host_len);
  conn->port = port;

  /* Set callbacks */
  conn->callback = callback;
  conn->userdata = userdata;

  /* Initialize state */
  conn->state = RECONNECT_DISCONNECTED;
  conn->circuit_state = CIRCUIT_CLOSED;
  conn->state_start_time_ms = socketreconnect_now_ms ();

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Created reconnection context for %s:%d", host, port);

  return conn;
}

void
SocketReconnect_free (T *conn)
{
  if (!conn || !*conn)
    return;

  T ctx = *conn;

  /* Close socket if connected */
  close_socket (ctx);

  /* Free arena */
  if (ctx->arena)
    Arena_dispose (&ctx->arena);

  free (ctx);
  *conn = NULL;
}

/* ============================================================================
 * Connection Control
 * ============================================================================
 */

void
SocketReconnect_connect (T conn)
{
  assert (conn);

  switch (conn->state)
    {
    case RECONNECT_CONNECTED:
    case RECONNECT_CONNECTING:
      /* Already connected or connecting */
      return;

    case RECONNECT_BACKOFF:
    case RECONNECT_CIRCUIT_OPEN:
      /* Will be handled by tick() */
      return;

    case RECONNECT_DISCONNECTED:
      /* Start connection */
      transition_state (conn, RECONNECT_CONNECTING);
      if (start_connect (conn))
        {
          if (!conn->connect_in_progress)
            {
              /* Immediate connect (rare) */
              handle_connect_success (conn);
            }
        }
      else
        {
          handle_connect_failure (conn);
        }
      break;
    }
}

void
SocketReconnect_disconnect (T conn)
{
  assert (conn);

  close_socket (conn);
  conn->attempt_count = 0;
  transition_state (conn, RECONNECT_DISCONNECTED);

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT, "%s:%d disconnected",
                   conn->host, conn->port);
}

void
SocketReconnect_reset (T conn)
{
  assert (conn);

  conn->attempt_count = 0;
  conn->consecutive_failures = 0;
  conn->circuit_state = CIRCUIT_CLOSED;
  conn->error_buf[0] = '\0';
  conn->last_error = 0;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d reset backoff and circuit breaker state", conn->host,
                   conn->port);
}

/* ============================================================================
 * Socket Access
 * ============================================================================
 */

Socket_T
SocketReconnect_socket (T conn)
{
  assert (conn);

  if (conn->state != RECONNECT_CONNECTED)
    return NULL;

  return conn->socket;
}

/* ============================================================================
 * State Query
 * ============================================================================
 */

SocketReconnect_State
SocketReconnect_state (T conn)
{
  assert (conn);
  return conn->state;
}

int
SocketReconnect_isconnected (T conn)
{
  assert (conn);
  return conn->state == RECONNECT_CONNECTED;
}

int
SocketReconnect_attempts (T conn)
{
  assert (conn);
  return conn->attempt_count;
}

int
SocketReconnect_failures (T conn)
{
  assert (conn);
  return conn->consecutive_failures;
}

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

int
SocketReconnect_pollfd (T conn)
{
  assert (conn);

  if (!conn->socket)
    return -1;

  return Socket_fd (conn->socket);
}

void
SocketReconnect_process (T conn)
{
  assert (conn);

  /* LCOV_EXCL_START - requires non-routable address for EINPROGRESS */
  if (conn->state == RECONNECT_CONNECTING)
    {
      /* Check if TCP connect is still in progress */
      if (conn->connect_in_progress)
        {
          int result = check_connect_completion (conn);
          if (result > 0)
            {
              handle_connect_success (conn);
            }
          else if (result < 0)
            {
              handle_connect_failure (conn);
            }
          /* result == 0: still connecting */
          return;
        }

#if SOCKET_HAS_TLS
      /* Check if TLS handshake is in progress */
      if (conn->tls_ctx && conn->tls_handshake_started
          && conn->tls_handshake_state != TLS_HANDSHAKE_COMPLETE
          && conn->tls_handshake_state != TLS_HANDSHAKE_ERROR)
        {
          int hs_result = perform_tls_handshake_step (conn);
          if (hs_result == 1)
            {
              /* TLS handshake complete */
              complete_tls_connection (conn);
            }
          else if (hs_result < 0)
            {
              /* TLS handshake failed */
              handle_connect_failure (conn);
            }
          /* hs_result == 0: handshake in progress */
        }
#endif /* SOCKET_HAS_TLS */
    }
  /* LCOV_EXCL_STOP */
}

int
SocketReconnect_next_timeout_ms (T conn)
{
  int64_t now, remaining;
  int timeout = -1;

  assert (conn);

  now = socketreconnect_now_ms ();

  switch (conn->state)
    {
    case RECONNECT_BACKOFF:
      remaining = conn->backoff_until_ms - now;
      if (remaining <= 0)
        return 0;
      timeout = (int)remaining;
      break;

    case RECONNECT_CIRCUIT_OPEN:
      remaining = (conn->circuit_open_time_ms
                   + conn->policy.circuit_reset_timeout_ms)
                  - now;
      if (remaining <= 0)
        return 0;
      timeout = (int)remaining;
      break;

    case RECONNECT_CONNECTED:
      /* Health check timer */
      if (conn->policy.health_check_interval_ms > 0)
        {
          remaining = (conn->last_health_check_ms
                       + conn->policy.health_check_interval_ms)
                      - now;
          if (remaining <= 0)
            return 0;
          timeout = (int)remaining;
        }
      break;

    default:
      break;
    }

  return timeout;
}

void
SocketReconnect_tick (T conn)
{
  int64_t now;

  assert (conn);

  now = socketreconnect_now_ms ();

  switch (conn->state)
    {
    case RECONNECT_BACKOFF:
      if (now >= conn->backoff_until_ms)
        {
          /* Backoff expired, retry */
          transition_state (conn, RECONNECT_CONNECTING);
          if (start_connect (conn))
            {
              if (!conn->connect_in_progress)
                handle_connect_success (conn);
            }
          else
            {
              handle_connect_failure (conn);
            }
        }
      break;

    case RECONNECT_CIRCUIT_OPEN:
      if (now >= conn->circuit_open_time_ms
                     + conn->policy.circuit_reset_timeout_ms)
        {
          /* Try probe connection */
          conn->circuit_state = CIRCUIT_HALF_OPEN;
          transition_state (conn, RECONNECT_CONNECTING);
          if (start_connect (conn))
            {
              if (!conn->connect_in_progress)
                handle_connect_success (conn);
            }
          else
            {
              handle_connect_failure (conn);
            }
        }
      break;

    case RECONNECT_CONNECTED:
      /* Health check */
      if (conn->policy.health_check_interval_ms > 0
          && now >= conn->last_health_check_ms
                        + conn->policy.health_check_interval_ms)
        {
          perform_health_check (conn);
        }
      break;

    default:
      break;
    }
}

/* ============================================================================
 * Health Check Configuration
 * ============================================================================
 */

void
SocketReconnect_set_health_check (T conn, SocketReconnect_HealthCheck check)
{
  assert (conn);
  conn->health_check = check;
}

/* ============================================================================
 * I/O Passthrough
 * ============================================================================
 */

ssize_t
SocketReconnect_send (T conn, const void *buf, size_t len)
{
  volatile ssize_t result = -1;

  assert (conn);
  assert (buf || len == 0);

  if (conn->state != RECONNECT_CONNECTED || !conn->socket)
    {
      errno = ENOTCONN;
      return -1;
    }

  TRY
  {
    result = socket_send_internal (conn->socket, buf, len, 0);
  }
  EXCEPT (Socket_Failed)
  {
    /* Connection error - trigger reconnect */
    int err = Socket_geterrno ();
    reconnect_set_socket_error (conn, "Send failed", err);
    close_socket (conn);
    handle_connect_failure (conn);
    errno = ENOTCONN;
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    /* Connection closed by peer */
    close_socket (conn);
    handle_connect_failure (conn);
    errno = ENOTCONN;
    return -1;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_Failed)
  {
    /* TLS error - trigger reconnect */
    reconnect_set_tls_error (conn, "TLS send failed");
    close_socket (conn);
    handle_connect_failure (conn);
    errno = ENOTCONN;
    return -1;
  }
  EXCEPT (SocketTLS_ProtocolError)
  {
    /* TLS protocol error - trigger reconnect */
    reconnect_set_tls_error (conn, "TLS protocol error");
    close_socket (conn);
    handle_connect_failure (conn);
    errno = ENOTCONN;
    return -1;
  }
#endif /* SOCKET_HAS_TLS */
  END_TRY;

  return result;
}

ssize_t
SocketReconnect_recv (T conn, void *buf, size_t len)
{
  volatile ssize_t result = 0;

  assert (conn);
  assert (buf);

  if (conn->state != RECONNECT_CONNECTED || !conn->socket)
    {
      errno = ENOTCONN;
      return -1;
    }

  TRY
  {
    result = socket_recv_internal (conn->socket, buf, len, 0);
  }
  EXCEPT (Socket_Failed)
  {
    /* Connection error - trigger reconnect */
    int err = Socket_geterrno ();
    reconnect_set_socket_error (conn, "Recv failed", err);
    close_socket (conn);
    handle_connect_failure (conn);
    return 0;
  }
  EXCEPT (Socket_Closed)
  {
    /* Connection closed by peer */
    close_socket (conn);
    handle_connect_failure (conn);
    return 0;
  }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_Failed)
  {
    /* TLS error - trigger reconnect */
    reconnect_set_tls_error (conn, "TLS recv failed");
    close_socket (conn);
    handle_connect_failure (conn);
    return 0;
  }
  EXCEPT (SocketTLS_ProtocolError)
  {
    /* TLS protocol error - trigger reconnect */
    reconnect_set_tls_error (conn, "TLS protocol error");
    close_socket (conn);
    handle_connect_failure (conn);
    return 0;
  }
#endif /* SOCKET_HAS_TLS */
  END_TRY;

  if (result == 0)
    {
      /* EOF - connection closed */
      close_socket (conn);
      handle_connect_failure (conn);
    }

  return result;
}

/* ============================================================================
 * TLS Integration Functions (Conditional)
 * ============================================================================
 */

#if SOCKET_HAS_TLS

void
SocketReconnect_set_tls (T conn, SocketTLSContext_T ctx, const char *hostname)
{
  assert (conn);
  assert (ctx);

  if (!hostname || hostname[0] == '\0')
    {
      RAISE_RECONNECT_ERROR_MSG (SocketReconnect_Failed,
                                 "TLS hostname cannot be NULL or empty");
    }

  size_t hostname_len = strlen (hostname);
  if (hostname_len > SOCKET_RECONNECT_MAX_HOST_LEN)
    {
      RAISE_RECONNECT_ERROR_MSG (SocketReconnect_Failed,
                                 "TLS hostname exceeds maximum length (%d)",
                                 SOCKET_RECONNECT_MAX_HOST_LEN);
    }

  /* Store context reference (caller retains ownership) */
  conn->tls_ctx = ctx;

  /* Copy hostname to arena for lifetime management */
  conn->tls_hostname
      = Arena_alloc (conn->arena, hostname_len + 1, __FILE__, __LINE__);
  if (!conn->tls_hostname)
    {
      conn->tls_ctx = NULL;
      RAISE_RECONNECT_ERROR_MSG (SocketReconnect_Failed,
                                 "Failed to allocate TLS hostname buffer");
    }
  memcpy (conn->tls_hostname, hostname, hostname_len + 1);

  /* Enable session resumption by default */
  conn->tls_session_resumption_enabled = 1;

  /* Reset handshake state */
  conn->tls_handshake_state = TLS_HANDSHAKE_NOT_STARTED;
  conn->tls_handshake_started = 0;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d TLS configured with hostname '%s'", conn->host,
                   conn->port, hostname);
}

void
SocketReconnect_disable_tls (T conn)
{
  assert (conn);

  if (conn->tls_ctx)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d TLS disabled", conn->host, conn->port);
    }

  conn->tls_ctx = NULL;
  conn->tls_hostname = NULL; /* Arena-allocated, freed with arena */
  conn->tls_handshake_state = TLS_HANDSHAKE_NOT_STARTED;
  conn->tls_handshake_started = 0;
  conn->tls_session_resumption_enabled = 0;

  /* Clear saved session data */
  conn->tls_session_data = NULL;
  conn->tls_session_data_len = 0;
}

int
SocketReconnect_tls_enabled (T conn)
{
  assert (conn);
  return conn->tls_ctx != NULL;
}

const char *
SocketReconnect_get_tls_hostname (T conn)
{
  assert (conn);
  return conn->tls_hostname;
}

TLSHandshakeState
SocketReconnect_tls_handshake_state (T conn)
{
  assert (conn);
  if (!conn->tls_ctx)
    return TLS_HANDSHAKE_NOT_STARTED;
  return conn->tls_handshake_state;
}

void
SocketReconnect_set_session_resumption (T conn, int enable)
{
  assert (conn);
  conn->tls_session_resumption_enabled = enable ? 1 : 0;

  if (!enable)
    {
      /* Clear saved session */
      conn->tls_session_data = NULL;
      conn->tls_session_data_len = 0;
    }
}

int
SocketReconnect_is_session_reused (T conn)
{
  assert (conn);

  if (!conn->tls_ctx || conn->state != RECONNECT_CONNECTED || !conn->socket)
    return -1;

  return SocketTLS_is_session_reused (conn->socket);
}

/**
 * save_tls_session - Save TLS session for future resumption
 * @conn: Reconnection context
 *
 * Saves the current TLS session data to the arena for use on reconnect.
 * Called after successful TLS handshake if session resumption is enabled.
 */
static void
save_tls_session (T conn)
{
  if (!conn->tls_session_resumption_enabled || !conn->socket)
    return;

  /* Query required buffer size */
  size_t required_len = 0;
  if (SocketTLS_session_save (conn->socket, NULL, &required_len) != 0)
    return; /* No session available */

  if (required_len == 0)
    return;

  /* Allocate buffer in arena */
  unsigned char *session_buf
      = Arena_alloc (conn->arena, required_len, __FILE__, __LINE__);
  if (!session_buf)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "%s:%d failed to allocate session buffer (%zu bytes)",
                       conn->host, conn->port, required_len);
      return;
    }

  /* Save session */
  size_t actual_len = required_len;
  if (SocketTLS_session_save (conn->socket, session_buf, &actual_len) == 1)
    {
      conn->tls_session_data = session_buf;
      conn->tls_session_data_len = actual_len;
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d saved TLS session (%zu bytes)", conn->host,
                       conn->port, actual_len);
    }
}

/**
 * restore_tls_session - Restore saved TLS session for resumption
 * @conn: Reconnection context
 *
 * Attempts to restore a previously saved session. Called after TLS enable
 * but before handshake.
 *
 * Returns: 1 if session restored, 0 if no session or restore failed
 */
static int
restore_tls_session (T conn)
{
  if (!conn->tls_session_resumption_enabled || !conn->tls_session_data
      || conn->tls_session_data_len == 0)
    return 0;

  int result = SocketTLS_session_restore (conn->socket, conn->tls_session_data,
                                          conn->tls_session_data_len);
  if (result == 1)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d restored TLS session for resumption", conn->host,
                       conn->port);
    }
  else
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "%s:%d TLS session restore failed (full handshake)",
                       conn->host, conn->port);
    }

  return result == 1 ? 1 : 0;
}

#endif /* SOCKET_HAS_TLS */

#undef T
