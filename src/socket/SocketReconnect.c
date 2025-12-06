/**
 * SocketReconnect.c - Automatic Reconnection Framework Implementation
 *
 * Part of the Socket Library
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

#include "socket/SocketReconnect.h"
#include "socket/SocketReconnect-private.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* ============================================================================
 * State Names
 * ============================================================================ */

static const char *state_names[] = {
  "DISCONNECTED",
  "CONNECTING",
  "CONNECTED",
  "BACKOFF",
  "CIRCUIT_OPEN"
};

const char *
SocketReconnect_state_name (SocketReconnect_State state)
{
  if (state >= 0 && state <= RECONNECT_CIRCUIT_OPEN)
    return state_names[state];
  return "UNKNOWN";
}

/* ============================================================================
 * Policy Defaults
 * ============================================================================ */

void
SocketReconnect_policy_defaults (SocketReconnect_Policy_T *policy)
{
  assert (policy);
  policy->initial_delay_ms = SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS;
  policy->max_delay_ms = SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS;
  policy->multiplier = SOCKET_RECONNECT_DEFAULT_MULTIPLIER;
  policy->jitter = SOCKET_RECONNECT_DEFAULT_JITTER;
  policy->max_attempts = SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS;
  policy->circuit_failure_threshold = SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD;
  policy->circuit_reset_timeout_ms = SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS;
  policy->health_check_interval_ms = SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS;
  policy->health_check_timeout_ms = SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS;
}

/* ============================================================================
 * Internal State Machine Helpers
 * ============================================================================ */

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
  conn->state_start_time_ms = socketreconnect_get_time_ms ();

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d state transition: %s -> %s",
                   conn->host, conn->port,
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

  /* Cap at max delay */
  if (delay > (double)conn->policy.max_delay_ms)
    delay = (double)conn->policy.max_delay_ms;

  /* Add jitter: delay * (1 + jitter * (2*random - 1)) */
  if (conn->policy.jitter > 0.0)
    {
      double jitter_range = delay * conn->policy.jitter;
      double jitter_offset
          = jitter_range * (2.0 * socketreconnect_random_double () - 1.0);
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
          SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
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
          conn->circuit_open_time_ms = socketreconnect_get_time_ms ();
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "%s:%d circuit breaker reopened after probe failure",
                           conn->host, conn->port);
        }
      else if (conn->consecutive_failures >= conn->policy.circuit_failure_threshold
               && conn->circuit_state == CIRCUIT_CLOSED)
        {
          /* Too many failures, open circuit */
          conn->circuit_state = CIRCUIT_OPEN;
          conn->circuit_open_time_ms = socketreconnect_get_time_ms ();
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
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
      int64_t elapsed = socketreconnect_elapsed_ms (conn->circuit_open_time_ms);
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
 */
static void
close_socket (T conn)
{
  if (conn->socket)
    {
      Socket_free (&conn->socket);
      conn->socket = NULL;
    }
  conn->connect_in_progress = 0;
}

/* ============================================================================
 * Connection Handling
 * ============================================================================ */

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
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "%s:%d %s", conn->host, conn->port, conn->error_buf);
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

  /* Create new socket */
  TRY
  {
    conn->socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    snprintf (conn->error_buf, sizeof (conn->error_buf), /* LCOV_EXCL_LINE */
              "Failed to create socket: %s", strerror (Socket_geterrno ())); /* LCOV_EXCL_LINE */
    conn->last_error = Socket_geterrno (); /* LCOV_EXCL_LINE */
    return 0; /* LCOV_EXCL_LINE */
  }
  END_TRY;

  if (!conn->socket)
    return 0;

  /* Set non-blocking for async connect */
  fd = Socket_fd (conn->socket);
  flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      conn->last_error = errno; /* LCOV_EXCL_LINE */
      close_socket (conn); /* LCOV_EXCL_LINE */
      return 0; /* LCOV_EXCL_LINE */
    }

  /* Update attempt tracking */
  conn->attempt_count++;
  conn->total_attempts++;
  conn->last_attempt_time_ms = socketreconnect_get_time_ms ();

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d starting connection attempt %d",
                   conn->host, conn->port, conn->attempt_count);

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
    /* LCOV_EXCL_START - requires non-routable address for async connect */
    if (Socket_geterrno () == EINPROGRESS || Socket_geterrno () == EINTR)
      {
        conn->connect_in_progress = 1;
        return 1;
      }
    /* LCOV_EXCL_STOP */

    /* Real failure */
    snprintf (conn->error_buf, sizeof (conn->error_buf),
              "Connect failed: %s", strerror (Socket_geterrno ()));
    conn->last_error = Socket_geterrno ();
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
      conn->last_error = errno;
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
      conn->last_error = error ? error : ECONNREFUSED;
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Connect failed: %s", strerror (conn->last_error));
      return -1;
    }

  /* Check SO_ERROR */
  error = 0;
  len = sizeof (error);
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
      conn->last_error = errno;
      return -1;
    }

  if (error != 0)
    {
      conn->last_error = error;
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Connect failed: %s", strerror (error));
      return -1;
    }

  /* Success! Restore blocking mode */
  int flags = fcntl (fd, F_GETFL);
  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);

  conn->connect_in_progress = 0;
  return 1;
}
/* LCOV_EXCL_STOP */

/**
 * handle_connect_success - Process successful connection
 * @conn: Reconnection context
 */
static void
handle_connect_success (T conn)
{
  conn->consecutive_failures = 0;
  conn->attempt_count = 0;
  conn->total_successes++;
  conn->last_success_time_ms = socketreconnect_get_time_ms ();
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
                   "%s:%d connection attempt %d failed: %s",
                   conn->host, conn->port, conn->attempt_count,
                   conn->error_buf);

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
  conn->backoff_until_ms = socketreconnect_get_time_ms ()
                           + conn->current_backoff_delay_ms;

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "%s:%d backing off for %d ms",
                   conn->host, conn->port, conn->current_backoff_delay_ms);

  transition_state (conn, RECONNECT_BACKOFF);
}

/* ============================================================================
 * Health Check
 * ============================================================================ */

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
default_health_check (T conn, Socket_T socket, void *userdata)
{
  struct pollfd pfd;
  int fd, result;
  char buf;

  (void)conn;
  (void)userdata;

  if (!socket)
    return 0;

  fd = Socket_fd (socket);
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  result = poll (&pfd, 1, 0);
  if (result < 0)
    return errno == EINTR ? 1 : 0;

  if (result == 0)
    return 1; /* No data, but that's OK */

  /* Check for error conditions */
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return 0;

  /* If readable, peek to check for EOF */
  if (pfd.revents & POLLIN)
    {
      result = recv (fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
      if (result == 0)
        return 0; /* EOF - disconnected */
      if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return 0; /* Error */
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
  healthy = check (conn, conn->socket, conn->userdata);

  conn->last_health_check_ms = socketreconnect_get_time_ms ();

  if (!healthy)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "%s:%d health check failed, reconnecting",
                       conn->host, conn->port);
      close_socket (conn);
      handle_connect_failure (conn);
    }
}

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================ */

T
SocketReconnect_new (const char *host, int port,
                     const SocketReconnect_Policy_T *policy,
                     SocketReconnect_Callback callback, void *userdata)
{
  T conn;
  size_t host_len;

  assert (host);
  assert (port > 0 && port <= 65535);

  conn = calloc (1, sizeof (*conn));
  if (!conn)
    {
      SOCKET_ERROR_MSG ("Failed to allocate reconnection context"); /* LCOV_EXCL_LINE */
      RAISE_MODULE_ERROR (SocketReconnect_Failed); /* LCOV_EXCL_LINE */
    }

  conn->arena = Arena_new ();
  if (!conn->arena)
    {
      free (conn); /* LCOV_EXCL_LINE */
      SOCKET_ERROR_MSG ("Failed to create arena for reconnection context"); /* LCOV_EXCL_LINE */
      RAISE_MODULE_ERROR (SocketReconnect_Failed); /* LCOV_EXCL_LINE */
    }

  /* Copy configuration */
  if (policy)
    conn->policy = *policy;
  else
    SocketReconnect_policy_defaults (&conn->policy);

  /* Copy hostname with length validation */
  host_len = strlen (host) + 1;
  if (host_len > SOCKET_ERROR_MAX_HOSTNAME + 1)
    {
      Arena_dispose (&conn->arena);
      free (conn);
      SOCKET_ERROR_FMT ("Hostname too long (%zu > %d max)",
                        host_len - 1, SOCKET_ERROR_MAX_HOSTNAME);
      RAISE_MODULE_ERROR (SocketReconnect_Failed);
    }

  conn->host = Arena_alloc (conn->arena, host_len, __FILE__, __LINE__);
  if (!conn->host)
    {
      Arena_dispose (&conn->arena); /* LCOV_EXCL_LINE */
      free (conn); /* LCOV_EXCL_LINE */
      SOCKET_ERROR_MSG ("Failed to allocate hostname"); /* LCOV_EXCL_LINE */
      RAISE_MODULE_ERROR (SocketReconnect_Failed); /* LCOV_EXCL_LINE */
    }
  memcpy (conn->host, host, host_len);
  conn->port = port;

  /* Set callbacks */
  conn->callback = callback;
  conn->userdata = userdata;

  /* Initialize state */
  conn->state = RECONNECT_DISCONNECTED;
  conn->circuit_state = CIRCUIT_CLOSED;
  conn->state_start_time_ms = socketreconnect_get_time_ms ();

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
 * ============================================================================ */

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

  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                   "%s:%d disconnected", conn->host, conn->port);
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
                   "%s:%d reset backoff and circuit breaker state",
                   conn->host, conn->port);
}

/* ============================================================================
 * Socket Access
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
  if (conn->state == RECONNECT_CONNECTING && conn->connect_in_progress)
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
    }
  /* LCOV_EXCL_STOP */
}

int
SocketReconnect_next_timeout_ms (T conn)
{
  int64_t now, remaining;
  int timeout = -1;

  assert (conn);

  now = socketreconnect_get_time_ms ();

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
                   + conn->policy.circuit_reset_timeout_ms) - now;
      if (remaining <= 0)
        return 0;
      timeout = (int)remaining;
      break;

    case RECONNECT_CONNECTED:
      /* Health check timer */
      if (conn->policy.health_check_interval_ms > 0)
        {
          remaining = (conn->last_health_check_ms
                       + conn->policy.health_check_interval_ms) - now;
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

  now = socketreconnect_get_time_ms ();

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
      if (now >= conn->circuit_open_time_ms + conn->policy.circuit_reset_timeout_ms)
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
          && now >= conn->last_health_check_ms + conn->policy.health_check_interval_ms)
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
 * ============================================================================ */

void
SocketReconnect_set_health_check (T conn, SocketReconnect_HealthCheck check)
{
  assert (conn);
  conn->health_check = check;
}

/* ============================================================================
 * I/O Passthrough
 * ============================================================================ */

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

  TRY { result = Socket_send (conn->socket, buf, len); }
  EXCEPT (Socket_Failed)
  {
    /* Connection error - trigger reconnect */
    conn->last_error = Socket_geterrno ();
    snprintf (conn->error_buf, sizeof (conn->error_buf),
              "Send failed: %s", strerror (Socket_geterrno ()));
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

  TRY { result = Socket_recv (conn->socket, buf, len); }
  EXCEPT (Socket_Failed)
  {
    /* Connection error - trigger reconnect */
    conn->last_error = Socket_geterrno ();
    snprintf (conn->error_buf, sizeof (conn->error_buf),
              "Recv failed: %s", strerror (Socket_geterrno ()));
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
  END_TRY;

  if (result == 0)
    {
      /* EOF - connection closed */
      close_socket (conn);
      handle_connect_failure (conn);
    }

  return result;
}

#undef T

