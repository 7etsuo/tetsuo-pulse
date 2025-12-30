/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-reconnect.c
 * @brief Automatic reconnection implementation for Simple API.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-reconnect.h"

#include "socket/SocketReconnect.h"

/*============================================================================
 * Internal Structure
 *============================================================================*/

struct SocketSimple_Reconnect
{
  SocketReconnect_T core;
  SocketSimple_Reconnect_Callback user_callback;
  void *user_data;
  SocketSimple_Socket_T simple_socket; /* Wrapper for underlying socket */
};

/*============================================================================
 * Internal Callback Wrapper
 *============================================================================*/

static void
state_callback_wrapper (SocketReconnect_T core __attribute__ ((unused)),
                         SocketReconnect_State old_state,
                         SocketReconnect_State new_state, void *userdata)
{
  struct SocketSimple_Reconnect *conn
      = (struct SocketSimple_Reconnect *)userdata;
  if (conn && conn->user_callback)
    {
      conn->user_callback (conn, (SocketSimple_Reconnect_State)old_state,
                           (SocketSimple_Reconnect_State)new_state,
                           conn->user_data);
    }
}

/*============================================================================
 * Policy Helpers
 *============================================================================*/

/**
 * @brief Map Simple API policy to Core API policy.
 *
 * Translates field names from the simpler Simple API to the more verbose
 * Core API names. This centralizes the API translation logic.
 *
 * @param core Core policy structure to populate.
 * @param simple Simple policy to translate.
 */
static void
map_policy_to_core (SocketReconnect_Policy_T *core,
                    const SocketSimple_Reconnect_Policy *simple)
{
  core->initial_delay_ms = simple->initial_delay_ms;
  core->max_delay_ms = simple->max_delay_ms;
  core->multiplier = simple->multiplier;
  core->jitter = simple->jitter;
  core->max_attempts = simple->max_attempts;
  core->circuit_failure_threshold = simple->circuit_threshold;
  core->circuit_reset_timeout_ms = simple->circuit_reset_ms;
  core->health_check_interval_ms = simple->health_interval_ms;
  core->health_check_timeout_ms = simple->health_timeout_ms;
}

void
Socket_simple_reconnect_policy_defaults (SocketSimple_Reconnect_Policy *policy)
{
  if (!policy)
    return;

  policy->initial_delay_ms = 100;
  policy->max_delay_ms = 30000;
  policy->multiplier = 2.0;
  policy->jitter = 0.25;
  policy->max_attempts = 10;
  policy->circuit_threshold = 5;
  policy->circuit_reset_ms = 60000;
  policy->health_interval_ms = 30000;
  policy->health_timeout_ms = 5000;
}

/*============================================================================
 * Lifecycle Functions
 *============================================================================*/

SocketSimple_Reconnect_T
Socket_simple_reconnect_new (const char *host, int port,
                              const SocketSimple_Reconnect_Policy *policy)
{
  volatile SocketReconnect_T core = NULL;

  Socket_simple_clear_error ();

  if (!host || host[0] == '\0')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid host");
      return NULL;
    }

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  struct SocketSimple_Reconnect *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  /* Build core policy */
  SocketReconnect_Policy_T core_policy;
  SocketReconnect_policy_defaults (&core_policy);

  if (policy)
    {
      map_policy_to_core (&core_policy, policy);
    }

  TRY
  {
    core = SocketReconnect_new (host, port, &core_policy,
                                 state_callback_wrapper, handle);
    handle->core = core;
  }
  EXCEPT (SocketReconnect_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT,
                      "Failed to create reconnect handle");
    free (handle);
    return NULL;
  }
  END_TRY;

  return handle;
}

void
Socket_simple_reconnect_free (SocketSimple_Reconnect_T *conn)
{
  if (!conn || !*conn)
    return;

  struct SocketSimple_Reconnect *c = *conn;

  if (c->simple_socket)
    {
      /* Don't free socket - it's owned by core */
      c->simple_socket->socket = NULL;
      free (c->simple_socket);
    }

  if (c->core)
    {
      SocketReconnect_free (&c->core);
    }

  free (c);
  *conn = NULL;
}

/*============================================================================
 * Connection Control
 *============================================================================*/

int
Socket_simple_reconnect_connect (SocketSimple_Reconnect_T conn)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  TRY { SocketReconnect_connect (conn->core); }
  EXCEPT (SocketReconnect_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CONNECT, "Connect failed");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_reconnect_disconnect (SocketSimple_Reconnect_T conn)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  SocketReconnect_disconnect (conn->core);
  return 0;
}

int
Socket_simple_reconnect_reset (SocketSimple_Reconnect_T conn)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  SocketReconnect_reset (conn->core);
  return 0;
}

/*============================================================================
 * State Query
 *============================================================================*/

SocketSimple_Reconnect_State
Socket_simple_reconnect_state (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return SIMPLE_RECONNECT_DISCONNECTED;

  return (SocketSimple_Reconnect_State)SocketReconnect_state (conn->core);
}

const char *
Socket_simple_reconnect_state_name (SocketSimple_Reconnect_State state)
{
  switch (state)
    {
    case SIMPLE_RECONNECT_DISCONNECTED:
      return "disconnected";
    case SIMPLE_RECONNECT_CONNECTING:
      return "connecting";
    case SIMPLE_RECONNECT_CONNECTED:
      return "connected";
    case SIMPLE_RECONNECT_BACKOFF:
      return "backoff";
    case SIMPLE_RECONNECT_CIRCUIT_OPEN:
      return "circuit_open";
    default:
      return "unknown";
    }
}

int
Socket_simple_reconnect_is_connected (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return 0;

  return SocketReconnect_isconnected (conn->core);
}

int
Socket_simple_reconnect_attempts (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return 0;

  return SocketReconnect_attempts (conn->core);
}

int
Socket_simple_reconnect_failures (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return 0;

  return SocketReconnect_failures (conn->core);
}

/*============================================================================
 * Event Loop Integration
 *============================================================================*/

int
Socket_simple_reconnect_fd (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return -1;

  return SocketReconnect_pollfd (conn->core);
}

int
Socket_simple_reconnect_next_timeout (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return -1;

  return SocketReconnect_next_timeout_ms (conn->core);
}

int
Socket_simple_reconnect_tick (SocketSimple_Reconnect_T conn)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  SocketReconnect_tick (conn->core);
  return 0;
}

int
Socket_simple_reconnect_process (SocketSimple_Reconnect_T conn)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  SocketReconnect_process (conn->core);
  return 0;
}

/*============================================================================
 * Passthrough I/O
 *============================================================================*/

ssize_t
Socket_simple_reconnect_send (SocketSimple_Reconnect_T conn, const void *data,
                               size_t len)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  if (!data && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid data");
      return -1;
    }

  ssize_t n = SocketReconnect_send (conn->core, data, len);
  if (n < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "Send failed");
    }

  return n;
}

ssize_t
Socket_simple_reconnect_recv (SocketSimple_Reconnect_T conn, void *buf,
                               size_t len)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  if (!buf && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  ssize_t n = SocketReconnect_recv (conn->core, buf, len);
  if (n < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "Receive failed");
    }

  return n;
}

/*============================================================================
 * Configuration
 *============================================================================*/

int
Socket_simple_reconnect_set_callback (SocketSimple_Reconnect_T conn,
                                       SocketSimple_Reconnect_Callback callback,
                                       void *userdata)
{
  Socket_simple_clear_error ();

  if (!conn)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  conn->user_callback = callback;
  conn->user_data = userdata;
  return 0;
}

int
Socket_simple_reconnect_set_health_check (
    SocketSimple_Reconnect_T conn, SocketSimple_Reconnect_HealthCheck check)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->core)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid handle");
      return -1;
    }

  /* Note: Custom health check integration requires internal wrapper.
   * For now, just allow disabling by passing NULL. */
  if (check)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                        "Custom health checks not yet supported");
      return -1;
    }

  SocketReconnect_set_health_check (conn->core, NULL);
  return 0;
}

/*============================================================================
 * Underlying Socket Access
 *============================================================================*/

SocketSimple_Socket_T
Socket_simple_reconnect_get_socket (SocketSimple_Reconnect_T conn)
{
  if (!conn || !conn->core)
    return NULL;

  Socket_T core_sock = SocketReconnect_socket (conn->core);
  if (!core_sock)
    return NULL;

  /* Create/update wrapper if needed */
  if (!conn->simple_socket)
    {
      conn->simple_socket = calloc (1, sizeof (struct SocketSimple_Socket));
      if (!conn->simple_socket)
        return NULL;
    }

  conn->simple_socket->socket = core_sock;
  conn->simple_socket->is_connected = 1;

  return conn->simple_socket;
}
