/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-pool.c
 * @brief Simple connection pool management implementation.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-pool.h"

#include "core/Arena.h"
#include "pool/SocketPool.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define SOCKET_SIMPLE_DEFAULT_BUFFER_SIZE 4096
#define SOCKET_SIMPLE_DEFAULT_MAX_CONNECTIONS 1024

/**
 * @brief Convert milliseconds to seconds, rounding up.
 * Examples: 0ms→0s, 1ms→1s, 999ms→1s, 1000ms→1s, 1001ms→2s
 */
#define MS_TO_SEC_ROUND_UP(ms) (((ms) + 999) / 1000)

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

struct SocketSimple_Pool
{
  SocketPool_T pool;
  Arena_T arena;
  int max_connections;
};

struct SocketSimple_Conn
{
  Connection_T conn;
  SocketSimple_Socket_T simple_sock; /* Cached simple socket wrapper */
};

/* ============================================================================
 * Helper: Map pool state to simple state
 * ============================================================================
 */

static SocketSimple_PoolState
core_to_simple_state (SocketPool_State state)
{
  switch (state)
    {
    case POOL_STATE_RUNNING:
      return SOCKET_SIMPLE_POOL_RUNNING;
    case POOL_STATE_DRAINING:
      return SOCKET_SIMPLE_POOL_DRAINING;
    case POOL_STATE_STOPPED:
      return SOCKET_SIMPLE_POOL_STOPPED;
    default:
      return SOCKET_SIMPLE_POOL_STOPPED;
    }
}

/* ============================================================================
 * Pool Lifecycle
 * ============================================================================
 */

void
Socket_simple_pool_options_init (SocketSimple_PoolOptions *opts)
{
  if (!opts)
    return;

  opts->max_connections = SOCKET_SIMPLE_DEFAULT_MAX_CONNECTIONS;
  opts->buffer_size = SOCKET_SIMPLE_DEFAULT_BUFFER_SIZE;
  opts->idle_timeout_ms = 0;
  opts->conn_rate_limit = 0;
  opts->max_per_ip = 0;
}

SocketSimple_Pool_T
Socket_simple_pool_new (int max_connections)
{
  SocketSimple_PoolOptions opts;
  Socket_simple_pool_options_init (&opts);
  opts.max_connections = max_connections;
  return Socket_simple_pool_new_ex (&opts);
}

SocketSimple_Pool_T
Socket_simple_pool_new_ex (const SocketSimple_PoolOptions *opts)
{
  volatile SocketPool_T pool = NULL;
  volatile Arena_T arena = NULL;

  Socket_simple_clear_error ();

  if (!opts || opts->max_connections <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid pool options or max_connections");
      return NULL;
    }

  TRY
  {
    arena = Arena_new ();
    pool = SocketPool_new (
        arena, (size_t)opts->max_connections, (size_t)opts->buffer_size);
  }
  EXCEPT (SocketPool_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POOL, "Failed to create pool");
    if (arena)
      Arena_dispose ((Arena_T *)&arena);
    return NULL;
  }
  END_TRY;

  struct SocketSimple_Pool *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      SocketPool_free ((SocketPool_T *)&pool);
      Arena_dispose ((Arena_T *)&arena);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  handle->pool = pool;
  handle->arena = arena;
  handle->max_connections = opts->max_connections;

  /* Apply optional settings */
  if (opts->conn_rate_limit > 0)
    {
      SocketPool_setconnrate (
          pool, opts->conn_rate_limit, opts->conn_rate_limit);
    }
  if (opts->max_per_ip > 0)
    {
      SocketPool_setmaxperip (pool, opts->max_per_ip);
    }
  if (opts->idle_timeout_ms > 0)
    {
      time_t timeout_sec = MS_TO_SEC_ROUND_UP (opts->idle_timeout_ms);
      SocketPool_set_idle_timeout (pool, timeout_sec);
    }

  return handle;
}

void
Socket_simple_pool_free (SocketSimple_Pool_T *pool)
{
  if (!pool || !*pool)
    return;

  struct SocketSimple_Pool *p = *pool;

  if (p->pool)
    {
      SocketPool_free (&p->pool);
    }

  if (p->arena)
    {
      Arena_dispose (&p->arena);
    }

  free (p);
  *pool = NULL;
}

/* ============================================================================
 * Connection Management
 * ============================================================================
 */

/**
 * @brief Helper: Validate pool and socket for operations
 *
 * @param pool Pool to validate
 * @param sock Socket to validate
 * @param custom_msg Custom error message for invalid socket (NULL for default)
 * @return 0 on success, -1 on validation failure
 */
static int
validate_pool_and_socket (SocketSimple_Pool_T pool,
                          SocketSimple_Socket_T sock,
                          const char *custom_msg)
{
  if (!pool || !sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid pool or socket");
      return -1;
    }

  if (!sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        custom_msg ? custom_msg : "Invalid socket");
      return -1;
    }

  return 0;
}

SocketSimple_Conn_T
Socket_simple_pool_add (SocketSimple_Pool_T pool, SocketSimple_Socket_T sock)
{
  volatile Connection_T conn = NULL;

  Socket_simple_clear_error ();

  if (validate_pool_and_socket (pool, sock, "UDP sockets not supported in pool")
      != 0)
    return NULL;

  TRY
  {
    conn = SocketPool_add (pool->pool, sock->socket);
  }
  EXCEPT (SocketPool_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POOL, "Failed to add socket to pool");
    return NULL;
  }
  END_TRY;

  if (!conn)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POOL_FULL, "Pool is full");
      return NULL;
    }

  /* Create wrapper */
  struct SocketSimple_Conn *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      SocketPool_remove (pool->pool, sock->socket);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  handle->conn = conn;
  handle->simple_sock = sock;

  /* Store the simple conn handle as user data for later retrieval */
  Connection_setdata (conn, handle);

  return handle;
}

SocketSimple_Conn_T
Socket_simple_pool_get (SocketSimple_Pool_T pool, SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (validate_pool_and_socket (pool, sock, NULL) != 0)
    return NULL;

  Connection_T conn = SocketPool_get (pool->pool, sock->socket);
  if (!conn)
    {
      return NULL; /* Not found, not an error */
    }

  /* Return the simple conn handle stored as user data */
  return (SocketSimple_Conn_T)Connection_data (conn);
}

int
Socket_simple_pool_remove (SocketSimple_Pool_T pool, SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (validate_pool_and_socket (pool, sock, NULL) != 0)
    return -1;

  /* Get the simple conn handle to free it */
  Connection_T conn = SocketPool_get (pool->pool, sock->socket);
  if (conn)
    {
      struct SocketSimple_Conn *handle
          = (struct SocketSimple_Conn *)Connection_data (conn);
      if (handle)
        {
          free (handle);
        }
    }

  SocketPool_remove (pool->pool, sock->socket);

  return 0;
}

int
Socket_simple_pool_cleanup (SocketSimple_Pool_T pool, int max_idle_ms)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  time_t idle_timeout = MS_TO_SEC_ROUND_UP (max_idle_ms);
  SocketPool_cleanup (pool->pool, idle_timeout);

  return 0;
}

/* ============================================================================
 * Accept with Rate Limiting - Helper Functions
 * ============================================================================
 */

/**
 * @brief Validate listener socket for accept operations.
 * @param pool Pool instance
 * @param listener Listener socket to validate
 * @return 0 on success, -1 on error (sets simple error)
 */
static int
validate_listener_for_accept (SocketSimple_Pool_T pool,
                              SocketSimple_Socket_T listener)
{
  if (!pool || !listener)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid pool or listener");
      return -1;
    }

  if (!listener->socket || !listener->is_server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid listener socket");
      return -1;
    }

  return 0;
}

/**
 * @brief Create simple wrapper and add accepted socket to pool.
 * @param pool Pool instance
 * @param client Accepted client socket
 * @return Connection handle on success, NULL on error (sets simple error)
 */
static SocketSimple_Conn_T
wrap_and_add_to_pool (SocketSimple_Pool_T pool, Socket_T client)
{
  SocketSimple_Socket_T simple_sock = simple_create_handle (client, 0, 0);
  if (!simple_sock)
    {
      Socket_free ((Socket_T *)&client);
      return NULL;
    }

  SocketSimple_Conn_T conn = Socket_simple_pool_add (pool, simple_sock);
  if (!conn)
    {
      Socket_simple_close (&simple_sock);
      return NULL;
    }

  return conn;
}

/* ============================================================================
 * Accept with Rate Limiting - Public Functions
 * ============================================================================
 */

SocketSimple_Conn_T
Socket_simple_pool_accept (SocketSimple_Pool_T pool,
                           SocketSimple_Socket_T listener)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (validate_listener_for_accept (pool, listener) != 0)
    return NULL;

  TRY
  {
    client = Socket_accept (listener->socket);
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    return NULL;
  }
  END_TRY;

  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_ACCEPT, "Accept returned NULL");
      return NULL;
    }

  return wrap_and_add_to_pool (pool, client);
}

SocketSimple_Conn_T
Socket_simple_pool_accept_limited (SocketSimple_Pool_T pool,
                                   SocketSimple_Socket_T listener)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (validate_listener_for_accept (pool, listener) != 0)
    return NULL;

  /* Check pool state */
  if (SocketPool_is_draining (pool->pool))
    {
      simple_set_error (SOCKET_SIMPLE_ERR_POOL_DRAINING, "Pool is draining");
      return NULL;
    }

  /* Use rate-limited accept */
  TRY
  {
    client = SocketPool_accept_limited (pool->pool, listener->socket);
  }
  EXCEPT (SocketPool_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_POOL, "Rate limited accept failed");
    return NULL;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    return NULL;
  }
  END_TRY;

  if (!client)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_RATELIMIT, "Rate limit exceeded");
      return NULL;
    }

  return wrap_and_add_to_pool (pool, client);
}

/* ============================================================================
 * Rate Limiting Configuration
 * ============================================================================
 */

int
Socket_simple_pool_set_conn_rate (SocketSimple_Pool_T pool, int conns_per_sec)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  SocketPool_setconnrate (pool->pool, conns_per_sec, conns_per_sec);
  return 0;
}

int
Socket_simple_pool_set_max_per_ip (SocketSimple_Pool_T pool, int max)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  SocketPool_setmaxperip (pool->pool, max);
  return 0;
}

/* ============================================================================
 * Graceful Shutdown (Drain)
 * ============================================================================
 */

int
Socket_simple_pool_drain (SocketSimple_Pool_T pool, int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  SocketPool_drain (pool->pool, timeout_ms);
  return 0;
}

int
Socket_simple_pool_drain_poll (SocketSimple_Pool_T pool)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  return SocketPool_drain_poll (pool->pool);
}

int
Socket_simple_pool_drain_wait (SocketSimple_Pool_T pool, int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  int result = SocketPool_drain_wait (pool->pool, timeout_ms);
  return (result == 0) ? 1 : 0;
}

SocketSimple_PoolState
Socket_simple_pool_state (SocketSimple_Pool_T pool)
{
  if (!pool)
    return SOCKET_SIMPLE_POOL_STOPPED;

  return core_to_simple_state (SocketPool_state (pool->pool));
}

/* ============================================================================
 * Statistics
 * ============================================================================
 */

int
Socket_simple_pool_get_stats (SocketSimple_Pool_T pool,
                              SocketSimple_PoolStats *stats)
{
  Socket_simple_clear_error ();

  if (!pool || !stats)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool or stats");
      return -1;
    }

  SocketPool_Stats core_stats;
  SocketPool_get_stats (pool->pool, &core_stats);

  stats->active_connections = (int)core_stats.current_active;
  stats->total_accepted = (int)core_stats.total_added;
  stats->total_rejected = (int)core_stats.total_validation_failures;
  stats->total_closed = (int)core_stats.total_removed;
  stats->hit_rate = core_stats.reuse_rate;
  stats->bytes_in = 0;  /* Not tracked by core pool */
  stats->bytes_out = 0; /* Not tracked by core pool */

  return 0;
}

int
Socket_simple_pool_count (SocketSimple_Pool_T pool)
{
  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  return (int)SocketPool_count (pool->pool);
}

int
Socket_simple_pool_reset_stats (SocketSimple_Pool_T pool)
{
  Socket_simple_clear_error ();

  if (!pool)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid pool");
      return -1;
    }

  SocketPool_reset_stats (pool->pool);
  return 0;
}

/* ============================================================================
 * Connection Accessors
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_conn_socket (SocketSimple_Conn_T conn)
{
  if (!conn)
    return NULL;

  return conn->simple_sock;
}

void *
Socket_simple_conn_data (SocketSimple_Conn_T conn)
{
  if (!conn || !conn->conn)
    return NULL;

  /* User data is stored in the simple conn wrapper, not core connection
   * since we use core connection's data for our own wrapper pointer.
   * For simplicity, we don't support user data on simple connections yet. */
  return NULL;
}

int
Socket_simple_conn_set_data (SocketSimple_Conn_T conn, void *data)
{
  (void)conn;
  (void)data;
  /* Not implemented - core connection data is used for our wrapper */
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "User data on pool connections not supported");
  return -1;
}

uint64_t
Socket_simple_conn_last_activity (SocketSimple_Conn_T conn)
{
  if (!conn || !conn->conn)
    return 0;

  return (uint64_t)Connection_lastactivity (conn->conn);
}

int
Socket_simple_conn_is_active (SocketSimple_Conn_T conn)
{
  if (!conn || !conn->conn)
    return 0;

  return Connection_isactive (conn->conn);
}

int
Socket_simple_conn_peer_ip (SocketSimple_Conn_T conn, char *buf, size_t len)
{
  Socket_simple_clear_error ();

  if (!conn || !conn->conn || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid connection or buffer");
      return -1;
    }

  Socket_T sock = Connection_socket (conn->conn);
  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  const char *peer = Socket_getpeeraddr (sock);
  if (!peer)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "Failed to get peer address");
      return -1;
    }

  strncpy (buf, peer, len - 1);
  buf[len - 1] = '\0';

  return 0;
}
