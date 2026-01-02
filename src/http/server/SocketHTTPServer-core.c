/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTPServer-core.c - Server lifecycle, configuration, and event loop */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/SocketIPTracker.h"
#include "core/SocketMetrics.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTPServer-private.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#endif

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HTTPServer-Core"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTPServer);

/* ============================================================================
 * Server Lifecycle
 * ========================================================================= */

void
SocketHTTPServer_config_defaults (SocketHTTPServer_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));

  config->port = HTTPSERVER_DEFAULT_PORT;
  config->bind_address = HTTPSERVER_DEFAULT_BIND_ADDR;
  config->backlog = HTTPSERVER_DEFAULT_BACKLOG;

  config->tls_context = NULL;

  config->max_version = HTTP_VERSION_2;
  config->enable_h2c_upgrade = HTTPSERVER_DEFAULT_ENABLE_H2C_UPGRADE;

  config->max_header_size = HTTPSERVER_DEFAULT_MAX_HEADER_SIZE;
  config->max_body_size = HTTPSERVER_DEFAULT_MAX_BODY_SIZE;
  config->request_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS;
  config->keepalive_timeout_ms = HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS;
  config->request_read_timeout_ms = HTTPSERVER_DEFAULT_REQUEST_READ_TIMEOUT_MS;
  config->response_write_timeout_ms
      = HTTPSERVER_DEFAULT_RESPONSE_WRITE_TIMEOUT_MS;
  config->tls_handshake_timeout_ms
      = HTTPSERVER_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS;
  config->max_connection_lifetime_ms
      = HTTPSERVER_DEFAULT_MAX_CONNECTION_LIFETIME_MS;
  config->max_connections = HTTPSERVER_DEFAULT_MAX_CONNECTIONS;
  config->max_requests_per_connection
      = HTTPSERVER_DEFAULT_MAX_REQUESTS_PER_CONN;
  config->max_connections_per_client
      = HTTPSERVER_DEFAULT_MAX_CONNECTIONS_PER_CLIENT;
  config->max_concurrent_requests = HTTPSERVER_DEFAULT_MAX_CONCURRENT_REQUESTS;

  SocketWS_config_defaults (&config->ws_config);
  config->ws_config.role = WS_ROLE_SERVER;

  config->per_server_metrics = 0;
}

SocketHTTPServer_T
SocketHTTPServer_new (const SocketHTTPServer_Config *config)
{
  SocketHTTPServer_T server;
  SocketHTTPServer_Config default_config;
  Arena_T arena;

  if (config == NULL)
    {
      SocketHTTPServer_config_defaults (&default_config);
      config = &default_config;
    }

  server = malloc (sizeof (*server));
  if (server == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate server structure");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  arena = Arena_new ();
  if (arena == NULL)
    {
      free (server);
      HTTPSERVER_ERROR_MSG ("Failed to create server arena");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  memset (server, 0, sizeof (*server));
  server->arena = arena;
  server->config = *config;
  server->state = HTTPSERVER_STATE_RUNNING;

  /* Initialize per-server stats mutex */
  if (pthread_mutex_init (&server->stats_mutex, NULL) != 0)
    {
      /* Log error but continue - fallback to no RPS calc */
      SOCKET_LOG_WARN_MSG ("Failed to init HTTPServer stats mutex");
    }

  /* Create poll instance */
  server->poll = SocketPoll_new ((int)config->max_connections + 1);
  if (server->poll == NULL)
    {
      Arena_dispose (&arena);
      free (server);
      HTTPSERVER_ERROR_MSG ("Failed to create poll instance");
      RAISE_HTTPSERVER_ERROR (SocketHTTPServer_Failed);
    }

  /* Create IP tracker for per-client limits */
  if (config->max_connections_per_client > 0)
    {
      server->ip_tracker
          = SocketIPTracker_new (arena, config->max_connections_per_client);
    }

  return server;
}

void
SocketHTTPServer_free (SocketHTTPServer_T *server)
{
  if (server == NULL || *server == NULL)
    return;

  SocketHTTPServer_T s = *server;

  SocketHTTPServer_stop (s);

  while (s->connections != NULL)
    {
      connection_close (s, s->connections);
    }

  /* Free any connections that were closed but deferred deletion */
  connection_free_pending (s);

  /* Free rate limit entries */
  RateLimitEntry *e = s->rate_limiters;
  while (e != NULL)
    {
      RateLimitEntry *next = e->next;
      free (e->path_prefix);
      free (e);
      e = next;
    }

  /* Free static route entries */
  StaticRoute *sr = s->static_routes;
  while (sr != NULL)
    {
      StaticRoute *next = sr->next;
      free (sr->prefix);
      free (sr->directory);
      free (sr->resolved_directory);
      free (sr);
      sr = next;
    }

  if (s->ip_tracker != NULL)
    {
      SocketIPTracker_free (&s->ip_tracker);
    }

  if (s->poll != NULL)
    {
      SocketPoll_free (&s->poll);
    }

  if (s->listen_socket != NULL)
    {
      Socket_free (&s->listen_socket);
    }

  if (s->arena != NULL)
    {
      Arena_dispose (&s->arena);
    }

  /* Destroy stats mutex */
  pthread_mutex_destroy (&s->stats_mutex);

  free (s);
  *server = NULL;
}

static int
is_ipv6_address (const char *addr)
{
  struct in6_addr dummy;
  return inet_pton (AF_INET6, addr, &dummy) == 1;
}

int
SocketHTTPServer_start (SocketHTTPServer_T server)
{
  const char *volatile bind_addr;
  volatile int socket_family;

  assert (server != NULL);

  if (server->running)
    return 0;

  bind_addr = server->config.bind_address;
  if (bind_addr == NULL || strcmp (bind_addr, "") == 0)
    {
      bind_addr = "::";
      socket_family = AF_INET6;
    }
  else if (inet_pton (AF_INET, bind_addr, &(struct in_addr){ 0 }) == 1)
    {
      socket_family = AF_INET;
    }
  else if (is_ipv6_address (bind_addr))
    {
      socket_family = AF_INET6;
    }
  else
    {
      socket_family = AF_INET6;
    }

  server->listen_socket = Socket_new (socket_family, SOCK_STREAM, 0);
  if (server->listen_socket == NULL && socket_family == AF_INET6)
    {
      socket_family = AF_INET;
      server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
      if (bind_addr && strcmp (bind_addr, "::") == 0)
        bind_addr = "0.0.0.0";
    }

  if (server->listen_socket == NULL)
    {
      HTTPSERVER_ERROR_FMT ("Failed to create listen socket");
      return -1;
    }

  Socket_setreuseaddr (server->listen_socket);

#ifdef AF_INET6
  if (socket_family == AF_INET6)
    {
      int v6only = 0;
      if (setsockopt (Socket_fd (server->listen_socket),
                      IPPROTO_IPV6,
                      IPV6_V6ONLY,
                      &v6only,
                      sizeof (v6only))
          < 0)
        {
          HTTPSERVER_ERROR_MSG ("Failed to disable IPv6-only mode: %s",
                                strerror (errno));
        }
    }
#endif

  TRY
  {
    Socket_bind (server->listen_socket, bind_addr, server->config.port);
  }
  EXCEPT (Socket_Failed)
  {
    if (socket_family == AF_INET6 && strcmp (bind_addr, "::") == 0)
      {
        TRY
        {
          Socket_bind (server->listen_socket, "0.0.0.0", server->config.port);
        }
        EXCEPT (Socket_Failed)
        {
          Socket_free (&server->listen_socket);
          HTTPSERVER_ERROR_FMT ("Failed to bind to port %d",
                                server->config.port);
          return -1;
        }
        END_TRY;
      }
    else
      {
        Socket_free (&server->listen_socket);
        HTTPSERVER_ERROR_FMT (
            "Failed to bind to %s:%d", bind_addr, server->config.port);
        return -1;
      }
  }
  END_TRY;

  Socket_listen (server->listen_socket, server->config.backlog);
  Socket_setnonblocking (server->listen_socket);

  SocketPoll_add (server->poll, server->listen_socket, POLL_READ, NULL);

  server->running = 1;
  server->state = HTTPSERVER_STATE_RUNNING;
  return 0;
}

void
SocketHTTPServer_stop (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (!server->running)
    return;

  if (server->listen_socket != NULL)
    {
      SocketPoll_del (server->poll, server->listen_socket);
    }

  server->running = 0;
}

/* ============================================================================
 * Handler & Configuration Registration
 * ========================================================================= */

void
SocketHTTPServer_set_handler (SocketHTTPServer_T server,
                              SocketHTTPServer_Handler handler,
                              void *userdata)
{
  assert (server != NULL);
  server->handler = handler;
  server->handler_userdata = userdata;
}

void
SocketHTTPServer_set_rate_limit (SocketHTTPServer_T server,
                                 const char *path_prefix,
                                 SocketRateLimit_T limiter)
{
  assert (server != NULL);

  if (path_prefix == NULL)
    {
      server->global_rate_limiter = limiter;
      return;
    }

  /* Find existing entry */
  for (RateLimitEntry *e = server->rate_limiters; e != NULL; e = e->next)
    {
      if (strcmp (e->path_prefix, path_prefix) == 0)
        {
          e->limiter = limiter;
          return;
        }
    }

  /* Create new entry */
  if (limiter != NULL)
    {
      RateLimitEntry *entry = malloc (sizeof (*entry));
      if (entry == NULL)
        return;

      entry->path_prefix = strdup (path_prefix);
      if (entry->path_prefix == NULL)
        {
          free (entry);
          return;
        }

      entry->limiter = limiter;
      entry->next = server->rate_limiters;
      server->rate_limiters = entry;
    }
}

void
SocketHTTPServer_set_validator (SocketHTTPServer_T server,
                                SocketHTTPServer_Validator validator,
                                void *userdata)
{
  assert (server != NULL);
  server->validator = validator;
  server->validator_userdata = userdata;
}

int
SocketHTTPServer_add_middleware (SocketHTTPServer_T server,
                                 SocketHTTPServer_Middleware middleware,
                                 void *userdata)
{
  MiddlewareEntry *entry;
  MiddlewareEntry *tail;

  assert (server != NULL);
  assert (middleware != NULL);

  /* Allocate middleware entry from server arena */
  entry = Arena_alloc (server->arena, sizeof (*entry), __FILE__, __LINE__);
  if (entry == NULL)
    {
      HTTPSERVER_ERROR_MSG ("Failed to allocate middleware entry");
      return -1;
    }

  entry->func = middleware;
  entry->userdata = userdata;
  entry->next = NULL;

  /* Append to end of chain to preserve order of addition */
  if (server->middleware_chain == NULL)
    {
      server->middleware_chain = entry;
    }
  else
    {
      /* Find tail of chain */
      tail = server->middleware_chain;
      while (tail->next != NULL)
        {
          tail = tail->next;
        }
      tail->next = entry;
    }

  SOCKET_LOG_DEBUG_MSG ("Added middleware to chain");

  return 0;
}

void
SocketHTTPServer_set_error_handler (SocketHTTPServer_T server,
                                    SocketHTTPServer_ErrorHandler handler,
                                    void *userdata)
{
  assert (server != NULL);

  server->error_handler = handler;
  server->error_handler_userdata = userdata;

  SOCKET_LOG_DEBUG_MSG ("Custom error handler %s",
                        handler != NULL ? "registered" : "cleared");
}

/* ============================================================================
 * Event Loop
 * ========================================================================= */

/* Accept new client connections up to max limit */
static void
server_accept_clients (SocketHTTPServer_T server)
{
  for (int j = 0; j < HTTPSERVER_MAX_CLIENTS_PER_ACCEPT; j++)
    {
      if (server->connection_count >= server->config.max_connections)
        break;

      Socket_T client = Socket_accept (server->listen_socket);
      if (client == NULL)
        break;

      Socket_setnonblocking (client);

      ServerConnection *conn = connection_new (server, client);
      if (conn == NULL)
        {
          /* connection_new takes ownership of the socket and frees it
           * in its FINALLY block on failure - do NOT double-free here */
          continue;
        }

      /* During TLS handshake we must poll for write readiness too. */
      if (conn->state == CONN_STATE_TLS_HANDSHAKE)
        SocketPoll_add (server->poll, client, POLL_READ | POLL_WRITE, conn);
      else
        SocketPoll_add (server->poll, client, POLL_READ, conn);
    }
}

/**
 * server_cleanup_timed_out - Clean up timed-out connections
 * @server: HTTP server
 *
 * Iterates all connections and closes those that have timed out.
 */
static void
server_cleanup_timed_out (SocketHTTPServer_T server)
{
  int64_t now = Socket_get_monotonic_ms ();
  ServerConnection *conn = server->connections;

  while (conn != NULL)
    {
      ServerConnection *next = conn->next;
      server_check_connection_timeout (server, conn, now);
      conn = next;
    }
}

int
SocketHTTPServer_fd (SocketHTTPServer_T server)
{
  assert (server != NULL);
  if (server->listen_socket == NULL)
    return -1;
  return Socket_fd (server->listen_socket);
}

SocketPoll_T
SocketHTTPServer_poll (SocketHTTPServer_T server)
{
  assert (server != NULL);
  return server->poll;
}

/* Process server events. Returns number of requests processed */
int
SocketHTTPServer_process (SocketHTTPServer_T server, int timeout_ms)
{
  SocketEvent_T *events;
  int nevents;
  int requests_processed = 0;

  assert (server != NULL);

  nevents = SocketPoll_wait (server->poll, &events, timeout_ms);

  for (int i = 0; i < nevents; i++)
    {
      SocketEvent_T *ev = &events[i];

      if (ev->socket == server->listen_socket)
        {
          /* Accept new connections if running */
          if (server->state == HTTPSERVER_STATE_RUNNING)
            {
              server_accept_clients (server);
            }
        }
      else
        {
          ServerConnection *conn = (ServerConnection *)ev->data;
          /* Skip connections marked for deferred deletion.
           * This can happen when io_uring or other backends return
           * multiple events for the same connection in a single batch,
           * and an earlier event closed the connection. */
          if (conn != NULL && !conn->pending_close)
            {
              requests_processed
                  += server_process_client_event (server, conn, ev->events);
            }
        }
    }

  server_cleanup_timed_out (server);

  /* Free connections that were closed during this event loop iteration.
   * Deferred deletion prevents use-after-free when multiple events
   * for the same connection arrive in a single poll batch. */
  connection_free_pending (server);

  return requests_processed;
}

/* ============================================================================
 * Drain / Graceful Shutdown
 * ========================================================================= */

int
SocketHTTPServer_drain (SocketHTTPServer_T server, int timeout_ms)
{
  assert (server != NULL);

  if (server->state != HTTPSERVER_STATE_RUNNING)
    return -1;

  server->state = HTTPSERVER_STATE_DRAINING;
  server->drain_start_ms = Socket_get_monotonic_ms ();
  server->drain_timeout_ms = timeout_ms;

  /* Stop accepting new connections */
  if (server->listen_socket != NULL)
    {
      SocketPoll_del (server->poll, server->listen_socket);
    }

  /* For HTTP/2 connections, send GOAWAY so clients stop opening new streams.
   */
  for (ServerConnection *conn = server->connections; conn != NULL;
       conn = conn->next)
    {
      if (conn->state == CONN_STATE_HTTP2 && conn->http2_conn != NULL)
        {
          TRY
          {
            SocketHTTP2_Conn_goaway (conn->http2_conn, HTTP2_NO_ERROR, NULL, 0);
          }
          EXCEPT (SocketHTTP2_ProtocolError)
          {
            /* Best-effort during drain. */
          }
          EXCEPT (SocketHTTP2_FlowControlError)
          {
            /* Best-effort during drain. */
          }
          END_TRY;
        }
    }

  return 0;
}

int
SocketHTTPServer_drain_poll (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (server->state == HTTPSERVER_STATE_STOPPED)
    return 0;

  if (server->state != HTTPSERVER_STATE_DRAINING)
    return (int)server->connection_count;

  /* Check if all connections are closed */
  if (server->connection_count == 0)
    {
      server->state = HTTPSERVER_STATE_STOPPED;
      server->running = 0;

      if (server->drain_callback != NULL)
        {
          server->drain_callback (server, 0, server->drain_callback_userdata);
        }
      return 0;
    }

  /* Check timeout */
  if (server->drain_timeout_ms >= 0)
    {
      int64_t now = Socket_get_monotonic_ms ();
      if ((now - server->drain_start_ms) >= server->drain_timeout_ms)
        {
          /* Force close all connections */
          while (server->connections != NULL)
            {
              connection_close (server, server->connections);
            }

          server->state = HTTPSERVER_STATE_STOPPED;
          server->running = 0;

          if (server->drain_callback != NULL)
            {
              server->drain_callback (
                  server, 1, server->drain_callback_userdata);
            }
          return -1;
        }
    }

  return (int)server->connection_count;
}

int
SocketHTTPServer_drain_wait (SocketHTTPServer_T server, int timeout_ms)
{
  assert (server != NULL);

  if (server->state == HTTPSERVER_STATE_RUNNING)
    {
      if (SocketHTTPServer_drain (server, timeout_ms) < 0)
        return -1;
    }

  while (server->state == HTTPSERVER_STATE_DRAINING)
    {
      /* Process any remaining I/O */
      SocketHTTPServer_process (server, HTTPSERVER_DRAIN_POLL_MS);

      int result = SocketHTTPServer_drain_poll (server);
      if (result <= 0)
        return result;
    }

  return 0;
}

int64_t
SocketHTTPServer_drain_remaining_ms (SocketHTTPServer_T server)
{
  assert (server != NULL);

  if (server->state != HTTPSERVER_STATE_DRAINING)
    return 0;

  if (server->drain_timeout_ms < 0)
    return -1;

  int64_t elapsed = Socket_get_monotonic_ms () - server->drain_start_ms;
  int64_t remaining = server->drain_timeout_ms - elapsed;
  return remaining > 0 ? remaining : 0;
}

void
SocketHTTPServer_set_drain_callback (SocketHTTPServer_T server,
                                     SocketHTTPServer_DrainCallback callback,
                                     void *userdata)
{
  assert (server != NULL);
  server->drain_callback = callback;
  server->drain_callback_userdata = userdata;
}

SocketHTTPServer_State
SocketHTTPServer_state (SocketHTTPServer_T server)
{
  assert (server != NULL);
  return (SocketHTTPServer_State)server->state;
}
