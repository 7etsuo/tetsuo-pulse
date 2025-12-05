/**
 * SocketProxy.c - Proxy Tunneling Support Core Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Core module providing:
 * - Configuration defaults and URL parsing
 * - Synchronous and asynchronous connection APIs
 * - State machine driver
 * - Error handling and utility functions
 *
 * Protocol-specific implementations are in separate files:
 * - SocketProxy-socks5.c - SOCKS5 protocol (RFC 1928/1929)
 * - SocketProxy-socks4.c - SOCKS4/4a protocol
 * - SocketProxy-http.c - HTTP CONNECT protocol
 */

#include "socket/SocketProxy.h"
#include "socket/SocketProxy-private.h"

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/SocketHappyEyeballs.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketProxy_Failed
    = { &SocketProxy_Failed, "Proxy operation failed" };

/**
 * Thread-local exception for detailed error messages.
 * REFACTOR: Now uses centralized SOCKET_DECLARE_MODULE_EXCEPTION macro
 * from SocketUtil.h instead of manual platform-specific declarations.
 */
SOCKET_DECLARE_MODULE_EXCEPTION (Proxy);

/* ============================================================================
 * Thread-Local Static Buffer for URL Parsing
 * ============================================================================ */

/* Thread-local static buffer for URL parsing when arena is NULL */
#ifdef _WIN32
static __declspec (thread) char
    proxy_static_buf[SOCKET_PROXY_STATIC_BUFFER_SIZE];
static __declspec (thread) size_t proxy_static_offset = 0;
#else
static __thread char proxy_static_buf[SOCKET_PROXY_STATIC_BUFFER_SIZE];
static __thread size_t proxy_static_offset = 0;
#endif

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/**
 * proxy_clear_nonblocking - Clear non-blocking mode from socket
 * @fd: File descriptor
 *
 * Restores socket to blocking mode for caller convenience.
 */
static void
proxy_clear_nonblocking (int fd)
{
  int flags = fcntl (fd, F_GETFL);

  if (flags >= 0)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void
SocketProxy_config_defaults (SocketProxy_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));
  config->type = SOCKET_PROXY_NONE;
  config->connect_timeout_ms = SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS;
  config->handshake_timeout_ms = SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS;
}

/* ============================================================================
 * URL Parser - Internal Helpers
 * ============================================================================ */

/**
 * Allocate string in arena or static buffer
 */
static char *
proxy_alloc_string (const char *src, size_t len, Arena_T arena)
{
  char *dst;

  if (arena != NULL)
    {
      dst = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
    }
  else
    {
      /* Use static thread-local buffer */
      if (proxy_static_offset + len + 1 > SOCKET_PROXY_STATIC_BUFFER_SIZE)
        {
          proxy_static_offset = 0; /* Wrap around */
        }
      dst = proxy_static_buf + proxy_static_offset;
      proxy_static_offset += len + 1;
    }

  memcpy (dst, src, len);
  dst[len] = '\0';
  return dst;
}

int
socketproxy_parse_scheme (const char *url, SocketProxy_Config *config,
                          const char **end)
{
  /* Match scheme:// */
  if (strncasecmp (url, "http://", 7) == 0)
    {
      config->type = SOCKET_PROXY_HTTP;
      config->port = SOCKET_PROXY_DEFAULT_HTTP_PORT;
      *end = url + 7;
      return 0;
    }
  if (strncasecmp (url, "https://", 8) == 0)
    {
      config->type = SOCKET_PROXY_HTTPS;
      config->port = SOCKET_PROXY_DEFAULT_HTTPS_PORT;
      *end = url + 8;
      return 0;
    }
  if (strncasecmp (url, "socks4://", 9) == 0)
    {
      config->type = SOCKET_PROXY_SOCKS4;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 9;
      return 0;
    }
  if (strncasecmp (url, "socks4a://", 10) == 0)
    {
      config->type = SOCKET_PROXY_SOCKS4A;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 10;
      return 0;
    }
  if (strncasecmp (url, "socks5://", 9) == 0)
    {
      config->type = SOCKET_PROXY_SOCKS5;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 9;
      return 0;
    }
  if (strncasecmp (url, "socks5h://", 10) == 0)
    {
      config->type = SOCKET_PROXY_SOCKS5H;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 10;
      return 0;
    }
  if (strncasecmp (url, "socks://", 8) == 0)
    {
      /* Treat bare socks:// as SOCKS5 */
      config->type = SOCKET_PROXY_SOCKS5;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 8;
      return 0;
    }

  return -1; /* Unknown scheme */
}

int
socketproxy_parse_userinfo (const char *start, SocketProxy_Config *config,
                            Arena_T arena, const char **end)
{
  const char *at_sign;
  const char *colon;

  /* Look for @ sign indicating end of userinfo */
  at_sign = strchr (start, '@');
  if (at_sign == NULL)
    {
      /* No userinfo */
      *end = start;
      return 0;
    }

  /* Check for port-like pattern (host:port) - @ should come before : in host */
  colon = strchr (start, ':');
  if (colon != NULL && colon > at_sign)
    {
      /* The @ is in the userinfo, colon is after it */
      colon = NULL;
      for (const char *p = start; p < at_sign; p++)
        {
          if (*p == ':')
            {
              colon = p;
              break;
            }
        }
    }
  else if (colon != NULL && colon < at_sign)
    {
      /* Colon is before @ so it's password separator */
    }
  else
    {
      colon = NULL;
      for (const char *p = start; p < at_sign; p++)
        {
          if (*p == ':')
            {
              colon = p;
              break;
            }
        }
    }

  if (colon != NULL && colon < at_sign)
    {
      /* user:pass@host */
      size_t user_len = (size_t)(colon - start);
      size_t pass_len = (size_t)(at_sign - colon - 1);

      if (user_len > SOCKET_PROXY_MAX_USERNAME_LEN
          || pass_len > SOCKET_PROXY_MAX_PASSWORD_LEN)
        {
          return -1;
        }

      config->username = proxy_alloc_string (start, user_len, arena);
      config->password = proxy_alloc_string (colon + 1, pass_len, arena);
    }
  else
    {
      /* user@host (no password) */
      size_t user_len = (size_t)(at_sign - start);

      if (user_len > SOCKET_PROXY_MAX_USERNAME_LEN)
        {
          return -1;
        }

      config->username = proxy_alloc_string (start, user_len, arena);
      config->password = NULL;
    }

  *end = at_sign + 1;
  return 0;
}

int
socketproxy_parse_hostport (const char *start, SocketProxy_Config *config,
                            Arena_T arena)
{
  const char *bracket_open;
  const char *bracket_close;
  const char *colon;
  const char *host_start;
  const char *host_end;
  const char *port_start;
  size_t host_len;

  /* Handle IPv6 address in brackets */
  bracket_open = strchr (start, '[');
  if (bracket_open == start)
    {
      /* [ipv6]:port format */
      bracket_close = strchr (start, ']');
      if (bracket_close == NULL)
        return -1;

      host_start = start + 1;
      host_end = bracket_close;
      port_start = bracket_close + 1;

      if (*port_start == ':')
        {
          config->port = atoi (port_start + 1);
          if (config->port <= 0 || config->port > 65535)
            return -1;
        }
    }
  else
    {
      /* host:port or just host */
      host_start = start;

      /* Find end of host (path, query, or end) */
      host_end = start;
      while (*host_end && *host_end != '/' && *host_end != '?'
             && *host_end != '#')
        host_end++;

      /* Look for port */
      colon = NULL;
      for (const char *p = start; p < host_end; p++)
        {
          if (*p == ':')
            colon = p;
        }

      if (colon != NULL)
        {
          host_end = colon;
          config->port = atoi (colon + 1);
          if (config->port <= 0 || config->port > 65535)
            return -1;
        }
    }

  host_len = (size_t)(host_end - host_start);
  if (host_len == 0 || host_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    return -1;

  config->host = proxy_alloc_string (host_start, host_len, arena);
  return 0;
}

/* ============================================================================
 * URL Parser - Public API
 * ============================================================================ */

int
SocketProxy_parse_url (const char *url, SocketProxy_Config *config,
                       Arena_T arena)
{
  const char *p;

  assert (config != NULL);

  if (url == NULL || *url == '\0')
    return -1;

  /* Reset static buffer if not using arena */
  if (arena == NULL)
    proxy_static_offset = 0;

  /* Initialize config */
  SocketProxy_config_defaults (config);

  /* Parse scheme */
  if (socketproxy_parse_scheme (url, config, &p) < 0)
    return -1;

  /* Parse optional userinfo */
  if (socketproxy_parse_userinfo (p, config, arena, &p) < 0)
    return -1;

  /* Parse host[:port] */
  if (socketproxy_parse_hostport (p, config, arena) < 0)
    return -1;

  return 0;
}

/* ============================================================================
 * State Machine Helpers
 * ============================================================================ */

void
socketproxy_set_error (struct SocketProxy_Conn_T *conn, SocketProxy_Result result,
                       const char *fmt, ...)
{
  va_list ap;

  conn->state = PROXY_STATE_FAILED;
  conn->result = result;

  va_start (ap, fmt);
  vsnprintf (conn->error_buf, sizeof (conn->error_buf), fmt, ap);
  va_end (ap);
}

int
socketproxy_do_send (struct SocketProxy_Conn_T *conn)
{
  volatile ssize_t n = 0;
  volatile int caught_closed = 0;

  while (conn->send_offset < conn->send_len)
    {
      caught_closed = 0;
      TRY
        n = Socket_send (conn->socket, conn->send_buf + conn->send_offset,
                         conn->send_len - conn->send_offset);
      EXCEPT (Socket_Closed)
        /* Connection closed by peer */
        caught_closed = 1;
      END_TRY;

      if (caught_closed)
        return -1;

      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 1; /* More to send */
          return -1;  /* Error */
        }
      conn->send_offset += (size_t)n;
    }

  return 0; /* All sent */
}

int
socketproxy_do_recv (struct SocketProxy_Conn_T *conn)
{
  volatile ssize_t n = 0;
  volatile int caught_closed = 0;
  size_t space;

  space = sizeof (conn->recv_buf) - conn->recv_len;
  if (space == 0)
    {
      /* Buffer full - protocol error */
      return -1;
    }

  TRY
    n = Socket_recv (conn->socket, conn->recv_buf + conn->recv_len, space);
  EXCEPT (Socket_Closed)
    /* Connection closed by peer */
    caught_closed = 1;
  END_TRY;

  if (caught_closed)
    return 0; /* Treat as EOF */

  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0; /* No data available */
      return -1;  /* Error */
    }
  if (n == 0)
    {
      return 0; /* EOF */
    }

  conn->recv_len += (size_t)n;
  return (int)n;
}

/* ============================================================================
 * State Machine Driver
 * ============================================================================ */

void
socketproxy_advance_state (struct SocketProxy_Conn_T *conn)
{
  /* Handle send completion -> move to receive */
  if (conn->state == PROXY_STATE_HANDSHAKE_SEND
      || conn->state == PROXY_STATE_AUTH_SEND)
    {
      if (conn->send_offset >= conn->send_len)
        {
          /* All data sent, move to receive */
          if (conn->state == PROXY_STATE_AUTH_SEND)
            conn->state = PROXY_STATE_AUTH_RECV;
          else
            conn->state = PROXY_STATE_HANDSHAKE_RECV;

          conn->send_offset = 0;
          conn->send_len = 0;
          conn->recv_offset = 0;
          conn->recv_len = 0;
        }
      return;
    }

  /* Handle receive completion based on protocol */
  /* Protocol-specific handlers call this after successful parse */
}

/* ============================================================================
 * Async Connection - Helper Functions
 * ============================================================================ */

/**
 * proxy_validate_config - Validate proxy configuration
 * @proxy: Proxy configuration
 *
 * Returns: 0 on success, raises SocketProxy_Failed on error
 */
static int
proxy_validate_config (const SocketProxy_Config *proxy)
{
  if (proxy->type == SOCKET_PROXY_NONE || proxy->host == NULL)
    {
      PROXY_ERROR_MSG ("Invalid proxy configuration");
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  return 0;
}

/**
 * proxy_validate_target - Validate target hostname length
 * @target_host: Target hostname
 *
 * Returns: 0 on success, raises SocketProxy_Failed on error
 *
 * REFACTOR: Removed target_len_out parameter - validation is
 * self-contained and caller no longer needs the length value.
 */
static int
proxy_validate_target (const char *target_host)
{
  size_t target_len = strlen (target_host);

  if (target_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    {
      PROXY_ERROR_MSG ("Target hostname too long (max %d)",
                       SOCKET_PROXY_MAX_HOSTNAME_LEN);
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  return 0;
}

/* REFACTOR: Removed proxy_copy_string() - now uses socket_util_arena_strdup()
 * from SocketUtil.h which provides the same functionality. */

/**
 * proxy_init_context - Initialize connection context
 * @conn: Connection context
 * @arena: Memory arena
 * @proxy: Proxy configuration
 * @target_host: Target hostname
 * @target_port: Target port
 *
 * REFACTOR: Removed target_len parameter - socket_util_arena_strdup
 * handles length calculation internally.
 */
static void
proxy_init_context (struct SocketProxy_Conn_T *conn, Arena_T arena,
                    const SocketProxy_Config *proxy, const char *target_host,
                    int target_port)
{
  memset (conn, 0, sizeof (*conn));
  conn->arena = arena;
  conn->type = proxy->type;
  conn->proxy_port = proxy->port;
  conn->target_port = target_port;
  conn->connect_timeout_ms = proxy->connect_timeout_ms > 0
                                 ? proxy->connect_timeout_ms
                                 : SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS;
  conn->handshake_timeout_ms = proxy->handshake_timeout_ms > 0
                                   ? proxy->handshake_timeout_ms
                                   : SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS;

  conn->proxy_host = socket_util_arena_strdup (arena, proxy->host);
  conn->target_host = socket_util_arena_strdup (arena, target_host);
  conn->username = socket_util_arena_strdup (arena, proxy->username);
  conn->password = socket_util_arena_strdup (arena, proxy->password);
  conn->extra_headers = proxy->extra_headers;

  conn->state = PROXY_STATE_IDLE;
  conn->proto_state = PROTO_STATE_INIT;
  conn->result = PROXY_IN_PROGRESS;
  conn->start_time_ms = socketproxy_get_time_ms ();
}

/**
 * proxy_build_initial_request - Build initial protocol request
 * @conn: Connection context
 *
 * Returns: 0 on success, sets error on failure
 */
static int
proxy_build_initial_request (struct SocketProxy_Conn_T *conn)
{
  switch (conn->type)
    {
    case SOCKET_PROXY_SOCKS5:
    case SOCKET_PROXY_SOCKS5H:
      if (proxy_socks5_send_greeting (conn) < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                 "Failed to build SOCKS5 greeting");
          return -1;
        }
      break;

    case SOCKET_PROXY_SOCKS4:
      if (proxy_socks4_send_connect (conn) < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                 "Failed to build SOCKS4 request");
          return -1;
        }
      break;

    case SOCKET_PROXY_SOCKS4A:
      if (proxy_socks4a_send_connect (conn) < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                 "Failed to build SOCKS4a request");
          return -1;
        }
      break;

    case SOCKET_PROXY_HTTP:
    case SOCKET_PROXY_HTTPS:
      if (proxy_http_send_connect (conn) < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                 "Failed to build HTTP CONNECT request");
          return -1;
        }
      break;

    default:
      socketproxy_set_error (conn, PROXY_ERROR_UNSUPPORTED,
                             "Unsupported proxy type");
      return -1;
    }

  return 0;
}

/**
 * proxy_connect_to_server_sync - Connect to proxy server via HappyEyeballs (blocking)
 * @conn: Connection context
 *
 * Returns: 0 on success, -1 on failure (sets error)
 */
static int
proxy_connect_to_server_sync (struct SocketProxy_Conn_T *conn)
{
  SocketHE_Config_T he_config;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = conn->connect_timeout_ms;

  TRY
    conn->socket = SocketHappyEyeballs_connect (conn->proxy_host,
                                                conn->proxy_port, &he_config);
  EXCEPT (SocketHE_Failed)
    socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                           "HappyEyeballs connection failed");
    return -1;
  END_TRY;

  if (conn->socket == NULL)
    {
      socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                             "Failed to connect to proxy %s:%d",
                             conn->proxy_host, conn->proxy_port);
      return -1;
    }

  return 0;
}

/**
 * proxy_start_async_connect - Start async connection to proxy server
 * @conn: Connection context
 *
 * Returns: 0 on success, -1 on failure (sets error)
 */
static int
proxy_start_async_connect (struct SocketProxy_Conn_T *conn)
{
  SocketHE_Config_T he_config;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = conn->connect_timeout_ms;

  TRY
    conn->he = SocketHappyEyeballs_start (conn->dns, conn->poll, conn->proxy_host,
                                          conn->proxy_port, &he_config);
  EXCEPT (SocketHE_Failed)
    socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                           "Failed to start async connection to proxy");
    return -1;
  END_TRY;

  if (conn->he == NULL)
    {
      socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                             "Failed to start connection to proxy %s:%d",
                             conn->proxy_host, conn->proxy_port);
      return -1;
    }

  conn->state = PROXY_STATE_CONNECTING_PROXY;
  return 0;
}

/* ============================================================================
 * Async Connection - Lifecycle
 * ============================================================================ */

SocketProxy_Conn_T
SocketProxy_Conn_start (SocketDNS_T dns, SocketPoll_T poll,
                        const SocketProxy_Config *proxy, const char *target_host,
                        int target_port)
{
  SocketProxy_Conn_T conn;
  Arena_T arena;

  assert (dns != NULL);
  assert (poll != NULL);
  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= 65535);

  /* Validate inputs */
  proxy_validate_config (proxy);
  proxy_validate_target (target_host);

  /* Create arena */
  arena = Arena_new ();
  if (arena == NULL)
    {
      PROXY_ERROR_MSG ("Failed to create arena");
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }

  /* Allocate and initialize context */
  conn = Arena_alloc (arena, sizeof (*conn), __FILE__, __LINE__);
  proxy_init_context (conn, arena, proxy, target_host, target_port);

  /* Store external DNS/poll references */
  conn->dns = dns;
  conn->poll = poll;
  conn->owns_dns_poll = 0; /* External resources - don't free */

  /* Start async connection to proxy server */
  if (proxy_start_async_connect (conn) < 0)
    return conn; /* Return in FAILED state */

  return conn;
}

SocketProxy_Conn_T
SocketProxy_Conn_new (const SocketProxy_Config *proxy, const char *target_host,
                      int target_port)
{
  SocketProxy_Conn_T conn;
  Arena_T arena;

  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= 65535);

  /* Validate inputs */
  proxy_validate_config (proxy);
  proxy_validate_target (target_host);

  /* Create arena */
  arena = Arena_new ();
  if (arena == NULL)
    {
      PROXY_ERROR_MSG ("Failed to create arena");
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }

  /* Allocate and initialize context */
  conn = Arena_alloc (arena, sizeof (*conn), __FILE__, __LINE__);
  proxy_init_context (conn, arena, proxy, target_host, target_port);

  /* Connect to proxy server (blocking) */
  if (proxy_connect_to_server_sync (conn) < 0)
    return conn;

  /* Set non-blocking for async I/O */
  Socket_setnonblocking (conn->socket);

  /* Move to handshake phase */
  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();

  /* Build initial protocol request */
  proxy_build_initial_request (conn);

  return conn;
}

void
SocketProxy_Conn_free (SocketProxy_Conn_T *conn)
{
  SocketProxy_Conn_T c;
  Arena_T arena;

  if (conn == NULL || *conn == NULL)
    return;

  c = *conn;

  /* CRITICAL: Save arena pointer BEFORE any cleanup that might free connection
   * structure. The connection is allocated from its own arena, so we must save
   * the arena pointer before disposing it. */
  arena = c->arena;

  /* Clear credentials from memory */
  if (c->password != NULL)
    {
      SocketCrypto_secure_clear (c->password, strlen (c->password));
    }

  /* Free HappyEyeballs context if active */
  if (c->he != NULL)
    {
      SocketHappyEyeballs_free (&c->he);
    }

  /* Close socket if not transferred */
  if (c->socket != NULL && !c->transferred)
    {
      Socket_free (&c->socket);
    }

  /* Free HTTP parser if allocated */
  if (c->http_parser != NULL)
    {
      SocketHTTP1_Parser_free (&c->http_parser);
    }

  /* Free owned DNS/poll resources (sync wrapper case) */
  if (c->owns_dns_poll)
    {
      if (c->dns != NULL)
        SocketDNS_free (&c->dns);
      if (c->poll != NULL)
        SocketPoll_free (&c->poll);
    }

  /* Free arena (releases all memory including connection structure itself) */
  Arena_dispose (&arena);

  *conn = NULL;
}

/* ============================================================================
 * Async Connection - State Query
 * ============================================================================ */

int
SocketProxy_Conn_poll (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  return conn->state == PROXY_STATE_CONNECTED
         || conn->state == PROXY_STATE_FAILED
         || conn->state == PROXY_STATE_CANCELLED;
}

SocketProxy_State
SocketProxy_Conn_state (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);
  return conn->state;
}

SocketProxy_Result
SocketProxy_Conn_result (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);
  return conn->result;
}

const char *
SocketProxy_Conn_error (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  if (conn->state != PROXY_STATE_FAILED)
    return NULL;

  return conn->error_buf[0] ? conn->error_buf : "Unknown error";
}

Socket_T
SocketProxy_Conn_socket (SocketProxy_Conn_T conn)
{
  Socket_T sock;

  assert (conn != NULL);

  if (conn->state != PROXY_STATE_CONNECTED || conn->transferred)
    return NULL;

  sock = conn->socket;
  conn->socket = NULL;
  conn->transferred = 1;

  /* Restore blocking mode for caller */
  proxy_clear_nonblocking (Socket_fd (sock));

  return sock;
}

/* ============================================================================
 * Async Connection - Event Loop Integration
 * ============================================================================ */

int
SocketProxy_Conn_fd (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  /* During CONNECTING_PROXY, HappyEyeballs manages its own fds via
   * the poll instance passed to SocketProxy_Conn_start(). Return -1
   * to indicate no direct fd to poll. */
  if (conn->state == PROXY_STATE_CONNECTING_PROXY)
    return -1;

  if (conn->socket == NULL)
    return -1;

  return Socket_fd (conn->socket);
}

unsigned
SocketProxy_Conn_events (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  switch (conn->state)
    {
    case PROXY_STATE_CONNECTING_PROXY:
      /* HappyEyeballs manages its own poll events via the poll
       * instance passed to SocketProxy_Conn_start(). Caller should
       * use SocketPoll_wait() on their poll instance. */
      return 0;

    case PROXY_STATE_HANDSHAKE_SEND:
    case PROXY_STATE_AUTH_SEND:
      return POLL_WRITE;

    case PROXY_STATE_HANDSHAKE_RECV:
    case PROXY_STATE_AUTH_RECV:
      return POLL_READ;

    default:
      return 0;
    }
}

int
SocketProxy_Conn_next_timeout_ms (SocketProxy_Conn_T conn)
{
  int64_t elapsed;
  int remaining;

  assert (conn != NULL);

  if (SocketProxy_Conn_poll (conn))
    return -1;

  /* During CONNECTING_PROXY, use HappyEyeballs timeout */
  if (conn->state == PROXY_STATE_CONNECTING_PROXY && conn->he != NULL)
    return SocketHappyEyeballs_next_timeout_ms (conn->he);

  /* During handshake phases, use handshake timeout */
  if (conn->handshake_start_time_ms == 0)
    return SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS;

  elapsed = socketproxy_elapsed_ms (conn->handshake_start_time_ms);
  remaining = conn->handshake_timeout_ms - (int)elapsed;

  return (remaining > 0) ? remaining : 0;
}

void
SocketProxy_Conn_cancel (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  if (SocketProxy_Conn_poll (conn))
    return;

  conn->state = PROXY_STATE_CANCELLED;
  conn->result = PROXY_ERROR_CANCELLED;

  /* Cancel HappyEyeballs if still connecting */
  if (conn->he != NULL)
    {
      SocketHappyEyeballs_cancel (conn->he);
      SocketHappyEyeballs_free (&conn->he);
    }

  if (conn->socket != NULL && !conn->transferred)
    {
      Socket_free (&conn->socket);
    }
}

/* ============================================================================
 * Async Connection - Process Helper Functions
 * ============================================================================ */

/**
 * proxy_check_timeout - Check if handshake has timed out
 * @conn: Connection context
 *
 * Returns: 0 if not timed out, -1 if timed out (sets error)
 */
static int
proxy_check_timeout (struct SocketProxy_Conn_T *conn)
{
  int64_t elapsed = socketproxy_elapsed_ms (conn->handshake_start_time_ms);

  if (elapsed >= conn->handshake_timeout_ms)
    {
      socketproxy_set_error (conn, PROXY_ERROR_TIMEOUT,
                             "Proxy handshake timeout (%d ms)",
                             conn->handshake_timeout_ms);
      return -1;
    }
  return 0;
}

/**
 * proxy_process_connecting - Process CONNECTING_PROXY state
 * @conn: Connection context
 *
 * Returns: 0 if still connecting, 1 if connected and transitioned, -1 on error
 */
static int
proxy_process_connecting (struct SocketProxy_Conn_T *conn)
{
  SocketHE_State he_state;

  if (conn->he == NULL)
    {
      socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                             "No HappyEyeballs context");
      return -1;
    }

  /* Process HappyEyeballs state machine */
  SocketHappyEyeballs_process (conn->he);

  /* Check if HappyEyeballs is complete */
  if (!SocketHappyEyeballs_poll (conn->he))
    return 0; /* Still connecting */

  he_state = SocketHappyEyeballs_state (conn->he);

  if (he_state == HE_STATE_CONNECTED)
    {
      /* Get the connected socket */
      conn->socket = SocketHappyEyeballs_result (conn->he);
      SocketHappyEyeballs_free (&conn->he);

      if (conn->socket == NULL)
        {
          socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                                 "Failed to get socket from HappyEyeballs");
          return -1;
        }

      /* Set non-blocking for async handshake */
      Socket_setnonblocking (conn->socket);

      /* Transition to handshake phase */
      conn->state = PROXY_STATE_HANDSHAKE_SEND;
      conn->handshake_start_time_ms = socketproxy_get_time_ms ();

      /* Build initial protocol request */
      if (proxy_build_initial_request (conn) < 0)
        return -1;

      return 1; /* Connected and transitioned */
    }
  else
    {
      /* Connection failed */
      const char *error = SocketHappyEyeballs_error (conn->he);
      socketproxy_set_error (conn, PROXY_ERROR_CONNECT,
                             "Failed to connect to proxy: %s",
                             error ? error : "unknown error");
      SocketHappyEyeballs_free (&conn->he);
      return -1;
    }
}

/**
 * proxy_process_send - Process send states
 * @conn: Connection context
 *
 * Returns: 0 on success, -1 on error
 */
static int
proxy_process_send (struct SocketProxy_Conn_T *conn)
{
  int ret = socketproxy_do_send (conn);

  if (ret < 0)
    {
      socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                             "Send failed: %s", strerror (errno));
      return -1;
    }
  if (ret == 0)
    socketproxy_advance_state (conn);

  return 0;
}

/**
 * proxy_socks5_send_connect_request - Send SOCKS5 connect after auth
 * @conn: Connection context
 *
 * Returns: 0 on success, -1 on error
 */
static int
proxy_socks5_send_connect_request (struct SocketProxy_Conn_T *conn)
{
  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->recv_len = 0;
  conn->recv_offset = 0;

  if (proxy_socks5_send_connect (conn) < 0)
    {
      socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                             "Failed to build connect");
      return -1;
    }
  return 0;
}

/**
 * proxy_socks5_handle_method_response - Handle SOCKS5 method selection response
 * @conn: Connection context
 *
 * Returns: Result code
 */
static SocketProxy_Result
proxy_socks5_handle_method_response (struct SocketProxy_Conn_T *conn)
{
  SocketProxy_Result res = proxy_socks5_recv_method (conn);

  if (res != PROXY_OK)
    return res;

  if (conn->socks5_need_auth)
    {
      conn->state = PROXY_STATE_AUTH_SEND;
      if (proxy_socks5_send_auth (conn) < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                                 "Failed to build auth");
          return PROXY_ERROR_PROTOCOL;
        }
    }
  else
    {
      if (proxy_socks5_send_connect_request (conn) < 0)
        return PROXY_ERROR_PROTOCOL;
    }

  return PROXY_IN_PROGRESS;
}

/**
 * proxy_socks5_process_recv - Process SOCKS5 receive state
 * @conn: Connection context
 *
 * Returns: Result code
 */
static SocketProxy_Result
proxy_socks5_process_recv (struct SocketProxy_Conn_T *conn)
{
  SocketProxy_Result res;

  if (conn->state == PROXY_STATE_AUTH_RECV)
    {
      res = proxy_socks5_recv_auth (conn);
      if (res == PROXY_OK)
        {
          if (proxy_socks5_send_connect_request (conn) < 0)
            return PROXY_ERROR_PROTOCOL;
          return PROXY_IN_PROGRESS;
        }
      return res;
    }

  switch (conn->proto_state)
    {
    case PROTO_STATE_SOCKS5_GREETING_SENT:
      return proxy_socks5_handle_method_response (conn);

    case PROTO_STATE_SOCKS5_AUTH_RECEIVED:
      if (proxy_socks5_send_connect_request (conn) < 0)
        return PROXY_ERROR_PROTOCOL;
      return PROXY_IN_PROGRESS;

    case PROTO_STATE_SOCKS5_CONNECT_SENT:
      return proxy_socks5_recv_connect (conn);

    default:
      return PROXY_IN_PROGRESS;
    }
}

/**
 * proxy_dispatch_protocol_recv - Dispatch to protocol-specific receive handler
 * @conn: Connection context
 *
 * Returns: Result code
 */
static SocketProxy_Result
proxy_dispatch_protocol_recv (struct SocketProxy_Conn_T *conn)
{
  switch (conn->type)
    {
    case SOCKET_PROXY_SOCKS5:
    case SOCKET_PROXY_SOCKS5H:
      return proxy_socks5_process_recv (conn);

    case SOCKET_PROXY_SOCKS4:
    case SOCKET_PROXY_SOCKS4A:
      return proxy_socks4_recv_response (conn);

    case SOCKET_PROXY_HTTP:
    case SOCKET_PROXY_HTTPS:
      return proxy_http_recv_response (conn);

    default:
      return PROXY_ERROR_UNSUPPORTED;
    }
}

/**
 * proxy_process_recv - Process receive states
 * @conn: Connection context
 *
 * Returns: 0 on success, -1 on error
 */
static int
proxy_process_recv (struct SocketProxy_Conn_T *conn)
{
  int ret;
  SocketProxy_Result res;

  ret = socketproxy_do_recv (conn);
  if (ret < 0)
    {
      socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                             "Receive failed: %s", strerror (errno));
      return -1;
    }
  if (ret == 0 && conn->recv_len == 0)
    {
      socketproxy_set_error (conn, PROXY_ERROR_PROTOCOL,
                             "Connection closed by proxy");
      return -1;
    }

  res = proxy_dispatch_protocol_recv (conn);

  if (res == PROXY_OK)
    {
      conn->state = PROXY_STATE_CONNECTED;
      conn->result = PROXY_OK;
    }
  else if (res != PROXY_IN_PROGRESS)
    {
      socketproxy_set_error (conn, res, "Protocol handshake failed");
    }

  return 0;
}

/* ============================================================================
 * Async Connection - Process
 * ============================================================================ */

void
SocketProxy_Conn_process (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

  if (SocketProxy_Conn_poll (conn))
    return;

  switch (conn->state)
    {
    case PROXY_STATE_CONNECTING_PROXY:
      proxy_process_connecting (conn);
      break;

    case PROXY_STATE_HANDSHAKE_SEND:
    case PROXY_STATE_AUTH_SEND:
      if (proxy_check_timeout (conn) < 0)
        return;
      proxy_process_send (conn);
      break;

    case PROXY_STATE_HANDSHAKE_RECV:
    case PROXY_STATE_AUTH_RECV:
      if (proxy_check_timeout (conn) < 0)
        return;
      proxy_process_recv (conn);
      break;

    default:
      break;
    }
}

/* ============================================================================
 * Synchronous API
 * ============================================================================ */

SocketProxy_Result
SocketProxy_tunnel (Socket_T socket, const SocketProxy_Config *proxy,
                    const char *target_host, int target_port)
{
  struct SocketProxy_Conn_T conn_struct;
  struct SocketProxy_Conn_T *conn = &conn_struct;
  size_t target_len;
  int fd;
  int was_nonblocking;
  int flags;
  struct pollfd pfd;
  int timeout;
  SocketProxy_Result result;

  assert (socket != NULL);
  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= 65535);

  if (proxy->type == SOCKET_PROXY_NONE)
    return PROXY_ERROR_UNSUPPORTED;

  target_len = strlen (target_host);
  if (target_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    return PROXY_ERROR_PROTOCOL;

  /* Initialize context on stack (no arena allocation) */
  memset (conn, 0, sizeof (*conn));
  conn->type = proxy->type;
  conn->proxy_host = (char *)proxy->host;
  conn->proxy_port = proxy->port;
  conn->target_host = (char *)target_host;
  conn->target_port = target_port;
  conn->username = (char *)proxy->username;
  conn->password = (char *)proxy->password;
  conn->extra_headers = proxy->extra_headers;
  conn->connect_timeout_ms = proxy->connect_timeout_ms > 0
                                 ? proxy->connect_timeout_ms
                                 : SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS;
  conn->handshake_timeout_ms = proxy->handshake_timeout_ms > 0
                                   ? proxy->handshake_timeout_ms
                                   : SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS;
  conn->socket = socket;
  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->proto_state = PROTO_STATE_INIT;
  conn->result = PROXY_IN_PROGRESS;
  conn->start_time_ms = socketproxy_get_time_ms ();
  conn->handshake_start_time_ms = conn->start_time_ms;

  /* Check and set non-blocking mode */
  fd = Socket_fd (socket);
  flags = fcntl (fd, F_GETFL);
  was_nonblocking = (flags >= 0 && (flags & O_NONBLOCK));

  if (!was_nonblocking)
    {
      Socket_setnonblocking (socket);
    }

  /* Build initial protocol request */
  if (proxy_build_initial_request (conn) < 0)
    {
      if (!was_nonblocking)
        proxy_clear_nonblocking (fd);
      return conn->result;
    }

  /* Poll loop for handshake */
  while (!SocketProxy_Conn_poll (conn))
    {
      pfd.fd = fd;
      pfd.events = 0;
      if (SocketProxy_Conn_events (conn) & POLL_READ)
        pfd.events |= POLLIN;
      if (SocketProxy_Conn_events (conn) & POLL_WRITE)
        pfd.events |= POLLOUT;
      pfd.revents = 0;

      timeout = SocketProxy_Conn_next_timeout_ms (conn);
      if (timeout < 0)
        timeout = SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS;

      if (poll (&pfd, 1, timeout) < 0)
        {
          if (errno == EINTR)
            continue;
          socketproxy_set_error (conn, PROXY_ERROR, "poll failed");
          break;
        }

      SocketProxy_Conn_process (conn);
    }

  result = conn->result;

  /* Restore blocking mode if it was originally blocking */
  if (!was_nonblocking)
    proxy_clear_nonblocking (fd);

  /* Clear password from stack buffer */
  if (conn->password != NULL)
    {
      /* Note: We don't clear here because conn->password points to
       * the caller's proxy->password string which we shouldn't modify.
       * The caller is responsible for clearing their credentials. */
    }

  return result;
}

Socket_T
SocketProxy_connect (const SocketProxy_Config *proxy, const char *target_host,
                     int target_port)
{
  SocketProxy_Conn_T conn;
  volatile Socket_T result = NULL;
  int fd;
  struct pollfd pfd;
  int timeout;

  assert (proxy != NULL);
  assert (target_host != NULL);

  TRY
    /* Create async connection */
    conn = SocketProxy_Conn_new (proxy, target_host, target_port);

    /* Poll loop until complete */
    while (!SocketProxy_Conn_poll (conn))
      {
        fd = SocketProxy_Conn_fd (conn);
        if (fd < 0)
          break;

        pfd.fd = fd;
        pfd.events = 0;
        if (SocketProxy_Conn_events (conn) & POLL_READ)
          pfd.events |= POLLIN;
        if (SocketProxy_Conn_events (conn) & POLL_WRITE)
          pfd.events |= POLLOUT;
        pfd.revents = 0;

        timeout = SocketProxy_Conn_next_timeout_ms (conn);
        if (timeout < 0)
          timeout = SOCKET_PROXY_DEFAULT_POLL_TIMEOUT_MS;

        if (poll (&pfd, 1, timeout) < 0)
          {
            if (errno == EINTR)
              continue;
            break;
          }

        SocketProxy_Conn_process (conn);
      }

    /* Get result */
    if (SocketProxy_Conn_result (conn) == PROXY_OK)
      {
        result = SocketProxy_Conn_socket (conn);
      }
    else
      {
        PROXY_ERROR_MSG ("Proxy connection failed: %s",
                         SocketProxy_Conn_error (conn));
      }

    SocketProxy_Conn_free (&conn);

    if (result == NULL)
      {
        RAISE_PROXY_ERROR (SocketProxy_Failed);
      }
  END_TRY;

  return result;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *
SocketProxy_result_string (SocketProxy_Result result)
{
  switch (result)
    {
    case PROXY_OK:
      return "Success";
    case PROXY_IN_PROGRESS:
      return "In progress";
    case PROXY_ERROR:
      return "Error";
    case PROXY_ERROR_CONNECT:
      return "Connection to proxy failed";
    case PROXY_ERROR_AUTH_REQUIRED:
      return "Authentication required";
    case PROXY_ERROR_AUTH_FAILED:
      return "Authentication failed";
    case PROXY_ERROR_FORBIDDEN:
      return "Connection forbidden by proxy";
    case PROXY_ERROR_HOST_UNREACHABLE:
      return "Target host unreachable";
    case PROXY_ERROR_NETWORK_UNREACHABLE:
      return "Target network unreachable";
    case PROXY_ERROR_CONNECTION_REFUSED:
      return "Target connection refused";
    case PROXY_ERROR_TTL_EXPIRED:
      return "TTL expired";
    case PROXY_ERROR_PROTOCOL:
      return "Protocol error";
    case PROXY_ERROR_UNSUPPORTED:
      return "Unsupported command";
    case PROXY_ERROR_TIMEOUT:
      return "Operation timed out";
    case PROXY_ERROR_CANCELLED:
      return "Operation cancelled";
    default:
      return "Unknown error";
    }
}

const char *
SocketProxy_state_string (SocketProxy_State state)
{
  switch (state)
    {
    case PROXY_STATE_IDLE:
      return "IDLE";
    case PROXY_STATE_CONNECTING_PROXY:
      return "CONNECTING_PROXY";
    case PROXY_STATE_TLS_TO_PROXY:
      return "TLS_TO_PROXY";
    case PROXY_STATE_HANDSHAKE_SEND:
      return "HANDSHAKE_SEND";
    case PROXY_STATE_HANDSHAKE_RECV:
      return "HANDSHAKE_RECV";
    case PROXY_STATE_AUTH_SEND:
      return "AUTH_SEND";
    case PROXY_STATE_AUTH_RECV:
      return "AUTH_RECV";
    case PROXY_STATE_CONNECTED:
      return "CONNECTED";
    case PROXY_STATE_FAILED:
      return "FAILED";
    case PROXY_STATE_CANCELLED:
      return "CANCELLED";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketProxy_type_string (SocketProxyType type)
{
  switch (type)
    {
    case SOCKET_PROXY_NONE:
      return "NONE";
    case SOCKET_PROXY_HTTP:
      return "HTTP CONNECT";
    case SOCKET_PROXY_HTTPS:
      return "HTTPS CONNECT";
    case SOCKET_PROXY_SOCKS4:
      return "SOCKS4";
    case SOCKET_PROXY_SOCKS4A:
      return "SOCKS4A";
    case SOCKET_PROXY_SOCKS5:
      return "SOCKS5";
    case SOCKET_PROXY_SOCKS5H:
      return "SOCKS5H";
    default:
      return "UNKNOWN";
    }
}

