/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * SocketProxy.c - Proxy Tunneling Support Core Implementation
 *
 * Protocol-specific implementations are in separate files:
 * - SocketProxy-socks5.c - SOCKS5 protocol (RFC 1928/1929)
 * - SocketProxy-socks4.c - SOCKS4/4a protocol
 * - SocketProxy-http.c - HTTP CONNECT protocol
 */

#include "core/SocketSecurity.h"
#include "socket/SocketCommon.h"
#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"
#include "tls/SocketTLSConfig.h"

SOCKET_DECLARE_MODULE_EXCEPTION (Proxy);

#define RAISE_PROXY_ERROR_MSG(exception, fmt, ...) \
  SOCKET_RAISE_FMT (Proxy, exception, fmt, ##__VA_ARGS__)

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "dns/SocketDNSResolver.h"
#include "poll/SocketPoll.h"
#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"

#define TLS_VERSION_1_3 TLS1_3_VERSION /* OpenSSL constant for TLS 1.3 */
#include "tls/SocketTLSContext.h"
#endif
#include "socket/SocketHappyEyeballs.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const Except_T SocketProxy_Failed
    = { &SocketProxy_Failed, "Proxy operation failed" };
#ifdef _WIN32
static
    __declspec (thread) char proxy_static_buf[SOCKET_PROXY_STATIC_BUFFER_SIZE];
static __declspec (thread) size_t proxy_static_offset = 0;
static __declspec (thread) size_t proxy_static_total_used = 0;
#else
static __thread char proxy_static_buf[SOCKET_PROXY_STATIC_BUFFER_SIZE];
static __thread size_t proxy_static_offset = 0;
static __thread size_t proxy_static_total_used = 0;
#endif

static int proxy_check_timeout (struct SocketProxy_Conn_T *conn);

void
SocketProxy_config_defaults (SocketProxy_Config *config)
{
  assert (config != NULL);

  memset (config, 0, sizeof (*config));
#if SOCKET_HAS_TLS
  config->tls_ctx = NULL; /* Use secure defaults if not provided */
#endif
  config->type = SOCKET_PROXY_NONE;
  config->connect_timeout_ms = SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS;
  config->handshake_timeout_ms = SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS;
}

/**
 * proxy_alloc_from_arena - Allocate string from arena with overflow checks
 */
static char *
proxy_alloc_from_arena (Arena_T arena, size_t len)
{
  size_t total_size;

  if (!SocketSecurity_check_add (len, 1, &total_size)
      || !SocketSecurity_check_size (total_size))
    {
      RAISE_PROXY_ERROR_MSG (SocketProxy_Failed,
                             "Proxy URL component too long");
    }

  return Arena_alloc (arena, total_size, __FILE__, __LINE__);
}

/**
 * proxy_alloc_from_static - Allocate string from static buffer with
 * wrap-around
 */
static char *
proxy_alloc_from_static (size_t needed)
{
  /* Guard: Check total buffer overflow */
  if (proxy_static_total_used + needed > SOCKET_PROXY_STATIC_BUFFER_SIZE)
    {
      PROXY_ERROR_MSG ("Static buffer overflow in URL parsing (total used "
                       "%zu + %zu > %d)",
                       proxy_static_total_used,
                       needed,
                       SOCKET_PROXY_STATIC_BUFFER_SIZE);
      return NULL;
    }

  /* Wrap around if needed */
  if (proxy_static_offset + needed > SOCKET_PROXY_STATIC_BUFFER_SIZE)
    {
      proxy_static_offset = 0;
    }

  char *dst = proxy_static_buf + proxy_static_offset;
  proxy_static_offset += needed;
  proxy_static_total_used += needed;

  return dst;
}

/**
 * proxy_alloc_string - Allocate and copy string from arena or static buffer
 *
 * FLATTENED VERSION - Guard clauses at top level
 */
static char *
proxy_alloc_string (const char *src, size_t len, Arena_T arena)
{
  char *dst;

  /* Dispatch to appropriate allocator */
  if (arena != NULL)
    {
      dst = proxy_alloc_from_arena (arena, len);
    }
  else
    {
      size_t needed = len + 1;
      dst = proxy_alloc_from_static (needed);
    }

  /* Guard: Early return on allocation failure */
  if (dst == NULL)
    return NULL;

  /* Success path at normal indentation */
  memcpy (dst, src, len);
  dst[len] = '\0';
  return dst;
}

int
socketproxy_parse_scheme (const char *url,
                          SocketProxy_Config *config,
                          const char **end)
{
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
      config->type = SOCKET_PROXY_SOCKS5;
      config->port = SOCKET_PROXY_DEFAULT_SOCKS_PORT;
      *end = url + 8;
      return 0;
    }

  return -1;
}

/* Helper to validate string contains only printable ASCII */
static int
validate_printable_string (const char *str, const char *field_name)
{
  for (const char *s = str; *s; s++)
    {
      if (!isprint ((unsigned char)*s))
        {
          PROXY_ERROR_MSG ("Invalid character in %s", field_name);
          return -1;
        }
    }
  return 0;
}

/* Helper to parse username:password format */
static int
parse_username_password (const char *start,
                         const char *colon,
                         const char *at_sign,
                         SocketProxy_Config *config,
                         Arena_T arena)
{
  size_t user_len = (size_t)(colon - start);
  size_t pass_len = (size_t)(at_sign - colon - 1);

  if (user_len > SOCKET_PROXY_MAX_USERNAME_LEN)
    return -1;
  if (pass_len > SOCKET_PROXY_MAX_PASSWORD_LEN)
    return -1;

  config->username = proxy_alloc_string (start, user_len, arena);
  if (config->username == NULL)
    return -1;

  if (validate_printable_string (config->username, "username") < 0)
    return -1;

  config->password = proxy_alloc_string (colon + 1, pass_len, arena);
  if (config->password == NULL)
    return -1;

  if (validate_printable_string (config->password, "password") < 0)
    return -1;

  return 0;
}

/* Helper to parse username-only format */
static int
parse_username_only (const char *start,
                     const char *at_sign,
                     SocketProxy_Config *config,
                     Arena_T arena)
{
  size_t user_len = (size_t)(at_sign - start);

  if (user_len > SOCKET_PROXY_MAX_USERNAME_LEN)
    return -1;

  config->username = proxy_alloc_string (start, user_len, arena);
  if (config->username == NULL)
    return -1;

  if (validate_printable_string (config->username, "username") < 0)
    return -1;

  config->password = NULL;
  return 0;
}

int
socketproxy_parse_userinfo (const char *start,
                            SocketProxy_Config *config,
                            Arena_T arena,
                            const char **end)
{
  const char *at_sign;
  const char *colon;

  /* Guard: No userinfo present */
  at_sign = strchr (start, '@');
  if (at_sign == NULL)
    {
      *end = start;
      return 0;
    }

  /* Guard: Userinfo too long */
  size_t userinfo_len = (size_t)(at_sign - start);
  if (userinfo_len > SOCKET_PROXY_MAX_USERINFO_LEN)
    {
      PROXY_ERROR_MSG ("Userinfo too long (max %d)",
                       SOCKET_PROXY_MAX_USERINFO_LEN);
      return -1;
    }

  colon = memchr (start, ':', (size_t)(at_sign - start));

  /* Parse based on format: username:password or username-only */
  int result;
  if (colon != NULL && colon < at_sign)
    result = parse_username_password (start, colon, at_sign, config, arena);
  else
    result = parse_username_only (start, at_sign, config, arena);

  if (result < 0)
    return -1;

  *end = at_sign + 1;
  return 0;
}

/**
 * socketproxy_parse_ipv6_hostport - Parse IPv6 bracket notation [host]:port
 *
 * Extracts host and optional port from IPv6 bracket format.
 */
static int
socketproxy_parse_ipv6_hostport (const char *start,
                                 SocketProxy_Config *config,
                                 const char **host_start_out,
                                 const char **host_end_out,
                                 const char **authority_end_out)
{
  const char *bracket_close;
  const char *port_start;
  const char *authority_end;

  bracket_close = strchr (start, ']');
  if (bracket_close == NULL)
    return -1;

  *host_start_out = start + 1;
  *host_end_out = bracket_close;
  port_start = bracket_close + 1;
  authority_end = bracket_close + 1;

  if (*port_start == ':')
    {
      char *endptr;
      long p = strtol (port_start + 1, &endptr, 10);

      if (endptr == port_start + 1)
        return -1;

      if (*endptr != '\0' && *endptr != '/' && *endptr != '?' && *endptr != '#')
        return -1;

      if (p < 1 || p > SOCKET_MAX_PORT)
        return -1;

      config->port = (int)p;
      authority_end = endptr;
    }

  *authority_end_out = authority_end;
  return 0;
}

/**
 * socketproxy_parse_ipv4_hostport - Parse regular host:port format
 *
 * Extracts host and optional port from standard format.
 */
static int
socketproxy_parse_ipv4_hostport (const char *start,
                                 SocketProxy_Config *config,
                                 const char **host_start_out,
                                 const char **host_end_out,
                                 const char **authority_end_out)
{
  const char *authority_end;
  const char *host_end;
  const char *colon;

  *host_start_out = start;

  authority_end = start;
  while (*authority_end && *authority_end != '/' && *authority_end != '?'
         && *authority_end != '#')
    authority_end++;

  host_end = authority_end;

  colon = NULL;
  for (const char *p = start; p < authority_end; p++)
    {
      if (*p == ':')
        colon = p;
    }

  if (colon != NULL)
    {
      host_end = colon;
      char *endptr;
      long p = strtol (colon + 1, &endptr, 10);
      if (endptr <= colon + 1 || p < 1 || p > SOCKET_MAX_PORT)
        {
          return -1;
        }
      config->port = (int)p;
      if (endptr > authority_end)
        authority_end = endptr;
      if (config->port <= 0 || config->port > SOCKET_MAX_PORT)
        return -1;
    }

  *host_end_out = host_end;
  *authority_end_out = authority_end;
  return 0;
}

int
socketproxy_parse_hostport (const char *start,
                            SocketProxy_Config *config,
                            Arena_T arena,
                            size_t *consumed_out)
{
  const char *bracket_open;
  const char *host_start;
  const char *host_end;
  const char *authority_end;
  size_t host_len;

  bracket_open = strchr (start, '[');
  if (bracket_open == start)
    {
      if (socketproxy_parse_ipv6_hostport (
              start, config, &host_start, &host_end, &authority_end)
          < 0)
        return -1;
    }
  else
    {
      if (socketproxy_parse_ipv4_hostport (
              start, config, &host_start, &host_end, &authority_end)
          < 0)
        return -1;
    }

  host_len = (size_t)(host_end - host_start);
  if (host_len == 0 || host_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    return -1;

  if (strpbrk (host_start, "\r\n") != NULL)
    return -1;

  config->host = proxy_alloc_string (host_start, host_len, arena);
  if (config->host == NULL)
    return -1;

  if (consumed_out != NULL)
    *consumed_out = (size_t)(authority_end - start);

  return 0;
}

int
SocketProxy_parse_url (const char *url,
                       SocketProxy_Config *config,
                       Arena_T arena)
{
  const char *p;

  assert (config != NULL);

  if (url == NULL || *url == '\0')
    return -1;

  if (arena == NULL)
    {
      proxy_static_offset = 0;
      proxy_static_total_used = 0;
    }

  SocketProxy_config_defaults (config);

  if (socketproxy_parse_scheme (url, config, &p) < 0)
    return -1;

  if (socketproxy_parse_userinfo (p, config, arena, &p) < 0)
    return -1;

  {
    size_t consumed;
    if (socketproxy_parse_hostport (p, config, arena, &consumed) < 0)
      return -1;

    size_t remaining = strlen (p) - consumed;
    if (remaining > 0)
      {
        const char *after = p + consumed;
        while (*after && isspace ((unsigned char)*after))
          after++;
        if (*after != '\0')
          {
            PROXY_ERROR_MSG (
                "Invalid trailing characters in proxy URL after authority "
                "(e.g., path/query/fragment not allowed per RFC 3986)");
            return -1;
          }
      }
  }

  return 0;
}

void
socketproxy_set_error (struct SocketProxy_Conn_T *conn,
                       SocketProxy_Result result,
                       const char *fmt,
                       ...)
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
      TRY n = Socket_send (conn->socket,
                           conn->send_buf + conn->send_offset,
                           conn->send_len - conn->send_offset);
      EXCEPT (Socket_Closed)
      caught_closed = 1;
      END_TRY;

      /* Guard clause: handle connection closed */
      if (caught_closed)
        return -1;

      /* Guard clause: handle EAGAIN/EWOULDBLOCK (would block) */
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 1;

      /* Guard clause: handle other errors */
      if (n < 0)
        return -1;

      /* Main work: advance offset */
      conn->send_offset += (size_t)n;
    }

  return 0;
}

int
socketproxy_do_recv (struct SocketProxy_Conn_T *conn)
{
  volatile ssize_t n = 0;
  volatile int caught_closed = 0;
  size_t space;

  if (conn->recvbuf != NULL)
    {
      space = SocketBuf_space (conn->recvbuf);
    }
  else
    {
      space = sizeof (conn->recv_buf) - conn->recv_len;
    }
  if (space == 0)
    {
      return -1;
    }

  TRY
  {
    if (conn->recvbuf != NULL)
      {
        size_t wlen;
        void *ptr = SocketBuf_writeptr (conn->recvbuf, &wlen);
        if (ptr == NULL || wlen == 0)
          break;
        wlen = (wlen < space) ? wlen : space;
        n = Socket_recv (conn->socket, ptr, wlen);
        if (n > 0)
          SocketBuf_written (conn->recvbuf, (size_t)n);
      }
    else
      {
        n = Socket_recv (conn->socket, conn->recv_buf + conn->recv_len, space);
      }
  }
  EXCEPT (Socket_Closed)
  caught_closed = 1;
  END_TRY;

  if (caught_closed)
    return 0;

  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return -1;
    }
  if (n == 0)
    {
      return 0;
    }
  if (conn->recvbuf == NULL)
    {
      conn->recv_len += (size_t)n;
    }

  return (int)n;
}

void
socketproxy_advance_state (struct SocketProxy_Conn_T *conn)
{
  /* Guard clause: only process SEND states */
  if (conn->state != PROXY_STATE_HANDSHAKE_SEND
      && conn->state != PROXY_STATE_AUTH_SEND)
    return;

  /* Guard clause: only advance if send complete */
  if (conn->send_offset < conn->send_len)
    return;

  /* Determine next state based on current state */
  if (conn->state == PROXY_STATE_AUTH_SEND)
    conn->state = PROXY_STATE_AUTH_RECV;
  else
    conn->state = PROXY_STATE_HANDSHAKE_RECV;

  /* Reset buffers */
  conn->send_offset = 0;
  conn->send_len = 0;
  conn->recv_offset = 0;
  conn->recv_len = 0;
}

static int
proxy_validate_config (const SocketProxy_Config *proxy)
{
  if (proxy->type == SOCKET_PROXY_NONE || proxy->host == NULL)
    {
      if (proxy->type == SOCKET_PROXY_HTTPS && !SocketSecurity_has_tls ())
        {
          PROXY_ERROR_MSG ("HTTPS proxy requires TLS support (SOCKET_HAS_TLS)");
          RAISE_PROXY_ERROR (SocketProxy_Failed);
        }
      else
        {
          PROXY_ERROR_MSG ("Invalid proxy configuration");
          RAISE_PROXY_ERROR (SocketProxy_Failed);
        }
    }

  if (proxy->username)
    {
      size_t ulen = strlen (proxy->username);
      if (ulen > SOCKET_PROXY_MAX_USERNAME_LEN)
        {
          PROXY_ERROR_MSG ("Username too long (max %d): %zu",
                           SOCKET_PROXY_MAX_USERNAME_LEN,
                           ulen);
          RAISE_PROXY_ERROR (SocketProxy_Failed);
        }
      SocketCommon_validate_hostname (proxy->username, SocketProxy_Failed);
    }
  if (proxy->password)
    {
      size_t plen = strlen (proxy->password);
      if (plen > SOCKET_PROXY_MAX_PASSWORD_LEN)
        {
          PROXY_ERROR_MSG ("Password too long (max %d): %zu",
                           SOCKET_PROXY_MAX_PASSWORD_LEN,
                           plen);
          RAISE_PROXY_ERROR (SocketProxy_Failed);
        }
    }

  return 0;
}

static int
proxy_validate_target (const char *target_host, int target_port)
{
  size_t target_len = strlen (target_host);

  if (target_len == 0)
    {
      PROXY_ERROR_MSG ("Target hostname empty");
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  if (target_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    {
      PROXY_ERROR_MSG ("Target hostname too long (max %d)",
                       SOCKET_PROXY_MAX_HOSTNAME_LEN);
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  if (strpbrk (target_host, "\r\n") != NULL)
    {
      PROXY_ERROR_MSG (
          "Target hostname contains forbidden characters (CR or LF)");
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  if (target_port < 1 || target_port > SOCKET_MAX_PORT)
    {
      PROXY_ERROR_MSG (
          "Invalid target port %d (must be " SOCKET_PORT_VALID_RANGE ")",
          target_port);
      RAISE_PROXY_ERROR (SocketProxy_Failed);
    }
  return 0;
}

static void
proxy_init_context (struct SocketProxy_Conn_T *conn,
                    Arena_T arena,
                    const SocketProxy_Config *proxy,
                    const char *target_host,
                    int target_port)
{
  memset (conn, 0, sizeof (*conn));
  conn->arena = arena;
  conn->recvbuf = SocketBuf_new (arena, SOCKET_PROXY_BUFFER_SIZE);
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

#if SOCKET_HAS_TLS
  conn->tls_ctx = proxy->tls_ctx;
  conn->tls_enabled = 0; /* Set after successful handshake */
#endif

  conn->state = PROXY_STATE_IDLE;
  conn->proto_state = PROTO_STATE_INIT;
  conn->result = PROXY_IN_PROGRESS;
  conn->start_time_ms = socketproxy_get_time_ms ();
}

static int
proxy_build_initial_request (struct SocketProxy_Conn_T *conn)
{
  switch (conn->type)
    {
    case SOCKET_PROXY_SOCKS5:
    case SOCKET_PROXY_SOCKS5H:
      if (proxy_socks5_send_greeting (conn) < 0)
        {
          socketproxy_set_error (
              conn, PROXY_ERROR_PROTOCOL, "Failed to build SOCKS5 greeting");
          return -1;
        }
      break;

    case SOCKET_PROXY_SOCKS4:
      if (proxy_socks4_send_connect (conn) < 0)
        {
          socketproxy_set_error (
              conn, PROXY_ERROR_PROTOCOL, "Failed to build SOCKS4 request");
          return -1;
        }
      break;

    case SOCKET_PROXY_SOCKS4A:
      if (proxy_socks4a_send_connect (conn) < 0)
        {
          socketproxy_set_error (
              conn, PROXY_ERROR_PROTOCOL, "Failed to build SOCKS4a request");
          return -1;
        }
      break;

    case SOCKET_PROXY_HTTP:
    case SOCKET_PROXY_HTTPS:
      if (proxy_http_send_connect (conn) < 0)
        {
          socketproxy_set_error (conn,
                                 PROXY_ERROR_PROTOCOL,
                                 "Failed to build HTTP CONNECT request");
          return -1;
        }
      break;

    default:
      socketproxy_set_error (
          conn, PROXY_ERROR_UNSUPPORTED, "Unsupported proxy type");
      return -1;
    }

  return 0;
}

static int
proxy_connect_to_server_sync (struct SocketProxy_Conn_T *conn)
{
  SocketHE_Config_T he_config;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = conn->connect_timeout_ms;

  TRY conn->socket = SocketHappyEyeballs_connect (
      conn->proxy_host, conn->proxy_port, &he_config);
  EXCEPT (SocketHE_Failed)
  socketproxy_set_error (
      conn, PROXY_ERROR_CONNECT, "HappyEyeballs connection failed");
  return -1;
  END_TRY;

  if (conn->socket == NULL)
    {
      socketproxy_set_error (conn,
                             PROXY_ERROR_CONNECT,
                             "Failed to connect to proxy %s:%d",
                             conn->proxy_host,
                             conn->proxy_port);
      return -1;
    }

  return 0;
}

static int
proxy_start_async_connect (struct SocketProxy_Conn_T *conn)
{
  SocketHE_Config_T he_config;

  SocketHappyEyeballs_config_defaults (&he_config);
  he_config.total_timeout_ms = conn->connect_timeout_ms;

  TRY conn->he = SocketHappyEyeballs_start (conn->resolver,
                                            conn->poll,
                                            conn->proxy_host,
                                            conn->proxy_port,
                                            &he_config);
  EXCEPT (SocketHE_Failed)
  socketproxy_set_error (
      conn, PROXY_ERROR_CONNECT, "Failed to start async connection to proxy");
  return -1;
  END_TRY;

  if (conn->he == NULL)
    {
      socketproxy_set_error (conn,
                             PROXY_ERROR_CONNECT,
                             "Failed to start connection to proxy %s:%d",
                             conn->proxy_host,
                             conn->proxy_port);
      return -1;
    }

  conn->state = PROXY_STATE_CONNECTING_PROXY;
  return 0;
}

static int
proxy_setup_tls_to_proxy (struct SocketProxy_Conn_T *conn)
{
#if SOCKET_HAS_TLS
  if (conn->tls_ctx == NULL)
    {
      TRY
      {
        conn->tls_ctx = SocketTLSContext_new_client (NULL);

        const char *alpn_protos[] = { "http/1.1" };
        SocketTLSContext_set_alpn_protos (conn->tls_ctx, alpn_protos, 1);
      }
      EXCEPT (SocketTLS_Failed)
      {
        socketproxy_set_error (
            conn,
            PROXY_ERROR_PROTOCOL,
            "Failed to create TLS context for HTTPS proxy: %s",
            Socket_GetLastError ());
        return -1;
      }
      END_TRY;
    }

  SocketTLS_set_hostname (conn->socket, conn->proxy_host);

  conn->state = PROXY_STATE_TLS_TO_PROXY;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();
  return 0;
#else
  socketproxy_set_error (conn,
                         PROXY_ERROR_UNSUPPORTED,
                         "HTTPS proxy requires TLS support (SOCKET_HAS_TLS)");
  return -1;
#endif
}

static int
proxy_perform_sync_tls_handshake (struct SocketProxy_Conn_T *conn)
{
#if SOCKET_HAS_TLS
  int64_t deadline_ms
      = conn->handshake_start_time_ms + (int64_t)conn->handshake_timeout_ms;

  while (1)
    {
      /* Check timeout before each attempt */
      if (proxy_check_timeout (conn) < 0)
        return -1;

      TLSHandshakeState hs = SocketTLS_handshake (conn->socket);

      if (hs == TLS_HANDSHAKE_COMPLETE)
        {
          conn->tls_enabled = 1;
          return 0;
        }

      if (hs == TLS_HANDSHAKE_ERROR)
        {
          socketproxy_set_error (conn,
                                 PROXY_ERROR_PROTOCOL,
                                 "TLS handshake to proxy failed: %s",
                                 Socket_GetLastError ());
          return -1;
        }

      /* Handshake wants I/O - prepare to poll */
      unsigned events
          = (hs == TLS_HANDSHAKE_WANT_READ ? POLL_READ : POLL_WRITE);
      short poll_events = (events == POLL_READ ? POLLIN : POLLOUT);
      struct pollfd pfd;
      SOCKET_INIT_POLLFD (pfd, Socket_fd (conn->socket), poll_events);

      int64_t now_ms = socketproxy_get_time_ms ();
      int poll_to = (int)SocketTimeout_remaining_ms (deadline_ms - now_ms);

      int ret = poll (&pfd, 1, poll_to);

      /* Early continue for EINTR - reduces nesting */
      if (ret < 0 && errno == EINTR)
        continue;

      /* Handle poll errors */
      if (ret < 0)
        {
          socketproxy_set_error (
              conn,
              PROXY_ERROR,
              "poll failed during TLS handshake to proxy: %s",
              strerror (errno));
          return -1;
        }

      /* Handle poll timeout */
      if (ret == 0)
        {
          socketproxy_set_error (conn,
                                 PROXY_ERROR_TIMEOUT,
                                 "TLS handshake to proxy timeout (%d ms)",
                                 conn->handshake_timeout_ms);
          return -1;
        }

      /* Socket ready, loop to retry handshake */
    }
#else
  return -1;
#endif
}

static int
proxy_setup_after_tcp_connect (struct SocketProxy_Conn_T *conn, int sync_mode)
{
  if (conn->type != SOCKET_PROXY_HTTPS)
    {
      conn->state = PROXY_STATE_HANDSHAKE_SEND;
      conn->handshake_start_time_ms = socketproxy_get_time_ms ();
      return (proxy_build_initial_request (conn) == 0 ? 0 : -1);
    }

  if (proxy_setup_tls_to_proxy (conn) < 0)
    {
      return -1;
    }

  if (sync_mode)
    {
      if (proxy_perform_sync_tls_handshake (conn) < 0)
        {
          return -1;
        }
      conn->state = PROXY_STATE_HANDSHAKE_SEND;
      conn->handshake_start_time_ms = socketproxy_get_time_ms ();
      return (proxy_build_initial_request (conn) == 0 ? 0 : -1);
    }

  return 0;
}

/* ============================================================================
 * Async Connection - Lifecycle
 * ============================================================================
 */

SocketProxy_Conn_T
SocketProxy_Conn_start (SocketDNSResolver_T resolver,
                        SocketPoll_T poll,
                        const SocketProxy_Config *proxy,
                        const char *target_host,
                        int target_port)
{
  SocketProxy_Conn_T conn;
  Arena_T arena;

  assert (resolver != NULL);
  assert (poll != NULL);
  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= SOCKET_MAX_PORT);

  /* Validate inputs */
  proxy_validate_config (proxy);
  proxy_validate_target (target_host, target_port);

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

  conn->resolver = resolver;
  conn->poll = poll;
  conn->owns_resolver_poll = 0;

  if (proxy_start_async_connect (conn) < 0)
    return conn;

  return conn;
}

SocketProxy_Conn_T
SocketProxy_Conn_new (const SocketProxy_Config *proxy,
                      const char *target_host,
                      int target_port)
{
  SocketProxy_Conn_T conn;
  Arena_T arena;

  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= SOCKET_MAX_PORT);

  /* Validate inputs */
  proxy_validate_config (proxy);
  proxy_validate_target (target_host, target_port);

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

  if (proxy_connect_to_server_sync (conn) < 0)
    return conn;

  TRY
  {
    Socket_setnonblocking (conn->socket);
  }
  EXCEPT (Socket_Failed)
  {
    socketproxy_set_error (
        conn, PROXY_ERROR_CONNECT, "Failed to set socket non-blocking");
    return conn;
  }
  END_TRY;

  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();

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

  arena = c->arena;

  if (c->password != NULL)
    {
      SocketCrypto_secure_clear (c->password, strlen (c->password));
    }

  if (c->he != NULL)
    {
      SocketHappyEyeballs_free (&c->he);
    }

  if (c->socket != NULL && !c->transferred)
    {
      Socket_free (&c->socket);
    }

  if (c->http_parser != NULL)
    {
      SocketHTTP1_Parser_free (&c->http_parser);
    }

#if SOCKET_HAS_TLS
  if (c->tls_enabled && c->socket != NULL && !c->transferred)
    {
      SocketTLS_shutdown (c->socket);
    }
#endif

  if (c->owns_resolver_poll)
    {
      if (c->resolver != NULL)
        SocketDNSResolver_free (&c->resolver);
      if (c->poll != NULL)
        SocketPoll_free (&c->poll);
    }

  Arena_dispose (&arena);

  *conn = NULL;
}

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

  SocketCommon_clear_nonblock (Socket_fd (sock));

  return sock;
}

int
SocketProxy_Conn_fd (SocketProxy_Conn_T conn)
{
  assert (conn != NULL);

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
      return 0;

    case PROXY_STATE_TLS_TO_PROXY:
#if SOCKET_HAS_TLS
      {
        TLSHandshakeState hs = SocketTLS_handshake (conn->socket);
        if (hs == TLS_HANDSHAKE_WANT_READ)
          return POLL_READ;
        if (hs == TLS_HANDSHAKE_WANT_WRITE)
          return POLL_WRITE;
        return 0;
      }
#else
      return 0;
#endif

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

  if (conn->state == PROXY_STATE_CONNECTING_PROXY && conn->he != NULL)
    return SocketHappyEyeballs_next_timeout_ms (conn->he);

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

static int
proxy_check_timeout (struct SocketProxy_Conn_T *conn)
{
  int64_t elapsed = socketproxy_elapsed_ms (conn->handshake_start_time_ms);

  if (elapsed >= conn->handshake_timeout_ms)
    {
      socketproxy_set_error (conn,
                             PROXY_ERROR_TIMEOUT,
                             "Proxy handshake timeout (%d ms)",
                             conn->handshake_timeout_ms);
      return -1;
    }
  return 0;
}

/**
 * proxy_validate_he_context - Validate HappyEyeballs context exists
 */
static int
proxy_validate_he_context (struct SocketProxy_Conn_T *conn)
{
  if (conn->he == NULL)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_CONNECT, "No HappyEyeballs context");
      return -1;
    }
  return 0;
}

/**
 * proxy_extract_connected_socket - Extract socket from HappyEyeballs
 *
 * Retrieves the connected socket, frees the HE context,
 * and sets the socket to non-blocking mode.
 */
static int
proxy_extract_connected_socket (struct SocketProxy_Conn_T *conn)
{
  conn->socket = SocketHappyEyeballs_result (conn->he);
  SocketHappyEyeballs_free (&conn->he);

  if (conn->socket == NULL)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_CONNECT, "Failed to get socket from HappyEyeballs");
      return -1;
    }

  Socket_setnonblocking (conn->socket);
  return 0;
}

#if SOCKET_HAS_TLS
/**
 * proxy_create_tls_context_for_https - Create TLS context for HTTPS proxy
 *
 * Creates a new client TLS context with HTTP/1.1 ALPN if one doesn't exist.
 */
static int
proxy_create_tls_context_for_https (struct SocketProxy_Conn_T *conn)
{
  if (conn->tls_ctx == NULL)
    {
      TRY
      {
        conn->tls_ctx = SocketTLSContext_new_client (NULL);

        const char *alpn_protos[] = { "http/1.1" };
        SocketTLSContext_set_alpn_protos (conn->tls_ctx, alpn_protos, 1);
      }
      EXCEPT (SocketTLS_Failed)
      {
        socketproxy_set_error (conn,
                               PROXY_ERROR_PROTOCOL,
                               "Failed to create TLS context: %s",
                               Socket_GetLastError ());
        return -1;
      }
      END_TRY;
    }

  SocketTLS_set_hostname (conn->socket, conn->proxy_host);
  return 0;
}
#endif

/**
 * proxy_transition_to_handshake - Transition to appropriate handshake state
 *
 * For HTTPS proxies, transitions to TLS_TO_PROXY state.
 * For other proxies, transitions to HANDSHAKE_SEND state.
 */
static int
proxy_transition_to_handshake (struct SocketProxy_Conn_T *conn)
{
#if SOCKET_HAS_TLS
  if (conn->type == SOCKET_PROXY_HTTPS)
    {
      if (proxy_create_tls_context_for_https (conn) < 0)
        return -1;

      conn->state = PROXY_STATE_TLS_TO_PROXY;
      conn->handshake_start_time_ms = socketproxy_get_time_ms ();
      return 1;
    }
#endif

  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();

  if (proxy_build_initial_request (conn) < 0)
    return -1;

  return 1;
}

/**
 * proxy_handle_he_connection_failure - Handle HappyEyeballs connection failure
 */
static int
proxy_handle_he_connection_failure (struct SocketProxy_Conn_T *conn)
{
  const char *error = SocketHappyEyeballs_error (conn->he);
  socketproxy_set_error (conn,
                         PROXY_ERROR_CONNECT,
                         "Failed to connect to proxy: %s",
                         error ? error : "unknown error");
  SocketHappyEyeballs_free (&conn->he);
  return -1;
}

/**
 * proxy_process_connecting - Process CONNECTING_PROXY state
 *
 * Polls HappyEyeballs for connection completion. On success, extracts the
 * socket and transitions to the appropriate handshake state.
 */
static int
proxy_process_connecting (struct SocketProxy_Conn_T *conn)
{
  SocketHE_State he_state;

  if (proxy_validate_he_context (conn) < 0)
    return -1;

  SocketHappyEyeballs_process (conn->he);

  if (!SocketHappyEyeballs_poll (conn->he))
    return 0;

  he_state = SocketHappyEyeballs_state (conn->he);

  if (he_state == HE_STATE_CONNECTED)
    {
      if (proxy_extract_connected_socket (conn) < 0)
        return -1;

      return proxy_transition_to_handshake (conn);
    }

  return proxy_handle_he_connection_failure (conn);
}

static int
proxy_process_send (struct SocketProxy_Conn_T *conn)
{
  int ret = socketproxy_do_send (conn);

  if (ret < 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "Send failed: %s", strerror (errno));
      return -1;
    }
  if (ret == 0)
    socketproxy_advance_state (conn);

  return 0;
}

static int
proxy_socks5_send_connect_request (struct SocketProxy_Conn_T *conn)
{
  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->recv_len = 0;
  conn->recv_offset = 0;

  if (proxy_socks5_send_connect (conn) < 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "Failed to build connect");
      return -1;
    }
  return 0;
}

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
          socketproxy_set_error (
              conn, PROXY_ERROR_PROTOCOL, "Failed to build auth");
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

static SocketProxy_Result
proxy_socks5_process_recv (struct SocketProxy_Conn_T *conn)
{
  /* Handle auth receive state with guard clauses */
  if (conn->state == PROXY_STATE_AUTH_RECV)
    {
      SocketProxy_Result res = proxy_socks5_recv_auth (conn);

      /* Early return on non-OK results */
      if (res != PROXY_OK)
        return res;

      /* Success path at normal indentation */
      if (proxy_socks5_send_connect_request (conn) < 0)
        return PROXY_ERROR_PROTOCOL;

      return PROXY_IN_PROGRESS;
    }

  /* Dispatch based on protocol state */
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

static int
proxy_process_recv (struct SocketProxy_Conn_T *conn)
{
  int ret;
  SocketProxy_Result res;
  size_t avail;

  ret = socketproxy_do_recv (conn);
  if (ret < 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "Receive failed: %s", strerror (errno));
      return -1;
    }

  avail = (conn->recvbuf != NULL) ? SocketBuf_available (conn->recvbuf)
                                  : conn->recv_len;
  if (ret == 0 && avail == 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_PROTOCOL, "Connection closed by proxy");
      return -1;
    }

  if (conn->recvbuf != NULL && avail > 0)
    {
      size_t read_avail = avail;
      const void *ptr = SocketBuf_readptr (conn->recvbuf, &read_avail);
      if (ptr == NULL)
        return -1;
      avail = (read_avail > sizeof (conn->recv_buf)) ? sizeof (conn->recv_buf)
                                                     : read_avail;
      memcpy (conn->recv_buf, ptr, avail);
      conn->recv_len = avail;
      conn->recv_offset = 0;
    }

  res = proxy_dispatch_protocol_recv (conn);

  size_t consumed = conn->recv_offset;
  if (consumed > 0)
    {
      if (conn->recvbuf != NULL)
        {
          SocketBuf_consume (conn->recvbuf, consumed);
        }
      else
        {
          conn->recv_len -= consumed;
          memmove (conn->recv_buf, conn->recv_buf + consumed, conn->recv_len);
        }
      conn->recv_offset = 0;
    }

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

#if SOCKET_HAS_TLS
static void
proxy_process_tls_handshake (SocketProxy_Conn_T conn)
{
  if (proxy_check_timeout (conn) < 0)
    return;

  TLSHandshakeState hs = SocketTLS_handshake (conn->socket);

  /* Guard clause: Handle error state first */
  if (hs == TLS_HANDSHAKE_ERROR)
    {
      socketproxy_set_error (conn,
                             PROXY_ERROR_PROTOCOL,
                             "TLS handshake failed: %s",
                             Socket_GetLastError ());
      conn->state = PROXY_STATE_FAILED;
      return;
    }

  /* Guard clause: Nothing to do if still in progress */
  if (hs != TLS_HANDSHAKE_COMPLETE)
    return;

  /* Success path: flat and prominent */
  conn->tls_enabled = 1;
  conn->state = PROXY_STATE_HANDSHAKE_SEND;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();

  if (proxy_build_initial_request (conn) < 0)
    return;
}
#endif

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

    case PROXY_STATE_TLS_TO_PROXY:
#if SOCKET_HAS_TLS
      proxy_process_tls_handshake (conn);
#endif
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

static void
proxy_tunnel_init_context (struct SocketProxy_Conn_T *conn,
                           Socket_T socket,
                           const SocketProxy_Config *proxy,
                           const char *target_host,
                           int target_port,
                           Arena_T arena)
{
  memset (conn, 0, sizeof (*conn));
  conn->arena = arena;
  if (arena != NULL)
    conn->recvbuf = SocketBuf_new (arena, SOCKET_PROXY_BUFFER_SIZE);
  else
    conn->recvbuf = NULL;
#if SOCKET_HAS_TLS
  conn->tls_ctx = proxy->tls_ctx;
  conn->tls_enabled = 0;
#endif
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
}

static int
proxy_run_poll_loop (struct SocketProxy_Conn_T *conn, int fd)
{
  struct pollfd pfd;
  int timeout;
  int poll_result;

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

      poll_result = poll (&pfd, 1, timeout);

      /* Guard clause: retry on EINTR */
      if (poll_result < 0 && errno == EINTR)
        continue;

      /* Guard clause: error on poll failure */
      if (poll_result < 0)
        {
          socketproxy_set_error (conn, PROXY_ERROR, "poll failed");
          return -1;
        }

      SocketProxy_Conn_process (conn);
    }

  return 0;
}

/* ============================================================================
 * Synchronous API
 * ============================================================================
 */

#if SOCKET_HAS_TLS
/**
 * proxy_tunnel_ensure_tls_context - Create TLS context if not provided
 *
 * Creates a new client TLS context with HTTP/1.1 ALPN if conn->tls_ctx is NULL.
 */
static SocketProxy_Result
proxy_tunnel_ensure_tls_context (SocketProxy_Conn_T conn)
{
  if (conn->tls_ctx != NULL)
    return PROXY_OK;

  TRY
  {
    conn->tls_ctx = SocketTLSContext_new_client (NULL);

    const char *alpn_protos[] = { "http/1.1" };
    SocketTLSContext_set_alpn_protos (conn->tls_ctx, alpn_protos, 1);
  }
  EXCEPT (SocketTLS_Failed)
  {
    socketproxy_set_error (conn,
                           PROXY_ERROR_PROTOCOL,
                           "Failed to create TLS context: %s",
                           Socket_GetLastError ());
    return conn->result;
  }
  END_TRY;

  return PROXY_OK;
}

/**
 * proxy_tunnel_init_tls_state - Initialize TLS handshake state
 *
 * Sets the TLS hostname and transitions connection to TLS handshake state.
 */
static void
proxy_tunnel_init_tls_state (SocketProxy_Conn_T conn)
{
  SocketTLS_set_hostname (conn->socket, conn->proxy_host);
  conn->state = PROXY_STATE_TLS_TO_PROXY;
  conn->handshake_start_time_ms = socketproxy_get_time_ms ();
}

/**
 * proxy_tunnel_poll_for_io - Wait for I/O readiness with timeout
 *
 * Polls for the requested event with remaining timeout.
 * Returns 1 if ready, 0 if EINTR (retry), -1 on error/timeout.
 */
static int
proxy_tunnel_poll_for_io (SocketProxy_Conn_T conn,
                          int fd,
                          int64_t deadline_ms,
                          unsigned events)
{
  struct pollfd pfd;
  SOCKET_INIT_POLLFD (pfd, fd, (short)events);
  int64_t now_ms = socketproxy_get_time_ms ();
  int poll_to = (int)SocketTimeout_remaining_ms (deadline_ms - now_ms);

  if (poll_to <= 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_TIMEOUT, "TLS handshake timeout");
      return -1;
    }

  int ret = poll (&pfd, 1, poll_to);
  if (ret < 0)
    {
      if (errno == EINTR)
        return 0; /* Retry */

      socketproxy_set_error (
          conn, PROXY_ERROR, "poll failed during TLS: %s", strerror (errno));
      return -1;
    }

  if (ret == 0)
    {
      socketproxy_set_error (
          conn, PROXY_ERROR_TIMEOUT, "TLS handshake timeout");
      return -1;
    }

  return 1;
}

/**
 * proxy_tunnel_perform_handshake_loop - Execute TLS handshake loop
 *
 * Repeatedly attempts TLS handshake, polling for I/O as needed, until
 * completion, error, or timeout.
 */
static SocketProxy_Result
proxy_tunnel_perform_handshake_loop (SocketProxy_Conn_T conn,
                                     int fd,
                                     int64_t deadline_ms)
{
  while (1)
    {
      TLSHandshakeState hs = SocketTLS_handshake (conn->socket);

      if (hs == TLS_HANDSHAKE_COMPLETE)
        {
          conn->tls_enabled = 1;
          return PROXY_OK;
        }

      if (hs == TLS_HANDSHAKE_ERROR)
        {
          socketproxy_set_error (conn,
                                 PROXY_ERROR_PROTOCOL,
                                 "TLS handshake failed: %s",
                                 Socket_GetLastError ());
          return conn->result;
        }

      /* Need to wait for I/O */
      unsigned events = (hs == TLS_HANDSHAKE_WANT_READ ? POLLIN : POLLOUT);
      int poll_ret = proxy_tunnel_poll_for_io (conn, fd, deadline_ms, events);

      if (poll_ret == 0)
        continue; /* EINTR - retry handshake */

      if (poll_ret < 0)
        return conn->result;

      /* Socket ready, loop to retry handshake */
    }
}

/**
 * proxy_tunnel_tls_handshake - Perform TLS handshake for HTTPS proxy
 *
 * Handles TLS context creation and handshake loop with timeout.
 */
static SocketProxy_Result
proxy_tunnel_tls_handshake (SocketProxy_Conn_T conn, int fd)
{
  SocketProxy_Result result;

  result = proxy_tunnel_ensure_tls_context (conn);
  if (result != PROXY_OK)
    return result;

  proxy_tunnel_init_tls_state (conn);

  int64_t deadline_ms
      = conn->handshake_start_time_ms + conn->handshake_timeout_ms;

  return proxy_tunnel_perform_handshake_loop (conn, fd, deadline_ms);
}
#endif

SocketProxy_Result
SocketProxy_tunnel (Socket_T socket,
                    const SocketProxy_Config *proxy,
                    const char *target_host,
                    int target_port,
                    Arena_T arena /* optional, NULL ok */)
{
  struct SocketProxy_Conn_T conn_struct;
  struct SocketProxy_Conn_T *conn = &conn_struct;
  int fd;
  int was_nonblocking;
  int flags;
  SocketProxy_Result result = PROXY_OK;

  assert (socket != NULL);
  assert (proxy != NULL);
  assert (target_host != NULL);
  assert (target_port > 0 && target_port <= SOCKET_MAX_PORT);

  /* Early validation guards */
  if (proxy->type == SOCKET_PROXY_NONE)
    return PROXY_ERROR_UNSUPPORTED;

  size_t host_len = strlen (target_host);
  if (host_len == 0 || host_len > SOCKET_PROXY_MAX_HOSTNAME_LEN)
    return PROXY_ERROR_PROTOCOL;
  if (strpbrk (target_host, "\r\n") != NULL)
    return PROXY_ERROR_PROTOCOL;
  if (target_port < 1 || target_port > SOCKET_MAX_PORT)
    return PROXY_ERROR_PROTOCOL;

  proxy_tunnel_init_context (
      conn, socket, proxy, target_host, target_port, arena);

  fd = Socket_fd (socket);
  flags = fcntl (fd, F_GETFL);
  was_nonblocking = (flags >= 0 && (flags & O_NONBLOCK));

  if (!was_nonblocking)
    Socket_setnonblocking (socket);

    /* TLS handshake if needed */
#if SOCKET_HAS_TLS
  if (conn->type == SOCKET_PROXY_HTTPS)
    {
      result = proxy_tunnel_tls_handshake (conn, fd);
      if (result != PROXY_OK)
        goto cleanup;
    }
#endif

  /* Build and send initial request */
  if (proxy_build_initial_request (conn) < 0)
    {
      result = conn->result;
      goto cleanup;
    }

  /* Run the main poll loop */
  proxy_run_poll_loop (conn, fd);
  result = conn->result;

cleanup:
  /* Single cleanup point - restore blocking state */
  if (!was_nonblocking)
    SocketCommon_clear_nonblock (fd);

  return result;
}

static int
proxy_connect_poll_loop (SocketProxy_Conn_T conn)
{
  struct pollfd pfd;
  int timeout;
  int fd;

  while (!SocketProxy_Conn_poll (conn))
    {
      fd = SocketProxy_Conn_fd (conn);
      if (fd < 0)
        return -1;

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
          return -1;
        }

      SocketProxy_Conn_process (conn);
    }

  return 0;
}

Socket_T
SocketProxy_connect (const SocketProxy_Config *proxy,
                     const char *target_host,
                     int target_port)
{
  SocketProxy_Conn_T conn;
  volatile Socket_T result = NULL;

  assert (proxy != NULL);
  assert (target_host != NULL);

  TRY conn = SocketProxy_Conn_new (proxy, target_host, target_port);

  proxy_connect_poll_loop (conn);

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
    RAISE_PROXY_ERROR (SocketProxy_Failed);
  END_TRY;

  return result;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

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
