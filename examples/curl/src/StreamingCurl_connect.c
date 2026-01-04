/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_connect.c
 * @brief Connection establishment layer for streaming curl module.
 *
 * Implements connection establishment with:
 * - Happy Eyeballs for dual-stack racing (RFC 8305)
 * - Proxy tunneling (SOCKS4/5, HTTP CONNECT)
 * - TLS handshake with ALPN for HTTP/2 negotiation
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketHappyEyeballs.h"
#include "socket/SocketProxy.h"

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#endif

#include <stdlib.h>
#include <string.h>

/* Connection timeout and protocol constants */
#define ATTEMPT_TIMEOUT_DIVISOR 2
#define DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS 30000
#define ALPN_PROTOCOL_COUNT_HTTP2 2
#define ALPN_PROTOCOL_COUNT_HTTP1 1

/**
 * @brief Allocate a connection structure from arena.
 */
static CurlConnection *
alloc_connection (Arena_T arena)
{
  CurlConnection *conn = ALLOC (arena, sizeof (CurlConnection));
  memset (conn, 0, sizeof (*conn));
  return conn;
}

/**
 * @brief Establish TCP connection using Happy Eyeballs.
 */
static Socket_T
connect_direct (const char *host, int port, const CurlOptions *options)
{
  SocketHE_Config_T he_config;
  SocketHappyEyeballs_config_defaults (&he_config);

  /* Apply curl options to Happy Eyeballs config */
  if (options->connect_timeout_ms > 0)
    {
      he_config.total_timeout_ms = options->connect_timeout_ms;
      he_config.attempt_timeout_ms = options->connect_timeout_ms / ATTEMPT_TIMEOUT_DIVISOR;
    }

  if (options->dns_timeout_ms > 0)
    {
      he_config.dns_timeout_ms = options->dns_timeout_ms;
    }

  /* Perform Happy Eyeballs connection */
  return SocketHappyEyeballs_connect (host, port, &he_config);
}

/**
 * @brief Establish TCP connection through proxy.
 */
static Socket_T
connect_via_proxy (const char *host, int port, const CurlOptions *options,
                   Arena_T arena)
{
  if (!options->proxy_url)
    return NULL;

  SocketProxy_Config proxy_config;
  SocketProxy_config_defaults (&proxy_config);

  /* Parse proxy URL */
  if (SocketProxy_parse_url (options->proxy_url, &proxy_config, arena) != 0)
    {
      return NULL;
    }

  /* Apply timeouts */
  if (options->connect_timeout_ms > 0)
    {
      proxy_config.connect_timeout_ms = options->connect_timeout_ms;
      proxy_config.handshake_timeout_ms = options->connect_timeout_ms;
    }

  /* Connect through proxy */
  return SocketProxy_connect (&proxy_config, host, port);
}

#if SOCKET_HAS_TLS
/**
 * @brief Create TLS context for client connection.
 */
static SocketTLSContext_T
create_tls_context (const CurlOptions *options)
{
  SocketTLSContext_T ctx;

  /* Use provided context if available */
  if (options->tls_context)
    {
      return options->tls_context;
    }

  /* Create new client context */
  ctx = SocketTLSContext_new_client (NULL);

  /* Configure verification */
  if (!options->verify_ssl)
    {
      SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
    }

  /* Set ALPN protocols for HTTP/2 negotiation */
  if (options->max_version >= HTTP_VERSION_2)
    {
      const char *protos[] = { "h2", "http/1.1" };
      SocketTLSContext_set_alpn_protos (ctx, protos, ALPN_PROTOCOL_COUNT_HTTP2);
    }
  else
    {
      const char *protos[] = { "http/1.1" };
      SocketTLSContext_set_alpn_protos (ctx, protos, ALPN_PROTOCOL_COUNT_HTTP1);
    }

  return ctx;
}

/**
 * @brief Perform TLS handshake on socket.
 */
static int
perform_tls_handshake (Socket_T socket, const char *hostname,
                       SocketTLSContext_T ctx, const CurlOptions *options)
{
  /* Enable TLS on socket */
  SocketTLS_enable (socket, ctx);

  /* Set SNI hostname */
  SocketTLS_set_hostname (socket, hostname);

  /* Perform handshake with timeout */
  int timeout_ms
      = options->connect_timeout_ms > 0 ? options->connect_timeout_ms : DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS;
  TLSHandshakeState state = SocketTLS_handshake_loop (socket, timeout_ms);

  if (state != TLS_HANDSHAKE_COMPLETE)
    {
      return -1;
    }

  /* Verify certificate if required */
  if (options->verify_ssl)
    {
      long verify_result = SocketTLS_get_verify_result (socket);
      if (verify_result != 0)
        {
          return -1;
        }
    }

  return 0;
}

#endif /* SOCKET_HAS_TLS */

CurlConnection *
curl_connect (const CurlParsedURL *url, const CurlOptions *options,
              Arena_T arena)
{
  if (!url || !options || !arena)
    return NULL;

  CurlConnection *conn = alloc_connection (arena);
  volatile Socket_T sock = NULL;

  TRY
  {
    /* Get host and port */
    int port = url->port > 0 ? url->port : (url->is_secure ? CURL_HTTPS_DEFAULT_PORT : CURL_HTTP_DEFAULT_PORT);

    /* Step 1: Establish TCP connection */
    if (options->proxy_url)
      {
        /* Connect through proxy */
        sock = connect_via_proxy (url->host, port, options, arena);
        if (!sock)
          {
            RAISE (Curl_ConnectFailed);
          }
      }
    else
      {
        /* Direct connection with Happy Eyeballs */
        sock = connect_direct (url->host, port, options);
      }

    conn->socket = sock;
    sock = NULL; /* Transfer ownership - don't close in FINALLY */
    conn->connected = 1;

    /* Step 2: TLS handshake if HTTPS */
    if (url->is_secure)
      {
#if SOCKET_HAS_TLS
        /* Create or use provided TLS context */
        volatile SocketTLSContext_T tls_ctx = create_tls_context (options);
        if (!tls_ctx)
          {
            RAISE (Curl_TLSFailed);
          }

        /* Track if we own the context */
        conn->owns_tls_context = (options->tls_context == NULL);
        conn->tls_context = tls_ctx;

        /* Perform TLS handshake */
        if (perform_tls_handshake (conn->socket, url->host, tls_ctx, options) != 0)
          {
            RAISE (Curl_TLSFailed);
          }

        conn->is_tls = 1;

        /* Step 3: Check ALPN result for HTTP/2 */
        const char *alpn = SocketTLS_get_alpn_selected (conn->socket);
        if (alpn && strcmp (alpn, "h2") == 0)
          {
            conn->http_version = HTTP_VERSION_2;
          }
        else
          {
            conn->http_version = HTTP_VERSION_1_1;
          }
#else
        /* TLS not available */
        RAISE (Curl_TLSFailed);
#endif
      }
    else
      {
        /* Plain HTTP */
        conn->is_tls = 0;
        conn->http_version = HTTP_VERSION_1_1;

        /* HTTP/2 cleartext (h2c) not supported by default */
        if (options->max_version >= HTTP_VERSION_2
            && options->allow_http2_cleartext)
          {
            /* Would require h2c upgrade, not implemented yet */
            conn->http_version = HTTP_VERSION_1_1;
          }
      }

    /* Store connection info for reuse checking */
    conn->host = curl_arena_strdup (arena, url->host, url->host_len);
    conn->port = port;
    conn->reusable = 1;
  }
  EXCEPT (SocketHE_Failed) { RAISE (Curl_DNSFailed); }
  EXCEPT (SocketProxy_Failed) { RAISE (Curl_ConnectFailed); }
#if SOCKET_HAS_TLS
  EXCEPT (SocketTLS_Failed) { RAISE (Curl_TLSFailed); }
  EXCEPT (SocketTLS_HandshakeFailed) { RAISE (Curl_TLSFailed); }
  EXCEPT (SocketTLS_VerifyFailed) { RAISE (Curl_TLSFailed); }
#endif
  FINALLY
  {
    /* Clean up socket if we still own it (exception occurred before transfer)
     */
    if (sock)
      {
        Socket_T s = (Socket_T)sock;
        Socket_free (&s);
      }
  }
  END_TRY;

  return conn;
}

void
curl_connection_close (CurlConnection *conn)
{
  if (!conn)
    return;

  if (conn->socket)
    {
#if SOCKET_HAS_TLS
      if (conn->is_tls)
        {
          /* Best-effort TLS shutdown */
          SocketTLS_disable (conn->socket);
        }

      /* Free TLS context if we own it */
      if (conn->owns_tls_context && conn->tls_context)
        {
          SocketTLSContext_free (&conn->tls_context);
        }
#endif

      /* Close and free socket */
      Socket_free (&conn->socket);
    }

  conn->connected = 0;
  conn->reusable = 0;
}

int
curl_connection_reusable (const CurlConnection *conn, const CurlParsedURL *url)
{
  if (!conn || !url)
    return 0;

  /* Must be connected and marked reusable */
  if (!conn->connected || !conn->reusable)
    return 0;

  /* Check TLS requirement match */
  if (url->is_secure != conn->is_tls)
    return 0;

  /* Check host match */
  if (!conn->host || !url->host)
    return 0;

  if (conn->host && url->host)
    {
      if (url->host_len != strlen (conn->host))
        return 0;
      if (strncasecmp (conn->host, url->host, url->host_len) != 0)
        return 0;
    }

  /* Check port match */
  int target_port = url->port > 0 ? url->port : (url->is_secure ? CURL_HTTPS_DEFAULT_PORT : CURL_HTTP_DEFAULT_PORT);
  if (conn->port != target_port)
    return 0;

  return 1;
}

const char *
curl_connection_alpn (const CurlConnection *conn)
{
  if (!conn)
    return NULL;

#if SOCKET_HAS_TLS
  if (conn->is_tls && conn->socket)
    {
      return SocketTLS_get_alpn_selected (conn->socket);
    }
#endif

  return NULL;
}

int
curl_connection_is_http2 (const CurlConnection *conn)
{
  if (!conn)
    return 0;

  return conn->http_version == HTTP_VERSION_2;
}
