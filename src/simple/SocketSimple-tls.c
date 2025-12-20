/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-tls.c
 * @brief TLS implementation for Simple API.
 */

#include "SocketSimple-internal.h"

#include "socket/SocketCommon.h"

/* ============================================================================
 * TLS Options Init
 * ============================================================================
 */

void
Socket_simple_tls_options_init (SocketSimple_TLSOptions *opts)
{
  if (!opts)
    return;
  memset (opts, 0, sizeof (*opts));
  opts->verify_cert = 1;
  opts->timeout_ms = 30000;
}

#ifdef SOCKET_HAS_TLS

/* ============================================================================
 * TLS Client Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_connect_tls (const char *host, int port)
{
  return Socket_simple_connect_tls_ex (host, port, NULL);
}

SocketSimple_Socket_T
Socket_simple_connect_tls_ex (const char *host, int port,
                              const SocketSimple_TLSOptions *opts_param)
{
  volatile Socket_T sock = NULL;
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_Socket *handle = NULL;
  SocketSimple_TLSOptions opts_local;

  /* Copy options to local before TRY block to avoid longjmp issues */
  int timeout_ms;
  const char *ca_file;
  const char *client_cert;
  const char *client_key;
  int verify_cert;

  Socket_simple_clear_error ();

  if (!host || port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid host or port");
      return NULL;
    }

  if (!opts_param)
    {
      Socket_simple_tls_options_init (&opts_local);
      opts_param = &opts_local;
    }

  /* Copy values before TRY to avoid clobbering issues */
  timeout_ms = opts_param->timeout_ms;
  ca_file = opts_param->ca_file;
  client_cert = opts_param->client_cert;
  client_key = opts_param->client_key;
  verify_cert = opts_param->verify_cert;

  TRY
  {
    if (timeout_ms > 0)
      {
        sock = Socket_connect_tcp (host, port, timeout_ms);
      }
    else
      {
        sock = Socket_new (AF_INET, SOCK_STREAM, 0);
        Socket_connect (sock, host, port);
      }

    ctx = SocketTLSContext_new_client (ca_file);

    if (client_cert && client_key)
      {
        SocketTLSContext_load_certificate (ctx, client_cert, client_key);
      }

    if (!verify_cert)
      {
        SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
      }

    SocketTLS_enable (sock, ctx);
    SocketTLS_set_hostname (sock, host);
    SocketTLS_handshake_auto (sock);
  }
  EXCEPT (SocketTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "TLS handshake failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "Certificate verification failed");
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        if (ctx)
          SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
        if (sock)
          Socket_free ((Socket_T *)&sock);
      }
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
      Socket_free ((Socket_T *)&sock);
      return NULL;
    }

  handle->socket = sock;
  handle->tls_ctx = ctx;
  handle->is_tls = 1;
  handle->is_connected = 1;
  return handle;
}

int
Socket_simple_enable_tls (SocketSimple_Socket_T sock, const char *hostname)
{
  return Socket_simple_enable_tls_ex (sock, hostname, NULL);
}

int
Socket_simple_enable_tls_ex (SocketSimple_Socket_T sock, const char *hostname,
                             const SocketSimple_TLSOptions *opts_param)
{
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  SocketSimple_TLSOptions opts_local;

  /* Copy options to local before TRY block */
  const char *ca_file;
  int verify_cert;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !hostname)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "TLS already enabled");
      return -1;
    }

  if (!opts_param)
    {
      Socket_simple_tls_options_init (&opts_local);
      opts_param = &opts_local;
    }

  ca_file = opts_param->ca_file;
  verify_cert = opts_param->verify_cert;

  TRY
  {
    ctx = SocketTLSContext_new_client (ca_file);

    if (!verify_cert)
      {
        SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
      }

    SocketTLS_enable (sock->socket, ctx);
    SocketTLS_set_hostname (sock->socket, hostname);
    SocketTLS_handshake_auto (sock->socket);
  }
  EXCEPT (SocketTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "TLS handshake failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && ctx)
      SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
  }
  END_TRY;

  if (exception_occurred)
    return -1;

  sock->tls_ctx = ctx;
  sock->is_tls = 1;
  return 0;
}

/* ============================================================================
 * TLS Information
 * ============================================================================
 */

int
Socket_simple_is_tls (SocketSimple_Socket_T sock)
{
  return sock ? sock->is_tls : 0;
}

const char *
Socket_simple_get_alpn (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return NULL;
    }
  return SocketTLS_get_alpn_selected (sock->socket);
}

const char *
Socket_simple_get_tls_version (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return NULL;
    }
  return SocketTLS_get_version (sock->socket);
}

int
Socket_simple_get_cert_info (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  if (!sock || !sock->socket || !sock->is_tls || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  SocketTLS_CertInfo info;
  int ret = SocketTLS_get_peer_cert_info (sock->socket, &info);
  if (ret == 1)
    {
      snprintf (buf, len, "Subject: %s\nIssuer: %s\nFingerprint: %s",
                info.subject, info.issuer, info.fingerprint);
      return 0;
    }
  else if (ret == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "No peer certificate");
      return -1;
    }
  simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Failed to get certificate info");
  return -1;
}

int
Socket_simple_get_cert_cn (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  if (!sock || !sock->socket || !sock->is_tls || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  int ret = SocketTLS_get_cert_subject (sock->socket, buf, len);
  if (ret > 0)
    {
      return 0;
    }
  else if (ret == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "No peer certificate");
      return -1;
    }
  simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                    "Failed to get certificate subject");
  return -1;
}

/* ============================================================================
 * TLS Server Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_listen_tls (const char *host, int port, int backlog,
                          const char *cert_file, const char *key_file)
{
  volatile Socket_T sock = NULL;
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_Socket *handle = NULL;

  Socket_simple_clear_error ();

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  if (!cert_file || !key_file)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Certificate and key files required");
      return NULL;
    }

  TRY
  {
    /* Use library convenience function - handles address family automatically
     */
    sock = Socket_listen_tcp (host ? host : "0.0.0.0", port,
                              backlog > 0 ? backlog : 128);

    /* Create server TLS context */
    ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
  }
  EXCEPT (SocketTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                      "Failed to create TLS server context");
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (err == EADDRINUSE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_BIND, "Address already in use");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_LISTEN, "Listen failed");
      }
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        if (ctx)
          SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
        if (sock)
          Socket_free ((Socket_T *)&sock);
      }
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketTLSContext_free ((SocketTLSContext_T *)&ctx);
      Socket_free ((Socket_T *)&sock);
      return NULL;
    }

  handle->socket = sock;
  handle->tls_ctx = ctx;
  handle->is_tls = 1;
  handle->is_server = 1;
  handle->is_connected = 0;
  return handle;
}

SocketSimple_Socket_T
Socket_simple_accept_tls (SocketSimple_Socket_T server)
{
  volatile Socket_T client = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_Socket *handle = NULL;

  Socket_simple_clear_error ();

  if (!server || !server->socket || !server->tls_ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid TLS server socket");
      return NULL;
    }

  if (!server->is_server || !server->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Socket is not a TLS server");
      return NULL;
    }

  TRY
  {
    /* Accept the connection */
    client = Socket_accept (server->socket);

    /* Enable TLS on the accepted socket using server's context */
    SocketTLS_enable (client, server->tls_ctx);

    /* Perform TLS handshake */
    SocketTLS_handshake_auto (client);
  }
  EXCEPT (SocketTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error during accept");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                      "TLS handshake failed during accept");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "Client certificate verification failed");
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && client)
      {
        SocketTLS_disable (client);
        Socket_free ((Socket_T *)&client);
      }
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SocketTLS_disable (client);
      Socket_free ((Socket_T *)&client);
      return NULL;
    }

  handle->socket = client;
  handle->tls_ctx = NULL; /* Client doesn't own the context, server does */
  handle->is_tls = 1;
  handle->is_server = 0;
  handle->is_connected = 1;
  return handle;
}

#else /* !SOCKET_HAS_TLS */

/* ============================================================================
 * TLS Stubs (when TLS disabled)
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_connect_tls (const char *host, int port)
{
  (void)host;
  (void)port;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_connect_tls_ex (const char *host, int port,
                              const SocketSimple_TLSOptions *opts)
{
  (void)host;
  (void)port;
  (void)opts;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

int
Socket_simple_enable_tls (SocketSimple_Socket_T sock, const char *hostname)
{
  (void)sock;
  (void)hostname;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_enable_tls_ex (SocketSimple_Socket_T sock, const char *hostname,
                             const SocketSimple_TLSOptions *opts)
{
  (void)sock;
  (void)hostname;
  (void)opts;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_is_tls (SocketSimple_Socket_T sock)
{
  (void)sock;
  return 0;
}

const char *
Socket_simple_get_alpn (SocketSimple_Socket_T sock)
{
  (void)sock;
  return NULL;
}

const char *
Socket_simple_get_tls_version (SocketSimple_Socket_T sock)
{
  (void)sock;
  return NULL;
}

int
Socket_simple_get_cert_info (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_get_cert_cn (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

SocketSimple_Socket_T
Socket_simple_listen_tls (const char *host, int port, int backlog,
                          const char *cert_file, const char *key_file)
{
  (void)host;
  (void)port;
  (void)backlog;
  (void)cert_file;
  (void)key_file;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_accept_tls (SocketSimple_Socket_T server)
{
  (void)server;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

#endif /* SOCKET_HAS_TLS */
