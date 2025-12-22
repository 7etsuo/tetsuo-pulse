/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-dtls.c
 * @brief DTLS (Datagram TLS) implementation for Simple API.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-dtls.h"

#ifdef SOCKET_HAS_TLS

#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSContext.h"

/*============================================================================
 * Options Helpers
 *============================================================================*/

void
Socket_simple_dtls_options_defaults (SocketSimple_DTLSOptions *opts)
{
  if (!opts)
    return;

  opts->timeout_ms = 30000;
  opts->verify_cert = 1;
  opts->ca_file = NULL;
  opts->ca_path = NULL;
  opts->client_cert = NULL;
  opts->client_key = NULL;
  opts->mtu = 0; /* Use default 1400 */
  opts->alpn = NULL;
  opts->alpn_count = 0;
}

/*============================================================================
 * DTLS Client Functions
 *============================================================================*/

SocketSimple_Socket_T
Socket_simple_dtls_connect (const char *host, int port)
{
  return Socket_simple_dtls_connect_ex (host, port, NULL);
}

SocketSimple_Socket_T
Socket_simple_dtls_connect_ex (const char *host, int port,
                               const SocketSimple_DTLSOptions *opts_param)
{
  volatile SocketDgram_T dgram = NULL;
  volatile SocketDTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;

  /* Copy options before TRY to avoid longjmp clobbering */
  SocketSimple_DTLSOptions opts_local;
  int timeout_ms;
  int verify_cert;
  const char *ca_file;
  const char *client_cert;
  const char *client_key;
  size_t mtu;
  const char **alpn;
  size_t alpn_count;

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

  if (!opts_param)
    {
      Socket_simple_dtls_options_defaults (&opts_local);
      opts_param = &opts_local;
    }

  /* Copy all values before TRY block */
  timeout_ms = opts_param->timeout_ms;
  verify_cert = opts_param->verify_cert;
  ca_file = opts_param->ca_file;
  client_cert = opts_param->client_cert;
  client_key = opts_param->client_key;
  mtu = opts_param->mtu;
  alpn = opts_param->alpn;
  alpn_count = opts_param->alpn_count;

  TRY
  {
    /* Create UDP socket */
    dgram = SocketDgram_new (AF_INET, 0);

    /* Connect UDP socket to peer */
    SocketDgram_connect (dgram, host, port);

    /* Create DTLS context */
    ctx = SocketDTLSContext_new_client (ca_file);

    /* Configure verification */
    if (!verify_cert)
      {
        SocketDTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
      }

    /* Load client cert if specified (for mTLS) */
    if (client_cert && client_key)
      {
        SocketDTLSContext_load_certificate (ctx, client_cert, client_key);
      }

    /* Set MTU if specified */
    if (mtu > 0)
      {
        SocketDTLSContext_set_mtu (ctx, mtu);
      }

    /* Set ALPN protocols if specified */
    if (alpn && alpn_count > 0)
      {
        SocketDTLSContext_set_alpn_protos (ctx, alpn, alpn_count);
      }

    /* Enable DTLS on socket */
    SocketDTLS_enable (dgram, ctx);
    ctx = NULL; /* Context now owned by socket */

    /* Set hostname for SNI and verification */
    SocketDTLS_set_hostname (dgram, host);

    /* Perform blocking handshake */
    DTLSHandshakeState state
        = SocketDTLS_handshake_loop (dgram, timeout_ms);
    if (state != DTLS_HANDSHAKE_COMPLETE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                          "DTLS handshake failed");
        exception_occurred = 1;
      }
  }
  EXCEPT (SocketDTLS_VerifyFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "DTLS certificate verification failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketDTLS_TimeoutExpired)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "DTLS handshake timed out");
    exception_occurred = 1;
  }
  EXCEPT (SocketDTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "DTLS handshake failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS operation failed");
    exception_occurred = 1;
  }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT,
                            "UDP socket operation failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        if (ctx)
          SocketDTLSContext_free ((SocketDTLSContext_T *)&ctx);
        if (dgram)
          SocketDgram_free ((SocketDgram_T *)&dgram);
      }
  }
  END_TRY;

  if (exception_occurred)
    return NULL;

  /* Create simple handle */
  SocketSimple_Socket_T handle = simple_create_udp_handle (dgram);
  if (!handle)
    {
      SocketDgram_free ((SocketDgram_T *)&dgram);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Failed to create handle");
      return NULL;
    }

  handle->is_tls = 1;
  handle->is_connected = 1;

  return handle;
}

int
Socket_simple_dtls_enable (SocketSimple_Socket_T sock, const char *hostname,
                           const SocketSimple_DTLSOptions *opts_param)
{
  volatile SocketDTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;

  /* Copy options before TRY to avoid longjmp clobbering */
  SocketSimple_DTLSOptions opts_local;
  const char *ca_file;
  int verify_cert;
  const char *client_cert;
  const char *client_key;
  size_t mtu;
  const char **alpn;
  size_t alpn_count;

  Socket_simple_clear_error ();

  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Socket is not a UDP socket");
      return -1;
    }

  if (sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "DTLS already enabled on socket");
      return -1;
    }

  if (!opts_param)
    {
      Socket_simple_dtls_options_defaults (&opts_local);
      opts_param = &opts_local;
    }

  /* Copy all values before TRY block */
  ca_file = opts_param->ca_file;
  verify_cert = opts_param->verify_cert;
  client_cert = opts_param->client_cert;
  client_key = opts_param->client_key;
  mtu = opts_param->mtu;
  alpn = opts_param->alpn;
  alpn_count = opts_param->alpn_count;

  TRY
  {
    /* Create client context */
    ctx = SocketDTLSContext_new_client (ca_file);

    if (!verify_cert)
      {
        SocketDTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
      }

    if (client_cert && client_key)
      {
        SocketDTLSContext_load_certificate (ctx, client_cert, client_key);
      }

    if (mtu > 0)
      {
        SocketDTLSContext_set_mtu (ctx, mtu);
      }

    if (alpn && alpn_count > 0)
      {
        SocketDTLSContext_set_alpn_protos (ctx, alpn, alpn_count);
      }

    /* Enable DTLS */
    SocketDTLS_enable (sock->dgram, ctx);
    ctx = NULL;

    /* Set hostname if provided */
    if (hostname)
      {
        SocketDTLS_set_hostname (sock->dgram, hostname);
      }

    sock->is_tls = 1;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Failed to enable DTLS");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred && ctx)
      SocketDTLSContext_free ((SocketDTLSContext_T *)&ctx);
  }
  END_TRY;

  return exception_occurred ? -1 : 0;
}

/*============================================================================
 * DTLS Server Functions
 *============================================================================*/

SocketSimple_Socket_T
Socket_simple_dtls_listen (const char *host, int port, const char *cert_file,
                           const char *key_file)
{
  volatile SocketDgram_T dgram = NULL;
  volatile SocketDTLSContext_T ctx = NULL;

  Socket_simple_clear_error ();

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  if (!cert_file || !key_file)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Certificate and key required for DTLS server");
      return NULL;
    }

  TRY
  {
    /* Create UDP socket */
    dgram = SocketDgram_new (AF_INET, 0);

    /* Bind to address */
    SocketDgram_bind (dgram, host, port);

    /* Create server context */
    ctx = SocketDTLSContext_new_server (cert_file, key_file, NULL);

    /* Enable cookie exchange for DoS protection */
    SocketDTLSContext_enable_cookie_exchange (ctx);

    /* Enable DTLS on socket */
    SocketDTLS_enable (dgram, ctx);
    ctx = NULL;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                      "Failed to create DTLS server context");
    if (ctx)
      SocketDTLSContext_free ((SocketDTLSContext_T *)&ctx);
    if (dgram)
      SocketDgram_free ((SocketDgram_T *)&dgram);
    return NULL;
  }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_BIND, "Failed to bind UDP socket");
    if (ctx)
      SocketDTLSContext_free ((SocketDTLSContext_T *)&ctx);
    if (dgram)
      SocketDgram_free ((SocketDgram_T *)&dgram);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_udp_handle (dgram);
  if (!handle)
    {
      SocketDgram_free ((SocketDgram_T *)&dgram);
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Failed to create handle");
      return NULL;
    }

  handle->is_tls = 1;
  handle->is_server = 1;

  return handle;
}

SocketSimple_Socket_T
Socket_simple_dtls_accept (SocketSimple_Socket_T server_sock, int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!server_sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid server socket");
      return NULL;
    }

  if (!server_sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Server socket is not UDP");
      return NULL;
    }

  if (!server_sock->is_server)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Socket is not a server socket");
      return NULL;
    }

  TRY
  {
    /* Wait for client hello */
    DTLSHandshakeState state = SocketDTLS_listen (server_sock->dgram);

    if (state == DTLS_HANDSHAKE_ERROR)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Failed to receive ClientHello");
        return NULL;
      }

    /* Complete handshake */
    state = SocketDTLS_handshake_loop (server_sock->dgram,
                                       timeout_ms > 0 ? timeout_ms : 30000);

    if (state != DTLS_HANDSHAKE_COMPLETE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                          "DTLS handshake with client failed");
        return NULL;
      }
  }
  EXCEPT (SocketDTLS_TimeoutExpired)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "DTLS accept timed out");
    return NULL;
  }
  EXCEPT (SocketDTLS_CookieFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS cookie verification failed");
    return NULL;
  }
  EXCEPT (SocketDTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                      "DTLS handshake with client failed");
    return NULL;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS accept failed");
    return NULL;
  }
  END_TRY;

  /* For DTLS, we return the same socket handle after handshake
   * (connectionless - unlike TCP accept) */
  server_sock->is_connected = 1;
  return server_sock;
}

/*============================================================================
 * DTLS I/O Functions
 *============================================================================*/

ssize_t
Socket_simple_dtls_send (SocketSimple_Socket_T sock, const void *data,
                         size_t len)
{
  Socket_simple_clear_error ();

  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Not a UDP socket");
      return -1;
    }

  if (!sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "DTLS not enabled on socket");
      return -1;
    }

  if (!data && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid data buffer");
      return -1;
    }

  ssize_t sent = 0;
  TRY { sent = SocketDTLS_send (sock->dgram, data, len); }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "DTLS send failed");
    return -1;
  }
  END_TRY;

  return sent;
}

ssize_t
Socket_simple_dtls_recv (SocketSimple_Socket_T sock, void *buf, size_t len)
{
  Socket_simple_clear_error ();

  if (!sock)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Not a UDP socket");
      return -1;
    }

  if (!sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "DTLS not enabled on socket");
      return -1;
    }

  if (!buf && len > 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid buffer");
      return -1;
    }

  ssize_t received = 0;
  TRY { received = SocketDTLS_recv (sock->dgram, buf, len); }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "DTLS recv failed");
    return -1;
  }
  END_TRY;

  return received;
}

ssize_t
Socket_simple_dtls_sendto (SocketSimple_Socket_T sock, const void *data,
                           size_t len, const char *host, int port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid DTLS socket");
      return -1;
    }

  if (!host || port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid destination");
      return -1;
    }

  ssize_t sent = 0;
  TRY { sent = SocketDTLS_sendto (sock->dgram, data, len, host, port); }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "DTLS sendto failed");
    return -1;
  }
  END_TRY;

  return sent;
}

ssize_t
Socket_simple_dtls_recvfrom (SocketSimple_Socket_T sock, void *buf, size_t len,
                             char *host, size_t host_len, int *port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid DTLS socket");
      return -1;
    }

  ssize_t received = 0;
  TRY
  {
    received = SocketDTLS_recvfrom (sock->dgram, buf, len, host, host_len, port);
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "DTLS recvfrom failed");
    return -1;
  }
  END_TRY;

  return received;
}

/*============================================================================
 * DTLS Control Functions
 *============================================================================*/

int
Socket_simple_dtls_handshake (SocketSimple_Socket_T sock, int timeout_ms)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid DTLS socket");
      return -1;
    }

  if (SocketDTLS_is_handshake_done (sock->dgram))
    {
      return 0; /* Already done */
    }

  TRY
  {
    DTLSHandshakeState state
        = SocketDTLS_handshake_loop (sock->dgram,
                                     timeout_ms > 0 ? timeout_ms : 30000);

    if (state != DTLS_HANDSHAKE_COMPLETE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                          "DTLS handshake failed");
        return -1;
      }
  }
  EXCEPT (SocketDTLS_TimeoutExpired)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "DTLS handshake timed out");
    return -1;
  }
  EXCEPT (SocketDTLS_VerifyFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "DTLS certificate verification failed");
    return -1;
  }
  EXCEPT (SocketDTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "DTLS handshake failed");
    return -1;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS handshake failed");
    return -1;
  }
  END_TRY;

  sock->is_connected = 1;
  return 0;
}

int
Socket_simple_dtls_shutdown (SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid DTLS socket");
      return -1;
    }

  TRY { SocketDTLS_shutdown (sock->dgram); }
  EXCEPT (SocketDTLS_ShutdownFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS shutdown failed");
    return -1;
  }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "DTLS shutdown failed");
    return -1;
  }
  END_TRY;

  sock->is_connected = 0;
  return 0;
}

int
Socket_simple_dtls_set_mtu (SocketSimple_Socket_T sock, size_t mtu)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid DTLS socket");
      return -1;
    }

  TRY { SocketDTLS_set_mtu (sock->dgram, mtu); }
  EXCEPT (SocketDTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid MTU value");
    return -1;
  }
  END_TRY;

  return 0;
}

/*============================================================================
 * DTLS Info Functions
 *============================================================================*/

int
Socket_simple_is_dtls (SocketSimple_Socket_T sock)
{
  if (!sock)
    return -1;

  if (!sock->dgram)
    return 0; /* Not a UDP socket */

  return sock->is_tls && SocketDTLS_is_enabled (sock->dgram) ? 1 : 0;
}

int
Socket_simple_dtls_is_handshake_done (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return -1;

  return SocketDTLS_is_handshake_done (sock->dgram) ? 1 : 0;
}

const char *
Socket_simple_dtls_cipher (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return NULL;

  return SocketDTLS_get_cipher (sock->dgram);
}

const char *
Socket_simple_dtls_version (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return NULL;

  return SocketDTLS_get_version (sock->dgram);
}

size_t
Socket_simple_dtls_mtu (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return 0;

  return SocketDTLS_get_mtu (sock->dgram);
}

const char *
Socket_simple_dtls_alpn (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return NULL;

  return SocketDTLS_get_alpn_selected (sock->dgram);
}

int
Socket_simple_dtls_is_session_reused (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->dgram || !sock->is_tls)
    return -1;

  return SocketDTLS_is_session_reused (sock->dgram);
}

#else /* !SOCKET_HAS_TLS */

/* Stub implementations when TLS is disabled */

void
Socket_simple_dtls_options_defaults (SocketSimple_DTLSOptions *opts)
{
  if (opts)
    memset (opts, 0, sizeof (*opts));
}

SocketSimple_Socket_T
Socket_simple_dtls_connect (const char *host __attribute__ ((unused)),
                            int port __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_dtls_connect_ex (
    const char *host __attribute__ ((unused)),
    int port __attribute__ ((unused)),
    const SocketSimple_DTLSOptions *opts __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return NULL;
}

int
Socket_simple_dtls_enable (
    SocketSimple_Socket_T sock __attribute__ ((unused)),
    const char *hostname __attribute__ ((unused)),
    const SocketSimple_DTLSOptions *opts __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

SocketSimple_Socket_T
Socket_simple_dtls_listen (const char *host __attribute__ ((unused)),
                           int port __attribute__ ((unused)),
                           const char *cert_file __attribute__ ((unused)),
                           const char *key_file __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_dtls_accept (
    SocketSimple_Socket_T server_sock __attribute__ ((unused)),
    int timeout_ms __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return NULL;
}

ssize_t
Socket_simple_dtls_send (SocketSimple_Socket_T sock __attribute__ ((unused)),
                         const void *data __attribute__ ((unused)),
                         size_t len __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

ssize_t
Socket_simple_dtls_recv (SocketSimple_Socket_T sock __attribute__ ((unused)),
                         void *buf __attribute__ ((unused)),
                         size_t len __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

ssize_t
Socket_simple_dtls_sendto (SocketSimple_Socket_T sock __attribute__ ((unused)),
                           const void *data __attribute__ ((unused)),
                           size_t len __attribute__ ((unused)),
                           const char *host __attribute__ ((unused)),
                           int port __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

ssize_t
Socket_simple_dtls_recvfrom (SocketSimple_Socket_T sock __attribute__ ((unused)),
                             void *buf __attribute__ ((unused)),
                             size_t len __attribute__ ((unused)),
                             char *host __attribute__ ((unused)),
                             size_t host_len __attribute__ ((unused)),
                             int *port __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

int
Socket_simple_dtls_handshake (
    SocketSimple_Socket_T sock __attribute__ ((unused)),
    int timeout_ms __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

int
Socket_simple_dtls_shutdown (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

int
Socket_simple_dtls_set_mtu (SocketSimple_Socket_T sock __attribute__ ((unused)),
                            size_t mtu __attribute__ ((unused)))
{
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "DTLS not available (TLS support disabled)");
  return -1;
}

int
Socket_simple_is_dtls (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return 0;
}

int
Socket_simple_dtls_is_handshake_done (
    SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return -1;
}

const char *
Socket_simple_dtls_cipher (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return NULL;
}

const char *
Socket_simple_dtls_version (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return NULL;
}

size_t
Socket_simple_dtls_mtu (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return 0;
}

const char *
Socket_simple_dtls_alpn (SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return NULL;
}

int
Socket_simple_dtls_is_session_reused (
    SocketSimple_Socket_T sock __attribute__ ((unused)))
{
  return -1;
}

#endif /* SOCKET_HAS_TLS */
