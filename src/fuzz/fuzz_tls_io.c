/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_io.c - Fuzzer for SocketTLS I/O operations
 *
 * Tests TLS socket I/O operations:
 * - TLS context creation
 * - TLS enable on socket
 * - SNI hostname setting
 * - TLS info queries
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * TLS operations on unconnected sockets will fail, which is expected.
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"

/* Ignore SIGPIPE - OpenSSL may trigger it on unconnected sockets */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_CONTEXT_CLIENT = 0,
  OP_CONTEXT_SERVER,
  OP_ENABLE_SOCKET,
  OP_HOSTNAME_SET,
  OP_INFO_QUERIES,
  OP_HANDSHAKE,
  OP_SEND_RECV,
  OP_SHUTDOWN,
  OP_SEND_ZERO_LEN,
  OP_RECV_ZERO_LEN,
  OP_SEND_LARGE_BUF
} TLSIOOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 11 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  char send_buf[256];
  char recv_buf[256];

  /* Initialize send buffer with fuzz data */
  size_t copy_len = size > sizeof (send_buf) ? sizeof (send_buf) : size;
  memcpy (send_buf, data, copy_len);

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_CONTEXT_CLIENT:
        /* Test client context creation */
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLSContext_free (&ctx);
        break;

      case OP_CONTEXT_SERVER:
        /* Server context needs cert/key - just test the API exists */
        /* Can't create without valid cert files, so skip actual creation */
        break;

      case OP_ENABLE_SOCKET:
        /* Test TLS enable on unconnected socket (will fail) */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* If we get here, check the flag */
        if (socket->tls_enabled != 1)
          abort ();
        break;

      case OP_HOSTNAME_SET:
        /* Test hostname setting - needs TLS enabled first */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* Try setting hostname from fuzz data */
        if (size > 1)
          {
            char hostname[64];
            size_t hlen = (size - 1) > 63 ? 63 : (size - 1);
            memcpy (hostname, data + 1, hlen);
            hostname[hlen] = '\0';
            SocketTLS_set_hostname (socket, hostname);
          }
        break;

      case OP_INFO_QUERIES:
        /* Test info queries on TLS-enabled socket */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* These should return NULL/0 on unconnected socket */
        (void)SocketTLS_get_cipher (socket);
        (void)SocketTLS_get_version (socket);
        (void)SocketTLS_get_alpn_selected (socket);
        (void)SocketTLS_is_session_reused (socket);
        break;

      case OP_HANDSHAKE:
        /* Test handshake on unconnected socket (will fail) */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        SocketTLS_handshake (socket);
        break;

      case OP_SEND_RECV:
        /* Test send/recv on unconnected TLS socket (will fail) */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        SocketTLS_send (socket, send_buf, 64);
        break;

      case OP_SHUTDOWN:
        /* Test shutdown on TLS socket */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        SocketTLS_shutdown (socket);
        break;

      case OP_SEND_ZERO_LEN:
        /* Test zero-length send - should return 0 immediately without SSL call
         */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* Force handshake_done to bypass handshake check for zero-len test */
        socket->tls_handshake_done = 1;
        {
          ssize_t result = SocketTLS_send (socket, send_buf, 0);
          if (result != 0)
            abort (); /* Zero-length should always return 0 */
        }
        break;

      case OP_RECV_ZERO_LEN:
        /* Test zero-length recv - should return 0 immediately without SSL call
         */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* Force handshake_done to bypass handshake check for zero-len test */
        socket->tls_handshake_done = 1;
        {
          ssize_t result = SocketTLS_recv (socket, recv_buf, 0);
          if (result != 0)
            abort (); /* Zero-length should always return 0 */
        }
        break;

      case OP_SEND_LARGE_BUF:
        /* Test that large buffer sizes are handled (capped to INT_MAX) */
        socket = Socket_new (AF_INET, SOCK_STREAM, 0);
        ctx = SocketTLSContext_new_client (NULL);
        SocketTLS_enable (socket, ctx);
        /* Can't really test with actual large buffer, just verify the path */
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
  }
  EXCEPT (SocketTLS_ProtocolError)
  {
  }
  EXCEPT (SocketTLS_ShutdownFailed)
  {
  }
  EXCEPT (Socket_Failed)
  {
  }
  EXCEPT (Socket_Closed)
  {
  }
  ELSE
  {
  }
  END_TRY;

  /* Cleanup */
  if (socket)
    Socket_free (&socket);
  if (ctx)
    SocketTLSContext_free (&ctx);

  return 0;
}

#else /* !SOCKET_HAS_TLS */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
