/**
 * fuzz_dtls_io.c - Fuzzer for SocketDTLS I/O operations
 *
 * Tests DTLS socket I/O operations:
 * - DTLS enable on socket
 * - MTU configuration
 * - Info queries
 * - State queries
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * DTLS operations on unconnected sockets will fail, which is expected.
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

#include "socket/SocketDgram.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_ENABLE_DTLS = 0,
  OP_SET_MTU,
  OP_INFO_QUERIES,
  OP_STATE_QUERIES,
  OP_HANDSHAKE,
  OP_SEND_RECV,
  OP_SHUTDOWN
} DTLSIOOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 7 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  char send_buf[256];

  /* Initialize send buffer with fuzz data */
  size_t copy_len = size > sizeof (send_buf) ? sizeof (send_buf) : size;
  memcpy (send_buf, data, copy_len);

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_ENABLE_DTLS:
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        if (SocketDTLS_is_enabled (socket) != 1)
          abort ();
        break;

      case OP_SET_MTU:
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        if (size > 2)
          {
            size_t mtu = (data[1] << 8) | data[2];
            SocketDTLS_set_mtu (socket, mtu);
          }
        break;

      case OP_INFO_QUERIES:
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        /* These should return NULL/0 before handshake */
        (void)SocketDTLS_get_cipher (socket);
        (void)SocketDTLS_get_version (socket);
        (void)SocketDTLS_get_alpn_selected (socket);
        (void)SocketDTLS_is_session_reused (socket);
        (void)SocketDTLS_get_mtu (socket);
        break;

      case OP_STATE_QUERIES:
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        (void)SocketDTLS_is_enabled (socket);
        (void)SocketDTLS_is_handshake_done (socket);
        (void)SocketDTLS_is_shutdown (socket);
        (void)SocketDTLS_get_last_state (socket);
        break;

      case OP_HANDSHAKE:
        /* Handshake on unconnected socket will fail */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        SocketDTLS_handshake (socket);
        break;

      case OP_SEND_RECV:
        /* Send/recv on unconnected socket will fail */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        SocketDTLS_send (socket, send_buf, 64);
        break;

      case OP_SHUTDOWN:
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        SocketDTLS_shutdown (socket);
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketDTLS_Failed) {}
  EXCEPT (SocketDTLS_HandshakeFailed) {}
  EXCEPT (SocketDTLS_VerifyFailed) {}
  EXCEPT (SocketDTLS_CookieFailed) {}
  EXCEPT (SocketDTLS_TimeoutExpired) {}
  EXCEPT (SocketDTLS_ShutdownFailed) {}
  EXCEPT (SocketDgram_Failed) {}
  EXCEPT (Socket_Closed) {}
  ELSE {}
  END_TRY;

  /* Cleanup */
  if (socket)
    SocketDgram_free (&socket);
  if (ctx)
    SocketDTLSContext_free (&ctx);

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
