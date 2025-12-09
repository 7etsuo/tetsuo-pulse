/**
 * fuzz_dtls_handshake.c - Fuzzer for DTLS handshake operations
 *
 * Tests DTLS handshake state machine:
 * - Handshake initiation
 * - Handshake loop with timeout
 * - Listen operation
 * - State transitions
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * Handshake operations on unconnected sockets will fail, which is expected.
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
  OP_HANDSHAKE_SINGLE = 0,
  OP_HANDSHAKE_LOOP_SHORT,
  OP_HANDSHAKE_LOOP_ZERO,
  OP_STATE_TRANSITIONS,
  OP_HOSTNAME_SET
} DTLSHandshakeOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 5 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_HANDSHAKE_SINGLE:
        /* Single handshake step on unconnected socket */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        SocketDTLS_handshake (socket);
        break;

      case OP_HANDSHAKE_LOOP_SHORT:
        /* Handshake loop with short timeout */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        /* Very short timeout - will fail quickly */
        SocketDTLS_handshake_loop (socket, 10);
        break;

      case OP_HANDSHAKE_LOOP_ZERO:
        /* Handshake loop with zero timeout (non-blocking) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        SocketDTLS_handshake_loop (socket, 0);
        break;

      case OP_STATE_TRANSITIONS:
        /* Test state query functions */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);

        /* Before enable */
        (void)SocketDTLS_is_enabled (socket);
        (void)SocketDTLS_is_handshake_done (socket);
        (void)SocketDTLS_get_last_state (socket);

        SocketDTLS_enable (socket, ctx);

        /* After enable, before handshake */
        (void)SocketDTLS_is_enabled (socket);
        (void)SocketDTLS_is_handshake_done (socket);
        (void)SocketDTLS_get_last_state (socket);

        /* Try handshake (will fail) */
        SocketDTLS_handshake (socket);

        /* After failed handshake */
        (void)SocketDTLS_get_last_state (socket);
        break;

      case OP_HOSTNAME_SET:
        /* Test hostname setting with fuzz data */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);

        if (size > 2)
          {
            char hostname[64];
            size_t hlen = (size - 1) > 63 ? 63 : (size - 1);
            memcpy (hostname, data + 1, hlen);
            hostname[hlen] = '\0';
            SocketDTLS_set_hostname (socket, hostname);
          }
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
