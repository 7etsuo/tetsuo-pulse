/**
 * fuzz_dtls_context.c - Fuzzer for SocketDTLSContext operations
 *
 * Tests DTLS context creation and configuration:
 * - Context creation (client/server)
 * - MTU configuration
 * - Cookie exchange setup
 * - ALPN configuration
 * - Session cache configuration
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
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
  OP_CREATE_CLIENT = 0,
  OP_SET_MTU,
  OP_SET_ALPN,
  OP_ENABLE_CACHE,
  OP_SET_CIPHER,
  OP_SET_TIMEOUT
} DTLSContextOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 6 : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDTLSContext_T ctx = NULL;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_CREATE_CLIENT:
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLSContext_free (&ctx);
        break;

      case OP_SET_MTU:
        ctx = SocketDTLSContext_new_client (NULL);
        if (size > 2)
          {
            /* Use fuzz data for MTU value */
            size_t mtu = (data[1] << 8) | data[2];
            SocketDTLSContext_set_mtu (ctx, mtu);
          }
        break;

      case OP_SET_ALPN:
        ctx = SocketDTLSContext_new_client (NULL);
        if (size > 3)
          {
            /* Build protocol list from fuzz data */
            char proto[64];
            size_t proto_len = (size - 1) > 63 ? 63 : (size - 1);
            memcpy (proto, data + 1, proto_len);
            proto[proto_len] = '\0';

            const char *protos[] = { proto };
            SocketDTLSContext_set_alpn_protos (ctx, protos, 1);
          }
        break;

      case OP_ENABLE_CACHE:
        ctx = SocketDTLSContext_new_client (NULL);
        if (size > 4)
          {
            size_t max_sessions = (data[1] << 8) | data[2];
            long timeout = (data[3] << 8) | data[4];
            SocketDTLSContext_enable_session_cache (ctx, max_sessions,
                                                    timeout);
          }
        break;

      case OP_SET_CIPHER:
        ctx = SocketDTLSContext_new_client (NULL);
        if (size > 2)
          {
            char ciphers[128];
            size_t cipher_len = (size - 1) > 127 ? 127 : (size - 1);
            memcpy (ciphers, data + 1, cipher_len);
            ciphers[cipher_len] = '\0';
            SocketDTLSContext_set_cipher_list (ctx, ciphers);
          }
        break;

      case OP_SET_TIMEOUT:
        ctx = SocketDTLSContext_new_client (NULL);
        if (size > 4)
          {
            int initial_ms = (data[1] << 8) | data[2];
            int max_ms = (data[3] << 8) | data[4];
            SocketDTLSContext_set_timeout (ctx, initial_ms, max_ms);
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
  ELSE {}
  END_TRY;

  /* Cleanup */
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
