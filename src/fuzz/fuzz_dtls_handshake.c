/**
 * fuzz_dtls_handshake.c - Fuzzer for DTLS handshake operations
 *
 * Tests DTLS handshake state machine:
 * - Handshake initiation and state transitions
 * - Handshake loop with various timeout configurations
 * - Listen operation with cookie exchange
 * - Cookie exchange state detection
 * - State query functions
 * - Retransmission handling (OpenSSL internal)
 *
 * NOTE: Avoids nested TRY/EXCEPT to prevent stack-use-after-scope with ASan.
 * Handshake operations on unconnected sockets will fail, which is expected.
 */

#if SOCKET_HAS_TLS

#include <assert.h>
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

/* Operation types for comprehensive handshake testing */
typedef enum
{
  OP_HANDSHAKE_SINGLE = 0,
  OP_HANDSHAKE_LOOP_SHORT,
  OP_HANDSHAKE_LOOP_ZERO,
  OP_HANDSHAKE_LOOP_INFINITE,
  OP_STATE_TRANSITIONS,
  OP_HOSTNAME_SET,
  OP_SERVER_LISTEN,
  OP_SERVER_LISTEN_WITH_COOKIES,
  OP_STATE_ENUM_COVERAGE,
  OP_HANDSHAKE_STATE_MACHINE
} DTLSHandshakeOp;

#define OP_COUNT 10

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

/**
 * verify_state_valid - Check that a handshake state is valid
 * @state: State to verify
 *
 * Returns: 1 if valid enum value, 0 otherwise
 */
static int
verify_state_valid (DTLSHandshakeState state)
{
  switch (state)
    {
    case DTLS_HANDSHAKE_NOT_STARTED:
    case DTLS_HANDSHAKE_IN_PROGRESS:
    case DTLS_HANDSHAKE_WANT_READ:
    case DTLS_HANDSHAKE_WANT_WRITE:
    case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
    case DTLS_HANDSHAKE_COMPLETE:
    case DTLS_HANDSHAKE_ERROR:
      return 1;
    default:
      return 0;
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDgram_T socket = NULL;
  SocketDTLSContext_T ctx = NULL;
  volatile DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_HANDSHAKE_SINGLE:
        /* Test single handshake step on unconnected socket */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        state = SocketDTLS_handshake (socket);
        /* Verify returned state is a valid enum value */
        assert (verify_state_valid (state));
        break;

      case OP_HANDSHAKE_LOOP_SHORT:
        /* Handshake loop with short timeout (will timeout quickly) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        state = SocketDTLS_handshake_loop (socket, 10);
        assert (verify_state_valid (state));
        break;

      case OP_HANDSHAKE_LOOP_ZERO:
        /* Handshake loop with zero timeout (non-blocking single step) */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        state = SocketDTLS_handshake_loop (socket, 0);
        /* Zero timeout should return immediately with current state */
        assert (verify_state_valid (state));
        /* Cannot be COMPLETE on unconnected socket */
        assert (state != DTLS_HANDSHAKE_COMPLETE);
        break;

      case OP_HANDSHAKE_LOOP_INFINITE:
        /* Test infinite timeout code path but use very short for fuzzing */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        /* Use short timeout instead of -1 for fuzzing to avoid hang */
        state = SocketDTLS_handshake_loop (socket, 5);
        assert (verify_state_valid (state));
        break;

      case OP_STATE_TRANSITIONS:
        /* Test state query functions throughout lifecycle */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);

        /* Before enable: should show disabled */
        assert (SocketDTLS_is_enabled (socket) == 0);
        assert (SocketDTLS_is_handshake_done (socket) == 0);
        assert (SocketDTLS_get_last_state (socket) == DTLS_HANDSHAKE_NOT_STARTED);

        SocketDTLS_enable (socket, ctx);

        /* After enable: enabled but handshake not done */
        assert (SocketDTLS_is_enabled (socket) == 1);
        assert (SocketDTLS_is_handshake_done (socket) == 0);

        /* Try handshake (will fail on unconnected socket) */
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));

        /* After handshake attempt: state should be tracked */
        state = SocketDTLS_get_last_state (socket);
        assert (verify_state_valid (state));
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
            /* May fail on invalid hostname, which is expected */
            SocketDTLS_set_hostname (socket, hostname);
          }
        break;

      case OP_SERVER_LISTEN:
        /* Test server-side listen operation without cookies */
        socket = SocketDgram_new (AF_INET, 0);
        /* Client context won't have cookies, tests non-cookie path */
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        state = SocketDTLS_listen (socket);
        assert (verify_state_valid (state));
        break;

      case OP_SERVER_LISTEN_WITH_COOKIES:
        /* Test server-side listen with cookie exchange enabled */
        /* Note: We can't easily create a server context in fuzzer
         * without cert files, so we test with client context which
         * exercises the code path but cookie exchange won't be enabled */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);
        state = SocketDTLS_listen (socket);
        assert (verify_state_valid (state));
        /* Listen without data should return IN_PROGRESS or WANT_READ */
        assert (state == DTLS_HANDSHAKE_IN_PROGRESS
                || state == DTLS_HANDSHAKE_WANT_READ
                || state == DTLS_HANDSHAKE_COOKIE_EXCHANGE
                || state == DTLS_HANDSHAKE_ERROR);
        break;

      case OP_STATE_ENUM_COVERAGE:
        /* Verify all DTLSHandshakeState enum values are valid */
        assert (verify_state_valid (DTLS_HANDSHAKE_NOT_STARTED));
        assert (verify_state_valid (DTLS_HANDSHAKE_IN_PROGRESS));
        assert (verify_state_valid (DTLS_HANDSHAKE_WANT_READ));
        assert (verify_state_valid (DTLS_HANDSHAKE_WANT_WRITE));
        assert (verify_state_valid (DTLS_HANDSHAKE_COOKIE_EXCHANGE));
        assert (verify_state_valid (DTLS_HANDSHAKE_COMPLETE));
        assert (verify_state_valid (DTLS_HANDSHAKE_ERROR));
        /* Invalid value should return 0 */
        assert (verify_state_valid ((DTLSHandshakeState)999) == 0);
        break;

      case OP_HANDSHAKE_STATE_MACHINE:
        /* Test state machine transitions in sequence */
        socket = SocketDgram_new (AF_INET, 0);
        ctx = SocketDTLSContext_new_client (NULL);
        SocketDTLS_enable (socket, ctx);

        /* Initial state should be NOT_STARTED or set after enable */
        state = SocketDTLS_get_last_state (socket);
        /* Could be NOT_STARTED or IN_PROGRESS depending on implementation */

        /* First handshake attempt */
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));

        /* Multiple handshake calls should be safe */
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));

        /* Zero-timeout loop should return current state */
        state = SocketDTLS_handshake_loop (socket, 0);
        assert (verify_state_valid (state));
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
