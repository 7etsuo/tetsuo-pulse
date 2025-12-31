/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * Performance Optimization:
 * - Caches DTLS context in static variable (expensive OpenSSL init)
 * - Uses very short timeouts (1-5ms) instead of blocking
 * - Early exit for tiny inputs
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

/* Cached DTLS client context - expensive to create */
static SocketDTLSContext_T g_client_ctx = NULL;

/**
 * LLVMFuzzerInitialize - One-time setup for fuzzer
 *
 * Creates the DTLS context once to avoid expensive OpenSSL initialization
 * on every fuzzer invocation.
 */
int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc;
  (void)argv;

  TRY
  {
    g_client_ctx = SocketDTLSContext_new_client (NULL);
  }
  EXCEPT (SocketDTLS_Failed)
  {
    g_client_ctx = NULL;
  }
  END_TRY;

  return 0;
}

/* Operation types for comprehensive handshake testing */
typedef enum
{
  OP_HANDSHAKE_SINGLE = 0,
  OP_HANDSHAKE_LOOP_SHORT,
  OP_HANDSHAKE_LOOP_ZERO,
  OP_STATE_TRANSITIONS,
  OP_HOSTNAME_SET,
  OP_SERVER_LISTEN,
  OP_STATE_ENUM_COVERAGE,
  OP_HANDSHAKE_STATE_MACHINE
} DTLSHandshakeOp;

#define OP_COUNT 8

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

  /* Skip if context creation failed at init time */
  if (!g_client_ctx)
    return 0;

  volatile uint8_t op = get_op (data, size);
  SocketDgram_T socket = NULL;
  volatile DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;

  /* Single TRY block - no nesting */
  TRY
  {
    switch (op)
      {
      case OP_HANDSHAKE_SINGLE:
        /* Test single handshake step on unconnected socket */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));
        break;

      case OP_HANDSHAKE_LOOP_SHORT:
        /* Handshake loop with very short timeout (1ms) */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);
        state = SocketDTLS_handshake_loop (socket, 1);
        assert (verify_state_valid (state));
        break;

      case OP_HANDSHAKE_LOOP_ZERO:
        /* Handshake loop with zero timeout (non-blocking single step) */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);
        state = SocketDTLS_handshake_loop (socket, 0);
        assert (verify_state_valid (state));
        assert (state != DTLS_HANDSHAKE_COMPLETE);
        break;

      case OP_STATE_TRANSITIONS:
        /* Test state query functions throughout lifecycle */
        socket = SocketDgram_new (AF_INET, 0);

        /* Before enable: should show disabled */
        assert (SocketDTLS_is_enabled (socket) == 0);
        assert (SocketDTLS_is_handshake_done (socket) == 0);
        assert (SocketDTLS_get_last_state (socket)
                == DTLS_HANDSHAKE_NOT_STARTED);

        SocketDTLS_enable (socket, g_client_ctx);

        /* After enable: enabled but handshake not done */
        assert (SocketDTLS_is_enabled (socket) == 1);
        assert (SocketDTLS_is_handshake_done (socket) == 0);

        /* Try handshake (will fail on unconnected socket) */
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));
        break;

      case OP_HOSTNAME_SET:
        /* Test hostname setting with fuzz data */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);

        if (size > 2)
          {
            char hostname[64];
            size_t hlen = (size - 1) > 63 ? 63 : (size - 1);
            memcpy (hostname, data + 1, hlen);
            hostname[hlen] = '\0';
            SocketDTLS_set_hostname (socket, hostname);
          }
        break;

      case OP_SERVER_LISTEN:
        /* Test server-side listen operation */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);
        state = SocketDTLS_listen (socket);
        assert (verify_state_valid (state));
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
        assert (verify_state_valid ((DTLSHandshakeState)999) == 0);
        break;

      case OP_HANDSHAKE_STATE_MACHINE:
        /* Test state machine transitions in sequence */
        socket = SocketDgram_new (AF_INET, 0);
        SocketDTLS_enable (socket, g_client_ctx);

        state = SocketDTLS_get_last_state (socket);
        state = SocketDTLS_handshake (socket);
        assert (verify_state_valid (state));
        state = SocketDTLS_handshake_loop (socket, 0);
        assert (verify_state_valid (state));
        break;

      default:
        break;
      }
  }
  EXCEPT (SocketDTLS_Failed)
  {
  }
  EXCEPT (SocketDTLS_HandshakeFailed)
  {
  }
  EXCEPT (SocketDTLS_VerifyFailed)
  {
  }
  EXCEPT (SocketDTLS_CookieFailed)
  {
  }
  EXCEPT (SocketDTLS_TimeoutExpired)
  {
  }
  EXCEPT (SocketDTLS_ShutdownFailed)
  {
  }
  EXCEPT (SocketDgram_Failed)
  {
  }
  EXCEPT (Socket_Closed)
  {
  }
  ELSE
  {
  }
  END_TRY;

  /* Cleanup - only the socket, context is reused */
  if (socket)
    SocketDgram_free (&socket);

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
