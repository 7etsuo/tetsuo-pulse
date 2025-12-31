/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_tls_handshake.c - Fuzzer for TLS Handshake Message Parsing
 *
 * Part of the Socket Library Fuzzing Suite (Section 8.3)
 *
 * Targets:
 * - TLS handshake state transitions
 * - Handshake message handling
 * - Non-blocking handshake behavior
 * - Timeout handling
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_handshake
 * Run:   ./fuzz_tls_handshake corpus/tls_handshake/ -fork=16 -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Ignore SIGPIPE */
__attribute__ ((constructor)) static void
ignore_sigpipe (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Suppress GCC clobbered warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types */
typedef enum
{
  OP_HANDSHAKE_SINGLE = 0,
  OP_HANDSHAKE_LOOP_ZERO,
  OP_HANDSHAKE_LOOP_TIMEOUT,
  OP_HANDSHAKE_LOOP_EX,
  OP_HANDSHAKE_AUTO,
  OP_HANDSHAKE_STATE_QUERY,
  OP_MULTIPLE_HANDSHAKE_STEPS,
  OP_COUNT
} HandshakeOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

static uint16_t
get_timeout (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;
  return (uint16_t)data[1] | ((uint16_t)data[2] << 8);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 3)
    return 0;

  volatile uint8_t op = get_op (data, size);
  uint16_t timeout_ms = get_timeout (data, size) % 100; /* Cap timeout */
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
    if (!socket)
      return 0;

    ctx = SocketTLSContext_new_client (NULL);
    if (!ctx)
      {
        Socket_free (&socket);
        return 0;
      }

    SocketTLS_enable (socket, ctx);

    switch (op)
      {
      case OP_HANDSHAKE_SINGLE:
        {
          /* Single handshake step */
          TLSHandshakeState state = SocketTLS_handshake (socket);
          (void)state;
        }
        break;

      case OP_HANDSHAKE_LOOP_ZERO:
        {
          /* Handshake loop with zero timeout (non-blocking) */
          TLSHandshakeState state = SocketTLS_handshake_loop (socket, 0);
          (void)state;
        }
        break;

      case OP_HANDSHAKE_LOOP_TIMEOUT:
        {
          /* Handshake loop with fuzzed timeout */
          TLSHandshakeState state
              = SocketTLS_handshake_loop (socket, (int)timeout_ms);
          (void)state;
        }
        break;

      case OP_HANDSHAKE_LOOP_EX:
        {
          /* Extended handshake loop with poll interval */
          int poll_interval = (size > 3) ? (data[3] % 50) : 10;
          TLSHandshakeState state = SocketTLS_handshake_loop_ex (
              socket, (int)timeout_ms, poll_interval);
          (void)state;
        }
        break;

      case OP_HANDSHAKE_AUTO:
        {
          /* Auto handshake mode */
          TLSHandshakeState state = SocketTLS_handshake_auto (socket);
          (void)state;
        }
        break;

      case OP_HANDSHAKE_STATE_QUERY:
        {
          /* Query handshake state without doing handshake */
          SocketTLS_handshake (socket);
          (void)SocketTLS_get_cipher (socket);
          (void)SocketTLS_get_version (socket);
          (void)SocketTLS_is_session_reused (socket);
        }
        break;

      case OP_MULTIPLE_HANDSHAKE_STEPS:
        {
          /* Multiple handshake attempts */
          int steps = (size > 3) ? (data[3] % 5 + 1) : 2;
          for (int i = 0; i < steps; i++)
            {
              TLSHandshakeState state = SocketTLS_handshake (socket);
              if (state == TLS_HANDSHAKE_COMPLETE
                  || state == TLS_HANDSHAKE_ERROR)
                break;
            }
        }
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
