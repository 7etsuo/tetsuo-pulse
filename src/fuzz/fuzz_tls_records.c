/**
 * fuzz_tls_records.c - Fuzzer for TLS Record Layer Processing
 *
 * Part of the Socket Library Fuzzing Suite (Section 8.3)
 *
 * Targets:
 * - TLS send/recv edge cases
 * - Buffer size handling
 * - Zero-length operations
 * - Large buffer handling
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_tls_records
 * Run:   ./fuzz_tls_records corpus/tls_records/ -fork=16 -max_len=65536
 */

#if SOCKET_HAS_TLS

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Except.h"
#include "socket/Socket-private.h"
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
  OP_SEND_NORMAL = 0,
  OP_RECV_NORMAL,
  OP_SEND_ZERO_LEN,
  OP_RECV_ZERO_LEN,
  OP_SEND_LARGE,
  OP_RECV_LARGE,
  OP_SEND_VARYING_SIZES,
  OP_BUFFER_BOUNDARY,
  OP_COUNT
} RecordOp;

static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % OP_COUNT : 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  volatile uint8_t op = get_op (data, size);
  Socket_T socket = NULL;
  SocketTLSContext_T ctx = NULL;
  char send_buf[16384];
  char recv_buf[16384];

  /* Initialize buffers */
  size_t copy_len = size > sizeof (send_buf) ? sizeof (send_buf) : size;
  memcpy (send_buf, data, copy_len);

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

    /* Force handshake done for I/O tests */
    socket->tls_handshake_done = 1;

    switch (op)
      {
      case OP_SEND_NORMAL:
        {
          /* Normal send with fuzzed data */
          size_t send_len = (size > 1) ? (data[1] % 256 + 1) : 64;
          if (send_len > copy_len)
            send_len = copy_len;
          (void)SocketTLS_send (socket, send_buf, send_len);
        }
        break;

      case OP_RECV_NORMAL:
        {
          /* Normal recv */
          size_t recv_len = (size > 1) ? (data[1] % 256 + 1) : 64;
          (void)SocketTLS_recv (socket, recv_buf, recv_len);
        }
        break;

      case OP_SEND_ZERO_LEN:
        {
          /* Zero-length send - should return 0 immediately */
          ssize_t result = SocketTLS_send (socket, send_buf, 0);
          if (result != 0)
            abort ();
        }
        break;

      case OP_RECV_ZERO_LEN:
        {
          /* Zero-length recv - should return 0 immediately */
          ssize_t result = SocketTLS_recv (socket, recv_buf, 0);
          if (result != 0)
            abort ();
        }
        break;

      case OP_SEND_LARGE:
        {
          /* Large buffer send */
          (void)SocketTLS_send (socket, send_buf, sizeof (send_buf));
        }
        break;

      case OP_RECV_LARGE:
        {
          /* Large buffer recv */
          (void)SocketTLS_recv (socket, recv_buf, sizeof (recv_buf));
        }
        break;

      case OP_SEND_VARYING_SIZES:
        {
          /* Multiple sends with varying sizes */
          for (size_t i = 1; i < size && i < 10; i++)
            {
              size_t send_len = data[i] % 128 + 1;
              if (send_len > copy_len)
                send_len = copy_len;
              (void)SocketTLS_send (socket, send_buf, send_len);
            }
        }
        break;

      case OP_BUFFER_BOUNDARY:
        {
          /* Test buffer boundary conditions */
          /* TLS record max is 16KB */
          size_t sizes[]
              = {1, 15, 16, 17, 255, 256, 257, 1023, 1024, 16383, 16384};
          for (size_t i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++)
            {
              if (sizes[i] <= sizeof (send_buf))
                {
                  (void)SocketTLS_send (socket, send_buf, sizes[i]);
                }
            }
        }
        break;
      }
  }
  EXCEPT (SocketTLS_Failed) {}
  EXCEPT (SocketTLS_HandshakeFailed) {}
  EXCEPT (Socket_Failed) {}
  EXCEPT (Socket_Closed) {}
  ELSE {}
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
