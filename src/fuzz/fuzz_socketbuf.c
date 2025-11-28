/**
 * fuzz_socketbuf.c - libFuzzer harness for SocketBuf circular buffer
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Buffer overflow/underflow in circular buffer operations
 * - Wraparound boundary conditions
 * - Reserve/resize overflow protection
 * - Invariant violations
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketbuf
 * Run:   ./fuzz_socketbuf corpus/socketbuf/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketBuf.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_WRITE = 0,
  OP_READ,
  OP_PEEK,
  OP_CONSUME,
  OP_RESERVE,
  OP_WRITEPTR,
  OP_CLEAR,
  OP_SECURECLEAR,
  OP_MAX
};

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 *
 * Input format:
 * - Byte 0: Operation selector (mod OP_MAX)
 * - Byte 1: Capacity hint (1-255, scaled)
 * - Bytes 2+: Payload data for operation
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketBuf_T buf = NULL;

  /* Need at least 2 bytes for op and capacity */
  if (size < 2)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  /* Capacity: 1-256 bytes (avoid 0) */
  size_t capacity = (size_t)(data[1] % 255) + 1;
  const uint8_t *payload = data + 2;
  size_t payload_size = size - 2;

  /* Create arena for this test */
  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    /* Create buffer with fuzz-controlled capacity */
    buf = SocketBuf_new (arena, capacity);
    if (!buf)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* Execute fuzz-selected operation */
    switch (op)
      {
      case OP_WRITE:
        {
          /* Write fuzz payload to buffer */
          size_t written = SocketBuf_write (buf, payload, payload_size);
          (void)written;

          /* Verify invariants after write */
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_READ:
        {
          /* Write then read */
          SocketBuf_write (buf, payload, payload_size);

          char out[512];
          size_t to_read = payload_size < sizeof (out) ? payload_size : sizeof (out);
          size_t bytes_read = SocketBuf_read (buf, out, to_read);
          (void)bytes_read;

          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_PEEK:
        {
          /* Write then peek (non-destructive) */
          SocketBuf_write (buf, payload, payload_size);

          char out[512];
          size_t to_peek = payload_size < sizeof (out) ? payload_size : sizeof (out);
          size_t bytes_peeked = SocketBuf_peek (buf, out, to_peek);
          (void)bytes_peeked;

          /* Peek should not change available bytes */
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_CONSUME:
        {
          /* Write then consume partial data */
          size_t written = SocketBuf_write (buf, payload, payload_size);
          if (written > 0)
            {
              /* Consume half of what was written */
              size_t to_consume = written / 2;
              if (to_consume > 0)
                {
                  SocketBuf_consume (buf, to_consume);
                }
            }
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_RESERVE:
        {
          /* Test reserve/resize with fuzz-controlled size */
          size_t reserve_size = 0;
          if (payload_size >= 2)
            {
              /* Use payload bytes to determine reserve size */
              reserve_size = ((size_t)payload[0] << 8) | payload[1];
              /* Cap at reasonable size to avoid OOM in fuzzer */
              reserve_size = reserve_size % (size_t)(64 * 1024);
            }
          else if (payload_size == 1)
            {
              reserve_size = payload[0];
            }

          if (reserve_size > 0)
            {
              TRY
              {
                SocketBuf_reserve (buf, reserve_size);
              }
              EXCEPT (SocketBuf_Failed)
              {
                /* Expected for overflow/large sizes - not a bug */
              }
              END_TRY;
            }
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_WRITEPTR:
        {
          /* Test zero-copy write interface */
          size_t len = 0;
          void *wptr = SocketBuf_writeptr (buf, &len);

          if (wptr && len > 0 && payload_size > 0)
            {
              size_t to_write = len < payload_size ? len : payload_size;
              memcpy (wptr, payload, to_write);
              SocketBuf_written (buf, to_write);
            }

          /* Also test readptr */
          const void *rptr = SocketBuf_readptr (buf, &len);
          (void)rptr;

          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_CLEAR:
        {
          /* Write then clear */
          SocketBuf_write (buf, payload, payload_size);
          SocketBuf_clear (buf);

          /* Buffer should be empty after clear */
          assert (SocketBuf_empty (buf));
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      case OP_SECURECLEAR:
        {
          /* Write then secure clear (zeros memory) */
          SocketBuf_write (buf, payload, payload_size);
          SocketBuf_secureclear (buf);

          assert (SocketBuf_empty (buf));
          assert (SocketBuf_check_invariants (buf));
        }
        break;

      default:
        /* Should not reach here due to mod OP_MAX above */
        break;
      }

    /* Final invariant check */
    (void)SocketBuf_check_invariants (buf);
    (void)SocketBuf_available (buf);
    (void)SocketBuf_space (buf);
    (void)SocketBuf_empty (buf);
    (void)SocketBuf_full (buf);
  }
  EXCEPT (Arena_Failed)
  {
    /* Arena allocation failure - expected for some inputs */
  }
  EXCEPT (SocketBuf_Failed)
  {
    /* Buffer operation failure - expected for some inputs */
  }
  FINALLY
  {
    /* Cleanup */
    if (buf)
      SocketBuf_release (&buf);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

