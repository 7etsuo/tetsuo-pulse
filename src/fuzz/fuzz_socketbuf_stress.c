/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_socketbuf_stress.c - State machine fuzzer for SocketBuf
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * This harness performs multi-operation sequences to find bugs that only
 * manifest after specific sequences of operations. It interprets the entire
 * fuzz input as a sequence of operations to execute.
 *
 * Targets:
 * - State corruption from specific operation sequences
 * - Invariant violations after complex operation chains
 * - Buffer wraparound edge cases
 * - Resize/reserve behavior under stress
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketbuf_stress
 * Run:   ./fuzz_socketbuf_stress corpus/socketbuf/ -fork=16 -max_len=8192
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketBuf.h"

/* Operation codes for state machine */
enum StressOp
{
  STRESS_WRITE = 0,
  STRESS_READ,
  STRESS_PEEK,
  STRESS_CONSUME,
  STRESS_RESERVE,
  STRESS_CLEAR,
  STRESS_WRITEPTR,
  STRESS_READPTR,
  STRESS_CHECK,
  STRESS_OP_COUNT
};

/* Scratch buffer for read/peek operations */
static char scratch[4096];

/**
 * execute_op - Execute a single buffer operation
 * @buf: Buffer to operate on
 * @op: Operation code
 * @arg: Operation argument (interpretation depends on op)
 * @payload: Optional data payload
 * @payload_len: Length of payload
 *
 * Returns: 0 on success, -1 on expected failure
 */
static int
execute_op (SocketBuf_T buf, uint8_t op, uint8_t arg, const uint8_t *payload,
            size_t payload_len)
{
  switch (op % STRESS_OP_COUNT)
    {
    case STRESS_WRITE:
      {
        /* Write arg bytes of payload (or less if not enough) */
        size_t to_write = arg;
        if (to_write > payload_len)
          to_write = payload_len;
        if (to_write > 0)
          {
            SocketBuf_write (buf, payload, to_write);
          }
      }
      break;

    case STRESS_READ:
      {
        /* Read arg bytes */
        size_t to_read = arg;
        if (to_read > sizeof (scratch))
          to_read = sizeof (scratch);
        size_t avail = SocketBuf_available (buf);
        if (to_read > avail)
          to_read = avail;
        if (to_read > 0)
          {
            SocketBuf_read (buf, scratch, to_read);
          }
      }
      break;

    case STRESS_PEEK:
      {
        /* Peek arg bytes */
        size_t to_peek = arg;
        if (to_peek > sizeof (scratch))
          to_peek = sizeof (scratch);
        if (to_peek > 0)
          {
            SocketBuf_peek (buf, scratch, to_peek);
          }
      }
      break;

    case STRESS_CONSUME:
      {
        /* Consume min(arg, available) bytes */
        size_t avail = SocketBuf_available (buf);
        size_t to_consume = arg;
        if (to_consume > avail)
          to_consume = avail;
        if (to_consume > 0)
          {
            SocketBuf_consume (buf, to_consume);
          }
      }
      break;

    case STRESS_RESERVE:
      {
        /* Reserve additional space - may fail */
        size_t reserve_size = ((size_t)arg * 16) + 1; /* Scale up arg */
        TRY { SocketBuf_reserve (buf, reserve_size); }
        EXCEPT (SocketBuf_Failed)
        {
          /* Expected for large reserves */
          return -1;
        }
        END_TRY;
      }
      break;

    case STRESS_CLEAR:
      {
        /* Clear based on arg: even = fast clear, odd = secure clear */
        if (arg & 1)
          {
            SocketBuf_secureclear (buf);
          }
        else
          {
            SocketBuf_clear (buf);
          }
      }
      break;

    case STRESS_WRITEPTR:
      {
        /* Use zero-copy write interface */
        size_t len = 0;
        void *wptr = SocketBuf_writeptr (buf, &len);
        if (wptr && len > 0 && payload_len > 0)
          {
            size_t to_write = len < payload_len ? len : payload_len;
            to_write = to_write < arg ? to_write : arg;
            if (to_write > 0)
              {
                memcpy (wptr, payload, to_write);
                SocketBuf_written (buf, to_write);
              }
          }
      }
      break;

    case STRESS_READPTR:
      {
        /* Use zero-copy read interface (just get pointer, don't consume) */
        size_t len = 0;
        const void *rptr = SocketBuf_readptr (buf, &len);
        (void)rptr;
        (void)len;
      }
      break;

    case STRESS_CHECK:
      {
        /* Verify invariants and query state */
        if (!SocketBuf_check_invariants (buf))
          {
            /* Invariant violation - this is a real bug! */
            assert (0 && "SocketBuf invariants violated!");
          }
        (void)SocketBuf_available (buf);
        (void)SocketBuf_space (buf);
        (void)SocketBuf_empty (buf);
        (void)SocketBuf_full (buf);
      }
      break;
    }

  return 0;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 *
 * Input format:
 * - Byte 0: Initial capacity (1-256, scaled)
 * - Remaining bytes: pairs of (op, arg) to execute
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketBuf_T buf = NULL;

  /* Need at least capacity byte + one (op, arg) pair */
  if (size < 3)
    return 0;

  /* Parse initial capacity */
  size_t capacity = ((size_t)data[0] % 255) + 1; /* 1-256 bytes */

  /* Use remaining bytes as payload and operation stream */
  const uint8_t *stream = data + 1;
  size_t stream_len = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    buf = SocketBuf_new (arena, capacity);
    if (!buf)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* Execute operation sequence */
    size_t i = 0;
    while (i + 1 < stream_len)
      {
        uint8_t op = stream[i];
        uint8_t arg = stream[i + 1];

        /* Use rest of stream as potential payload */
        const uint8_t *payload = stream + i + 2;
        size_t payload_len = stream_len - i - 2;

        execute_op (buf, op, arg, payload, payload_len);

        /* Verify invariants after each operation */
        if (!SocketBuf_check_invariants (buf))
          {
            assert (0 && "Invariants violated after operation!");
          }

        i += 2; /* Move to next (op, arg) pair */
      }

    /* Final state verification */
    (void)SocketBuf_check_invariants (buf);
  }
  EXCEPT (Arena_Failed) { /* Memory allocation failure */ }
  EXCEPT (SocketBuf_Failed) { /* Buffer operation failure */ }
  FINALLY
  {
    if (buf)
      SocketBuf_release (&buf);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
