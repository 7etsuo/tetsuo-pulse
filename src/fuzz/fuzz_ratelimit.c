/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_ratelimit.c - Fuzzer for SocketRateLimit token bucket
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Integer overflow in token calculations
 * - Underflow in token subtraction
 * - Rate limiting bypass edge cases
 * - Configuration change boundary conditions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_ratelimit
 * Run:   ./fuzz_ratelimit corpus/ratelimit/ -fork=16 -max_len=4096
 */

#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketRateLimit.h"

/* Operation codes for rate limiter fuzzing */
enum RateLimitOp
{
  RL_TRY_ACQUIRE = 0,
  RL_WAIT_TIME,
  RL_AVAILABLE,
  RL_RESET,
  RL_CONFIGURE,
  RL_GET_RATE,
  RL_GET_BUCKET,
  RL_OP_COUNT
};

/**
 * read_u32 - Read a 32-bit value from byte stream
 */
static uint32_t
read_u32 (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * execute_op - Execute a single rate limiter operation
 */
static void
execute_op (SocketRateLimit_T limiter,
            uint8_t op,
            const uint8_t *args,
            size_t args_len)
{
  switch (op % RL_OP_COUNT)
    {
    case RL_TRY_ACQUIRE:
      {
        size_t tokens = args_len >= 4 ? read_u32 (args) % 10000 : 1;
        (void)SocketRateLimit_try_acquire (limiter, tokens);
      }
      break;

    case RL_WAIT_TIME:
      {
        size_t tokens = args_len >= 4 ? read_u32 (args) % 10000 : 1;
        int64_t wait = SocketRateLimit_wait_time_ms (limiter, tokens);
        (void)wait;
      }
      break;

    case RL_AVAILABLE:
      {
        size_t avail = SocketRateLimit_available (limiter);
        (void)avail;
      }
      break;

    case RL_RESET:
      {
        SocketRateLimit_reset (limiter);
      }
      break;

    case RL_CONFIGURE:
      {
        size_t new_rate = args_len >= 4 ? read_u32 (args) % 100000 : 0;
        size_t new_bucket
            = args_len >= 8 ? read_u32 (args + 4) % 100000 : new_rate;
        SocketRateLimit_configure (limiter, new_rate, new_bucket);
      }
      break;

    case RL_GET_RATE:
      {
        size_t rate = SocketRateLimit_get_rate (limiter);
        (void)rate;
      }
      break;

    case RL_GET_BUCKET:
      {
        size_t bucket = SocketRateLimit_get_bucket_size (limiter);
        (void)bucket;
      }
      break;
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Bytes 0-3: Initial tokens_per_sec
 * - Bytes 4-7: Initial bucket_size
 * - Remaining: Sequence of (op, args...) operations
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketRateLimit_T limiter = NULL;

  /* Need at least initial config + one operation */
  if (size < 9)
    return 0;

  /* Parse initial configuration */
  size_t tokens_per_sec = read_u32 (data) % 1000000;
  size_t bucket_size = read_u32 (data + 4) % 1000000;

  /* Ensure non-zero rate */
  if (tokens_per_sec == 0)
    tokens_per_sec = 1;

  const uint8_t *stream = data + 8;
  size_t stream_len = size - 8;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    limiter = SocketRateLimit_new (arena, tokens_per_sec, bucket_size);
    if (!limiter)
      {
        Arena_dispose (&arena);
        return 0;
      }

    /* Execute operation sequence */
    size_t i = 0;
    while (i < stream_len)
      {
        uint8_t op = stream[i++];
        const uint8_t *args = stream + i;
        size_t args_len = stream_len - i;

        execute_op (limiter, op, args, args_len);

        /* Consume some argument bytes based on operation */
        i += (op % 4) + 1;
      }

    /* Final state verification */
    (void)SocketRateLimit_available (limiter);
    (void)SocketRateLimit_get_rate (limiter);
    (void)SocketRateLimit_get_bucket_size (limiter);
  }
  EXCEPT (Arena_Failed)
  { /* Memory allocation failure */
  }
  EXCEPT (SocketRateLimit_Failed)
  { /* Rate limiter operation failure */
  }
  FINALLY
  {
    if (limiter)
      SocketRateLimit_free (&limiter);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
