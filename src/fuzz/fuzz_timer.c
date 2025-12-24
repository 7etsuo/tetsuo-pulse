/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_timer.c - Fuzzer for SocketTimer min-heap
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Heap corruption from add/cancel sequences
 * - Index out-of-bounds in heap operations
 * - Timer ID reuse and lookup issues
 * - Use-after-cancel scenarios
 *
 * Note: SocketTimer requires a SocketPoll instance. We create a minimal
 * poll context just for timer management without real socket I/O.
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_timer
 * Run:   ./fuzz_timer corpus/timer/ -fork=16 -max_len=4096
 */

#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketTimer.h"
#include "poll/SocketPoll.h"

/* Maximum concurrent timers to track */
#define MAX_TIMERS 64

/* Operation codes for timer fuzzing */
enum TimerOp
{
  TIMER_ADD = 0,
  TIMER_ADD_REPEATING,
  TIMER_CANCEL,
  TIMER_REMAINING,
  TIMER_OP_COUNT
};

/* Track active timer handles */
static SocketTimer_T timers[MAX_TIMERS];
static int timer_count = 0;
static volatile int callback_count = 0;

/**
 * timer_callback - Timer callback function
 */
static void
timer_callback (void *userdata)
{
  (void)userdata;
  callback_count++;
}

/**
 * read_u16 - Read a 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * execute_op - Execute a single timer operation
 */
static void
execute_op (SocketPoll_T poll, uint8_t op, const uint8_t *args,
            size_t args_len)
{
  switch (op % TIMER_OP_COUNT)
    {
    case TIMER_ADD:
      {
        if (timer_count >= MAX_TIMERS)
          break;

        /* Delay in milliseconds (0-65535) */
        int64_t delay_ms = args_len >= 2 ? read_u16 (args) : 100;

        TRY
        {
          SocketTimer_T t
              = SocketTimer_add (poll, delay_ms, timer_callback, NULL);
          if (t)
            {
              timers[timer_count++] = t;
            }
        }
        EXCEPT (SocketTimer_Failed)
        {
          /* Expected for invalid params or resource limits */
        }
        END_TRY;
      }
      break;

    case TIMER_ADD_REPEATING:
      {
        if (timer_count >= MAX_TIMERS)
          break;

        /* Interval in milliseconds (1-65535, minimum 1) */
        int64_t interval_ms = args_len >= 2 ? read_u16 (args) : 100;
        if (interval_ms == 0)
          interval_ms = 1;

        TRY
        {
          SocketTimer_T t = SocketTimer_add_repeating (poll, interval_ms,
                                                       timer_callback, NULL);
          if (t)
            {
              timers[timer_count++] = t;
            }
        }
        EXCEPT (SocketTimer_Failed)
        {
          /* Expected for invalid params or resource limits */
        }
        END_TRY;
      }
      break;

    case TIMER_CANCEL:
      {
        if (timer_count == 0)
          break;

        /* Select timer by index (wrap around) */
        int idx = args_len >= 1 ? args[0] % timer_count : 0;

        TRY
        {
          int result = SocketTimer_cancel (poll, timers[idx]);
          (void)result;

          /* Remove from our tracking (swap with last) */
          timers[idx] = timers[timer_count - 1];
          timers[timer_count - 1] = NULL;
          timer_count--;
        }
        EXCEPT (SocketTimer_Failed) { /* Timer already fired or invalid */ }
        END_TRY;
      }
      break;

    case TIMER_REMAINING:
      {
        if (timer_count == 0)
          break;

        /* Select timer by index (wrap around) */
        int idx = args_len >= 1 ? args[0] % timer_count : 0;

        TRY
        {
          int64_t remaining = SocketTimer_remaining (poll, timers[idx]);
          (void)remaining;
        }
        EXCEPT (SocketTimer_Failed) { /* Timer already fired or invalid */ }
        END_TRY;
      }
      break;
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Max sockets for poll (scaled)
 * - Remaining: Sequence of (op, args...) operations
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketPoll_T poll = NULL;

  /* Reset global state */
  memset (timers, 0, sizeof (timers));
  timer_count = 0;
  callback_count = 0;

  /* Need at least config + one operation */
  if (size < 2)
    return 0;

  /* Parse poll configuration */
  int max_sockets = (data[0] % 64) + 8; /* 8-71 sockets */

  const uint8_t *stream = data + 1;
  size_t stream_len = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    poll = SocketPoll_new (max_sockets);
    if (!poll)
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

        execute_op (poll, op, args, args_len);

        /* Consume argument bytes based on operation */
        i += (op % 3) + 1;
      }

    /* Cancel all remaining timers */
    for (int j = 0; j < timer_count; j++)
      {
        if (timers[j])
          {
            TRY { SocketTimer_cancel (poll, timers[j]); }
            EXCEPT (SocketTimer_Failed) { /* Already fired */ }
            END_TRY;
          }
      }
  }
  EXCEPT (Arena_Failed) { /* Memory allocation failure */ }
  EXCEPT (SocketPoll_Failed) { /* Poll operation failure */ }
  EXCEPT (SocketTimer_Failed) { /* Timer operation failure */ }
  FINALLY
  {
    if (poll)
      SocketPoll_free (&poll);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
