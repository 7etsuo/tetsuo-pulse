/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_flow.c - libFuzzer for QUIC Flow Control (RFC 9000 Section 4)
 *
 * Fuzzes connection and stream-level flow control:
 * - Send/receive window management
 * - MAX_DATA/MAX_STREAM_DATA updates
 * - Stream count limits (MAX_STREAMS)
 * - Blocked state detection
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_flow
 * ./fuzz_quic_flow corpus/quic_flow/ -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICFlow.h"

/* Operation types */
enum
{
  OP_CONNECTION_FLOW,
  OP_STREAM_FLOW,
  OP_STREAM_COUNTS,
  OP_WINDOW_UPDATES,
  OP_RESULT_STRINGS,
  OP_MAX
};

/* Helper to read uint64_t from buffer */
static uint64_t
read_u64 (const uint8_t *data)
{
  uint64_t val = 0;
  for (int i = 0; i < 8; i++)
    val = (val << 8) | data[i];
  return val;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 50)
    return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    uint8_t op = data[0] % OP_MAX;

    switch (op)
      {
      case OP_CONNECTION_FLOW:
        {
          /* Test connection-level flow control */
          SocketQUICFlow_T fc = SocketQUICFlow_new (arena);
          if (!fc)
            break;

          /* Initialize with fuzzed values */
          uint64_t recv_max = read_u64 (data + 1);
          uint64_t send_max = read_u64 (data + 9);
          uint64_t max_bidi = read_u64 (data + 17) % 1000;
          uint64_t max_uni = read_u64 (data + 25) % 1000;

          SocketQUICFlow_Result result
              = SocketQUICFlow_init (fc, recv_max, send_max, max_bidi, max_uni);
          (void)result;

          /* Test can_send with various sizes */
          size_t bytes_to_send = (size_t)read_u64 (data + 33);
          int can = SocketQUICFlow_can_send (fc, bytes_to_send);
          (void)can;

          /* Consume some send window */
          result = SocketQUICFlow_consume_send (fc, 1000);
          (void)result;

          /* Check windows */
          uint64_t send_win = SocketQUICFlow_send_window (fc);
          uint64_t recv_win = SocketQUICFlow_recv_window (fc);
          (void)send_win;
          (void)recv_win;

          /* Consume receive window */
          result = SocketQUICFlow_consume_recv (fc, 500);
          (void)result;

          /* Try to exceed limits */
          result = SocketQUICFlow_consume_send (fc, QUIC_FLOW_MAX_WINDOW);
          (void)result;

          /* Update max data values */
          uint64_t new_send_max = read_u64 (data + 41);
          result = SocketQUICFlow_update_send_max (fc, new_send_max);
          (void)result;

          result = SocketQUICFlow_update_recv_max (fc, recv_max * 2);
          (void)result;

          /* Test NULL inputs */
          SocketQUICFlow_can_send (NULL, 100);
          SocketQUICFlow_consume_send (NULL, 100);
          SocketQUICFlow_consume_recv (NULL, 100);
          SocketQUICFlow_send_window (NULL);
          SocketQUICFlow_recv_window (NULL);
          SocketQUICFlow_update_send_max (NULL, 1000);
          SocketQUICFlow_update_recv_max (NULL, 1000);
          SocketQUICFlow_init (NULL, 0, 0, 0, 0);
          break;
        }

      case OP_STREAM_FLOW:
        {
          /* Test stream-level flow control */
          uint64_t stream_id = read_u64 (data + 1);

          SocketQUICFlowStream_T fs
              = SocketQUICFlowStream_new (arena, stream_id);
          if (!fs)
            break;

          /* Initialize with fuzzed values */
          uint64_t recv_max = read_u64 (data + 9);
          uint64_t send_max = read_u64 (data + 17);

          SocketQUICFlow_Result result
              = SocketQUICFlowStream_init (fs, stream_id, recv_max, send_max);
          (void)result;

          /* Test can_send */
          size_t bytes = (size_t)read_u64 (data + 25);
          int can = SocketQUICFlowStream_can_send (fs, bytes);
          (void)can;

          /* Consume windows */
          result = SocketQUICFlowStream_consume_send (fs, 100);
          (void)result;
          result = SocketQUICFlowStream_consume_recv (fs, 200);
          (void)result;

          /* Check windows */
          uint64_t send_win = SocketQUICFlowStream_send_window (fs);
          uint64_t recv_win = SocketQUICFlowStream_recv_window (fs);
          (void)send_win;
          (void)recv_win;

          /* Update max values */
          uint64_t new_max = read_u64 (data + 33);
          result = SocketQUICFlowStream_update_send_max (fs, new_max);
          (void)result;
          result = SocketQUICFlowStream_update_recv_max (fs, new_max);
          (void)result;

          /* Test with maximum window */
          result
              = SocketQUICFlowStream_update_send_max (fs, QUIC_FLOW_MAX_WINDOW);
          (void)result;

          /* Test NULL inputs */
          SocketQUICFlowStream_can_send (NULL, 100);
          SocketQUICFlowStream_consume_send (NULL, 100);
          SocketQUICFlowStream_consume_recv (NULL, 100);
          SocketQUICFlowStream_send_window (NULL);
          SocketQUICFlowStream_recv_window (NULL);
          SocketQUICFlowStream_update_send_max (NULL, 1000);
          SocketQUICFlowStream_update_recv_max (NULL, 1000);
          SocketQUICFlowStream_init (NULL, 0, 0, 0);
          break;
        }

      case OP_STREAM_COUNTS:
        {
          /* Test stream count management */
          SocketQUICFlow_T fc = SocketQUICFlow_new (arena);
          if (!fc)
            break;

          uint64_t max_bidi = (read_u64 (data + 1) % 100) + 1;
          uint64_t max_uni = (read_u64 (data + 9) % 100) + 1;

          SocketQUICFlow_init (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW,
                               QUIC_FLOW_DEFAULT_CONN_WINDOW, max_bidi,
                               max_uni);

          /* Check if we can open streams */
          int can_bidi = SocketQUICFlow_can_open_stream_bidi (fc);
          int can_uni = SocketQUICFlow_can_open_stream_uni (fc);
          (void)can_bidi;
          (void)can_uni;

          /* Open streams until limit */
          for (uint64_t i = 0; i < max_bidi + 5; i++)
            {
              can_bidi = SocketQUICFlow_can_open_stream_bidi (fc);
              SocketQUICFlow_Result result
                  = SocketQUICFlow_open_stream_bidi (fc);
              (void)can_bidi;
              (void)result;
            }

          for (uint64_t i = 0; i < max_uni + 5; i++)
            {
              can_uni = SocketQUICFlow_can_open_stream_uni (fc);
              SocketQUICFlow_Result result
                  = SocketQUICFlow_open_stream_uni (fc);
              (void)can_uni;
              (void)result;
            }

          /* Close some streams */
          for (int i = 0; i < 10; i++)
            {
              SocketQUICFlow_close_stream_bidi (fc);
              SocketQUICFlow_close_stream_uni (fc);
            }

          /* Update stream limits */
          uint64_t new_max_bidi = read_u64 (data + 17);
          uint64_t new_max_uni = read_u64 (data + 25);
          SocketQUICFlow_update_max_streams_bidi (fc, new_max_bidi);
          SocketQUICFlow_update_max_streams_uni (fc, new_max_uni);

          /* Test NULL inputs */
          SocketQUICFlow_can_open_stream_bidi (NULL);
          SocketQUICFlow_can_open_stream_uni (NULL);
          SocketQUICFlow_open_stream_bidi (NULL);
          SocketQUICFlow_open_stream_uni (NULL);
          SocketQUICFlow_close_stream_bidi (NULL);
          SocketQUICFlow_close_stream_uni (NULL);
          SocketQUICFlow_update_max_streams_bidi (NULL, 100);
          SocketQUICFlow_update_max_streams_uni (NULL, 100);
          break;
        }

      case OP_WINDOW_UPDATES:
        {
          /* Test window update edge cases */
          SocketQUICFlow_T fc = SocketQUICFlow_new (arena);
          if (!fc)
            break;

          /* Initialize with small windows */
          SocketQUICFlow_init (fc, 1000, 1000, 10, 10);

          /* Repeatedly consume and update */
          for (int i = 0; i < 20; i++)
            {
              size_t bytes = (size_t)(data[1 + i % (size - 1)] * 10);
              SocketQUICFlow_consume_send (fc, bytes);
              SocketQUICFlow_consume_recv (fc, bytes);

              uint64_t new_max = read_u64 (data + 1 + (i * 8) % (size - 8));
              SocketQUICFlow_update_send_max (fc, new_max);
              SocketQUICFlow_update_recv_max (fc, new_max);
            }

          /* Test with extreme values */
          SocketQUICFlow_update_send_max (fc, 0);
          SocketQUICFlow_update_recv_max (fc, 0);
          SocketQUICFlow_update_send_max (fc, UINT64_MAX);
          SocketQUICFlow_update_recv_max (fc, UINT64_MAX);
          SocketQUICFlow_update_send_max (fc, QUIC_FLOW_MAX_WINDOW);
          SocketQUICFlow_update_recv_max (fc, QUIC_FLOW_MAX_WINDOW);
          SocketQUICFlow_update_send_max (fc, QUIC_FLOW_MAX_WINDOW + 1);
          SocketQUICFlow_update_recv_max (fc, QUIC_FLOW_MAX_WINDOW + 1);

          /* Stream flow with extreme values */
          SocketQUICFlowStream_T fs = SocketQUICFlowStream_new (arena, 0);
          if (fs)
            {
              SocketQUICFlowStream_init (fs, 0, 0, 0);
              SocketQUICFlowStream_update_send_max (fs, QUIC_FLOW_MAX_WINDOW);
              SocketQUICFlowStream_consume_send (fs, QUIC_FLOW_MAX_WINDOW);
            }
          break;
        }

      case OP_RESULT_STRINGS:
        {
          /* Test result string function */
          SocketQUICFlow_Result results[]
              = { QUIC_FLOW_OK,        QUIC_FLOW_ERROR_NULL,
                  QUIC_FLOW_ERROR_BLOCKED, QUIC_FLOW_ERROR_OVERFLOW,
                  QUIC_FLOW_ERROR_INVALID };

          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICFlow_result_string (results[i]);
              (void)str;
            }

          /* Test with fuzzed value */
          const char *str
              = SocketQUICFlow_result_string ((SocketQUICFlow_Result)data[1]);
          (void)str;
          break;
        }
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose ((Arena_T *)&arena);
  return 0;
}
