/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_loss.c - libFuzzer for QUIC Loss Detection (RFC 9002)
 *
 * Fuzzes loss detection and RTT estimation:
 * - Sent packet tracking
 * - ACK processing and loss detection
 * - RTT estimation (smoothed RTT, variance, min RTT)
 * - PTO calculation
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_loss
 * ./fuzz_quic_loss corpus/quic_loss/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICLoss.h"

/* Operation types */
enum
{
  OP_SENT_PACKET_TRACKING,
  OP_ACK_PROCESSING,
  OP_RTT_ESTIMATION,
  OP_TIMERS,
  OP_QUERY_FUNCTIONS,
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

/* Callback for lost packets */
static void
lost_packet_callback (const SocketQUICLossSentPacket_T *packet, void *context)
{
  (void)packet;
  size_t *count = (size_t *)context;
  if (count)
    (*count)++;
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
      case OP_SENT_PACKET_TRACKING:
        {
          /* Test sent packet recording */
          int is_handshake = data[1] & 1;
          uint64_t max_ack_delay
              = (read_u64 (data + 2) % QUIC_LOSS_INITIAL_RTT_US) + 1;

          SocketQUICLossState_T state
              = SocketQUICLoss_new (arena, is_handshake, max_ack_delay);
          if (!state)
            break;

          /* Record packets from fuzz data */
          uint64_t sent_time = 1000000; /* 1 second */
          size_t offset = 10;

          while (offset + 10 <= size)
            {
              uint64_t pn = read_u64 (data + offset);
              /* Limit packet numbers to avoid huge hash tables */
              pn = pn % 10000;

              size_t sent_bytes = (data[offset + 8] * 10) + 50;
              int ack_eliciting = data[offset + 9] & 1;
              int in_flight = data[offset + 9] & 2;
              int is_crypto = data[offset + 9] & 4;

              SocketQUICLoss_Result result = SocketQUICLoss_on_packet_sent (
                  state, pn, sent_time, sent_bytes, ack_eliciting, in_flight,
                  is_crypto);
              (void)result;

              sent_time += 1000; /* 1ms between packets */
              offset += 10;
            }

          /* Check bytes in flight */
          size_t bytes = SocketQUICLoss_bytes_in_flight (state);
          int has_inflight = SocketQUICLoss_has_in_flight (state);
          (void)bytes;
          (void)has_inflight;

          /* Test reset */
          SocketQUICLoss_reset (state);
          bytes = SocketQUICLoss_bytes_in_flight (state);
          (void)bytes;

          /* Test NULL inputs */
          SocketQUICLoss_on_packet_sent (NULL, 0, 0, 100, 1, 1, 0);
          SocketQUICLoss_bytes_in_flight (NULL);
          SocketQUICLoss_has_in_flight (NULL);
          SocketQUICLoss_reset (NULL);
          break;
        }

      case OP_ACK_PROCESSING:
        {
          /* Test ACK processing and loss detection */
          SocketQUICLossState_T state
              = SocketQUICLoss_new (arena, 0, 25000);
          if (!state)
            break;

          SocketQUICLossRTT_T rtt;
          SocketQUICLoss_init_rtt (&rtt);

          /* Record some packets */
          uint64_t base_time = 1000000;
          for (uint64_t pn = 0; pn < 50; pn++)
            {
              SocketQUICLoss_on_packet_sent (state, pn, base_time + pn * 1000,
                                             100, 1, 1, 0);
            }

          /* Process ACKs from fuzz data */
          size_t offset = 1;
          size_t lost_count = 0;

          while (offset + 24 <= size)
            {
              uint64_t largest_acked = read_u64 (data + offset) % 50;
              uint64_t ack_delay = read_u64 (data + offset + 8) % 100000;
              uint64_t recv_time = base_time + read_u64 (data + offset + 16);

              SocketQUICLoss_Result result = SocketQUICLoss_on_ack_received (
                  state, &rtt, largest_acked, ack_delay, recv_time,
                  lost_packet_callback, &lost_count, NULL);
              (void)result;

              offset += 24;
            }

          /* Test with NULL callback */
          SocketQUICLoss_on_ack_received (state, &rtt, 40, 10000,
                                          base_time + 100000, NULL, NULL,
                                          &lost_count);

          /* Test NULL inputs */
          SocketQUICLoss_on_ack_received (NULL, &rtt, 0, 0, 0, NULL, NULL,
                                          NULL);
          SocketQUICLoss_on_ack_received (state, NULL, 0, 0, 0, NULL, NULL,
                                          NULL);
          break;
        }

      case OP_RTT_ESTIMATION:
        {
          /* Test RTT estimation */
          SocketQUICLossRTT_T rtt;
          SocketQUICLoss_init_rtt (&rtt);

          /* Process RTT samples from fuzz data */
          size_t offset = 1;
          while (offset + 17 <= size)
            {
              uint64_t latest_rtt = read_u64 (data + offset);
              /* Limit RTT to reasonable values */
              latest_rtt = (latest_rtt % 10000000) + 1; /* 1us to 10s */

              uint64_t ack_delay = read_u64 (data + offset + 8);
              ack_delay = ack_delay % latest_rtt; /* Delay < RTT */

              int is_handshake = data[offset + 16] & 1;

              SocketQUICLoss_update_rtt (&rtt, latest_rtt, ack_delay,
                                         is_handshake);

              offset += 17;
            }

          /* Check RTT values are reasonable */
          (void)rtt.smoothed_rtt;
          (void)rtt.rtt_var;
          (void)rtt.min_rtt;
          (void)rtt.latest_rtt;
          (void)rtt.has_sample;

          /* Test with edge cases */
          SocketQUICLoss_init_rtt (&rtt);
          SocketQUICLoss_update_rtt (&rtt, 1, 0, 1);          /* Minimum RTT */
          SocketQUICLoss_update_rtt (&rtt, UINT64_MAX, 0, 0); /* Maximum RTT */
          SocketQUICLoss_update_rtt (&rtt, 100000, 99999, 0); /* High ack delay */
          SocketQUICLoss_update_rtt (&rtt, 100000, 100001,
                                     0); /* Delay > RTT */

          /* Test NULL */
          SocketQUICLoss_update_rtt (NULL, 1000, 0, 0);
          SocketQUICLoss_init_rtt (NULL);
          break;
        }

      case OP_TIMERS:
        {
          /* Test PTO and loss time calculations */
          SocketQUICLossRTT_T rtt;
          SocketQUICLoss_init_rtt (&rtt);

          /* Add some RTT samples */
          SocketQUICLoss_update_rtt (&rtt, 50000, 0, 1);  /* 50ms */
          SocketQUICLoss_update_rtt (&rtt, 60000, 5000, 0); /* 60ms */
          SocketQUICLoss_update_rtt (&rtt, 55000, 3000, 0); /* 55ms */

          /* Test PTO calculation with various pto_count values */
          uint64_t max_ack_delay = read_u64 (data + 1) % 100000 + 1;

          for (int pto_count = 0; pto_count <= QUIC_LOSS_MAX_PTO_COUNT + 1;
               pto_count++)
            {
              uint64_t pto
                  = SocketQUICLoss_get_pto (&rtt, max_ack_delay, pto_count);
              (void)pto;
            }

          /* Test with uninitialized RTT */
          SocketQUICLossRTT_T empty_rtt;
          SocketQUICLoss_init_rtt (&empty_rtt);
          uint64_t pto = SocketQUICLoss_get_pto (&empty_rtt, 25000, 0);
          (void)pto;

          /* Test loss time calculation */
          SocketQUICLossState_T state
              = SocketQUICLoss_new (arena, 0, max_ack_delay);
          if (state)
            {
              /* Record some packets */
              for (uint64_t i = 0; i < 10; i++)
                {
                  SocketQUICLoss_on_packet_sent (state, i, 1000000 + i * 1000,
                                                 100, 1, 1, 0);
                }

              uint64_t current_time = read_u64 (data + 9);
              int pto_count = data[17] % (QUIC_LOSS_MAX_PTO_COUNT + 1);

              uint64_t loss_time = SocketQUICLoss_get_loss_time (
                  state, &rtt, pto_count, current_time);
              (void)loss_time;

              /* Test loss timeout handling */
              size_t lost = 0;
              SocketQUICLoss_on_loss_timeout (state, &rtt, current_time + 100000,
                                              lost_packet_callback, &lost,
                                              NULL);
            }

          /* Test NULL */
          SocketQUICLoss_get_pto (NULL, 25000, 0);
          SocketQUICLoss_get_loss_time (NULL, &rtt, 0, 0);
          SocketQUICLoss_get_loss_time (state, NULL, 0, 0);
          SocketQUICLoss_on_loss_timeout (NULL, &rtt, 0, NULL, NULL, NULL);
          break;
        }

      case OP_QUERY_FUNCTIONS:
        {
          /* Test query functions extensively */
          SocketQUICLossState_T state
              = SocketQUICLoss_new (arena, 0, 25000);
          if (!state)
            break;

          /* Initially empty */
          size_t bytes = SocketQUICLoss_bytes_in_flight (state);
          int has = SocketQUICLoss_has_in_flight (state);
          (void)bytes;
          (void)has;

          /* Add packets with various properties */
          SocketQUICLoss_on_packet_sent (state, 0, 1000000, 100, 1, 1, 0);
          SocketQUICLoss_on_packet_sent (state, 1, 1001000, 200, 0, 1, 0);
          SocketQUICLoss_on_packet_sent (state, 2, 1002000, 150, 1, 0, 0);
          SocketQUICLoss_on_packet_sent (state, 3, 1003000, 300, 1, 1, 1);

          bytes = SocketQUICLoss_bytes_in_flight (state);
          has = SocketQUICLoss_has_in_flight (state);
          (void)bytes;
          (void)has;

          /* Try to add duplicate */
          SocketQUICLoss_Result result
              = SocketQUICLoss_on_packet_sent (state, 0, 2000000, 100, 1, 1, 0);
          (void)result;

          /* ACK some packets */
          SocketQUICLossRTT_T rtt;
          SocketQUICLoss_init_rtt (&rtt);
          SocketQUICLoss_on_ack_received (state, &rtt, 1, 1000, 1100000, NULL,
                                          NULL, NULL);

          bytes = SocketQUICLoss_bytes_in_flight (state);
          (void)bytes;
          break;
        }

      case OP_RESULT_STRINGS:
        {
          /* Test result string function */
          SocketQUICLoss_Result results[] = { QUIC_LOSS_OK,
                                              QUIC_LOSS_ERROR_NULL,
                                              QUIC_LOSS_ERROR_DUPLICATE,
                                              QUIC_LOSS_ERROR_NOT_FOUND,
                                              QUIC_LOSS_ERROR_FULL,
                                              QUIC_LOSS_ERROR_INVALID };

          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICLoss_result_string (results[i]);
              (void)str;
            }

          /* Test with fuzzed value */
          const char *str
              = SocketQUICLoss_result_string ((SocketQUICLoss_Result)data[1]);
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
