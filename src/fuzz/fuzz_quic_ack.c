/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_ack.c - libFuzzer for QUIC ACK Generation (RFC 9000 Section 13.2)
 *
 * Fuzzes ACK state management and encoding:
 * - Packet number tracking with ranges
 * - ACK frame encoding
 * - Delayed ACK timing
 * - ECN count tracking
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_ack
 * ./fuzz_quic_ack corpus/quic_ack/ -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICAck.h"

/* Operation types */
enum
{
  OP_RECORD_PACKETS,
  OP_ENCODE_ACK,
  OP_SHOULD_SEND,
  OP_ECN_TRACKING,
  OP_QUERY_FUNCTIONS,
  OP_PRUNE,
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
  if (size < 18)
    return 0;

  volatile Arena_T arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    uint8_t op = data[0] % OP_MAX;

    switch (op)
      {
      case OP_RECORD_PACKETS:
        {
          /* Test packet recording */
          int is_handshake = data[1] & 1;
          uint64_t max_ack_delay = read_u64 (data + 2);

          SocketQUICAckState_T state = SocketQUICAck_new (
              arena,
              is_handshake,
              max_ack_delay % QUIC_ACK_DEFAULT_MAX_DELAY_US + 1);
          if (!state)
            break;

          /* Record multiple packets from fuzz data */
          size_t offset = 10;
          while (offset + 17 <= size)
            {
              uint64_t pn = read_u64 (data + offset);
              uint64_t recv_time = read_u64 (data + offset + 8);
              int ack_eliciting = data[offset + 16] & 1;

              SocketQUICAck_Result result = SocketQUICAck_record_packet (
                  state, pn, recv_time, ack_eliciting);
              (void)result;

              offset += 17;
            }

          /* Check contains for some packet numbers */
          for (size_t i = 0; i < 10 && 10 + i * 8 + 8 <= size; i++)
            {
              uint64_t pn = read_u64 (data + 10 + i * 8);
              int contains = SocketQUICAck_contains (state, pn);
              (void)contains;
            }

          /* Get largest and range count */
          uint64_t largest = SocketQUICAck_get_largest (state);
          size_t ranges = SocketQUICAck_range_count (state);
          (void)largest;
          (void)ranges;

          /* Test reset */
          SocketQUICAck_reset (state);

          /* Record again after reset */
          SocketQUICAck_record_packet (state, 100, 1000000, 1);
          break;
        }

      case OP_ENCODE_ACK:
        {
          /* Test ACK frame encoding */
          int is_handshake = data[1] & 1;

          SocketQUICAckState_T state = SocketQUICAck_new (
              arena, is_handshake, QUIC_ACK_DEFAULT_MAX_DELAY_US);
          if (!state)
            break;

          /* Record packets to create ranges */
          size_t offset = 2;
          int count = 0;
          while (offset + 9 <= size && count < 50)
            {
              uint64_t pn = read_u64 (data + offset);
              /* Limit packet numbers to avoid excessive range creation */
              pn = pn % 10000;

              SocketQUICAck_record_packet (
                  state, pn, 1000000 + count * 1000, 1);
              offset += 9;
              count++;
            }

          /* Encode ACK frame */
          uint8_t ack_buf[1024];
          size_t ack_len = 0;
          uint64_t current_time = read_u64 (data + 2);

          SocketQUICAck_Result result = SocketQUICAck_encode (
              state, current_time, ack_buf, sizeof (ack_buf), &ack_len);
          (void)result;

          /* Encode with small buffer */
          result = SocketQUICAck_encode (
              state, current_time, ack_buf, 10, &ack_len);
          (void)result;

          /* Mark as sent */
          SocketQUICAck_mark_sent (state, current_time);

          /* Record more and encode again */
          SocketQUICAck_record_packet (state, 20000, current_time + 1000, 1);
          result = SocketQUICAck_encode (
              state, current_time + 2000, ack_buf, sizeof (ack_buf), &ack_len);
          (void)result;

          /* Test NULL inputs */
          SocketQUICAck_encode (
              NULL, current_time, ack_buf, sizeof (ack_buf), &ack_len);
          SocketQUICAck_encode (state, current_time, NULL, 0, &ack_len);
          SocketQUICAck_encode (
              state, current_time, ack_buf, sizeof (ack_buf), NULL);
          break;
        }

      case OP_SHOULD_SEND:
        {
          /* Test should_send logic */
          int is_handshake = data[1] & 1;
          uint64_t max_ack_delay
              = (read_u64 (data + 2) % QUIC_ACK_DEFAULT_MAX_DELAY_US) + 1;

          SocketQUICAckState_T state
              = SocketQUICAck_new (arena, is_handshake, max_ack_delay);
          if (!state)
            break;

          uint64_t current_time = read_u64 (data + 10);

          /* Initially should not send */
          int should = SocketQUICAck_should_send (state, current_time);
          (void)should;

          /* Record one ack-eliciting packet */
          SocketQUICAck_record_packet (state, 0, current_time, 1);
          should = SocketQUICAck_should_send (state, current_time);
          (void)should;

          /* For handshake space, should send immediately */
          /* For application space, wait for threshold or delay */

          /* Record more packets up to threshold */
          for (int i = 1; i < QUIC_ACK_PACKET_THRESHOLD + 1; i++)
            {
              SocketQUICAck_record_packet (state, (uint64_t)i, current_time, 1);
              should = SocketQUICAck_should_send (state, current_time);
              (void)should;
            }

          /* Test after delay expires */
          should = SocketQUICAck_should_send (state,
                                              current_time + max_ack_delay * 2);
          (void)should;

          /* Mark sent and check again */
          SocketQUICAck_mark_sent (state, current_time + max_ack_delay * 2);
          should = SocketQUICAck_should_send (state,
                                              current_time + max_ack_delay * 2);
          (void)should;

          /* Test NULL */
          SocketQUICAck_should_send (NULL, current_time);
          break;
        }

      case OP_ECN_TRACKING:
        {
          /* Test ECN count tracking */
          SocketQUICAckState_T state
              = SocketQUICAck_new (arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);
          if (!state)
            break;

          /* Record ECN values */
          size_t offset = 1;
          while (offset < size)
            {
              int ecn_type = data[offset] % 4;
              SocketQUICAck_record_ecn (state, ecn_type);

              /* Also record a packet for this ECN */
              if (offset + 9 <= size)
                {
                  uint64_t pn = read_u64 (data + offset + 1);
                  SocketQUICAck_record_packet (
                      state, pn % 10000, 1000000 + offset * 1000, 1);
                }
              offset += 9;
            }

          /* Encode should include ECN if validated */
          uint8_t ack_buf[1024];
          size_t ack_len = 0;
          SocketQUICAck_encode (
              state, 2000000, ack_buf, sizeof (ack_buf), &ack_len);

          /* Test all ECN types explicitly */
          SocketQUICAck_record_ecn (state, QUIC_ECN_NOT_ECT);
          SocketQUICAck_record_ecn (state, QUIC_ECN_ECT0);
          SocketQUICAck_record_ecn (state, QUIC_ECN_ECT1);
          SocketQUICAck_record_ecn (state, QUIC_ECN_CE);

          /* Test NULL */
          SocketQUICAck_record_ecn (NULL, QUIC_ECN_ECT0);
          break;
        }

      case OP_QUERY_FUNCTIONS:
        {
          /* Test query functions */
          SocketQUICAckState_T state
              = SocketQUICAck_new (arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);
          if (!state)
            break;

          /* Initially empty */
          uint64_t largest = SocketQUICAck_get_largest (state);
          size_t range_count = SocketQUICAck_range_count (state);
          (void)largest;
          (void)range_count;

          /* Record packets with gaps to create ranges */
          SocketQUICAck_record_packet (state, 0, 1000000, 1);
          SocketQUICAck_record_packet (state, 1, 1001000, 1);
          SocketQUICAck_record_packet (state, 2, 1002000, 1);
          /* Gap */
          SocketQUICAck_record_packet (state, 10, 1003000, 1);
          SocketQUICAck_record_packet (state, 11, 1004000, 1);
          /* Gap */
          SocketQUICAck_record_packet (state, 100, 1005000, 1);

          largest = SocketQUICAck_get_largest (state);
          range_count = SocketQUICAck_range_count (state);
          (void)largest;
          (void)range_count;

          /* Test contains for various packet numbers */
          int c0 = SocketQUICAck_contains (state, 0);
          int c5 = SocketQUICAck_contains (state, 5);
          int c10 = SocketQUICAck_contains (state, 10);
          int c50 = SocketQUICAck_contains (state, 50);
          int c100 = SocketQUICAck_contains (state, 100);
          int c200 = SocketQUICAck_contains (state, 200);
          (void)c0;
          (void)c5;
          (void)c10;
          (void)c50;
          (void)c100;
          (void)c200;

          /* Test NULL */
          SocketQUICAck_get_largest (NULL);
          SocketQUICAck_range_count (NULL);
          SocketQUICAck_contains (NULL, 0);
          break;
        }

      case OP_PRUNE:
        {
          /* Test prune function */
          SocketQUICAckState_T state
              = SocketQUICAck_new (arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);
          if (!state)
            break;

          /* Record many packets */
          for (uint64_t i = 0; i < 100; i++)
            {
              SocketQUICAck_record_packet (state, i, 1000000 + i * 1000, 1);
            }

          /* Prune old packets */
          size_t removed = 0;
          uint64_t oldest_to_keep = read_u64 (data + 1) % 100;
          SocketQUICAck_prune (state, oldest_to_keep, &removed);
          (void)removed;

          /* Check what's left */
          size_t range_count = SocketQUICAck_range_count (state);
          (void)range_count;

          /* Prune with NULL removed_count */
          SocketQUICAck_prune (state, 80, NULL);

          /* Prune everything */
          SocketQUICAck_prune (state, UINT64_MAX, &removed);

          /* Test NULL state */
          SocketQUICAck_prune (NULL, 50, &removed);
          break;
        }

      case OP_RESULT_STRINGS:
        {
          /* Test result string function */
          SocketQUICAck_Result results[] = { QUIC_ACK_OK,
                                             QUIC_ACK_ERROR_NULL,
                                             QUIC_ACK_ERROR_DUPLICATE,
                                             QUIC_ACK_ERROR_OLD,
                                             QUIC_ACK_ERROR_RANGE,
                                             QUIC_ACK_ERROR_ENCODE,
                                             QUIC_ACK_ERROR_BUFFER };

          for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
            {
              const char *str = SocketQUICAck_result_string (results[i]);
              (void)str;
            }

          /* Test with fuzzed value */
          const char *str
              = SocketQUICAck_result_string ((SocketQUICAck_Result)data[1]);
          (void)str;

          /* Test reset with NULL */
          SocketQUICAck_reset (NULL);

          /* Test mark_sent with NULL */
          SocketQUICAck_mark_sent (NULL, 0);
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
