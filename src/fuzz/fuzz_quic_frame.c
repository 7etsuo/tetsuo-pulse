/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_frame.c - libFuzzer for QUIC Frame Parsing (RFC 9000)
 *
 * Fuzzes QUIC frame parsing and validation (RFC 9000 Section 19). Tests all
 * frame types including ACK, STREAM, CRYPTO, and control frames.
 *
 * Targets:
 * - Frame type parsing
 * - ACK frame with ranges (Section 19.3)
 * - STREAM frame with flags (Section 19.8)
 * - CRYPTO frame (Section 19.6)
 * - Flow control frames (Section 19.9-19.14)
 * - Connection management frames (Section 19.15-19.20)
 * - Frame validation per packet type
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_quic_frame
 * ./fuzz_quic_frame -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICFrame.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_PARSE_FRAME = 0,
  OP_PARSE_FRAME_ARENA,
  OP_VALIDATE_INITIAL,
  OP_VALIDATE_HANDSHAKE,
  OP_VALIDATE_0RTT,
  OP_VALIDATE_1RTT,
  OP_ENCODE_STREAM,
  OP_ENCODE_CRYPTO,
  OP_ENCODE_FLOW_CONTROL,
  OP_ENCODE_CONNECTION_CLOSE,
  OP_ENCODE_PATH,
  OP_ENCODE_NEW_CONNECTION_ID,
  OP_ROUNDTRIP_STREAM,
  OP_ROUNDTRIP_CRYPTO,
  OP_TYPE_DETECTION,
  OP_MAX
};

/**
 * @brief Read 64-bit value from byte array (little-endian)
 */
static uint64_t
read_u64 (const uint8_t *p)
{
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 17)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint64_t val1 = read_u64 (data + 1);
  uint64_t val2 = read_u64 (data + 9);

  SocketQUICFrame_Result res;
  SocketQUICFrame_T frame;
  size_t consumed = 0;
  uint8_t output[512];
  size_t written = 0;

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena;

  TRY
  {
    switch (op)
      {
      case OP_PARSE_FRAME:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse (
                  data + 17, size - 17, &frame, &consumed);
              (void)res;
              if (res == QUIC_FRAME_OK)
                {
                  (void)frame.type;
                  (void)frame.wire_length;
                }
              SocketQUICFrame_free (&frame);
            }
        }
        break;

      case OP_PARSE_FRAME_ARENA:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse_arena (
                  arena_instance, data + 17, size - 17, &frame, &consumed);
              (void)res;
              if (res == QUIC_FRAME_OK)
                {
                  (void)frame.type;
                  /* Access frame-specific data */
                  if (SocketQUICFrame_is_stream (frame.type))
                    {
                      (void)frame.data.stream.stream_id;
                      (void)frame.data.stream.offset;
                      (void)frame.data.stream.length;
                    }
                  else if (frame.type == QUIC_FRAME_ACK
                           || frame.type == QUIC_FRAME_ACK_ECN)
                    {
                      (void)frame.data.ack.largest_ack;
                      (void)frame.data.ack.range_count;
                    }
                  else if (frame.type == QUIC_FRAME_CRYPTO)
                    {
                      (void)frame.data.crypto.offset;
                      (void)frame.data.crypto.length;
                    }
                }
              /* No free needed with arena */
            }
        }
        break;

      case OP_VALIDATE_INITIAL:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse_arena (
                  arena_instance, data + 17, size - 17, &frame, &consumed);
              if (res == QUIC_FRAME_OK)
                {
                  res = SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL);
                  (void)res;
                }
            }
        }
        break;

      case OP_VALIDATE_HANDSHAKE:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse_arena (
                  arena_instance, data + 17, size - 17, &frame, &consumed);
              if (res == QUIC_FRAME_OK)
                {
                  res = SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE);
                  (void)res;
                }
            }
        }
        break;

      case OP_VALIDATE_0RTT:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse_arena (
                  arena_instance, data + 17, size - 17, &frame, &consumed);
              if (res == QUIC_FRAME_OK)
                {
                  res = SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT);
                  (void)res;
                }
            }
        }
        break;

      case OP_VALIDATE_1RTT:
        {
          if (size > 17)
            {
              SocketQUICFrame_init (&frame);
              res = SocketQUICFrame_parse_arena (
                  arena_instance, data + 17, size - 17, &frame, &consumed);
              if (res == QUIC_FRAME_OK)
                {
                  res = SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT);
                  (void)res;
                }
            }
        }
        break;

      case OP_ENCODE_STREAM:
        {
          uint64_t stream_id = val1 % 0x3FFFFFFF;
          uint64_t offset = val2 % 0xFFFFFF;
          int fin = data[16] & 1;
          size_t data_len = (size > 17) ? ((size - 17) % 100) : 0;

          written = SocketQUICFrame_encode_stream (stream_id,
                                                   offset,
                                                   data + 17,
                                                   data_len,
                                                   fin,
                                                   output,
                                                   sizeof (output));
          (void)written;
        }
        break;

      case OP_ENCODE_CRYPTO:
        {
          uint64_t offset = val1 % 0xFFFFFF;
          size_t data_len = (size > 17) ? ((size - 17) % 100) : 0;

          written = SocketQUICFrame_encode_crypto (
              offset, data + 17, data_len, output, sizeof (output));
          (void)written;
        }
        break;

      case OP_ENCODE_FLOW_CONTROL:
        {
          uint64_t max_data = val1;
          uint64_t stream_id = val2 % 0x3FFFFFFF;

          written = SocketQUICFrame_encode_max_data (
              max_data, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_max_stream_data (
              stream_id, max_data, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_max_streams (
              1, val1 % 0xFFFF, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_max_streams (
              0, val2 % 0xFFFF, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_data_blocked (
              max_data, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_stream_data_blocked (
              stream_id, max_data, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_streams_blocked (
              1, val1 % 0xFFFF, output, sizeof (output));
          (void)written;
        }
        break;

      case OP_ENCODE_CONNECTION_CLOSE:
        {
          uint64_t error_code = val1 % 0x1FFFFFFF;
          uint64_t frame_type = val2 % 0x100;

          written = SocketQUICFrame_encode_connection_close_transport (
              error_code, frame_type, "test", output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_connection_close_app (
              error_code, "app error", output, sizeof (output));
          (void)written;

          /* With NULL reason */
          written = SocketQUICFrame_encode_connection_close_transport (
              error_code, frame_type, NULL, output, sizeof (output));
          (void)written;
        }
        break;

      case OP_ENCODE_PATH:
        {
          uint8_t path_data[QUIC_PATH_DATA_SIZE];
          if (size >= 17 + QUIC_PATH_DATA_SIZE)
            memcpy (path_data, data + 17, QUIC_PATH_DATA_SIZE);
          else
            memset (path_data, 0x42, QUIC_PATH_DATA_SIZE);

          written = SocketQUICFrame_encode_path_challenge (
              path_data, output, sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_path_response (
              path_data, output, sizeof (output));
          (void)written;

          /* Decode */
          if (written > 0)
            {
              uint8_t decoded[QUIC_PATH_DATA_SIZE];
              int ret = SocketQUICFrame_decode_path_challenge (
                  output, written, decoded);
              (void)ret;
            }
        }
        break;

      case OP_ENCODE_NEW_CONNECTION_ID:
        {
          uint64_t sequence = (val1 % 0xFFFF) + 1; /* Ensure non-zero */
          uint64_t retire_prior = val2 % sequence;
          uint8_t cid_length = (data[16] % 20) + 1;
          uint8_t cid[20];
          uint8_t reset_token[16];

          if (size >= 17 + cid_length)
            memcpy (cid, data + 17, cid_length);
          if (size >= 17 + cid_length + 16)
            memcpy (reset_token, data + 17 + cid_length, 16);

          written = SocketQUICFrame_encode_new_connection_id (sequence,
                                                              retire_prior,
                                                              cid_length,
                                                              cid,
                                                              reset_token,
                                                              output,
                                                              sizeof (output));
          (void)written;

          written = SocketQUICFrame_encode_retire_connection_id (
              sequence, output, sizeof (output));
          (void)written;
        }
        break;

      case OP_ROUNDTRIP_STREAM:
        {
          uint64_t stream_id = val1 % 0xFFFF;
          uint64_t offset = val2 % 0xFFFF;
          size_t data_len = (size > 17) ? ((size - 17) % 50) : 0;

          written = SocketQUICFrame_encode_stream (stream_id,
                                                   offset,
                                                   data + 17,
                                                   data_len,
                                                   0,
                                                   output,
                                                   sizeof (output));
          if (written > 0)
            {
              SocketQUICFrameStream_T decoded;
              ssize_t dec_len
                  = SocketQUICFrame_decode_stream (output, written, &decoded);
              if (dec_len > 0)
                {
                  (void)decoded.stream_id;
                  (void)decoded.offset;
                  (void)decoded.length;
                }
            }
        }
        break;

      case OP_ROUNDTRIP_CRYPTO:
        {
          uint64_t offset = val1 % 0xFFFF;
          size_t data_len = (size > 17) ? ((size - 17) % 50) : 0;

          written = SocketQUICFrame_encode_crypto (
              offset, data + 17, data_len, output, sizeof (output));
          if (written > 0)
            {
              SocketQUICFrameCrypto_T decoded;
              ssize_t dec_len
                  = SocketQUICFrame_decode_crypto (output, written, &decoded);
              if (dec_len > 0)
                {
                  (void)decoded.offset;
                  (void)decoded.length;
                }
            }
        }
        break;

      case OP_TYPE_DETECTION:
        {
          /* Test frame type utilities */
          for (size_t i = 0; i < 256 && i < size; i++)
            {
              uint64_t ftype = data[i];

              int is_stream = SocketQUICFrame_is_stream (ftype);
              (void)is_stream;

              if (is_stream)
                {
                  int flags = SocketQUICFrame_stream_flags (ftype);
                  (void)flags;
                }

              int is_ack_eliciting = SocketQUICFrame_is_ack_eliciting (ftype);
              (void)is_ack_eliciting;

              int allowed = SocketQUICFrame_allowed_packets (ftype);
              (void)allowed;

              const char *type_str = SocketQUICFrame_type_string (ftype);
              (void)type_str;
            }
        }
        break;

      default:
        break;
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose (&arena_instance);

  /* Always try parsing raw fuzz data */
  {
    Arena_T test_arena = Arena_new ();
    if (test_arena)
      {
        SocketQUICFrame_init (&frame);
        res = SocketQUICFrame_parse_arena (
            test_arena, data, size, &frame, &consumed);
        (void)res;
        Arena_dispose (&test_arena);
      }
  }

  /* Test string and utility functions */
  {
    const char *s1 = SocketQUICFrame_type_string (QUIC_FRAME_ACK);
    const char *s2 = SocketQUICFrame_type_string (QUIC_FRAME_STREAM);
    const char *s3 = SocketQUICFrame_result_string (QUIC_FRAME_OK);
    const char *s4 = SocketQUICFrame_result_string (QUIC_FRAME_ERROR_TRUNCATED);
    (void)s1;
    (void)s2;
    (void)s3;
    (void)s4;

    int flags = SocketQUICFrame_packet_type_to_flags (QUIC_PACKET_TYPE_INITIAL);
    (void)flags;
    flags = SocketQUICFrame_packet_type_to_flags (QUIC_PACKET_TYPE_1RTT);
    (void)flags;
  }

  /* NULL pointer tests */
  {
    SocketQUICFrame_init (NULL); /* Should handle gracefully */

    res = SocketQUICFrame_parse (NULL, 0, &frame, &consumed);
    (void)res;

    res = SocketQUICFrame_parse (data, size, NULL, &consumed);
    (void)res;

    res = SocketQUICFrame_validate (NULL, QUIC_PKT_1RTT);
    (void)res;

    SocketQUICFrame_free (NULL);
  }

  return 0;
}
