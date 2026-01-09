/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_decoder_stream.c - libFuzzer for QPACK Decoder Stream (RFC 9204)
 *
 * Fuzzes QPACK decoder stream instruction encoding/decoding (RFC 9204 Section
 * 4.4). Tests Section Acknowledgment, Stream Cancellation, and Insert Count
 * Increment instructions.
 *
 * Targets:
 * - Section Acknowledgment decode (Section 4.4.1)
 * - Stream Cancellation decode (Section 4.4.2)
 * - Insert Count Increment decode (Section 4.4.3)
 * - Instruction type identification
 * - Zero increment error handling
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_decoder_stream
 * ./fuzz_qpack_decoder_stream -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACKDecoderStream.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_DECODE_SECTION_ACK = 0,
  OP_DECODE_STREAM_CANCEL,
  OP_DECODE_INSERT_COUNT_INC,
  OP_IDENTIFY_INSTRUCTION,
  OP_DECODE_INSTRUCTION,
  OP_VALIDATE_INSERT_COUNT_INC,
  OP_VALIDATE_STREAM_CANCEL_ID,
  OP_ENCODE_INSERT_COUNT_INC,
  OP_APPLY_INSERT_COUNT_INC,
  OP_ROUNDTRIP_SECTION_ACK,
  OP_ROUNDTRIP_STREAM_CANCEL,
  OP_ROUNDTRIP_INSERT_INC,
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
  if (size < 9)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint64_t val1 = read_u64 (data + 1);

  SocketQPACKStream_Result res;
  uint64_t stream_id = 0;
  uint64_t increment = 0;
  size_t consumed = 0;
  unsigned char output[64];
  size_t bytes_written = 0;

  switch (op)
    {
    case OP_DECODE_SECTION_ACK:
      {
        if (size > 9)
          {
            res = SocketQPACK_decode_section_ack (data + 9, size - 9,
                                                  &stream_id, &consumed);
            (void)res;
            (void)stream_id;
          }
      }
      break;

    case OP_DECODE_STREAM_CANCEL:
      {
        if (size > 9)
          {
            res = SocketQPACK_decode_stream_cancel (data + 9, size - 9,
                                                    &stream_id, &consumed);
            (void)res;
            (void)stream_id;
          }
      }
      break;

    case OP_DECODE_INSERT_COUNT_INC:
      {
        if (size > 9)
          {
            res = SocketQPACK_decode_insert_count_inc (data + 9, size - 9,
                                                       &increment, &consumed);
            (void)res;
            (void)increment;
          }
      }
      break;

    case OP_IDENTIFY_INSTRUCTION:
      {
        /* Test instruction identification for all bytes in input */
        for (size_t i = 0; i < size && i < 256; i++)
          {
            SocketQPACK_DecoderInstrType type
                = SocketQPACK_identify_decoder_instruction (data[i]);
            (void)type;
          }
      }
      break;

    case OP_DECODE_INSTRUCTION:
      {
        if (size > 9)
          {
            SocketQPACK_DecoderInstruction instr = { 0 };
            res = SocketQPACK_decode_decoder_instruction (data + 9, size - 9,
                                                          &instr, &consumed);
            (void)res;
            (void)instr.type;
            (void)instr.value;
          }
      }
      break;

    case OP_VALIDATE_INSERT_COUNT_INC:
      {
        uint64_t known_received = val1 % 10000;
        uint64_t insert_count = known_received + (data[0] % 1000) + 1;
        uint64_t inc = (data[8] % 100) + 1; /* Valid increment (non-zero) */

        res = SocketQPACK_validate_insert_count_inc (known_received,
                                                     insert_count, inc);
        (void)res;

        /* Test zero increment (should fail) */
        res = SocketQPACK_validate_insert_count_inc (known_received,
                                                     insert_count, 0);
        (void)res;

        /* Test overflow */
        res = SocketQPACK_validate_insert_count_inc (known_received,
                                                     insert_count, UINT64_MAX);
        (void)res;
      }
      break;

    case OP_VALIDATE_STREAM_CANCEL_ID:
      {
        res = SocketQPACK_stream_cancel_validate_id (val1);
        (void)res;

        /* Test stream ID 0 (reserved) */
        res = SocketQPACK_stream_cancel_validate_id (0);
        (void)res;

        /* Test valid stream IDs */
        res = SocketQPACK_stream_cancel_validate_id (4);
        (void)res;
      }
      break;

    case OP_ENCODE_INSERT_COUNT_INC:
      {
        uint64_t inc = (val1 % 1000) + 1; /* Non-zero */
        res = SocketQPACK_encode_insert_count_inc (output, sizeof (output), inc,
                                                   &bytes_written);
        (void)res;
        (void)bytes_written;

        /* Test zero increment (should fail) */
        res = SocketQPACK_encode_insert_count_inc (output, sizeof (output), 0,
                                                   &bytes_written);
        (void)res;
      }
      break;

    case OP_APPLY_INSERT_COUNT_INC:
      {
        uint64_t known_received = val1 % 10000;
        uint64_t insert_count = known_received + (data[0] % 1000) + 1;
        uint64_t inc = (data[8] % 100) + 1;

        res = SocketQPACK_apply_insert_count_inc (&known_received, insert_count,
                                                  inc);
        (void)res;
        (void)known_received;
      }
      break;

    case OP_ROUNDTRIP_SECTION_ACK:
      {
        /* Build a Section Acknowledgment instruction and decode it */
        uint64_t test_stream_id = val1 % 1000;
        unsigned char buf[16];
        buf[0] = 0x80 | (test_stream_id & 0x7F); /* 7-bit prefix */

        if (test_stream_id < 127)
          {
            res = SocketQPACK_decode_section_ack (buf, 1, &stream_id,
                                                  &consumed);
            (void)res;
          }
      }
      break;

    case OP_ROUNDTRIP_STREAM_CANCEL:
      {
        /* Build a Stream Cancellation instruction and decode it */
        uint64_t test_stream_id = val1 % 100;
        unsigned char buf[16];
        buf[0] = 0x40 | (test_stream_id & 0x3F); /* 6-bit prefix */

        if (test_stream_id < 63)
          {
            res = SocketQPACK_decode_stream_cancel (buf, 1, &stream_id,
                                                    &consumed);
            (void)res;
          }
      }
      break;

    case OP_ROUNDTRIP_INSERT_INC:
      {
        /* Encode then decode Insert Count Increment */
        uint64_t inc = (val1 % 100) + 1;
        res = SocketQPACK_encode_insert_count_inc (output, sizeof (output), inc,
                                                   &bytes_written);
        if (res == QPACK_STREAM_OK && bytes_written > 0)
          {
            uint64_t decoded_inc = 0;
            res = SocketQPACK_decode_insert_count_inc (output, bytes_written,
                                                       &decoded_inc, &consumed);
            (void)decoded_inc;
          }
        (void)res;
      }
      break;

    default:
      break;
    }

  /* Always try to decode raw fuzz bytes as instructions */
  if (size > 9)
    {
      SocketQPACK_DecoderInstruction instr = { 0 };
      res = SocketQPACK_decode_decoder_instruction (data + 9, size - 9, &instr,
                                                    &consumed);
      (void)res;
    }

  /* Test NULL pointer handling */
  {
    res = SocketQPACK_decode_section_ack (data + 1, size - 1, NULL, &consumed);
    (void)res;

    res = SocketQPACK_decode_section_ack (data + 1, size - 1, &stream_id, NULL);
    (void)res;

    res = SocketQPACK_decode_decoder_instruction (data + 1, size - 1, NULL,
                                                  &consumed);
    (void)res;

    res = SocketQPACK_apply_insert_count_inc (NULL, 100, 10);
    (void)res;

    res = SocketQPACK_encode_insert_count_inc (NULL, 0, 10, &bytes_written);
    (void)res;

    res = SocketQPACK_encode_insert_count_inc (output, sizeof (output), 10,
                                               NULL);
    (void)res;
  }

  return 0;
}
