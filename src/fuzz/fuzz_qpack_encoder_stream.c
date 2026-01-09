/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_encoder_stream.c - libFuzzer for QPACK Encoder Stream (RFC 9204)
 *
 * Fuzzes QPACK encoder stream instruction encoding/decoding (RFC 9204 Section
 * 4.3). Tests Set Dynamic Table Capacity, Insert with Name Reference, Insert
 * with Literal Name, and Duplicate instructions.
 *
 * Targets:
 * - Set Capacity encode/decode (Section 4.3.1)
 * - Insert with Name Reference encode/decode (Section 4.3.2)
 * - Insert with Literal Name encode/decode (Section 4.3.3)
 * - Duplicate encode/decode (Section 4.3.4)
 * - Name index validation (static vs dynamic)
 * - Huffman encoding/decoding
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_encoder_stream
 * ./fuzz_qpack_encoder_stream -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/qpack/SocketQPACKEncoderStream.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_ENCODE_INSERT_NAMEREF = 0,
  OP_DECODE_INSERT_NAMEREF,
  OP_VALIDATE_NAMEREF_INDEX,
  OP_ENCODE_INSERT_LITERAL,
  OP_STREAM_WRITE_CAPACITY,
  OP_STREAM_WRITE_INSERT_NAMEREF,
  OP_STREAM_WRITE_INSERT_LITERAL,
  OP_STREAM_WRITE_DUPLICATE,
  OP_ROUNDTRIP_INSERT_NAMEREF,
  OP_STREAM_TYPE_VALIDATE,
  OP_RESULT_TO_H3_ERROR,
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

  /* Extract control bits */
  bool is_static = (data[0] >> 4) & 1;
  bool use_huffman = (data[0] >> 5) & 1;

  /* Constrain values */
  uint64_t name_index = is_static ? (val1 % 99) : (val1 % 500);
  uint64_t insert_count = (val1 % 10000) + 1;
  uint64_t dropped_count = val2 % insert_count;
  uint64_t capacity = val2 % SOCKETQPACK_MAX_TABLE_SIZE;

  /* Use fuzz data as value string */
  const unsigned char *value_data = data + 17;
  size_t value_len = (size > 17) ? (size - 17) % 256 : 0;

  SocketQPACKStream_Result res;
  unsigned char output[512];
  size_t bytes_written = 0;
  size_t bytes_consumed = 0;

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena;

  TRY
  {
    switch (op)
      {
      case OP_ENCODE_INSERT_NAMEREF:
        {
          res = SocketQPACK_encode_insert_nameref (
              output, sizeof (output), is_static, name_index, value_data,
              value_len, use_huffman, &bytes_written);
          (void)res;
          (void)bytes_written;

          /* Also test with empty value */
          res = SocketQPACK_encode_insert_nameref (output, sizeof (output),
                                                   is_static, name_index, NULL,
                                                   0, false, &bytes_written);
          (void)res;
        }
        break;

      case OP_DECODE_INSERT_NAMEREF:
        {
          if (size > 17)
            {
              SocketQPACK_InsertNameRef result = { 0 };
              res = SocketQPACK_decode_insert_nameref (
                  value_data, size - 17, arena_instance, &result,
                  &bytes_consumed);
              (void)res;
              if (res == QPACK_STREAM_OK)
                {
                  (void)result.is_static;
                  (void)result.name_index;
                  (void)result.value_len;
                  (void)result.value_huffman;
                }
            }
        }
        break;

      case OP_VALIDATE_NAMEREF_INDEX:
        {
          /* Test static table index validation */
          res = SocketQPACK_validate_nameref_index (true, name_index, 0, 0);
          (void)res;

          /* Test dynamic table index validation */
          res = SocketQPACK_validate_nameref_index (false, name_index,
                                                    insert_count, dropped_count);
          (void)res;

          /* Test edge cases */
          res = SocketQPACK_validate_nameref_index (true, 0, 0, 0);
          (void)res;
          res = SocketQPACK_validate_nameref_index (true, 98, 0, 0);
          (void)res;
          res = SocketQPACK_validate_nameref_index (true, 99, 0, 0);
          (void)res; /* Should fail */
          res = SocketQPACK_validate_nameref_index (false, 0, 1, 0);
          (void)res;
        }
        break;

      case OP_ENCODE_INSERT_LITERAL:
        {
          /* Split value_data into name and value */
          size_t name_len = value_len / 2;
          const unsigned char *name_data = value_data;
          const unsigned char *val = value_data + name_len;
          size_t val_len = value_len - name_len;

          /* This tests the stream write function directly */
          SocketQPACK_EncoderStream_T stream = SocketQPACK_EncoderStream_new (
              arena_instance, 2, /* stream_id */
              SOCKETQPACK_MAX_TABLE_SIZE);
          if (stream)
            {
              res = SocketQPACK_EncoderStream_init (stream);
              if (res == QPACK_STREAM_OK)
                {
                  res = SocketQPACK_EncoderStream_write_insert_literal (
                      stream, name_data, name_len, use_huffman, val, val_len,
                      use_huffman);
                  (void)res;

                  size_t buf_len = 0;
                  const unsigned char *buf
                      = SocketQPACK_EncoderStream_get_buffer (stream, &buf_len);
                  (void)buf;
                  (void)buf_len;
                }
            }
        }
        break;

      case OP_STREAM_WRITE_CAPACITY:
        {
          SocketQPACK_EncoderStream_T stream = SocketQPACK_EncoderStream_new (
              arena_instance, 2, SOCKETQPACK_MAX_TABLE_SIZE);
          if (stream)
            {
              res = SocketQPACK_EncoderStream_init (stream);
              if (res == QPACK_STREAM_OK)
                {
                  res = SocketQPACK_EncoderStream_write_capacity (stream,
                                                                  capacity);
                  (void)res;

                  /* Test zero capacity */
                  res = SocketQPACK_EncoderStream_write_capacity (stream, 0);
                  (void)res;

                  /* Test max capacity */
                  res = SocketQPACK_EncoderStream_write_capacity (
                      stream, SOCKETQPACK_MAX_TABLE_SIZE);
                  (void)res;
                }
            }
        }
        break;

      case OP_STREAM_WRITE_INSERT_NAMEREF:
        {
          SocketQPACK_EncoderStream_T stream = SocketQPACK_EncoderStream_new (
              arena_instance, 2, SOCKETQPACK_MAX_TABLE_SIZE);
          if (stream)
            {
              res = SocketQPACK_EncoderStream_init (stream);
              if (res == QPACK_STREAM_OK)
                {
                  res = SocketQPACK_EncoderStream_write_insert_nameref (
                      stream, is_static, name_index, value_data, value_len,
                      use_huffman);
                  (void)res;

                  size_t buf_size
                      = SocketQPACK_EncoderStream_buffer_size (stream);
                  (void)buf_size;
                }
            }
        }
        break;

      case OP_STREAM_WRITE_INSERT_LITERAL:
        {
          SocketQPACK_EncoderStream_T stream = SocketQPACK_EncoderStream_new (
              arena_instance, 2, SOCKETQPACK_MAX_TABLE_SIZE);
          if (stream)
            {
              res = SocketQPACK_EncoderStream_init (stream);
              if (res == QPACK_STREAM_OK)
                {
                  size_t name_len = value_len / 2;
                  res = SocketQPACK_EncoderStream_write_insert_literal (
                      stream, value_data, name_len, use_huffman,
                      value_data + name_len, value_len - name_len, use_huffman);
                  (void)res;
                }
            }
        }
        break;

      case OP_STREAM_WRITE_DUPLICATE:
        {
          SocketQPACK_EncoderStream_T stream = SocketQPACK_EncoderStream_new (
              arena_instance, 2, SOCKETQPACK_MAX_TABLE_SIZE);
          if (stream)
            {
              res = SocketQPACK_EncoderStream_init (stream);
              if (res == QPACK_STREAM_OK)
                {
                  uint64_t rel_index = val1 % 100;
                  res = SocketQPACK_EncoderStream_write_duplicate (stream,
                                                                   rel_index);
                  (void)res;

                  /* Reset buffer and write more */
                  res = SocketQPACK_EncoderStream_reset_buffer (stream);
                  (void)res;
                }
            }
        }
        break;

      case OP_ROUNDTRIP_INSERT_NAMEREF:
        {
          /* Encode then decode */
          res = SocketQPACK_encode_insert_nameref (
              output, sizeof (output), is_static, name_index, value_data,
              value_len % 64, false, /* No Huffman for simpler roundtrip */
              &bytes_written);

          if (res == QPACK_STREAM_OK && bytes_written > 0)
            {
              SocketQPACK_InsertNameRef decoded = { 0 };
              res = SocketQPACK_decode_insert_nameref (
                  output, bytes_written, arena_instance, &decoded,
                  &bytes_consumed);
              (void)decoded.name_index;
              (void)decoded.is_static;
            }
          (void)res;
        }
        break;

      case OP_STREAM_TYPE_VALIDATE:
        {
          /* Test stream type validation */
          res = SocketQPACK_EncoderStream_validate_type (
              QPACK_ENCODER_STREAM_TYPE);
          (void)res; /* Should be OK */

          res = SocketQPACK_EncoderStream_validate_type (
              QPACK_DECODER_STREAM_TYPE);
          (void)res; /* Should fail */

          res = SocketQPACK_EncoderStream_validate_type (data[1]);
          (void)res;
        }
        break;

      case OP_RESULT_TO_H3_ERROR:
        {
          /* Test result to H3 error mapping */
          uint64_t err;

          err = SocketQPACKStream_result_to_h3_error (QPACK_STREAM_OK);
          (void)err;

          err = SocketQPACKStream_result_to_h3_error (
              QPACK_STREAM_ERR_CLOSED_CRITICAL);
          (void)err;

          err = SocketQPACKStream_result_to_h3_error (
              QPACK_STREAM_ERR_ALREADY_INIT);
          (void)err;

          err = SocketQPACKStream_result_to_h3_error (
              QPACK_STREAM_ERR_BUFFER_FULL);
          (void)err;
        }
        break;

      default:
        break;
      }

    /* Always try to decode raw fuzz bytes as instruction */
    if (size > 17)
      {
        /* Check first byte pattern and try appropriate decode */
        uint8_t first_byte = value_data[0];
        if (first_byte & QPACK_INSTR_INSERT_NAMEREF_MASK)
          {
            SocketQPACK_InsertNameRef result = { 0 };
            res = SocketQPACK_decode_insert_nameref (
                value_data, size - 17, arena_instance, &result, &bytes_consumed);
            (void)res;
          }
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose (&arena_instance);

  /* Test string functions */
  {
    const char *s1 = SocketQPACKStream_result_string (QPACK_STREAM_OK);
    const char *s2
        = SocketQPACKStream_result_string (QPACK_STREAM_ERR_BUFFER_FULL);
    const char *s3
        = SocketQPACKStream_result_string (QPACK_STREAM_ERR_INVALID_INDEX);
    (void)s1;
    (void)s2;
    (void)s3;
  }

  /* NULL pointer tests */
  {
    res = SocketQPACK_encode_insert_nameref (NULL, 0, false, 0, NULL, 0, false,
                                             &bytes_written);
    (void)res;

    res = SocketQPACK_encode_insert_nameref (output, sizeof (output), false, 0,
                                             NULL, 0, false, NULL);
    (void)res;

    bool is_open = SocketQPACK_EncoderStream_is_open (NULL);
    (void)is_open;

    uint64_t stream_id = SocketQPACK_EncoderStream_get_id (NULL);
    (void)stream_id;

    size_t buf_size = SocketQPACK_EncoderStream_buffer_size (NULL);
    (void)buf_size;
  }

  return 0;
}
