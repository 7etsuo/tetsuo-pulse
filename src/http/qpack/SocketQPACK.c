/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.c
 * @brief QPACK Header Compression (RFC 9204) - Core implementation.
 *
 * Implements QPACK decoder stream instructions including:
 * - Insert Count Increment (Section 4.4.3)
 *
 * Uses RFC 7541 integer encoding for variable-length integers.
 */

#include <assert.h>
#include <string.h>

#include "http/qpack/SocketQPACK.h"
#include "http/SocketHPACK.h" /* For integer encoding/decoding (RFC 7541 Section 5.1) */

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error = { &SocketQPACK_Error, "QPACK error" };

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_DECODER_STREAM_ERROR] = "Decoder stream protocol error",
  [QPACK_ENCODER_STREAM_ERROR] = "Encoder stream protocol error",
  [QPACK_DECOMPRESSION_FAILED] = "Header decompression failed",
  [QPACK_ERROR_INVALID_INCREMENT] = "Increment value is zero or invalid",
  [QPACK_ERROR_INCREMENT_OVERFLOW] = "Increment exceeds allowed range",
  [QPACK_ERROR_INTEGER] = "Integer encoding/decoding error",
  [QPACK_ERROR_TABLE_SIZE] = "Dynamic table size error",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_TABLE_SIZE)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Decoder Configuration
 * ============================================================================
 */

void
SocketQPACK_decoder_config_defaults (SocketQPACK_DecoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_capacity = SOCKETQPACK_DEFAULT_TABLE_SIZE;
  config->max_blocked_streams = SOCKETQPACK_MAX_BLOCKED_STREAMS;
}

/* ============================================================================
 * Decoder Implementation
 * ============================================================================
 */

SocketQPACK_Decoder_T
SocketQPACK_Decoder_new (const SocketQPACK_DecoderConfig *config, Arena_T arena)
{
  SocketQPACK_Decoder_T decoder;
  SocketQPACK_DecoderConfig default_config;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketQPACK_decoder_config_defaults (&default_config);
      config = &default_config;
    }

  decoder = ALLOC (arena, sizeof (*decoder));

  decoder->known_received_count = 0;
  decoder->dynamic_table_insert_count = 0;
  decoder->max_table_capacity = config->max_table_capacity;
  decoder->current_table_capacity = 0;
  decoder->max_blocked_streams = config->max_blocked_streams;
  decoder->arena = arena;

  return decoder;
}

void
SocketQPACK_Decoder_free (SocketQPACK_Decoder_T *decoder)
{
  if (decoder == NULL || *decoder == NULL)
    return;

  /* Arena-based allocation - nothing to free explicitly */
  *decoder = NULL;
}

size_t
SocketQPACK_Decoder_get_known_received_count (SocketQPACK_Decoder_T decoder)
{
  assert (decoder != NULL);
  return decoder->known_received_count;
}

void
SocketQPACK_Decoder_set_insert_count (SocketQPACK_Decoder_T decoder,
                                      size_t count)
{
  assert (decoder != NULL);
  decoder->dynamic_table_insert_count = count;
}

/* ============================================================================
 * Insert Count Increment Instruction (RFC 9204 Section 4.4.3)
 * ============================================================================
 */

/**
 * Encode Insert Count Increment instruction.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 |     Increment (6+)    |
 * +---+---+-----------------------+
 */
ssize_t
SocketQPACK_encode_insert_count_inc (size_t increment,
                                     unsigned char *output,
                                     size_t output_size)
{
  unsigned char int_buf[16];
  size_t int_len;

  /* Validate inputs */
  if (output == NULL || output_size == 0)
    return -1;

  /* RFC 9204 Section 4.4.3: Increment MUST be non-zero */
  if (increment == 0)
    return -1;

  /* Use RFC 7541 integer encoding with 6-bit prefix */
  int_len = SocketHPACK_int_encode (
      (uint64_t)increment, SOCKETQPACK_INSERT_COUNT_INC_PREFIX, int_buf,
      sizeof (int_buf));

  if (int_len == 0 || int_len > output_size)
    return -1;

  /* First byte: pattern 00xxxxxx OR'd with encoded integer */
  output[0]
      = (unsigned char)(SOCKETQPACK_INSERT_COUNT_INC_PATTERN | int_buf[0]);

  /* Copy remaining bytes if multi-byte encoding */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return (ssize_t)int_len;
}

/**
 * Decode Insert Count Increment instruction.
 *
 * Does not update decoder state - just parses the wire format.
 */
SocketQPACK_Result
SocketQPACK_decode_insert_count_inc (const unsigned char *input,
                                     size_t input_len,
                                     size_t *increment,
                                     size_t *consumed)
{
  uint64_t value;
  size_t bytes_consumed;
  SocketHPACK_Result hpack_result;

  /* Validate inputs */
  if (input == NULL || increment == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is an Insert Count Increment instruction (pattern 00xxxxxx) */
  if (!SocketQPACK_is_insert_count_inc (input[0]))
    return QPACK_DECODER_STREAM_ERROR;

  /* Decode 6-bit prefixed integer using RFC 7541 algorithm */
  hpack_result
      = SocketHPACK_int_decode (input, input_len,
                                SOCKETQPACK_INSERT_COUNT_INC_PREFIX, &value,
                                &bytes_consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;

  if (hpack_result != HPACK_OK)
    return QPACK_ERROR_INTEGER;

  /* Check for 32-bit platform overflow */
  if (value > SIZE_MAX)
    return QPACK_ERROR_INTEGER;

  *increment = (size_t)value;
  *consumed = bytes_consumed;

  return QPACK_OK;
}

/**
 * Apply Insert Count Increment to decoder state.
 *
 * Validates:
 * - Increment must be > 0 (RFC 9204 Section 4.4.3)
 * - known_received_count + increment must not exceed dynamic_table_insert_count
 */
SocketQPACK_Result
SocketQPACK_Decoder_apply_increment (SocketQPACK_Decoder_T decoder,
                                     size_t increment)
{
  size_t new_count;

  assert (decoder != NULL);

  /* RFC 9204 Section 4.4.3: Increment MUST be non-zero */
  if (increment == 0)
    return QPACK_DECODER_STREAM_ERROR;

  /* Check for overflow */
  if (increment > SIZE_MAX - decoder->known_received_count)
    return QPACK_ERROR_INCREMENT_OVERFLOW;

  new_count = decoder->known_received_count + increment;

  /* RFC 9204 Section 4.4.3: Increment MUST NOT exceed number of table
   * insertions sent by encoder */
  if (new_count > decoder->dynamic_table_insert_count)
    return QPACK_DECODER_STREAM_ERROR;

  decoder->known_received_count = new_count;
  return QPACK_OK;
}

/**
 * Process a full Insert Count Increment instruction.
 *
 * Convenience function that decodes and applies in one step.
 */
SocketQPACK_Result
SocketQPACK_Decoder_process_insert_count_inc (SocketQPACK_Decoder_T decoder,
                                              const unsigned char *input,
                                              size_t input_len,
                                              size_t *consumed)
{
  size_t increment;
  size_t bytes_consumed;
  SocketQPACK_Result result;

  assert (decoder != NULL);

  /* Decode the instruction */
  result = SocketQPACK_decode_insert_count_inc (input, input_len, &increment,
                                                &bytes_consumed);
  if (result != QPACK_OK)
    return result;

  /* Apply to decoder state */
  result = SocketQPACK_Decoder_apply_increment (decoder, increment);
  if (result != QPACK_OK)
    return result;

  if (consumed != NULL)
    *consumed = bytes_consumed;

  return QPACK_OK;
}
