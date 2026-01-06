/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-encoder.c
 * @brief QPACK Encoder implementation (RFC 9204).
 *
 * Implements the QPACK encoder with Known Received Count (KRC) tracking
 * per RFC 9204 Section 2.1.4. The encoder tracks which dynamic table entries
 * have been acknowledged by the decoder to determine safe references.
 *
 * Key concepts:
 * - Known Received Count (KRC): Number of insertions acknowledged by decoder
 * - Insert Count: Total entries ever inserted (monotonically increasing)
 * - Safe reference: Entry with absolute index < KRC (decoder has it)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-2.1.4
 * @since 1.0.0
 */

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"

#define T SocketQPACK_Encoder_T

/* ============================================================================
 * Result String Table
 * ============================================================================
 */

static const char *const result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete data",
  [QPACK_ERR_INVALID_INDEX] = "Invalid index",
  [QPACK_ERR_EVICTED_INDEX] = "Entry has been evicted",
  [QPACK_ERR_FUTURE_INDEX] = "Reference to not-yet-inserted entry",
  [QPACK_ERR_BASE_OVERFLOW] = "Base exceeds Insert Count",
  [QPACK_ERR_TABLE_SIZE] = "Table size limit exceeded",
  [QPACK_ERR_HEADER_SIZE] = "Header size limit exceeded",
  [QPACK_ERR_HUFFMAN] = "Huffman decoding error",
  [QPACK_ERR_INTEGER] = "Integer decoding error",
  [QPACK_ERR_DECOMPRESSION] = "Decompression failed",
  [QPACK_ERR_NULL_PARAM] = "NULL parameter",
  [QPACK_ERR_INTERNAL] = "Internal error",
};

#define RESULT_STRING_COUNT \
  (sizeof (result_strings) / sizeof (result_strings[0]))

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result >= 0 && (size_t)result < RESULT_STRING_COUNT
      && result_strings[result] != NULL)
    {
      return result_strings[result];
    }

  return "Unknown error";
}

/* ============================================================================
 * Encoder Creation/Destruction
 * ============================================================================
 */

SocketQPACK_Encoder_T
SocketQPACK_Encoder_new (Arena_T arena, size_t max_table_size)
{
  T encoder;

  assert (arena != NULL);

  encoder = ALLOC (arena, sizeof (*encoder));

  encoder->arena = arena;
  encoder->head = NULL;
  encoder->tail = NULL;
  encoder->entry_count = 0;
  encoder->table_size = 0;
  encoder->max_table_size = max_table_size;
  encoder->insert_count = 0;
  encoder->known_received_count = 0;

  return encoder;
}

void
SocketQPACK_Encoder_free (SocketQPACK_Encoder_T *encoder)
{
  if (encoder == NULL || *encoder == NULL)
    return;

  /* Memory is arena-managed, just clear pointer */
  *encoder = NULL;
}

/* ============================================================================
 * Known Received Count (KRC) - RFC 9204 Section 2.1.4
 * ============================================================================
 */

size_t
SocketQPACK_Encoder_known_received_count (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return encoder->known_received_count;
}

bool
SocketQPACK_Encoder_is_acknowledged (SocketQPACK_Encoder_T encoder,
                                     size_t abs_index)
{
  if (encoder == NULL)
    return false;

  /*
   * RFC 9204 Section 2.1.4:
   * "The encoder tracks the decoder's Known Received Count, which is the
   * highest absolute index that can be acknowledged."
   *
   * An entry is acknowledged (safe to reference without blocking) if its
   * absolute index is strictly less than the Known Received Count.
   */
  return abs_index < encoder->known_received_count;
}

SocketQPACK_Result
SocketQPACK_Encoder_on_section_ack (SocketQPACK_Encoder_T encoder, size_t ric)
{
  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.4.1 / Section 2.1.4:
   * "When a field section is acknowledged, the encoder knows that the
   * decoder has received all dynamic table entries with an absolute index
   * less than the Required Insert Count."
   *
   * Update KRC to max(KRC, RIC). KRC never decreases.
   */

  /* Clamp RIC to insert_count - cannot acknowledge what wasn't sent */
  if (ric > encoder->insert_count)
    ric = encoder->insert_count;

  /* Update KRC if RIC is higher (KRC never decreases) */
  if (ric > encoder->known_received_count)
    encoder->known_received_count = ric;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Encoder_on_insert_count_inc (SocketQPACK_Encoder_T encoder,
                                         size_t increment)
{
  size_t new_krc;

  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.4.3:
   * "The Insert Count Increment instruction informs the encoder that the
   * decoder has received and processed additional dynamic table entries."
   *
   * The increment must be > 0 per the RFC (an increment of 0 is meaningless).
   */
  if (increment == 0)
    return QPACK_ERR_INVALID_INDEX;

  /* Check for overflow */
  if (!SocketSecurity_check_add (
          encoder->known_received_count, increment, &new_krc))
    {
      /* On overflow, clamp to insert_count */
      new_krc = encoder->insert_count;
    }

  /* Clamp to insert_count - cannot exceed what was actually sent */
  if (new_krc > encoder->insert_count)
    new_krc = encoder->insert_count;

  encoder->known_received_count = new_krc;

  return QPACK_OK;
}

/* ============================================================================
 * Encoder State Queries
 * ============================================================================
 */

size_t
SocketQPACK_Encoder_insert_count (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return encoder->insert_count;
}

size_t
SocketQPACK_Encoder_table_size (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return encoder->table_size;
}

size_t
SocketQPACK_Encoder_entry_count (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return encoder->entry_count;
}

#undef T
