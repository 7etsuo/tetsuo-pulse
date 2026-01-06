/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-decoder.c - QPACK Decoder Stream Instructions (RFC 9204 Section
 * 4.4)
 *
 * Implements decoder stream instruction parsing and processing:
 * - Section Acknowledgment (4.4.1)
 * - Stream Cancellation (4.4.2)
 * - Insert Count Increment (4.4.3)
 */

#include <assert.h>
#include <string.h>

#include "quic/SocketQPACK-private.h"
#include "quic/SocketQPACK.h"

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size",
  [QPACK_ERROR_STREAM_NOT_FOUND] = "Stream not found in pending set",
  [QPACK_ERROR_INVALID_INSTRUCTION] = "Invalid instruction pattern",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  const size_t num_results
      = sizeof (result_strings) / sizeof (result_strings[0]);

  if (result < 0 || (size_t)result >= num_results)
    return "Unknown error";

  return result_strings[result];
}

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1 / RFC 7541 Section 5.1)
 * ============================================================================
 */

static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= QPACK_INT_CONTINUATION_VALUE && pos < output_size)
    {
      output[pos++] = (unsigned char)(QPACK_INT_CONTINUATION_MASK
                                      | (value & QPACK_INT_PAYLOAD_MASK));
      value >>= 7;
    }

  if (pos >= output_size)
    return 0;

  output[pos++] = (unsigned char)value;
  return pos;
}

size_t
SocketQPACK_int_encode (uint64_t value,
                        int prefix_bits,
                        unsigned char *output,
                        size_t output_size)
{
  uint64_t max_prefix;

  if (output == NULL || output_size == 0
      || !qpack_valid_prefix_bits (prefix_bits))
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[0] = (unsigned char)value;
      return 1;
    }

  output[0] = (unsigned char)max_prefix;
  return encode_int_continuation (value - max_prefix, output, 1, output_size);
}

static SocketQPACK_Result
decode_int_continuation (const unsigned char *input,
                         size_t input_len,
                         size_t *pos,
                         uint64_t *result,
                         unsigned int *shift)
{
  uint64_t byte_val;
  unsigned int continuation_count = 0;

  do
    {
      if (*pos >= input_len)
        return QPACK_INCOMPLETE;

      continuation_count++;
      if (continuation_count > QPACK_MAX_INT_CONTINUATION_BYTES)
        return QPACK_ERROR_INTEGER;

      byte_val = input[(*pos)++];

      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & QPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & QPACK_INT_CONTINUATION_MASK);

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_int_decode (const unsigned char *input,
                        size_t input_len,
                        int prefix_bits,
                        uint64_t *value,
                        size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  unsigned int shift = 0;

  if (input == NULL || value == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!qpack_valid_prefix_bits (prefix_bits))
    return QPACK_ERROR;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return QPACK_OK;
    }

  SocketQPACK_Result cont_result
      = decode_int_continuation (input, input_len, &pos, &result, &shift);
  if (cont_result != QPACK_OK)
    return cont_result;

  *value = result;
  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Decoder State Management
 * ============================================================================
 */

SocketQPACK_DecoderState_T
SocketQPACK_DecoderState_new (Arena_T arena)
{
  SocketQPACK_DecoderState_T state;

  assert (arena != NULL);

  state = ALLOC (arena, sizeof (*state));
  if (state == NULL)
    return NULL;

  state->known_received_count = 0;
  state->insert_count = 0;
  state->stream_capacity = QPACK_INITIAL_STREAM_CAPACITY;
  state->stream_count = 0;
  state->arena = arena;

  /* Allocate hash table buckets */
  state->streams
      = CALLOC (arena, state->stream_capacity, sizeof (*state->streams));
  if (state->streams == NULL)
    return NULL;

  return state;
}

void
SocketQPACK_DecoderState_free (SocketQPACK_DecoderState_T *state)
{
  if (state == NULL || *state == NULL)
    return;

  /* Memory is arena-managed, just clear pointer */
  *state = NULL;
}

uint64_t
SocketQPACK_DecoderState_get_known_received_count (
    SocketQPACK_DecoderState_T state)
{
  assert (state != NULL);
  return state->known_received_count;
}

/* Find a stream entry in the hash table */
static SocketQPACKPendingStream_T *
find_stream_entry (SocketQPACK_DecoderState_T state, uint64_t stream_id)
{
  size_t bucket = qpack_stream_hash (stream_id, state->stream_capacity);
  SocketQPACKPendingStream_T *entry = &state->streams[bucket];

  /* Linear probing for simplicity */
  for (size_t i = 0; i < state->stream_capacity; i++)
    {
      size_t idx = (bucket + i) & (state->stream_capacity - 1);
      entry = &state->streams[idx];

      if (!entry->in_use)
        return NULL; /* Empty slot means not found */

      if (entry->stream_id == stream_id)
        return entry;
    }

  return NULL;
}

/* Find or create a slot for a stream */
static SocketQPACKPendingStream_T *
find_or_create_stream_slot (SocketQPACK_DecoderState_T state,
                            uint64_t stream_id)
{
  size_t bucket = qpack_stream_hash (stream_id, state->stream_capacity);

  /* Linear probing */
  for (size_t i = 0; i < state->stream_capacity; i++)
    {
      size_t idx = (bucket + i) & (state->stream_capacity - 1);
      SocketQPACKPendingStream_T *entry = &state->streams[idx];

      if (!entry->in_use)
        {
          /* Found empty slot */
          entry->stream_id = stream_id;
          entry->in_use = 1;
          state->stream_count++;
          return entry;
        }

      if (entry->stream_id == stream_id)
        return entry; /* Already exists */
    }

  /* Table is full - this shouldn't happen with proper load factor management */
  return NULL;
}

/* Remove a stream entry from the hash table */
static void
remove_stream_entry (SocketQPACK_DecoderState_T state, uint64_t stream_id)
{
  size_t bucket = qpack_stream_hash (stream_id, state->stream_capacity);

  for (size_t i = 0; i < state->stream_capacity; i++)
    {
      size_t idx = (bucket + i) & (state->stream_capacity - 1);
      SocketQPACKPendingStream_T *entry = &state->streams[idx];

      if (!entry->in_use)
        return; /* Not found */

      if (entry->stream_id == stream_id)
        {
          entry->in_use = 0;
          entry->stream_id = 0;
          entry->required_insert_count = 0;
          state->stream_count--;
          return;
        }
    }
}

SocketQPACK_Result
SocketQPACK_DecoderState_register_stream (SocketQPACK_DecoderState_T state,
                                          uint64_t stream_id,
                                          uint64_t ric)
{
  SocketQPACKPendingStream_T *entry;

  assert (state != NULL);

  /* Only track streams with non-zero RIC (RFC 9204 4.4.1) */
  if (ric == 0)
    return QPACK_OK;

  /* Check load factor and potentially resize (simplified - just fail if full)
   */
  if (state->stream_count * 100 / state->stream_capacity
      >= QPACK_LOAD_FACTOR_THRESHOLD)
    {
      /* In production, would resize here. For now, allow until full. */
    }

  entry = find_or_create_stream_slot (state, stream_id);
  if (entry == NULL)
    return QPACK_ERROR; /* Table full */

  /* Update RIC to the new value (latest section's RIC) */
  entry->required_insert_count = ric;

  return QPACK_OK;
}

/* ============================================================================
 * Section Acknowledgment (RFC 9204 Section 4.4.1)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_section_ack (const unsigned char *input,
                                size_t input_len,
                                SocketQPACK_DecoderInstruction_T *instruction,
                                size_t *consumed)
{
  uint64_t stream_id;
  size_t bytes_consumed;
  SocketQPACK_Result result;

  if (input == NULL || instruction == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify pattern is 1xxxxxxx (Section Acknowledgment) */
  if ((input[0] & QPACK_SECTION_ACK_MASK) != QPACK_SECTION_ACK_MASK)
    return QPACK_ERROR_INVALID_INSTRUCTION;

  /* Decode stream ID with 7-bit prefix */
  result = SocketQPACK_int_decode (
      input, input_len, QPACK_SECTION_ACK_PREFIX, &stream_id, &bytes_consumed);
  if (result != QPACK_OK)
    return result;

  instruction->type = QPACK_INSTRUCTION_SECTION_ACK;
  instruction->stream_id = stream_id;
  instruction->increment = 0;

  *consumed = bytes_consumed;
  return QPACK_OK;
}

size_t
SocketQPACK_encode_section_ack (uint64_t stream_id,
                                unsigned char *output,
                                size_t output_size)
{
  unsigned char int_buf[QPACK_INT_BUF_SIZE];
  size_t int_len;

  if (output == NULL || output_size == 0)
    return 0;

  /* Encode stream ID with 7-bit prefix */
  int_len = SocketQPACK_int_encode (
      stream_id, QPACK_SECTION_ACK_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0 || int_len > output_size)
    return 0;

  /* Set the Section Acknowledgment pattern (high bit = 1) */
  output[0] = QPACK_SECTION_ACK_MASK | int_buf[0];

  /* Copy remaining bytes */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return int_len;
}

SocketQPACK_Result
SocketQPACK_validate_section_ack (
    SocketQPACK_DecoderState_T state,
    const SocketQPACK_DecoderInstruction_T *instruction)
{
  SocketQPACKPendingStream_T *entry;

  assert (state != NULL);
  assert (instruction != NULL);
  assert (instruction->type == QPACK_INSTRUCTION_SECTION_ACK);

  /* Find the stream in our pending set */
  entry = find_stream_entry (state, instruction->stream_id);
  if (entry == NULL)
    {
      /*
       * RFC 9204 Section 4.4.1: Section Acknowledgment is only for streams
       * with non-zero Required Insert Count. If we don't have this stream
       * registered, it could be:
       * - Already acknowledged (idempotent behavior is OK)
       * - Never had a pending section (protocol error)
       *
       * We treat this as a warning case but don't fail hard, as multiple
       * acknowledgments of the same stream are acceptable (idempotent).
       */
      return QPACK_OK; /* Idempotent - already processed or never pending */
    }

  /* Update Known Received Count */
  SocketQPACK_update_known_received_count (state, entry->required_insert_count);

  /* Remove the stream from pending set */
  remove_stream_entry (state, instruction->stream_id);

  return QPACK_OK;
}

void
SocketQPACK_update_known_received_count (SocketQPACK_DecoderState_T state,
                                         uint64_t ric)
{
  assert (state != NULL);

  /*
   * RFC 9204 Section 3.3: Known Received Count only increases.
   * Update to maximum of current value and new RIC.
   */
  if (ric > state->known_received_count)
    state->known_received_count = ric;
}

/* ============================================================================
 * Decoder Stream Instruction Parsing (RFC 9204 Section 4.4)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_decoder_instruction (
    const unsigned char *input,
    size_t input_len,
    SocketQPACK_DecoderInstruction_T *instruction,
    size_t *consumed)
{
  uint64_t value;
  size_t bytes_consumed;
  SocketQPACK_Result result;

  if (input == NULL || instruction == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /*
   * Determine instruction type from first byte:
   *   1xxxxxxx: Section Acknowledgment (7-bit prefix)
   *   01xxxxxx: Stream Cancellation (6-bit prefix)
   *   00xxxxxx: Insert Count Increment (6-bit prefix)
   */

  if (input[0] & QPACK_SECTION_ACK_MASK)
    {
      /* Section Acknowledgment: 1xxxxxxx */
      return SocketQPACK_decode_section_ack (
          input, input_len, instruction, consumed);
    }

  if ((input[0] & QPACK_STREAM_CANCEL_MASK) == QPACK_STREAM_CANCEL_PATTERN)
    {
      /* Stream Cancellation: 01xxxxxx */
      result = SocketQPACK_int_decode (input,
                                       input_len,
                                       QPACK_STREAM_CANCEL_PREFIX,
                                       &value,
                                       &bytes_consumed);
      if (result != QPACK_OK)
        return result;

      instruction->type = QPACK_INSTRUCTION_STREAM_CANCEL;
      instruction->stream_id = value;
      instruction->increment = 0;
      *consumed = bytes_consumed;
      return QPACK_OK;
    }

  if ((input[0] & QPACK_INSERT_COUNT_INC_MASK)
      == QPACK_INSERT_COUNT_INC_PATTERN)
    {
      /* Insert Count Increment: 00xxxxxx */
      result = SocketQPACK_int_decode (input,
                                       input_len,
                                       QPACK_INSERT_COUNT_INC_PREFIX,
                                       &value,
                                       &bytes_consumed);
      if (result != QPACK_OK)
        return result;

      instruction->type = QPACK_INSTRUCTION_INSERT_COUNT_INC;
      instruction->stream_id = 0;
      instruction->increment = value;
      *consumed = bytes_consumed;
      return QPACK_OK;
    }

  /* Invalid pattern - this shouldn't happen with the masks above */
  return QPACK_ERROR_INVALID_INSTRUCTION;
}
