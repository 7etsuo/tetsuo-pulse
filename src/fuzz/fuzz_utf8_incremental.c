/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_utf8_incremental.c - Fuzzing harness for UTF-8 incremental validation
 *
 * Part of the Socket Library
 * Tests SocketUTF8_update with data split at random boundaries
 *
 * This harness helps find:
 * - State machine bugs when sequences span chunk boundaries
 * - Inconsistencies between chunk sizes
 * - Memory safety issues in incremental parser
 * - Reset/reuse bugs
 */

#include "core/SocketUTF8.h"
#include <stddef.h>
#include <stdint.h>

/**
 * Validate data using incremental API with specified chunk sizes
 */
static SocketUTF8_Result
validate_chunked (const uint8_t *data, size_t size, const uint8_t *chunk_sizes,
                  size_t num_chunks)
{
  SocketUTF8_State state;
  SocketUTF8_Result result;
  size_t pos = 0;

  SocketUTF8_init (&state);

  for (size_t i = 0; i < num_chunks && pos < size; i++)
    {
      size_t chunk_size = chunk_sizes[i];
      if (chunk_size == 0)
        chunk_size = 1; /* Minimum 1 byte */

      if (pos + chunk_size > size)
        chunk_size = size - pos;

      result = SocketUTF8_update (&state, data + pos, chunk_size);

      /* If we hit an error, return it */
      if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
        return result;

      pos += chunk_size;
    }

  /* Process any remaining data */
  if (pos < size)
    {
      result = SocketUTF8_update (&state, data + pos, size - pos);
      if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
        return result;
    }

  return SocketUTF8_finish (&state);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketUTF8_Result oneshot_result;
  SocketUTF8_Result chunked_result;

  if (size == 0)
    return 0;

  /* Get one-shot result as reference */
  oneshot_result = SocketUTF8_validate (data, size);

  /* Test byte-by-byte incremental validation */
  {
    SocketUTF8_State state;
    SocketUTF8_Result result = UTF8_VALID;

    SocketUTF8_init (&state);

    for (size_t i = 0; i < size; i++)
      {
        result = SocketUTF8_update (&state, data + i, 1);
        if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
          break;
      }

    if (result == UTF8_VALID || result == UTF8_INCOMPLETE)
      result = SocketUTF8_finish (&state);

    /* Should match one-shot result */
    if (result != oneshot_result)
      __builtin_trap ();
  }

  /* Test with random chunk sizes derived from input */
  if (size >= 2)
    {
      /* Use first byte to determine number of chunks */
      size_t num_chunks = (data[0] % 16) + 1;

      /* Use subsequent bytes as chunk sizes */
      chunked_result
          = validate_chunked (data + 1, size - 1, data + 1,
                              num_chunks < size - 1 ? num_chunks : size - 1);

      /* One-shot on same data (minus first byte) */
      SocketUTF8_Result ref_result = SocketUTF8_validate (data + 1, size - 1);

      /* Should match */
      if (chunked_result != ref_result)
        __builtin_trap ();
    }

  /* Test reset functionality */
  {
    SocketUTF8_State state;

    SocketUTF8_init (&state);

    /* Feed some data */
    size_t half = size / 2;
    if (half > 0)
      SocketUTF8_update (&state, data, half);

    /* Reset and validate from start */
    SocketUTF8_reset (&state);

    SocketUTF8_Result after_reset = SocketUTF8_update (&state, data, size);
    if (after_reset == UTF8_VALID || after_reset == UTF8_INCOMPLETE)
      after_reset = SocketUTF8_finish (&state);

    /* Should match one-shot */
    if (after_reset != oneshot_result)
      __builtin_trap ();
  }

  /* Test decode consistency */
  if (oneshot_result == UTF8_VALID && size > 0)
    {
      size_t pos = 0;
      size_t count = 0;

      while (pos < size)
        {
          uint32_t cp;
          size_t consumed;

          SocketUTF8_Result dec_result
              = SocketUTF8_decode (data + pos, size - pos, &cp, &consumed);

          if (dec_result != UTF8_VALID)
            __builtin_trap (); /* Valid data should decode */

          if (consumed == 0 || consumed > 4)
            __builtin_trap ();

          /* Verify round-trip */
          unsigned char encoded[4];
          int enc_len = SocketUTF8_encode (cp, encoded);

          if (enc_len != (int)consumed)
            __builtin_trap ();

          for (int i = 0; i < enc_len; i++)
            {
              if (encoded[i] != data[pos + (size_t)i])
                __builtin_trap ();
            }

          pos += consumed;
          count++;

          /* Safety limit */
          if (count > size)
            __builtin_trap ();
        }

      /* Verify count matches */
      size_t expected_count;
      if (SocketUTF8_count_codepoints (data, size, &expected_count)
          != UTF8_VALID)
        __builtin_trap ();

      if (count != expected_count)
        __builtin_trap ();
    }

  return 0;
}
