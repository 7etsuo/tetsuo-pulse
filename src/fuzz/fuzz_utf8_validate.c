/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_utf8_validate.c - Fuzzing harness for UTF-8 one-shot validation
 *
 * Part of the Socket Library
 * Tests SocketUTF8_validate with arbitrary input
 *
 * This harness helps find:
 * - Buffer overflows on malformed input
 * - Crashes on edge cases
 * - Inconsistencies between one-shot and incremental validation
 * - DFA state machine bugs
 */

#include "core/SocketUTF8.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketUTF8_Result result;
  SocketUTF8_State state;
  size_t count;

  /* Test one-shot validation */
  result = SocketUTF8_validate (data, size);

  /* Result should be one of the defined values */
  if (result < UTF8_VALID || result > UTF8_TOO_LARGE)
    __builtin_trap ();

  /* Test validate_str with null-terminated copy */
  if (size < 4096)
    {
      char str[4097];
      memcpy (str, data, size);
      str[size] = '\0';

      SocketUTF8_Result str_result = SocketUTF8_validate_str (str);

      /* Results should match */
      if (str_result != result)
        {
          /* Might differ if data contains embedded NUL */
          int has_nul = 0;
          for (size_t i = 0; i < size; i++)
            {
              if (data[i] == 0)
                {
                  has_nul = 1;
                  break;
                }
            }
          if (!has_nul)
            __builtin_trap ();
        }
    }

  /* Test incremental validation - should match one-shot */
  SocketUTF8_init (&state);
  SocketUTF8_Result incr_result = SocketUTF8_update (&state, data, size);

  /* If one-shot found an error, incremental should too */
  if (result != UTF8_VALID && result != UTF8_INCOMPLETE)
    {
      /* Error should be detected by incremental */
      if (incr_result == UTF8_VALID)
        __builtin_trap ();
    }

  /* If incremental found no error, check finish */
  if (incr_result == UTF8_VALID || incr_result == UTF8_INCOMPLETE)
    {
      SocketUTF8_Result finish_result = SocketUTF8_finish (&state);

      /* If one-shot was valid, finish should be valid */
      if (result == UTF8_VALID && finish_result != UTF8_VALID)
        __builtin_trap ();

      /* If one-shot was incomplete, finish should be incomplete */
      if (result == UTF8_INCOMPLETE && finish_result != UTF8_INCOMPLETE)
        __builtin_trap ();
    }

  /* Test count_codepoints - should agree with validation result */
  SocketUTF8_Result count_result
      = SocketUTF8_count_codepoints (data, size, &count);
  if (result == UTF8_VALID)
    {
      if (count_result != UTF8_VALID)
        __builtin_trap ();
    }

  /* Test result_string doesn't crash */
  const char *result_str = SocketUTF8_result_string (result);
  if (!result_str)
    __builtin_trap ();

  /* Test edge cases: NULL input */
  if (SocketUTF8_validate (NULL, 0) != UTF8_VALID)
    __builtin_trap ();
  if (SocketUTF8_validate_str (NULL) != UTF8_VALID)
    __builtin_trap ();

  return 0;
}
