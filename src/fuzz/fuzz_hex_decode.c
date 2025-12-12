/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_hex_decode.c - Fuzzing harness for Hex decoding
 *
 * Part of the Socket Library
 * Tests SocketCrypto_hex_decode with arbitrary input
 *
 * This harness helps find:
 * - Buffer overflows on malformed input
 * - Crashes on edge cases (invalid chars, odd length)
 * - Memory safety issues
 */

#include "core/SocketCrypto.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Maximum decode output buffer size */
#define MAX_OUTPUT_SIZE 4096

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  /* Need at least 2 bytes for valid hex (1 decoded byte) */
  if (size == 0)
    return 0;

  /* Create null-terminated string from fuzz input */
  char *input = malloc (size + 1);
  if (!input)
    return 0;

  memcpy (input, data, size);
  input[size] = '\0';

  /* Calculate max output size (hex decodes to half the input length) */
  size_t max_decoded = (size + 1) / 2;
  if (max_decoded > MAX_OUTPUT_SIZE)
    max_decoded = MAX_OUTPUT_SIZE;

  unsigned char *output = malloc (max_decoded + 1);
  if (!output)
    {
      free (input);
      return 0;
    }

  /* Test decode */
  ssize_t result = SocketCrypto_hex_decode (input, size, output, max_decoded);

  /* Validate result is within expected bounds */
  if (result >= 0)
    {
      /* Successful decode - result should be exactly size/2 */
      if ((size_t)result > max_decoded)
        __builtin_trap (); /* Should never happen - indicates bug */

      if (result != (ssize_t)(size / 2))
        __builtin_trap (); /* Decoded length should be half input length */
    }
  else
    {
      /* Decode failed - this is expected for odd lengths or invalid chars */
      /* Just verify no crash occurred */
    }

  /* Test encode/decode roundtrip if we have valid decoded output */
  if (result > 0)
    {
      /* Encode the decoded data back */
      size_t encoded_size = (size_t)result * 2 + 1;
      char *reencoded = malloc (encoded_size);
      if (reencoded)
        {
          SocketCrypto_hex_encode (output, (size_t)result, reencoded, 1);

          /* Decode again */
          unsigned char *redecoded = malloc ((size_t)result);
          if (redecoded)
            {
              ssize_t result2 = SocketCrypto_hex_decode (
                  reencoded, (size_t)result * 2, redecoded, (size_t)result);
              if (result2 != result)
                __builtin_trap (); /* Roundtrip should produce same length */

              if (memcmp (output, redecoded, (size_t)result) != 0)
                __builtin_trap (); /* Roundtrip should produce same data */

              free (redecoded);
            }
          free (reencoded);
        }
    }

  /* Test edge cases: NULL input should return error */
  result = SocketCrypto_hex_decode (NULL, size, output, max_decoded);
  if (result >= 0)
    __builtin_trap (); /* NULL input should fail */

  /* Test edge case: NULL output should return error */
  result = SocketCrypto_hex_decode (input, size, NULL, 0);
  if (result >= 0)
    __builtin_trap (); /* NULL output should fail */

  free (output);
  free (input);

  return 0;
}
