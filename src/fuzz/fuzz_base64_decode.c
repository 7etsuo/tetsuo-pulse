/**
 * fuzz_base64_decode.c - Fuzzing harness for Base64 decoding
 *
 * Part of the Socket Library
 * Tests SocketCrypto_base64_decode with arbitrary input
 *
 * This harness helps find:
 * - Buffer overflows on malformed input
 * - Crashes on edge cases (invalid chars, wrong padding)
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
  /* Need at least 1 byte of input */
  if (size == 0)
    return 0;

  /* Create null-terminated string from fuzz input */
  char *input = malloc (size + 1);
  if (!input)
    return 0;

  memcpy (input, data, size);
  input[size] = '\0';

  /* Allocate output buffer */
  size_t max_decoded = SocketCrypto_base64_decoded_size (size);
  if (max_decoded > MAX_OUTPUT_SIZE)
    max_decoded = MAX_OUTPUT_SIZE;

  unsigned char *output = malloc (max_decoded + 1);
  if (!output)
    {
      free (input);
      return 0;
    }

  /* Test decode with explicit length */
  ssize_t result
      = SocketCrypto_base64_decode (input, size, output, max_decoded);

  /* Validate result is within expected bounds */
  if (result >= 0)
    {
      /* Successful decode - result should be <= max decoded size */
      if ((size_t)result > max_decoded)
        __builtin_trap (); /* Should never happen - indicates bug */
    }

  /* Test decode with auto-detect length (0 means use strlen) */
  result = SocketCrypto_base64_decode (input, 0, output, max_decoded);
  if (result >= 0)
    {
      if ((size_t)result > max_decoded)
        __builtin_trap ();
    }

  /* Test with minimal buffer size */
  if (max_decoded > 0)
    {
      unsigned char tiny_output[1];
      result = SocketCrypto_base64_decode (input, size, tiny_output, 1);
      /* Should either decode a single byte or return error */
      if (result > 1)
        __builtin_trap ();
    }

  /* Test edge cases: NULL input should not crash */
  result = SocketCrypto_base64_decode (NULL, 0, output, max_decoded);

  /* Test edge case: zero output buffer should fail safely */
  result = SocketCrypto_base64_decode (input, size, output, 0);

  free (output);
  free (input);

  return 0;
}
