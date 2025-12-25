/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_error.c - libFuzzer harness for QUIC Error Codes
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Error code classification with arbitrary values
 * - Error code validation boundary conditions
 * - String conversion with all possible error codes
 * - Category string functions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_quic_error
 * Run:   ./fuzz_quic_error -fork=16 -max_len=16
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICError.h"

/**
 * parse_u64 - Parse uint64_t from fuzz input (little-endian)
 */
static uint64_t
parse_u64 (const uint8_t *data, size_t len)
{
  uint64_t value = 0;

  for (size_t i = 0; i < len && i < 8; i++)
    value |= ((uint64_t)data[i]) << (i * 8);

  return value;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  /* Extract operation and error code from fuzz input */
  uint8_t op = data[0] % 6;
  uint64_t code = (size > 1) ? parse_u64 (data + 1, size - 1) : 0;

  switch (op)
    {
    case 0:
      {
        /* Test error category classification */
        SocketQUIC_ErrorCategory cat = SocketQUIC_error_category (code);

        /* Verify category is valid enum value */
        assert (cat >= QUIC_ERROR_CATEGORY_TRANSPORT
                && cat <= QUIC_ERROR_CATEGORY_UNKNOWN);

        /* Verify category string returns valid string */
        const char *cat_str = SocketQUIC_error_category_string (cat);
        assert (cat_str != NULL);
        assert (strlen (cat_str) > 0);
      }
      break;

    case 1:
      {
        /* Test error validation */
        int valid = SocketQUIC_error_is_valid (code);

        /* Verify consistency: if code > max, must be invalid */
        if (code > QUIC_ERROR_CODE_MAX)
          assert (valid == 0);
        else
          assert (valid == 1);
      }
      break;

    case 2:
      {
        /* Test transport error detection */
        int is_transport = SocketQUIC_is_transport_error (code);

        /* Verify consistency with known transport errors */
        if (code <= QUIC_TRANSPORT_ERROR_MAX)
          assert (is_transport == 1);
        else
          assert (is_transport == 0);
      }
      break;

    case 3:
      {
        /* Test crypto error macros */
        int is_crypto = QUIC_IS_CRYPTO_ERROR (code);

        if (code >= QUIC_CRYPTO_ERROR_BASE && code <= QUIC_CRYPTO_ERROR_MAX)
          {
            assert (is_crypto != 0);

            /* Verify alert extraction */
            uint8_t alert = QUIC_CRYPTO_ALERT (code);
            assert (alert == (code & 0xff));
          }
        else
          {
            assert (is_crypto == 0);
          }
      }
      break;

    case 4:
      {
        /* Test error string conversion */
        const char *str = SocketQUIC_error_string (code);

        /* Must never return NULL */
        assert (str != NULL);
        assert (strlen (str) > 0);

        /* Known transport errors should have specific names */
        if (code == QUIC_NO_ERROR)
          assert (strcmp (str, "NO_ERROR") == 0);
        if (code == QUIC_PROTOCOL_VIOLATION)
          assert (strcmp (str, "PROTOCOL_VIOLATION") == 0);
      }
      break;

    case 5:
      {
        /* Test CRYPTO_ERROR macro round-trip */
        if (size > 1)
          {
            uint8_t alert = data[1];
            uint64_t crypto_code = QUIC_CRYPTO_ERROR (alert);

            /* Verify it's in crypto range */
            assert (QUIC_IS_CRYPTO_ERROR (crypto_code));

            /* Verify alert extraction */
            assert (QUIC_CRYPTO_ALERT (crypto_code) == alert);

            /* Verify it's categorized as crypto */
            assert (SocketQUIC_error_category (crypto_code)
                    == QUIC_ERROR_CATEGORY_CRYPTO);
          }
      }
      break;
    }

  /* Exercise all transport error codes */
  for (uint64_t i = 0; i <= QUIC_TRANSPORT_ERROR_MAX; i++)
    {
      const char *s = SocketQUIC_error_string (i);
      assert (s != NULL);
      assert (SocketQUIC_is_transport_error (i));
      assert (SocketQUIC_error_category (i) == QUIC_ERROR_CATEGORY_TRANSPORT);
    }

  /* Exercise category string with invalid values */
  SocketQUIC_error_category_string ((SocketQUIC_ErrorCategory)255);

  return 0;
}
