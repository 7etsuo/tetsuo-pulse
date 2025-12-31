/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_version.c - libFuzzer harness for QUIC Version Constants
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - GREASE version detection with arbitrary values
 * - IETF reserved version detection
 * - Version validation and support checking
 * - Version string conversion
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_quic_version
 * Run:   ./fuzz_quic_version -fork=16 -max_len=8
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICVersion.h"

/**
 * parse_u32 - Parse uint32_t from fuzz input (little-endian)
 */
static uint32_t
parse_u32 (const uint8_t *data, size_t len)
{
  uint32_t value = 0;

  for (size_t i = 0; i < len && i < 4; i++)
    value |= ((uint32_t)data[i]) << (i * 8);

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

  /* Extract operation and version from fuzz input */
  uint8_t op = data[0] % 7;
  uint32_t version = (size > 1) ? parse_u32 (data + 1, size - 1) : 0;

  switch (op)
    {
    case 0:
      {
        /* Test GREASE detection */
        int is_grease = QUIC_VERSION_IS_GREASE (version);

        /* Verify GREASE pattern: low 4 bits of all bytes must be 1010 */
        int expected = ((version & 0x0f0f0f0f) == 0x0a0a0a0a);
        assert (is_grease == expected);
      }
      break;

    case 1:
      {
        /* Test IETF reserved detection */
        int is_ietf = QUIC_VERSION_IS_IETF_RESERVED (version);

        /* Verify IETF pattern: top 16 bits must be zero */
        int expected = ((version & 0xFFFF0000) == 0);
        assert (is_ietf == expected);
      }
      break;

    case 2:
      {
        /* Test version support */
        int is_supported = QUIC_VERSION_IS_SUPPORTED (version);

        /* Verify support only for known versions */
        int expected = (version == QUIC_VERSION_1 || version == QUIC_VERSION_2);
        assert (is_supported == expected);
      }
      break;

    case 3:
      {
        /* Test real version detection */
        int is_real = QUIC_VERSION_IS_REAL (version);

        /* Real versions: not 0, not GREASE */
        int expected = (version != QUIC_VERSION_NEGOTIATION
                        && !QUIC_VERSION_IS_GREASE (version));
        assert (is_real == expected);
      }
      break;

    case 4:
      {
        /* Test version validation function */
        int is_valid = SocketQUIC_version_is_valid (version);

        /* Valid if: not negotiation, not GREASE, and supported */
        int expected = (version != QUIC_VERSION_NEGOTIATION
                        && !QUIC_VERSION_IS_GREASE (version)
                        && QUIC_VERSION_IS_SUPPORTED (version));
        assert (is_valid == expected);
      }
      break;

    case 5:
      {
        /* Test version negotiation need */
        int needs_neg = SocketQUIC_version_needs_negotiation (version);

        /* Needs negotiation if: not 0 and not supported */
        int expected = (version != QUIC_VERSION_NEGOTIATION
                        && !QUIC_VERSION_IS_SUPPORTED (version));
        assert (needs_neg == expected);
      }
      break;

    case 6:
      {
        /* Test version string conversion */
        const char *str = SocketQUIC_version_string (version);

        /* Must never return NULL */
        assert (str != NULL);
        assert (strlen (str) > 0);

        /* Verify known versions return expected strings */
        if (version == QUIC_VERSION_NEGOTIATION)
          assert (strcmp (str, "VERSION_NEGOTIATION") == 0);
        if (version == QUIC_VERSION_1)
          assert (strstr (str, "QUICv1") != NULL);
        if (version == QUIC_VERSION_2)
          assert (strstr (str, "QUICv2") != NULL);
        if (QUIC_VERSION_IS_GREASE (version))
          assert (strcmp (str, "GREASE") == 0);
      }
      break;
    }

  /* Exercise GREASE macro with all nibble values */
  for (uint8_t nibble = 0; nibble < 16; nibble++)
    {
      uint32_t grease = QUIC_VERSION_GREASE (nibble);
      assert (QUIC_VERSION_IS_GREASE (grease));
    }

  /* Exercise supported versions list */
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);
  assert (versions != NULL);
  assert (count >= 2);
  for (size_t i = 0; i < count; i++)
    {
      assert (QUIC_VERSION_IS_SUPPORTED (versions[i]));
      assert (SocketQUIC_version_is_valid (versions[i]));
    }

  return 0;
}
