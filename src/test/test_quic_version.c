/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_version.c - QUIC Version Constants unit tests (RFC 9000 §15)
 *
 * Tests version constant definitions, GREASE detection, IETF reserved
 * detection, and version validation helpers.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICVersion.h"
#include "test/Test.h"

/* ============================================================================
 * Version Constant Value Tests
 * ============================================================================
 */

TEST (quic_version_negotiation_value)
{
  ASSERT_EQ (QUIC_VERSION_NEGOTIATION, 0x00000000);
}

TEST (quic_version_1_value)
{
  ASSERT_EQ (QUIC_VERSION_1, 0x00000001);
}

TEST (quic_version_2_value)
{
  ASSERT_EQ (QUIC_VERSION_2, 0x6b3343cf);
}

/* ============================================================================
 * GREASE Version Detection Tests
 * ============================================================================
 */

TEST (quic_version_grease_0a0a0a0a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x0a0a0a0a));
}

TEST (quic_version_grease_1a1a1a1a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x1a1a1a1a));
}

TEST (quic_version_grease_2a2a2a2a)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0x2a2a2a2a));
}

TEST (quic_version_grease_fafafafa)
{
  ASSERT (QUIC_VERSION_IS_GREASE (0xfafafafa));
}

TEST (quic_version_grease_all_nibbles)
{
  /* Test all 16 possible GREASE versions */
  for (uint32_t nibble = 0; nibble < 16; nibble++)
    {
      uint32_t version
          = (nibble << 28) | (nibble << 20) | (nibble << 12) | (nibble << 4)
            | 0x0a0a0a0a;
      ASSERT (QUIC_VERSION_IS_GREASE (version));
    }
}

TEST (quic_version_grease_macro)
{
  ASSERT_EQ (QUIC_VERSION_GREASE (0), 0x0a0a0a0a);
  ASSERT_EQ (QUIC_VERSION_GREASE (1), 0x1a1a1a1a);
  ASSERT_EQ (QUIC_VERSION_GREASE (15), 0xfafafafa);
}

TEST (quic_version_not_grease_v1)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_1));
}

TEST (quic_version_not_grease_v2)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_2));
}

TEST (quic_version_not_grease_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_GREASE (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_grease_almost)
{
  /* Close to GREASE but not quite */
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0a0a0b));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0a0b0a));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0a0b0a0a));
  ASSERT (!QUIC_VERSION_IS_GREASE (0x0b0a0a0a));
}

/* ============================================================================
 * IETF Reserved Version Tests
 * ============================================================================
 */

TEST (quic_version_ietf_reserved_v1)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_1));
}

TEST (quic_version_ietf_reserved_negotiation)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_ietf_reserved_0000ffff)
{
  ASSERT (QUIC_VERSION_IS_IETF_RESERVED (0x0000ffff));
}

TEST (quic_version_not_ietf_reserved_v2)
{
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (QUIC_VERSION_2));
}

TEST (quic_version_not_ietf_reserved_high_bits)
{
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0x00010000));
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0x10000000));
  ASSERT (!QUIC_VERSION_IS_IETF_RESERVED (0xffffffff));
}

/* ============================================================================
 * Version Support Tests
 * ============================================================================
 */

TEST (quic_version_supported_v1)
{
  ASSERT (QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_1));
}

TEST (quic_version_supported_v2)
{
  ASSERT (QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_2));
}

TEST (quic_version_not_supported_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_supported_grease)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0x0a0a0a0a));
}

TEST (quic_version_not_supported_unknown)
{
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0x12345678));
  ASSERT (!QUIC_VERSION_IS_SUPPORTED (0xffffffff));
}

/* ============================================================================
 * Real Version Detection Tests
 * ============================================================================
 */

TEST (quic_version_real_v1)
{
  ASSERT (QUIC_VERSION_IS_REAL (QUIC_VERSION_1));
}

TEST (quic_version_real_v2)
{
  ASSERT (QUIC_VERSION_IS_REAL (QUIC_VERSION_2));
}

TEST (quic_version_not_real_negotiation)
{
  ASSERT (!QUIC_VERSION_IS_REAL (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_not_real_grease)
{
  ASSERT (!QUIC_VERSION_IS_REAL (0x0a0a0a0a));
  ASSERT (!QUIC_VERSION_IS_REAL (0xfafafafa));
}

TEST (quic_version_real_unknown)
{
  /* Unknown versions are still "real" - they just aren't supported */
  ASSERT (QUIC_VERSION_IS_REAL (0x12345678));
}

/* ============================================================================
 * Version Validation Function Tests
 * ============================================================================
 */

TEST (quic_version_valid_v1)
{
  ASSERT (SocketQUIC_version_is_valid (QUIC_VERSION_1));
}

TEST (quic_version_valid_v2)
{
  ASSERT (SocketQUIC_version_is_valid (QUIC_VERSION_2));
}

TEST (quic_version_invalid_negotiation)
{
  ASSERT (!SocketQUIC_version_is_valid (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_invalid_grease)
{
  ASSERT (!SocketQUIC_version_is_valid (0x0a0a0a0a));
  ASSERT (!SocketQUIC_version_is_valid (0x1a1a1a1a));
  ASSERT (!SocketQUIC_version_is_valid (0xfafafafa));
}

TEST (quic_version_invalid_unknown)
{
  ASSERT (!SocketQUIC_version_is_valid (0x12345678));
  ASSERT (!SocketQUIC_version_is_valid (0xffffffff));
}

/* ============================================================================
 * Version Negotiation Need Tests
 * ============================================================================
 */

TEST (quic_version_negotiation_not_needed_v1)
{
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_1));
}

TEST (quic_version_negotiation_not_needed_v2)
{
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_2));
}

TEST (quic_version_negotiation_not_needed_zero)
{
  /* Client already doing version negotiation */
  ASSERT (!SocketQUIC_version_needs_negotiation (QUIC_VERSION_NEGOTIATION));
}

TEST (quic_version_negotiation_needed_unknown)
{
  ASSERT (SocketQUIC_version_needs_negotiation (0x12345678));
  ASSERT (SocketQUIC_version_needs_negotiation (0xffffffff));
}

TEST (quic_version_negotiation_needed_grease)
{
  ASSERT (SocketQUIC_version_needs_negotiation (0x0a0a0a0a));
}

/* ============================================================================
 * Version String Tests
 * ============================================================================
 */

TEST (quic_version_string_negotiation)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_NEGOTIATION);
  ASSERT (strcmp (str, "VERSION_NEGOTIATION") == 0);
}

TEST (quic_version_string_v1)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_1);
  ASSERT (strstr (str, "QUICv1") != NULL);
  ASSERT (strstr (str, "RFC 9000") != NULL);
}

TEST (quic_version_string_v2)
{
  const char *str = SocketQUIC_version_string (QUIC_VERSION_2);
  ASSERT (strstr (str, "QUICv2") != NULL);
  ASSERT (strstr (str, "RFC 9369") != NULL);
}

TEST (quic_version_string_grease)
{
  const char *str = SocketQUIC_version_string (0x0a0a0a0a);
  ASSERT (strcmp (str, "GREASE") == 0);
}

TEST (quic_version_string_unknown)
{
  const char *str = SocketQUIC_version_string (0x12345678);
  ASSERT (strcmp (str, "UNKNOWN") == 0);
}

TEST (quic_version_string_not_null)
{
  /* Ensure we never return NULL */
  ASSERT_NOT_NULL (SocketQUIC_version_string (0));
  ASSERT_NOT_NULL (SocketQUIC_version_string (1));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0x0a0a0a0a));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0x12345678));
  ASSERT_NOT_NULL (SocketQUIC_version_string (0xffffffff));
}

/* ============================================================================
 * Supported Versions List Tests
 * ============================================================================
 */

TEST (quic_supported_versions_count)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  ASSERT (count >= 2);
  ASSERT_NOT_NULL (versions);
}

TEST (quic_supported_versions_contains_v1)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (versions[i] == QUIC_VERSION_1)
        found = 1;
    }
  ASSERT (found);
}

TEST (quic_supported_versions_contains_v2)
{
  size_t count = 0;
  const uint32_t *versions = SocketQUIC_supported_versions (&count);

  int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (versions[i] == QUIC_VERSION_2)
        found = 1;
    }
  ASSERT (found);
}

TEST (quic_supported_versions_null_count)
{
  /* Should not crash with NULL count */
  const uint32_t *versions = SocketQUIC_supported_versions (NULL);
  ASSERT_NOT_NULL (versions);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
