/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http3_constants.c - HTTP/3 Constants Tests (RFC 9114)
 *
 * Part of the Socket Library
 * Verifies frame types, error codes, settings, stream types, and GREASE.
 */

#include "http/SocketHTTP3-constants.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Test Utilities
 * ============================================================================
 */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          return 0;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define TEST_BEGIN(name)                  \
  do                                      \
    {                                     \
      tests_run++;                        \
      printf ("  Testing %s... ", #name); \
      fflush (stdout);                    \
    }                                     \
  while (0)

#define TEST_PASS()        \
  do                       \
    {                      \
      tests_passed++;      \
      printf ("PASSED\n"); \
      return 1;            \
    }                      \
  while (0)

/* ============================================================================
 * Frame Type Tests (RFC 9114 Section 7.2)
 * ============================================================================
 */

static int
test_frame_type_values (void)
{
  TEST_BEGIN (frame_type_values);

  TEST_ASSERT (HTTP3_FRAME_DATA == 0x00, "DATA must be 0x00");
  TEST_ASSERT (HTTP3_FRAME_HEADERS == 0x01, "HEADERS must be 0x01");
  TEST_ASSERT (HTTP3_FRAME_CANCEL_PUSH == 0x03, "CANCEL_PUSH must be 0x03");
  TEST_ASSERT (HTTP3_FRAME_SETTINGS == 0x04, "SETTINGS must be 0x04");
  TEST_ASSERT (HTTP3_FRAME_PUSH_PROMISE == 0x05, "PUSH_PROMISE must be 0x05");
  TEST_ASSERT (HTTP3_FRAME_GOAWAY == 0x07, "GOAWAY must be 0x07");
  TEST_ASSERT (HTTP3_FRAME_MAX_PUSH_ID == 0x0d, "MAX_PUSH_ID must be 0x0d");

  TEST_PASS ();
}

static int
test_frame_type_names (void)
{
  TEST_BEGIN (frame_type_names);

  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x00), "DATA") == 0,
               "DATA name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x01), "HEADERS") == 0,
               "HEADERS name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x03), "CANCEL_PUSH") == 0,
               "CANCEL_PUSH name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x04), "SETTINGS") == 0,
               "SETTINGS name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x05), "PUSH_PROMISE") == 0,
               "PUSH_PROMISE name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x07), "GOAWAY") == 0,
               "GOAWAY name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0x0d), "MAX_PUSH_ID") == 0,
               "MAX_PUSH_ID name");
  TEST_ASSERT (strcmp (SocketHTTP3_frame_type_name (0xff), "UNKNOWN") == 0,
               "unknown frame type returns UNKNOWN");

  TEST_PASS ();
}

/* ============================================================================
 * Reserved HTTP/2 Frame Types (RFC 9114 Section 11.2.1)
 * ============================================================================
 */

static int
test_reserved_h2_frame_types (void)
{
  TEST_BEGIN (reserved_h2_frame_types);

  TEST_ASSERT (HTTP3_H2_FRAME_PRIORITY == 0x02, "PRIORITY must be 0x02");
  TEST_ASSERT (HTTP3_H2_FRAME_PING == 0x06, "PING must be 0x06");
  TEST_ASSERT (HTTP3_H2_FRAME_WINDOW_UPDATE == 0x08,
               "WINDOW_UPDATE must be 0x08");
  TEST_ASSERT (HTTP3_H2_FRAME_CONTINUATION == 0x09,
               "CONTINUATION must be 0x09");

  TEST_ASSERT (HTTP3_IS_RESERVED_H2_FRAME (0x02), "0x02 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_FRAME (0x06), "0x06 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_FRAME (0x08), "0x08 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_FRAME (0x09), "0x09 is reserved");

  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_FRAME (0x00), "DATA not reserved");
  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_FRAME (0x01), "HEADERS not reserved");
  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_FRAME (0x04), "SETTINGS not reserved");

  /* Verify name lookup identifies reserved types */
  TEST_ASSERT (strstr (SocketHTTP3_frame_type_name (0x02), "reserved") != NULL,
               "PRIORITY name contains 'reserved'");
  TEST_ASSERT (strstr (SocketHTTP3_frame_type_name (0x06), "reserved") != NULL,
               "PING name contains 'reserved'");

  TEST_PASS ();
}

/* ============================================================================
 * Error Code Tests (RFC 9114 Section 8.1)
 * ============================================================================
 */

static int
test_error_code_values (void)
{
  TEST_BEGIN (error_code_values);

  TEST_ASSERT (H3_NO_ERROR == 0x0100, "H3_NO_ERROR must be 0x0100");
  TEST_ASSERT (H3_GENERAL_PROTOCOL_ERROR == 0x0101,
               "H3_GENERAL_PROTOCOL_ERROR must be 0x0101");
  TEST_ASSERT (H3_INTERNAL_ERROR == 0x0102, "H3_INTERNAL_ERROR must be 0x0102");
  TEST_ASSERT (H3_STREAM_CREATION_ERROR == 0x0103,
               "H3_STREAM_CREATION_ERROR must be 0x0103");
  TEST_ASSERT (H3_CLOSED_CRITICAL_STREAM == 0x0104,
               "H3_CLOSED_CRITICAL_STREAM must be 0x0104");
  TEST_ASSERT (H3_FRAME_UNEXPECTED == 0x0105,
               "H3_FRAME_UNEXPECTED must be 0x0105");
  TEST_ASSERT (H3_FRAME_ERROR == 0x0106, "H3_FRAME_ERROR must be 0x0106");
  TEST_ASSERT (H3_EXCESSIVE_LOAD == 0x0107, "H3_EXCESSIVE_LOAD must be 0x0107");
  TEST_ASSERT (H3_ID_ERROR == 0x0108, "H3_ID_ERROR must be 0x0108");
  TEST_ASSERT (H3_SETTINGS_ERROR == 0x0109, "H3_SETTINGS_ERROR must be 0x0109");
  TEST_ASSERT (H3_MISSING_SETTINGS == 0x010a,
               "H3_MISSING_SETTINGS must be 0x010a");
  TEST_ASSERT (H3_REQUEST_REJECTED == 0x010b,
               "H3_REQUEST_REJECTED must be 0x010b");
  TEST_ASSERT (H3_REQUEST_CANCELLED == 0x010c,
               "H3_REQUEST_CANCELLED must be 0x010c");
  TEST_ASSERT (H3_REQUEST_INCOMPLETE == 0x010d,
               "H3_REQUEST_INCOMPLETE must be 0x010d");
  TEST_ASSERT (H3_MESSAGE_ERROR == 0x010e, "H3_MESSAGE_ERROR must be 0x010e");
  TEST_ASSERT (H3_CONNECT_ERROR == 0x010f, "H3_CONNECT_ERROR must be 0x010f");
  TEST_ASSERT (H3_VERSION_FALLBACK == 0x0110,
               "H3_VERSION_FALLBACK must be 0x0110");

  TEST_PASS ();
}

static int
test_error_code_names (void)
{
  TEST_BEGIN (error_code_names);

  TEST_ASSERT (strcmp (SocketHTTP3_error_code_name (H3_NO_ERROR), "H3_NO_ERROR")
                   == 0,
               "H3_NO_ERROR name");
  TEST_ASSERT (strcmp (SocketHTTP3_error_code_name (H3_GENERAL_PROTOCOL_ERROR),
                       "H3_GENERAL_PROTOCOL_ERROR")
                   == 0,
               "H3_GENERAL_PROTOCOL_ERROR name");
  TEST_ASSERT (strcmp (SocketHTTP3_error_code_name (H3_VERSION_FALLBACK),
                       "H3_VERSION_FALLBACK")
                   == 0,
               "H3_VERSION_FALLBACK name");
  TEST_ASSERT (strcmp (SocketHTTP3_error_code_name (0xffff), "UNKNOWN") == 0,
               "unknown error code returns UNKNOWN");

  /* Verify all 17 codes return non-NULL, non-UNKNOWN strings */
  for (uint64_t c = 0x0100; c <= 0x0110; c++)
    {
      const char *name = SocketHTTP3_error_code_name (c);
      TEST_ASSERT (name != NULL, "error code name not NULL");
      TEST_ASSERT (strcmp (name, "UNKNOWN") != 0,
                   "known error code should not be UNKNOWN");
    }

  TEST_PASS ();
}

/* ============================================================================
 * Settings Tests (RFC 9114 Section 7.2.4.1)
 * ============================================================================
 */

static int
test_settings_values (void)
{
  TEST_BEGIN (settings_values);

  TEST_ASSERT (H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY == 0x01,
               "QPACK_MAX_TABLE_CAPACITY must be 0x01");
  TEST_ASSERT (H3_SETTINGS_MAX_FIELD_SECTION_SIZE == 0x06,
               "MAX_FIELD_SECTION_SIZE must be 0x06");
  TEST_ASSERT (H3_SETTINGS_QPACK_BLOCKED_STREAMS == 0x07,
               "QPACK_BLOCKED_STREAMS must be 0x07");

  TEST_PASS ();
}

static int
test_settings_names (void)
{
  TEST_BEGIN (settings_names);

  TEST_ASSERT (
      strcmp (SocketHTTP3_settings_name (0x01), "QPACK_MAX_TABLE_CAPACITY")
          == 0,
      "QPACK_MAX_TABLE_CAPACITY name");
  TEST_ASSERT (
      strcmp (SocketHTTP3_settings_name (0x06), "MAX_FIELD_SECTION_SIZE") == 0,
      "MAX_FIELD_SECTION_SIZE name");
  TEST_ASSERT (
      strcmp (SocketHTTP3_settings_name (0x07), "QPACK_BLOCKED_STREAMS") == 0,
      "QPACK_BLOCKED_STREAMS name");
  TEST_ASSERT (strcmp (SocketHTTP3_settings_name (0xff), "UNKNOWN") == 0,
               "unknown setting returns UNKNOWN");

  TEST_PASS ();
}

static int
test_reserved_h2_settings (void)
{
  TEST_BEGIN (reserved_h2_settings);

  TEST_ASSERT (HTTP3_IS_RESERVED_H2_SETTING (0x02), "0x02 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_SETTING (0x03), "0x03 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_SETTING (0x04), "0x04 is reserved");
  TEST_ASSERT (HTTP3_IS_RESERVED_H2_SETTING (0x05), "0x05 is reserved");

  /* 0x01 is reused by QPACK_MAX_TABLE_CAPACITY and is valid */
  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_SETTING (0x01),
               "0x01 is NOT reserved (reused by QPACK)");
  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_SETTING (0x06), "0x06 is NOT reserved");
  TEST_ASSERT (!HTTP3_IS_RESERVED_H2_SETTING (0x07), "0x07 is NOT reserved");

  TEST_PASS ();
}

/* ============================================================================
 * Stream Type Tests (RFC 9114 Section 6.2)
 * ============================================================================
 */

static int
test_stream_type_values (void)
{
  TEST_BEGIN (stream_type_values);

  TEST_ASSERT (H3_STREAM_TYPE_CONTROL == 0x00, "CONTROL must be 0x00");
  TEST_ASSERT (H3_STREAM_TYPE_PUSH == 0x01, "PUSH must be 0x01");
  TEST_ASSERT (H3_STREAM_TYPE_QPACK_ENCODER == 0x02,
               "QPACK_ENCODER must be 0x02");
  TEST_ASSERT (H3_STREAM_TYPE_QPACK_DECODER == 0x03,
               "QPACK_DECODER must be 0x03");

  TEST_PASS ();
}

static int
test_stream_type_names (void)
{
  TEST_BEGIN (stream_type_names);

  TEST_ASSERT (strcmp (SocketHTTP3_stream_type_name (0x00), "CONTROL") == 0,
               "CONTROL name");
  TEST_ASSERT (strcmp (SocketHTTP3_stream_type_name (0x01), "PUSH") == 0,
               "PUSH name");
  TEST_ASSERT (strcmp (SocketHTTP3_stream_type_name (0x02), "QPACK_ENCODER")
                   == 0,
               "QPACK_ENCODER name");
  TEST_ASSERT (strcmp (SocketHTTP3_stream_type_name (0x03), "QPACK_DECODER")
                   == 0,
               "QPACK_DECODER name");
  TEST_ASSERT (strcmp (SocketHTTP3_stream_type_name (0xff), "UNKNOWN") == 0,
               "unknown stream type returns UNKNOWN");

  TEST_PASS ();
}

/* ============================================================================
 * GREASE Tests (RFC 9114 Section 7.2.8 / 6.2.3 / 8.1)
 * ============================================================================
 */

static int
test_grease_formula (void)
{
  TEST_BEGIN (grease_formula);

  /* Formula: 0x1f * N + 0x21 for N >= 0 */
  /* N=0: 0x21, N=1: 0x40, N=2: 0x5f, N=3: 0x7e */
  TEST_ASSERT (H3_IS_GREASE (0x21), "N=0 → 0x21 is GREASE");
  TEST_ASSERT (H3_IS_GREASE (0x40), "N=1 → 0x40 is GREASE");
  TEST_ASSERT (H3_IS_GREASE (0x5f), "N=2 → 0x5f is GREASE");
  TEST_ASSERT (H3_IS_GREASE (0x7e), "N=3 → 0x7e is GREASE");

  /* Larger values */
  TEST_ASSERT (H3_IS_GREASE (0x21 + 0x1f * 10), "N=10 is GREASE");
  TEST_ASSERT (H3_IS_GREASE (0x21 + 0x1f * 100), "N=100 is GREASE");

  /* Non-GREASE values */
  TEST_ASSERT (!H3_IS_GREASE (0x00), "0x00 is not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (0x01), "0x01 is not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (0x20), "0x20 is not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (0x22), "0x22 is not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (0x3f), "0x3f is not GREASE");

  /* Known frame/error/settings values should not be GREASE */
  TEST_ASSERT (!H3_IS_GREASE (HTTP3_FRAME_DATA), "DATA not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (HTTP3_FRAME_HEADERS), "HEADERS not GREASE");
  TEST_ASSERT (!H3_IS_GREASE (H3_NO_ERROR), "H3_NO_ERROR not GREASE");

  TEST_PASS ();
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("=== HTTP/3 Constants Tests (RFC 9114) ===\n\n");

  /* Frame type tests */
  printf ("Frame Type Tests (§7.2):\n");
  test_frame_type_values ();
  test_frame_type_names ();
  test_reserved_h2_frame_types ();
  printf ("\n");

  /* Error code tests */
  printf ("Error Code Tests (§8.1):\n");
  test_error_code_values ();
  test_error_code_names ();
  printf ("\n");

  /* Settings tests */
  printf ("Settings Tests (§7.2.4.1):\n");
  test_settings_values ();
  test_settings_names ();
  test_reserved_h2_settings ();
  printf ("\n");

  /* Stream type tests */
  printf ("Stream Type Tests (§6.2):\n");
  test_stream_type_values ();
  test_stream_type_names ();
  printf ("\n");

  /* GREASE tests */
  printf ("GREASE Tests (§7.2.8):\n");
  test_grease_formula ();
  printf ("\n");

  /* Summary */
  printf ("=====================\n");
  printf ("Tests: %d passed, %d failed, %d total\n",
          tests_passed,
          tests_run - tests_passed,
          tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
