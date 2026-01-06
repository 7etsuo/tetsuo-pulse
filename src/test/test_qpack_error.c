/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_error.c
 * @brief Unit tests for QPACK error handling (RFC 9204 Section 6).
 *
 * Tests error code definitions, result string conversion, HTTP/3
 * error code mapping, and inline utility functions.
 */

#include "http/SocketQPACK.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Error Code Constant Tests
 * ============================================================================
 */

TEST (qpack_error_decompression_failed_value)
{
  ASSERT_EQ (0x0200, QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_encoder_stream_error_value)
{
  ASSERT_EQ (0x0201, QPACK_ENCODER_STREAM_ERROR);
}

TEST (qpack_error_decoder_stream_error_value)
{
  ASSERT_EQ (0x0202, QPACK_DECODER_STREAM_ERROR);
}

TEST (h3_stream_creation_error_value)
{
  ASSERT_EQ (0x0101, H3_STREAM_CREATION_ERROR);
}

TEST (h3_closed_critical_stream_value)
{
  ASSERT_EQ (0x0104, H3_CLOSED_CRITICAL_STREAM);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (qpack_result_string_ok)
{
  const char *str = SocketQPACK_result_string (QPACK_OK);
  ASSERT_NOT_NULL (str);
  ASSERT (strcmp (str, "OK") == 0);
}

TEST (qpack_result_string_incomplete)
{
  const char *str = SocketQPACK_result_string (QPACK_INCOMPLETE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Incomplete") != NULL);
}

TEST (qpack_result_string_blocked)
{
  const char *str = SocketQPACK_result_string (QPACK_BLOCKED);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Blocked") != NULL);
}

TEST (qpack_result_string_generic_error)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "error") != NULL || strstr (str, "Error") != NULL);
}

TEST (qpack_result_string_invalid_index)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INVALID_INDEX);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "index") != NULL || strstr (str, "Index") != NULL);
}

TEST (qpack_result_string_invalid_capacity)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INVALID_CAPACITY);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "apacity") != NULL);
}

TEST (qpack_result_string_huffman)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_HUFFMAN);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Huffman") != NULL || strstr (str, "huffman") != NULL);
}

TEST (qpack_result_string_integer)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INTEGER);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Integer") != NULL || strstr (str, "integer") != NULL);
}

TEST (qpack_result_string_string)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_STRING);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "String") != NULL || strstr (str, "string") != NULL);
}

TEST (qpack_result_string_header_size)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_HEADER_SIZE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Header") != NULL || strstr (str, "header") != NULL);
}

TEST (qpack_result_string_list_size)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_LIST_SIZE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "list") != NULL || strstr (str, "List") != NULL);
}

TEST (qpack_result_string_required_insert)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_REQUIRED_INSERT);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Insert") != NULL || strstr (str, "insert") != NULL);
}

TEST (qpack_result_string_base)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_BASE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Base") != NULL || strstr (str, "base") != NULL);
}

TEST (qpack_result_string_duplicate_stream)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_DUPLICATE_STREAM);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "uplicate") != NULL || strstr (str, "stream") != NULL);
}

TEST (qpack_result_string_stream_closed)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_STREAM_CLOSED);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "losed") != NULL || strstr (str, "stream") != NULL);
}

TEST (qpack_result_string_not_found)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_NOT_FOUND);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "ound") != NULL || strstr (str, "table") != NULL);
}

TEST (qpack_result_string_evicted_index)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_EVICTED_INDEX);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "victed") != NULL || strstr (str, "dynamic") != NULL);
}

TEST (qpack_result_string_future_index)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_FUTURE_INDEX);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "uture") != NULL || strstr (str, "index") != NULL);
}

TEST (qpack_result_string_base_overflow)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_BASE_OVERFLOW);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "verflow") != NULL || strstr (str, "base") != NULL);
}

TEST (qpack_result_string_invalid_negative)
{
  const char *str = SocketQPACK_result_string ((SocketQPACK_Result) -1);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "nknown") != NULL);
}

TEST (qpack_result_string_invalid_large)
{
  const char *str = SocketQPACK_result_string ((SocketQPACK_Result) 999);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "nknown") != NULL);
}

TEST (qpack_result_string_at_count)
{
  const char *str = SocketQPACK_result_string (QPACK_RESULT_COUNT);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "nknown") != NULL);
}

/* ============================================================================
 * HTTP/3 Error Code Mapping Tests
 * ============================================================================
 */

TEST (qpack_error_code_ok)
{
  ASSERT_EQ (0, SocketQPACK_error_code (QPACK_OK));
}

TEST (qpack_error_code_incomplete)
{
  ASSERT_EQ (0, SocketQPACK_error_code (QPACK_INCOMPLETE));
}

TEST (qpack_error_code_blocked)
{
  ASSERT_EQ (0, SocketQPACK_error_code (QPACK_BLOCKED));
}

TEST (qpack_error_code_generic_error)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR));
}

TEST (qpack_error_code_invalid_index)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_INVALID_INDEX));
}

TEST (qpack_error_code_invalid_capacity)
{
  ASSERT_EQ (QPACK_ENCODER_STREAM_ERROR,
             SocketQPACK_error_code (QPACK_ERROR_INVALID_CAPACITY));
}

TEST (qpack_error_code_huffman)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_HUFFMAN));
}

TEST (qpack_error_code_integer)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_INTEGER));
}

TEST (qpack_error_code_string)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_STRING));
}

TEST (qpack_error_code_header_size)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_HEADER_SIZE));
}

TEST (qpack_error_code_list_size)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_LIST_SIZE));
}

TEST (qpack_error_code_required_insert)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_REQUIRED_INSERT));
}

TEST (qpack_error_code_base)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_BASE));
}

TEST (qpack_error_code_not_found)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_NOT_FOUND));
}

TEST (qpack_error_code_evicted_index)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_EVICTED_INDEX));
}

TEST (qpack_error_code_future_index)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_FUTURE_INDEX));
}

TEST (qpack_error_code_base_overflow)
{
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED,
             SocketQPACK_error_code (QPACK_ERROR_BASE_OVERFLOW));
}

/* RFC 9204 §4.2 compliance tests */
TEST (qpack_error_code_duplicate_stream_rfc9204_section4_2)
{
  /* RFC 9204 §4.2: "Receipt of a second instance of either stream type
   * MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR." */
  ASSERT_EQ (H3_STREAM_CREATION_ERROR,
             SocketQPACK_error_code (QPACK_ERROR_DUPLICATE_STREAM));
}

TEST (qpack_error_code_stream_closed_rfc9204_section4_2)
{
  /* RFC 9204 §4.2: "Closure of either unidirectional stream type MUST be
   * treated as a connection error of type H3_CLOSED_CRITICAL_STREAM." */
  ASSERT_EQ (H3_CLOSED_CRITICAL_STREAM,
             SocketQPACK_error_code (QPACK_ERROR_STREAM_CLOSED));
}

/* ============================================================================
 * HTTP/3 Error String Tests
 * ============================================================================
 */

TEST (qpack_http3_error_string_decompression_failed)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_DECOMPRESSION_FAILED);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "DECOMPRESSION") != NULL);
}

TEST (qpack_http3_error_string_encoder_stream)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_ENCODER_STREAM_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "ENCODER") != NULL);
}

TEST (qpack_http3_error_string_decoder_stream)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_DECODER_STREAM_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "DECODER") != NULL);
}

TEST (qpack_http3_error_string_stream_creation)
{
  const char *str = SocketQPACK_http3_error_string (H3_STREAM_CREATION_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "STREAM_CREATION") != NULL);
}

TEST (qpack_http3_error_string_closed_critical)
{
  const char *str = SocketQPACK_http3_error_string (H3_CLOSED_CRITICAL_STREAM);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "CLOSED_CRITICAL") != NULL);
}

TEST (qpack_http3_error_string_unknown)
{
  const char *str = SocketQPACK_http3_error_string (0x9999);
  ASSERT_NULL (str);
}

TEST (qpack_http3_error_string_zero)
{
  const char *str = SocketQPACK_http3_error_string (0);
  ASSERT_NULL (str);
}

/* ============================================================================
 * Inline Function Tests
 * ============================================================================
 */

TEST (qpack_is_qpack_error_decompression)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_DECOMPRESSION_FAILED));
}

TEST (qpack_is_qpack_error_encoder)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_ENCODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_error_decoder)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_DECODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_error_stream_creation_not)
{
  /* H3_STREAM_CREATION_ERROR is NOT a QPACK-specific error (RFC 9204 §6),
   * it's an HTTP/3 error (RFC 9114) referenced by QPACK (RFC 9204 §4.2) */
  ASSERT (!SocketQPACK_is_qpack_error (H3_STREAM_CREATION_ERROR));
}

TEST (qpack_is_qpack_error_closed_critical_not)
{
  /* H3_CLOSED_CRITICAL_STREAM is NOT a QPACK-specific error (RFC 9204 §6),
   * it's an HTTP/3 error (RFC 9114) referenced by QPACK (RFC 9204 §4.2) */
  ASSERT (!SocketQPACK_is_qpack_error (H3_CLOSED_CRITICAL_STREAM));
}

TEST (qpack_is_qpack_error_zero_not)
{
  ASSERT (!SocketQPACK_is_qpack_error (0));
}

TEST (qpack_is_qpack_error_below_range_not)
{
  ASSERT (!SocketQPACK_is_qpack_error (0x01FF));
}

TEST (qpack_is_qpack_error_above_range_not)
{
  ASSERT (!SocketQPACK_is_qpack_error (0x0203));
}

TEST (qpack_is_qpack_related_decompression)
{
  ASSERT (SocketQPACK_is_qpack_related_error (QPACK_DECOMPRESSION_FAILED));
}

TEST (qpack_is_qpack_related_encoder)
{
  ASSERT (SocketQPACK_is_qpack_related_error (QPACK_ENCODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_related_decoder)
{
  ASSERT (SocketQPACK_is_qpack_related_error (QPACK_DECODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_related_stream_creation)
{
  /* H3_STREAM_CREATION_ERROR IS a QPACK-related error (RFC 9204 §4.2) */
  ASSERT (SocketQPACK_is_qpack_related_error (H3_STREAM_CREATION_ERROR));
}

TEST (qpack_is_qpack_related_closed_critical)
{
  /* H3_CLOSED_CRITICAL_STREAM IS a QPACK-related error (RFC 9204 §4.2) */
  ASSERT (SocketQPACK_is_qpack_related_error (H3_CLOSED_CRITICAL_STREAM));
}

TEST (qpack_is_qpack_related_zero_not)
{
  ASSERT (!SocketQPACK_is_qpack_related_error (0));
}

TEST (qpack_is_qpack_related_unrelated_not)
{
  ASSERT (!SocketQPACK_is_qpack_related_error (0x0100));
}

/* ============================================================================
 * Enum Value Tests
 * ============================================================================
 */

TEST (qpack_result_enum_values_sequential)
{
  ASSERT_EQ (0, QPACK_OK);
  ASSERT_EQ (1, QPACK_INCOMPLETE);
  ASSERT_EQ (2, QPACK_BLOCKED);
  ASSERT_EQ (3, QPACK_ERROR);
  ASSERT_EQ (4, QPACK_ERROR_INVALID_INDEX);
  ASSERT_EQ (5, QPACK_ERROR_INVALID_CAPACITY);
  ASSERT_EQ (6, QPACK_ERROR_HUFFMAN);
  ASSERT_EQ (7, QPACK_ERROR_INTEGER);
  ASSERT_EQ (8, QPACK_ERROR_STRING);
  ASSERT_EQ (9, QPACK_ERROR_HEADER_SIZE);
  ASSERT_EQ (10, QPACK_ERROR_LIST_SIZE);
  ASSERT_EQ (11, QPACK_ERROR_REQUIRED_INSERT);
  ASSERT_EQ (12, QPACK_ERROR_BASE);
  ASSERT_EQ (13, QPACK_ERROR_DUPLICATE_STREAM);
  ASSERT_EQ (14, QPACK_ERROR_STREAM_CLOSED);
  ASSERT_EQ (15, QPACK_ERROR_NOT_FOUND);
  ASSERT_EQ (16, QPACK_ERROR_EVICTED_INDEX);
  ASSERT_EQ (17, QPACK_ERROR_FUTURE_INDEX);
  ASSERT_EQ (18, QPACK_ERROR_BASE_OVERFLOW);
  ASSERT_EQ (19, QPACK_RESULT_COUNT);
}

TEST (qpack_result_count_matches_enum_size)
{
  /* QPACK_RESULT_COUNT should be the number of actual result codes */
  ASSERT_EQ (19, QPACK_RESULT_COUNT);
}

/* ============================================================================
 * Exception Definition Test
 * ============================================================================
 */

TEST (qpack_exception_defined)
{
  ASSERT_NOT_NULL (&SocketQPACK_Error);
  ASSERT_NOT_NULL (SocketQPACK_Error.reason);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
