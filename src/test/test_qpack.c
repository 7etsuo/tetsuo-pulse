/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Error Handling (RFC 9204 Section 6)
 *
 * Tests error code definitions, result string conversion, and HTTP/3
 * error code mapping for QPACK header compression.
 */

#include <stdint.h>
#include <string.h>

#include "http/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * HTTP/3 Error Code Value Tests (RFC 9204 Section 6)
 * ============================================================================
 */

TEST (qpack_decompression_failed_value)
{
  /* RFC 9204 Section 6: QPACK_DECOMPRESSION_FAILED = 0x0200 */
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED, 0x0200);
}

TEST (qpack_encoder_stream_error_value)
{
  /* RFC 9204 Section 6: QPACK_ENCODER_STREAM_ERROR = 0x0201 */
  ASSERT_EQ (QPACK_ENCODER_STREAM_ERROR, 0x0201);
}

TEST (qpack_decoder_stream_error_value)
{
  /* RFC 9204 Section 6: QPACK_DECODER_STREAM_ERROR = 0x0202 */
  ASSERT_EQ (QPACK_DECODER_STREAM_ERROR, 0x0202);
}

/* ============================================================================
 * Result Code Value Tests
 * ============================================================================
 */

TEST (qpack_result_ok_value)
{
  ASSERT_EQ (QPACK_OK, 0);
}

TEST (qpack_result_incomplete_value)
{
  ASSERT_EQ (QPACK_INCOMPLETE, 1);
}

TEST (qpack_result_blocked_value)
{
  ASSERT_EQ (QPACK_BLOCKED, 2);
}

TEST (qpack_result_error_value)
{
  ASSERT_EQ (QPACK_ERROR, 3);
}

TEST (qpack_result_invalid_index_value)
{
  ASSERT_EQ (QPACK_ERROR_INVALID_INDEX, 4);
}

TEST (qpack_result_invalid_capacity_value)
{
  ASSERT_EQ (QPACK_ERROR_INVALID_CAPACITY, 5);
}

TEST (qpack_result_huffman_value)
{
  ASSERT_EQ (QPACK_ERROR_HUFFMAN, 6);
}

TEST (qpack_result_integer_value)
{
  ASSERT_EQ (QPACK_ERROR_INTEGER, 7);
}

TEST (qpack_result_string_value)
{
  ASSERT_EQ (QPACK_ERROR_STRING, 8);
}

TEST (qpack_result_header_size_value)
{
  ASSERT_EQ (QPACK_ERROR_HEADER_SIZE, 9);
}

TEST (qpack_result_list_size_value)
{
  ASSERT_EQ (QPACK_ERROR_LIST_SIZE, 10);
}

TEST (qpack_result_required_insert_value)
{
  ASSERT_EQ (QPACK_ERROR_REQUIRED_INSERT, 11);
}

TEST (qpack_result_base_value)
{
  ASSERT_EQ (QPACK_ERROR_BASE, 12);
}

TEST (qpack_result_duplicate_stream_value)
{
  ASSERT_EQ (QPACK_ERROR_DUPLICATE_STREAM, 13);
}

TEST (qpack_result_stream_closed_value)
{
  ASSERT_EQ (QPACK_ERROR_STREAM_CLOSED, 14);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (qpack_result_string_ok)
{
  const char *str = SocketQPACK_result_string (QPACK_OK);
  ASSERT_NOT_NULL (str);
  ASSERT_EQ (strcmp (str, "OK"), 0);
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

TEST (qpack_result_string_error)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "error") != NULL);
}

TEST (qpack_result_string_invalid_index)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INVALID_INDEX);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "index") != NULL);
}

TEST (qpack_result_string_invalid_capacity)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INVALID_CAPACITY);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Capacity") != NULL);
}

TEST (qpack_result_string_huffman)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_HUFFMAN);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Huffman") != NULL);
}

TEST (qpack_result_string_integer)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_INTEGER);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Integer") != NULL);
}

TEST (qpack_result_string_string)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_STRING);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "String") != NULL);
}

TEST (qpack_result_string_header_size)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_HEADER_SIZE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Header") != NULL);
}

TEST (qpack_result_string_list_size)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_LIST_SIZE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "list") != NULL);
}

TEST (qpack_result_string_required_insert)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_REQUIRED_INSERT);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Required Insert") != NULL);
}

TEST (qpack_result_string_base)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_BASE);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Base") != NULL);
}

TEST (qpack_result_string_duplicate_stream)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_DUPLICATE_STREAM);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Duplicate") != NULL);
}

TEST (qpack_result_string_stream_closed)
{
  const char *str = SocketQPACK_result_string (QPACK_ERROR_STREAM_CLOSED);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "stream") != NULL);
}

TEST (qpack_result_string_unknown)
{
  /* Test with invalid result code */
  const char *str = SocketQPACK_result_string ((SocketQPACK_Result)999);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Unknown") != NULL);
}

TEST (qpack_result_string_negative)
{
  /* Test with negative result code */
  const char *str = SocketQPACK_result_string ((SocketQPACK_Result)-1);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "Unknown") != NULL);
}

/* ============================================================================
 * Error Code Mapping Tests - Decompression Failures (0x0200)
 * ============================================================================
 */

TEST (qpack_error_code_invalid_index)
{
  /* Invalid index should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_INVALID_INDEX),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_huffman)
{
  /* Huffman error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_HUFFMAN),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_integer)
{
  /* Integer error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_INTEGER),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_string)
{
  /* String error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_STRING),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_header_size)
{
  /* Header size error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_HEADER_SIZE),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_list_size)
{
  /* List size error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_LIST_SIZE),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_required_insert)
{
  /* Required insert error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_REQUIRED_INSERT),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_base)
{
  /* Base error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_BASE),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_code_generic)
{
  /* Generic error should map to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR), QPACK_DECOMPRESSION_FAILED);
}

/* ============================================================================
 * Error Code Mapping Tests - Encoder Stream Errors (0x0201)
 * ============================================================================
 */

TEST (qpack_error_code_invalid_capacity)
{
  /* Capacity error should map to QPACK_ENCODER_STREAM_ERROR */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_INVALID_CAPACITY),
             QPACK_ENCODER_STREAM_ERROR);
}

TEST (qpack_error_code_duplicate_stream)
{
  /* RFC 9204 §4.2: "Receipt of a second instance of either stream type
   * MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR." */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_DUPLICATE_STREAM),
             H3_STREAM_CREATION_ERROR);
}

/* ============================================================================
 * Error Code Mapping Tests - HTTP/3 Stream Management Errors (RFC 9204 §4.2)
 * ============================================================================
 */

TEST (qpack_error_code_stream_closed)
{
  /* RFC 9204 §4.2: "Closure of either unidirectional stream type MUST be
   * treated as a connection error of type H3_CLOSED_CRITICAL_STREAM." */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_ERROR_STREAM_CLOSED),
             H3_CLOSED_CRITICAL_STREAM);
}

/* ============================================================================
 * Error Code Mapping Tests - Non-Error Conditions
 * ============================================================================
 */

TEST (qpack_error_code_ok)
{
  /* QPACK_OK is not an error - should return 0 */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_OK), 0);
}

TEST (qpack_error_code_incomplete)
{
  /* QPACK_INCOMPLETE is not an error - should return 0 */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_INCOMPLETE), 0);
}

TEST (qpack_error_code_blocked)
{
  /* QPACK_BLOCKED is not an error - should return 0 */
  ASSERT_EQ (SocketQPACK_error_code (QPACK_BLOCKED), 0);
}

/* ============================================================================
 * HTTP/3 Error String Tests
 * ============================================================================
 */

TEST (qpack_http3_error_string_decompression_failed)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_DECOMPRESSION_FAILED);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "DECOMPRESSION_FAILED") != NULL);
}

TEST (qpack_http3_error_string_encoder_stream_error)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_ENCODER_STREAM_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "ENCODER_STREAM_ERROR") != NULL);
}

TEST (qpack_http3_error_string_decoder_stream_error)
{
  const char *str = SocketQPACK_http3_error_string (QPACK_DECODER_STREAM_ERROR);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "DECODER_STREAM_ERROR") != NULL);
}

TEST (qpack_http3_error_string_non_qpack)
{
  /* Non-QPACK error code should return NULL */
  ASSERT_NULL (SocketQPACK_http3_error_string (0x0100));
}

TEST (qpack_http3_error_string_below_range)
{
  /* Error code below QPACK range should return NULL */
  ASSERT_NULL (SocketQPACK_http3_error_string (0x01ff));
}

TEST (qpack_http3_error_string_above_range)
{
  /* Error code above QPACK range should return NULL */
  ASSERT_NULL (SocketQPACK_http3_error_string (0x0203));
}

/* ============================================================================
 * is_qpack_error Tests
 * ============================================================================
 */

TEST (qpack_is_qpack_error_decompression_failed)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_DECOMPRESSION_FAILED));
}

TEST (qpack_is_qpack_error_encoder_stream)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_ENCODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_error_decoder_stream)
{
  ASSERT (SocketQPACK_is_qpack_error (QPACK_DECODER_STREAM_ERROR));
}

TEST (qpack_is_qpack_error_below_range)
{
  ASSERT (!SocketQPACK_is_qpack_error (0x01ff));
}

TEST (qpack_is_qpack_error_above_range)
{
  ASSERT (!SocketQPACK_is_qpack_error (0x0203));
}

TEST (qpack_is_qpack_error_zero)
{
  ASSERT (!SocketQPACK_is_qpack_error (0));
}

TEST (qpack_is_qpack_error_transport)
{
  /* QUIC transport errors should not be QPACK errors */
  ASSERT (!SocketQPACK_is_qpack_error (0x0a)); /* PROTOCOL_VIOLATION */
}

/* ============================================================================
 * Exception Type Tests
 * ============================================================================
 */

TEST (qpack_exception_type_defined)
{
  /* Verify exception type is properly defined */
  ASSERT_NOT_NULL (SocketQPACK_Error.reason);
  ASSERT (strlen (SocketQPACK_Error.reason) > 0);
}

TEST (qpack_exception_type_self_reference)
{
  /* Exception type should reference itself */
  ASSERT_EQ (SocketQPACK_Error.type, &SocketQPACK_Error);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
