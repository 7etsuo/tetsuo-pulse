/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Error Handling (RFC 9204 Section 6)
 *
 * Implements error code definitions, result string conversion, and
 * HTTP/3 error code mapping for QPACK header compression.
 */

#include "http/SocketQPACK.h"

#include <stddef.h>

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

/* ============================================================================
 * Result String Mapping
 * ============================================================================
 */

/**
 * Static result string table indexed by SocketQPACK_Result.
 * Provides human-readable descriptions for logging and debugging.
 *
 * Note: Array size is QPACK_RESULT_COUNT to ensure bounds safety.
 * If new result codes are added, this array must be updated.
 */
static const char *result_strings[QPACK_RESULT_COUNT] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_BLOCKED] = "Blocked - waiting for dynamic table state",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_INVALID_CAPACITY] = "Capacity exceeds limit",
  [QPACK_ERROR_HUFFMAN] = "Huffman decoding error",
  [QPACK_ERROR_INTEGER] = "Integer decoding error",
  [QPACK_ERROR_STRING] = "String decoding error",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_REQUIRED_INSERT] = "Invalid Required Insert Count",
  [QPACK_ERROR_BASE] = "Invalid Base",
  [QPACK_ERROR_DUPLICATE_STREAM] = "Duplicate encoder/decoder stream",
  [QPACK_ERROR_STREAM_CLOSED] = "Critical stream closed",
  [QPACK_ERROR_NOT_FOUND] = "Static table name not found",
  [QPACK_ERROR_EVICTED_INDEX] = "Dynamic table entry evicted",
  [QPACK_ERROR_FUTURE_INDEX] = "Dynamic table future index reference",
  [QPACK_ERROR_BASE_OVERFLOW] = "Dynamic table base overflow",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result >= QPACK_RESULT_COUNT)
    return "Unknown error";

  const char *str = result_strings[result];
  return str ? str : "Unknown error";
}

/* ============================================================================
 * HTTP/3 Error Code Mapping (RFC 9204 Section 6 and Section 4.2)
 * ============================================================================
 */

/**
 * Map internal QPACK result codes to HTTP/3 error codes.
 *
 * The mapping follows RFC 9204:
 *
 * QPACK_DECOMPRESSION_FAILED (0x0200) - RFC 9204 §6:
 *   - Used when decoder cannot interpret encoded field section data
 *   - Maps from: QPACK_ERROR_INVALID_INDEX, QPACK_ERROR_HUFFMAN,
 *                QPACK_ERROR_INTEGER, QPACK_ERROR_STRING,
 *                QPACK_ERROR_HEADER_SIZE, QPACK_ERROR_LIST_SIZE,
 *                QPACK_ERROR_REQUIRED_INSERT, QPACK_ERROR_BASE,
 *                QPACK_ERROR (generic)
 *
 * QPACK_ENCODER_STREAM_ERROR (0x0201) - RFC 9204 §6:
 *   - Used when decoder fails to interpret encoder stream instruction
 *   - Maps from: QPACK_ERROR_INVALID_CAPACITY (capacity update instruction)
 *
 * QPACK_DECODER_STREAM_ERROR (0x0202) - RFC 9204 §6:
 *   - Used when encoder fails to interpret decoder stream instruction
 *   - (No internal errors currently map to this)
 *
 * H3_STREAM_CREATION_ERROR (0x0101) - RFC 9204 §4.2:
 *   - "Receipt of a second instance of either stream type MUST be
 *      treated as a connection error of type H3_STREAM_CREATION_ERROR."
 *   - Maps from: QPACK_ERROR_DUPLICATE_STREAM
 *
 * H3_CLOSED_CRITICAL_STREAM (0x0104) - RFC 9204 §4.2:
 *   - "Closure of either unidirectional stream type MUST be treated
 *      as a connection error of type H3_CLOSED_CRITICAL_STREAM."
 *   - Maps from: QPACK_ERROR_STREAM_CLOSED
 */
uint64_t
SocketQPACK_error_code (SocketQPACK_Result result)
{
  switch (result)
    {
    /* Non-error conditions - return 0 */
    case QPACK_OK:
    case QPACK_INCOMPLETE:
    case QPACK_BLOCKED:
      return 0;

    /* Encoder stream errors (0x0201) - RFC 9204 §6 */
    case QPACK_ERROR_INVALID_CAPACITY:
      return QPACK_ENCODER_STREAM_ERROR;

    /* HTTP/3 stream management errors - RFC 9204 §4.2 */
    case QPACK_ERROR_DUPLICATE_STREAM:
      return H3_STREAM_CREATION_ERROR;

    case QPACK_ERROR_STREAM_CLOSED:
      return H3_CLOSED_CRITICAL_STREAM;

    /* Decompression failures (0x0200) - RFC 9204 §6 - all other errors */
    case QPACK_ERROR:
    case QPACK_ERROR_INVALID_INDEX:
    case QPACK_ERROR_HUFFMAN:
    case QPACK_ERROR_INTEGER:
    case QPACK_ERROR_STRING:
    case QPACK_ERROR_HEADER_SIZE:
    case QPACK_ERROR_LIST_SIZE:
    case QPACK_ERROR_REQUIRED_INSERT:
    case QPACK_ERROR_BASE:
    case QPACK_ERROR_NOT_FOUND:
    case QPACK_ERROR_EVICTED_INDEX:
    case QPACK_ERROR_FUTURE_INDEX:
    case QPACK_ERROR_BASE_OVERFLOW:
    default:
      return QPACK_DECOMPRESSION_FAILED;

    /* Note: QPACK_RESULT_COUNT is not a valid result, handled by default */
    }
}

/* ============================================================================
 * HTTP/3 Error String Conversion
 * ============================================================================
 */

const char *
SocketQPACK_http3_error_string (uint64_t code)
{
  switch (code)
    {
    /* QPACK-specific errors (RFC 9204 §6) */
    case QPACK_DECOMPRESSION_FAILED:
      return "QPACK_DECOMPRESSION_FAILED";
    case QPACK_ENCODER_STREAM_ERROR:
      return "QPACK_ENCODER_STREAM_ERROR";
    case QPACK_DECODER_STREAM_ERROR:
      return "QPACK_DECODER_STREAM_ERROR";

    /* HTTP/3 errors used by QPACK (RFC 9204 §4.2) */
    case H3_STREAM_CREATION_ERROR:
      return "H3_STREAM_CREATION_ERROR";
    case H3_CLOSED_CRITICAL_STREAM:
      return "H3_CLOSED_CRITICAL_STREAM";

    default:
      return NULL;
    }
}
