/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression/decompression for HTTP/3 (RFC 9204).
 *
 * Implements RFC 9204 Section 6 - Error Handling. QPACK is the header
 * compression format used by HTTP/3, evolved from HPACK (RFC 7541) to work
 * with QUIC's out-of-order delivery.
 *
 * QPACK-specific error codes (RFC 9204 §6):
 *   - 0x0200: QPACK_DECOMPRESSION_FAILED - decoder cannot interpret field
 *             section
 *   - 0x0201: QPACK_ENCODER_STREAM_ERROR - invalid encoder stream instruction
 *   - 0x0202: QPACK_DECODER_STREAM_ERROR - invalid decoder stream instruction
 *
 * HTTP/3 error codes used by QPACK (RFC 9114):
 *   - 0x0101: H3_STREAM_CREATION_ERROR - duplicate encoder/decoder stream
 *   - 0x0104: H3_CLOSED_CRITICAL_STREAM - encoder/decoder stream closed
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static functions are thread-safe.
 *
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/* ============================================================================
 * QPACK Result Codes (Internal Error Handling)
 * ============================================================================
 */

/**
 * @brief Internal QPACK operation result codes.
 *
 * These codes provide granular error information for internal API calls.
 * They are mapped to HTTP/3 error codes when errors need to be communicated
 * over the wire via QUIC CONNECTION_CLOSE frames.
 */
typedef enum
{
  /** Operation completed successfully. */
  QPACK_OK = 0,

  /** Need more data to complete operation. */
  QPACK_INCOMPLETE,

  /** Waiting for dynamic table state from encoder stream. */
  QPACK_BLOCKED,

  /** Generic error (unspecified). */
  QPACK_ERROR,

  /** Invalid static or dynamic table index. */
  QPACK_ERROR_INVALID_INDEX,

  /** Dynamic table capacity exceeds configured limit. */
  QPACK_ERROR_INVALID_CAPACITY,

  /** Huffman decoding error. */
  QPACK_ERROR_HUFFMAN,

  /** Integer decoding error (overflow or malformed). */
  QPACK_ERROR_INTEGER,

  /** String decoding error (length or encoding). */
  QPACK_ERROR_STRING,

  /** Individual header exceeds size limit. */
  QPACK_ERROR_HEADER_SIZE,

  /** Total header list exceeds size limit. */
  QPACK_ERROR_LIST_SIZE,

  /** Invalid Required Insert Count in encoded field section. */
  QPACK_ERROR_REQUIRED_INSERT,

  /** Invalid Base delta in encoded field section. */
  QPACK_ERROR_BASE,

  /**
   * Duplicate encoder or decoder stream on connection.
   * RFC 9204 §4.2: Maps to H3_STREAM_CREATION_ERROR (0x0101).
   */
  QPACK_ERROR_DUPLICATE_STREAM,

  /**
   * Critical unidirectional stream was closed.
   * RFC 9204 §4.2: Maps to H3_CLOSED_CRITICAL_STREAM (0x0104).
   */
  QPACK_ERROR_STREAM_CLOSED,

  /**
   * Static table lookup: name not found.
   * Used when searching static table for a header name that doesn't exist.
   */
  QPACK_ERROR_NOT_FOUND,

  /**
   * Dynamic table: referenced entry has been evicted.
   * RFC 9204 Section 2.1.1: Entries are evicted when table capacity exceeded.
   */
  QPACK_ERROR_EVICTED_INDEX,

  /**
   * Dynamic table: index references not-yet-inserted entry.
   * RFC 9204 Section 3.2.6: Post-base references must be valid.
   */
  QPACK_ERROR_FUTURE_INDEX,

  /**
   * Dynamic table: base would exceed Insert Count.
   * RFC 9204 Section 4.5.1: Base must be within valid range.
   */
  QPACK_ERROR_BASE_OVERFLOW,

  /** Count of result codes (for array bounds checking). */
  QPACK_RESULT_COUNT

} SocketQPACK_Result;

/* ============================================================================
 * HTTP/3 Error Codes (RFC 9204 Section 6)
 * ============================================================================
 */

/**
 * @brief QPACK decompression failed error code.
 *
 * RFC 9204 Section 6: "An error in the encoded data that indicates
 * a violation of QPACK. This error is raised when the decoder cannot
 * interpret an encoded field section."
 *
 * Used in CONNECTION_CLOSE frames (type 0x1d) to indicate that the
 * decoder encountered malformed or invalid QPACK-encoded data.
 */
#define QPACK_DECOMPRESSION_FAILED 0x0200

/**
 * @brief QPACK encoder stream error code.
 *
 * RFC 9204 Section 6: "An error on the encoder stream. This error is
 * raised when the decoder fails to interpret an instruction on the
 * encoder stream."
 *
 * Used in CONNECTION_CLOSE frames (type 0x1d) when an invalid
 * instruction is received on the encoder stream.
 */
#define QPACK_ENCODER_STREAM_ERROR 0x0201

/**
 * @brief QPACK decoder stream error code.
 *
 * RFC 9204 Section 6: "An error on the decoder stream. This error is
 * raised when the encoder fails to interpret an instruction on the
 * decoder stream."
 *
 * Used in CONNECTION_CLOSE frames (type 0x1d) when an invalid
 * instruction is received on the decoder stream.
 */
#define QPACK_DECODER_STREAM_ERROR 0x0202

/* ============================================================================
 * HTTP/3 Error Codes Used by QPACK (RFC 9114, referenced by RFC 9204 §4.2)
 * ============================================================================
 */

/**
 * @brief Duplicate critical stream error code.
 *
 * RFC 9204 §4.2: "Receipt of a second instance of either stream type
 * MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR."
 *
 * This is an HTTP/3 error code (RFC 9114), not a QPACK error code, but
 * is used for QPACK stream management violations.
 */
#define H3_STREAM_CREATION_ERROR 0x0101

/**
 * @brief Critical stream closed error code.
 *
 * RFC 9204 §4.2: "Closure of either unidirectional stream type MUST be
 * treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."
 *
 * This is an HTTP/3 error code (RFC 9114), not a QPACK error code, but
 * is used when the encoder or decoder stream is prematurely closed.
 */
#define H3_CLOSED_CRITICAL_STREAM 0x0104

/* ============================================================================
 * Exception Type
 * ============================================================================
 */

/**
 * @brief Exception raised on QPACK encoding/decoding errors.
 *
 * This exception is raised when QPACK operations encounter fatal errors
 * that cannot be recovered. The exception's reason field contains a
 * human-readable description of the error.
 *
 * Example usage:
 * @code
 * TRY {
 *     result = SocketQPACK_decode(...);
 * } EXCEPT(SocketQPACK_Error) {
 *     // Handle QPACK error
 * } END_TRY;
 * @endcode
 */
extern const Except_T SocketQPACK_Error;

/* ============================================================================
 * Error Handling Functions
 * ============================================================================
 */

/**
 * @brief Convert internal result code to human-readable string.
 *
 * Returns a static string describing the given result code. This function
 * is useful for logging and debugging QPACK operations.
 *
 * @param result QPACK operation result code.
 * @return Static string describing the result. Never returns NULL.
 *
 * @note Thread-safe: Returns pointer to static read-only string.
 *
 * Example:
 * @code
 * SocketQPACK_Result r = QPACK_ERROR_INVALID_INDEX;
 * printf("Error: %s\n", SocketQPACK_result_string(r));
 * // Output: "Error: Invalid table index"
 * @endcode
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/**
 * @brief Map internal result code to HTTP/3 error code.
 *
 * Converts an internal QPACK result code to the appropriate HTTP/3
 * error code for use in QUIC CONNECTION_CLOSE frames. The mapping
 * follows RFC 9204:
 *
 *   - Field section decoding errors -> QPACK_DECOMPRESSION_FAILED (0x0200)
 *   - Encoder stream instruction errors -> QPACK_ENCODER_STREAM_ERROR (0x0201)
 *   - Decoder stream instruction errors -> QPACK_DECODER_STREAM_ERROR (0x0202)
 *   - Duplicate stream (§4.2) -> H3_STREAM_CREATION_ERROR (0x0101)
 *   - Stream closed (§4.2) -> H3_CLOSED_CRITICAL_STREAM (0x0104)
 *
 * @param result Internal QPACK result code.
 * @return HTTP/3 error code, or 0 if result is not an error.
 *
 * @note For QPACK_OK, QPACK_INCOMPLETE, and QPACK_BLOCKED, returns 0
 *       since these are not error conditions requiring connection closure.
 *
 * Example:
 * @code
 * if (result != QPACK_OK) {
 *     uint64_t http3_error = SocketQPACK_error_code(result);
 *     SocketQUIC_send_connection_close(conn, http3_error, NULL, 0, buf, len);
 * }
 * @endcode
 */
extern uint64_t SocketQPACK_error_code (SocketQPACK_Result result);

/**
 * @brief Get human-readable string for HTTP/3 QPACK error code.
 *
 * Returns a static string describing the given HTTP/3 error code.
 * Handles both QPACK-specific error codes (0x0200-0x0202) and
 * HTTP/3 error codes used by QPACK (0x0101, 0x0104).
 *
 * @param code HTTP/3 error code.
 * @return Static string for recognized errors, or NULL if code is not
 *         a QPACK-related error.
 *
 * @note Thread-safe: Returns pointer to static read-only string.
 */
extern const char *SocketQPACK_http3_error_string (uint64_t code);

/**
 * @brief Check if HTTP/3 error code is a QPACK-specific error.
 *
 * Returns true only for QPACK error codes defined in RFC 9204 §6
 * (0x0200-0x0202). Does NOT return true for HTTP/3 errors that
 * QPACK uses (H3_STREAM_CREATION_ERROR, H3_CLOSED_CRITICAL_STREAM).
 *
 * @param code HTTP/3 error code to check.
 * @return Non-zero if code is in QPACK error range (0x0200-0x0202),
 *         0 otherwise.
 */
static inline int
SocketQPACK_is_qpack_error (uint64_t code)
{
  return code >= QPACK_DECOMPRESSION_FAILED
         && code <= QPACK_DECODER_STREAM_ERROR;
}

/**
 * @brief Check if HTTP/3 error code is QPACK-related (including H3 errors).
 *
 * Returns true for any error code that can be generated by QPACK
 * operations, including both RFC 9204 §6 errors and HTTP/3 errors
 * referenced in RFC 9204 §4.2.
 *
 * @param code HTTP/3 error code to check.
 * @return Non-zero if code is QPACK-related, 0 otherwise.
 */
static inline int
SocketQPACK_is_qpack_related_error (uint64_t code)
{
  return SocketQPACK_is_qpack_error (code)
         || code == H3_STREAM_CREATION_ERROR
         || code == H3_CLOSED_CRITICAL_STREAM;
}

/** @} */

#endif /* SOCKETQPACK_INCLUDED */
