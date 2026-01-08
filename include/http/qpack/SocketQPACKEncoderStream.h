/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACKEncoderStream.h
 * @brief QPACK Encoder Stream Infrastructure (RFC 9204 Section 4.2).
 *
 * Implements the encoder stream for QPACK, which carries encoder instructions
 * from encoder to decoder. The encoder stream is a unidirectional stream of
 * type 0x02 that carries an unframed sequence of encoder instructions.
 *
 * Encoder Instructions (RFC 9204 Section 4.3):
 * - Set Dynamic Table Capacity (Section 4.3.1)
 * - Insert with Name Reference (Section 4.3.2)
 * - Insert with Literal Name (Section 4.3.3)
 * - Duplicate (Section 4.3.4)
 *
 * Thread Safety: Encoder stream instances are NOT thread-safe. One instance
 * per connection recommended.
 *
 * @defgroup qpack_encoder_stream QPACK Encoder Stream
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#ifndef SOCKETQPACK_ENCODER_STREAM_INCLUDED
#define SOCKETQPACK_ENCODER_STREAM_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"

/* ============================================================================
 * STREAM TYPE CONSTANTS (RFC 9204 Section 4.2)
 * ============================================================================
 */

/**
 * @brief QPACK encoder stream type (RFC 9204 Section 4.2).
 *
 * An encoder stream is a unidirectional stream of type 0x02.
 */
#define QPACK_ENCODER_STREAM_TYPE 0x02

/**
 * @brief QPACK decoder stream type (RFC 9204 Section 4.2).
 *
 * A decoder stream is a unidirectional stream of type 0x03.
 */
#define QPACK_DECODER_STREAM_TYPE 0x03

/* ============================================================================
 * ERROR CODES
 * ============================================================================
 */

/**
 * @brief QPACK encoder stream error codes.
 *
 * RFC 9204 Section 4.2: Closing either stream type MUST be treated as
 * H3_CLOSED_CRITICAL_STREAM (0x0104).
 */
typedef enum
{
  QPACK_STREAM_OK = 0,              /**< Operation successful */
  QPACK_STREAM_ERR_BUFFER_FULL,     /**< Instruction buffer is full */
  QPACK_STREAM_ERR_ALREADY_INIT,    /**< Stream already initialized */
  QPACK_STREAM_ERR_NOT_INIT,        /**< Stream not initialized */
  QPACK_STREAM_ERR_INVALID_TYPE,    /**< Invalid stream type */
  QPACK_STREAM_ERR_CLOSED_CRITICAL, /**< Critical stream closed (H3 0x0104) */
  QPACK_STREAM_ERR_NULL_PARAM,      /**< NULL parameter passed */
  QPACK_STREAM_ERR_INVALID_INDEX,   /**< Invalid table index */
  QPACK_STREAM_ERR_CAPACITY_EXCEED, /**< Capacity exceeds maximum */
  QPACK_STREAM_ERR_INTERNAL         /**< Internal error */
} SocketQPACKStream_Result;

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

/**
 * @brief Default encoder stream buffer size.
 *
 * Pre-allocated buffer for encoder instructions. Grows as needed.
 */
#ifndef QPACK_ENCODER_STREAM_DEFAULT_BUFSIZE
#define QPACK_ENCODER_STREAM_DEFAULT_BUFSIZE 512
#endif

/**
 * @brief Maximum encoder stream buffer size.
 *
 * Limit to prevent unbounded memory growth.
 */
#ifndef QPACK_ENCODER_STREAM_MAX_BUFSIZE
#define QPACK_ENCODER_STREAM_MAX_BUFSIZE (256 * 1024)
#endif

/* ============================================================================
 * INSTRUCTION BIT PATTERNS (RFC 9204 Section 4.3)
 * ============================================================================
 */

/**
 * @brief Set Dynamic Table Capacity instruction prefix.
 *
 * RFC 9204 Section 4.3.1: Bit pattern 001xxxxx (3-bit prefix, 5-bit integer).
 */
#define QPACK_INSTR_SET_CAPACITY_MASK 0x20
#define QPACK_INSTR_SET_CAPACITY_PREFIX 5

/**
 * @brief Insert with Name Reference instruction prefix.
 *
 * RFC 9204 Section 4.3.2: Bit pattern 1Txxxxxx (1-bit prefix, T=static/dynamic,
 * 6-bit index).
 */
#define QPACK_INSTR_INSERT_NAMEREF_MASK 0x80
#define QPACK_INSTR_INSERT_NAMEREF_STATIC 0x40
#define QPACK_INSTR_INSERT_NAMEREF_PREFIX 6

/**
 * @brief Insert with Literal Name instruction prefix.
 *
 * RFC 9204 Section 4.3.3: Bit pattern 01Hxxxxx (2-bit prefix, H=huffman,
 * 5-bit name length).
 */
#define QPACK_INSTR_INSERT_LITERAL_MASK 0x40
#define QPACK_INSTR_INSERT_LITERAL_HUFFMAN 0x20
#define QPACK_INSTR_INSERT_LITERAL_PREFIX 5

/**
 * @brief Duplicate instruction prefix.
 *
 * RFC 9204 Section 4.3.4: Bit pattern 000xxxxx (3-bit prefix, 5-bit index).
 */
#define QPACK_INSTR_DUPLICATE_MASK 0x00
#define QPACK_INSTR_DUPLICATE_PREFIX 5

/**
 * @brief Value string Huffman flag mask.
 *
 * RFC 9204 Section 4.3.2/4.3.3: Bit 7 of value length byte indicates Huffman.
 */
#define QPACK_VALUE_HUFFMAN_MASK 0x80
#define QPACK_VALUE_LENGTH_PREFIX 7

/* ============================================================================
 * OPAQUE TYPE
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK encoder stream.
 *
 * Manages encoder stream state and instruction buffer.
 */
typedef struct SocketQPACK_EncoderStream *SocketQPACK_EncoderStream_T;

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Create a new QPACK encoder stream.
 *
 * Creates an encoder stream with the specified stream ID. The stream is
 * initially in an uninitialized state and must be initialized before use.
 *
 * @param arena     Memory arena for allocations (must not be NULL)
 * @param stream_id QUIC unidirectional stream ID for this encoder stream
 * @param max_capacity Maximum dynamic table capacity (decoder-advertised)
 * @return New encoder stream instance, or NULL on allocation failure
 *
 * @note The stream_id should be a client-initiated unidirectional stream
 *       (4*N+2 for client, 4*N+3 for server in QUIC terminology).
 *
 * @since 1.0.0
 */
extern SocketQPACK_EncoderStream_T
SocketQPACK_EncoderStream_new (Arena_T arena,
                               uint64_t stream_id,
                               uint64_t max_capacity);

/**
 * @brief Initialize encoder stream for sending.
 *
 * Marks the stream as initialized and ready to send encoder instructions.
 * Each endpoint MUST initiate at most one encoder stream per direction.
 *
 * @param stream Encoder stream to initialize
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_ALREADY_INIT if already initialized
 *
 * @note RFC 9204 Section 4.2: The encoder stream SHOULD be established
 *       early in the connection.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_EncoderStream_init (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Check if stream type matches encoder stream.
 *
 * Validates that a received stream type byte equals QPACK_ENCODER_STREAM_TYPE.
 *
 * @param type_byte Stream type byte received from peer
 * @return QPACK_STREAM_OK if type is 0x02,
 *         QPACK_STREAM_ERR_INVALID_TYPE otherwise
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_EncoderStream_validate_type (uint8_t type_byte);

/**
 * @brief Check if encoder stream is initialized.
 *
 * @param stream Encoder stream to check
 * @return true if initialized and ready for instructions, false otherwise
 *
 * @since 1.0.0
 */
extern bool
SocketQPACK_EncoderStream_is_open (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Get the stream ID.
 *
 * @param stream Encoder stream
 * @return Stream ID, or 0 if stream is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_EncoderStream_get_id (SocketQPACK_EncoderStream_T stream);

/* ============================================================================
 * ENCODER INSTRUCTIONS (RFC 9204 Section 4.3)
 * ============================================================================
 */

/**
 * @brief Write Set Dynamic Table Capacity instruction.
 *
 * RFC 9204 Section 4.3.1: The encoder informs the decoder of a change
 * to the dynamic table capacity. The new capacity MUST NOT exceed the
 * maximum that the decoder advertised.
 *
 * @param stream   Encoder stream
 * @param capacity New dynamic table capacity in bytes
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_CAPACITY_EXCEED if capacity exceeds maximum,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note Capacity 0 effectively disables the dynamic table.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_capacity (SocketQPACK_EncoderStream_T stream,
                                          uint64_t capacity);

/**
 * @brief Write Insert with Name Reference instruction.
 *
 * RFC 9204 Section 4.3.2: Insert a new entry using the name from an
 * existing entry (static or dynamic table) with a new value.
 *
 * @param stream       Encoder stream
 * @param is_static    true to reference static table, false for dynamic
 * @param name_index   Index of entry with name to reference
 * @param value        Value string (must not be NULL if value_len > 0)
 * @param value_len    Length of value string
 * @param use_huffman  true to Huffman-encode the value
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_INVALID_INDEX if name_index is invalid,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note For static table: name_index is 0-98 (RFC 9204 Appendix A)
 * @note For dynamic table: name_index is encoder-relative (0 = most recent)
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result SocketQPACK_EncoderStream_write_insert_nameref (
    SocketQPACK_EncoderStream_T stream,
    bool is_static,
    uint64_t name_index,
    const unsigned char *value,
    size_t value_len,
    bool use_huffman);

/**
 * @brief Write Insert with Literal Name instruction.
 *
 * RFC 9204 Section 4.3.3: Insert a new entry with both name and value
 * provided as string literals.
 *
 * @param stream            Encoder stream
 * @param name              Field name (must not be NULL if name_len > 0)
 * @param name_len          Length of name string
 * @param name_huffman      true to Huffman-encode the name
 * @param value             Field value (must not be NULL if value_len > 0)
 * @param value_len         Length of value string
 * @param value_huffman     true to Huffman-encode the value
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result SocketQPACK_EncoderStream_write_insert_literal (
    SocketQPACK_EncoderStream_T stream,
    const unsigned char *name,
    size_t name_len,
    bool name_huffman,
    const unsigned char *value,
    size_t value_len,
    bool value_huffman);

/**
 * @brief Write Duplicate instruction.
 *
 * RFC 9204 Section 4.3.4: Duplicate an existing entry in the dynamic
 * table. This causes the entry to be re-inserted at the end of the
 * dynamic table without re-transmitting name or value.
 *
 * @param stream    Encoder stream
 * @param rel_index Encoder-relative index of entry to duplicate (0 = most
 * recent)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_INVALID_INDEX if rel_index is invalid,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note The duplicated entry has a new absolute index but same name/value.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_duplicate (SocketQPACK_EncoderStream_T stream,
                                           uint64_t rel_index);

/* ============================================================================
 * BUFFER MANAGEMENT
 * ============================================================================
 */

/**
 * @brief Get accumulated instruction buffer for transmission.
 *
 * Returns a pointer to the internal buffer containing encoder instructions
 * ready to be sent on the QUIC stream. The buffer contains an unframed
 * sequence of encoder instructions.
 *
 * @param stream  Encoder stream
 * @param[out] len Output: buffer length in bytes (set to 0 if stream is NULL)
 * @return Pointer to instruction buffer, or NULL if empty or error
 *
 * @warning The returned pointer is only valid until the next write operation
 *          or reset_buffer call.
 *
 * @since 1.0.0
 */
extern const unsigned char *
SocketQPACK_EncoderStream_get_buffer (SocketQPACK_EncoderStream_T stream,
                                      size_t *len);

/**
 * @brief Reset instruction buffer after transmission.
 *
 * Clears the instruction buffer after successful transmission. Call this
 * after the QUIC stream has acknowledged the data.
 *
 * @param stream Encoder stream
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_EncoderStream_reset_buffer (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Get current buffer usage.
 *
 * @param stream Encoder stream
 * @return Number of bytes currently in the instruction buffer
 *
 * @since 1.0.0
 */
extern size_t
SocketQPACK_EncoderStream_buffer_size (SocketQPACK_EncoderStream_T stream);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Get human-readable string for stream result code.
 *
 * @param result Result code to describe
 * @return Static string describing the result (never NULL)
 *
 * @since 1.0.0
 */
extern const char *
SocketQPACKStream_result_string (SocketQPACKStream_Result result);

/**
 * @brief Convert stream result to HTTP/3 wire error code.
 *
 * RFC 9204 Section 4.2 & 6: Maps stream-level errors to appropriate HTTP/3
 * application error codes for connection termination.
 *
 * Mapping per RFC 9204:
 * - QPACK_STREAM_ERR_CLOSED_CRITICAL -> H3_CLOSED_CRITICAL_STREAM (0x0104)
 *   (Section 4.2: Closure of encoder/decoder stream)
 * - QPACK_STREAM_ERR_ALREADY_INIT -> H3_STREAM_CREATION_ERROR (0x0103)
 *   (Section 4.2: Receipt of second instance of stream type)
 * - Other errors -> QPACK_ENCODER_STREAM_ERROR (0x0201)
 *
 * @param result Stream result code
 * @return HTTP/3 error code (0x0103, 0x0104, or 0x0201), or 0 if not an error
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACKStream_result_to_h3_error (SocketQPACKStream_Result result);

/* ============================================================================
 * INSERT WITH NAME REFERENCE PRIMITIVES (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

/**
 * @brief Decoded Insert with Name Reference instruction.
 *
 * RFC 9204 Section 4.3.2: Represents the decoded form of an insert with
 * name reference instruction.
 */
typedef struct
{
  bool is_static;             /**< True if name references static table */
  uint64_t name_index;        /**< Index into static or dynamic table */
  const unsigned char *value; /**< Value string (points into input buffer) */
  size_t value_len;           /**< Length of value string */
  bool value_huffman;         /**< True if value was Huffman-encoded */
} SocketQPACK_InsertNameRef;

/**
 * @brief Encode Insert with Name Reference instruction to buffer.
 *
 * RFC 9204 Section 4.3.2: Encodes an insert instruction with name reference
 * into the provided output buffer. This is a low-level function for building
 * encoder stream data without using the stream abstraction.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | T |    Name Index (6+)    |
 * +---+---+-----------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param is_static     True to reference static table, false for dynamic
 * @param name_index    Index of entry with name to reference
 * @param value         Value string (may be NULL if value_len == 0)
 * @param value_len     Length of value string
 * @param use_huffman   True to Huffman-encode the value
 * @param[out] bytes_written Number of bytes written to output (must not be
 * NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if name_index is invalid for static
 * table, QPACK_STREAM_ERR_BUFFER_FULL if output buffer is too small
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_encode_insert_nameref (unsigned char *output,
                                   size_t output_size,
                                   bool is_static,
                                   uint64_t name_index,
                                   const unsigned char *value,
                                   size_t value_len,
                                   bool use_huffman,
                                   size_t *bytes_written);

/**
 * @brief Decode Insert with Name Reference instruction from buffer.
 *
 * RFC 9204 Section 4.3.2: Decodes an insert instruction with name reference
 * from the input buffer. The value pointer in the result points into the
 * input buffer (for Huffman-decoded values, decoding is done in-place or
 * to a provided arena).
 *
 * @param input         Input buffer containing the instruction
 * @param input_len     Length of input buffer
 * @param arena         Memory arena for Huffman decoding (must not be NULL)
 * @param[out] result   Decoded instruction (must not be NULL)
 * @param[out] consumed Number of bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if any required parameter is NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if input is incomplete,
 *         QPACK_STREAM_ERR_INTERNAL on decoding error
 *
 * @note The first byte of input must have the top bit set (0x80 mask)
 * @note The value pointer in result is valid until arena is disposed
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_insert_nameref (const unsigned char *input,
                                   size_t input_len,
                                   Arena_T arena,
                                   SocketQPACK_InsertNameRef *result,
                                   size_t *consumed);

/**
 * @brief Validate name reference index for Insert instruction.
 *
 * RFC 9204 Section 4.3.2: Validates that a name index is valid for use
 * in an Insert with Name Reference instruction. For static table references,
 * checks against the static table size (0-98). For dynamic table references,
 * checks against the current insert count and dropped count.
 *
 * @param is_static     True if referencing static table
 * @param name_index    Index to validate
 * @param insert_count  Current Insert Count (only used for dynamic table)
 * @param dropped_count Number of evicted entries (only used for dynamic table)
 * @return QPACK_STREAM_OK if index is valid,
 *         QPACK_STREAM_ERR_INVALID_INDEX if static index >= 99,
 *         QPACK_STREAM_ERR_INVALID_INDEX if dynamic index references future
 * entry, QPACK_STREAM_ERR_INVALID_INDEX if dynamic index references evicted
 * entry
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_validate_nameref_index (bool is_static,
                                    uint64_t name_index,
                                    uint64_t insert_count,
                                    uint64_t dropped_count);

/** @} */

#endif /* SOCKETQPACK_ENCODER_STREAM_INCLUDED */
