/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACKDecoderStream.h
 * @brief QPACK Decoder Stream Infrastructure (RFC 9204 Section 4.2).
 *
 * Implements the decoder stream for QPACK, which carries decoder instructions
 * from decoder to encoder. The decoder stream is a unidirectional stream of
 * type 0x03 that carries an unframed sequence of decoder instructions.
 *
 * Decoder Instructions (RFC 9204 Section 4.4):
 * - Section Acknowledgment (Section 4.4.1)
 * - Stream Cancellation (Section 4.4.2)
 * - Insert Count Increment (Section 4.4.3)
 *
 * Thread Safety: Decoder stream instances are NOT thread-safe. One instance
 * per connection recommended.
 *
 * @defgroup qpack_decoder_stream QPACK Decoder Stream
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#ifndef SOCKETQPACK_DECODER_STREAM_INCLUDED
#define SOCKETQPACK_DECODER_STREAM_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKEncoderStream.h" /* For SocketQPACKStream_Result */

/* ============================================================================
 * DECODER INSTRUCTION BIT PATTERNS (RFC 9204 Section 4.4)
 * ============================================================================
 */

/**
 * @brief Section Acknowledgment instruction prefix.
 *
 * RFC 9204 Section 4.4.1: Bit pattern 1xxxxxxx (1-bit prefix, 7-bit stream ID).
 */
#define QPACK_DINSTR_SECTION_ACK_MASK 0x80
#define QPACK_DINSTR_SECTION_ACK_PREFIX 7

/**
 * @brief Stream Cancellation instruction prefix.
 *
 * RFC 9204 Section 4.4.2: Bit pattern 01xxxxxx (2-bit prefix, 6-bit stream ID).
 */
#define QPACK_DINSTR_STREAM_CANCEL_MASK 0x40
#define QPACK_DINSTR_STREAM_CANCEL_PREFIX 6

/**
 * @brief Insert Count Increment instruction prefix.
 *
 * RFC 9204 Section 4.4.3: Bit pattern 00xxxxxx (2-bit prefix, 6-bit increment).
 */
#define QPACK_DINSTR_INSERT_COUNT_INC_MASK 0x00
#define QPACK_DINSTR_INSERT_COUNT_INC_PREFIX 6

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

/**
 * @brief Default decoder stream buffer size.
 *
 * Pre-allocated buffer for decoder instructions. Grows as needed.
 */
#ifndef QPACK_DECODER_STREAM_DEFAULT_BUFSIZE
#define QPACK_DECODER_STREAM_DEFAULT_BUFSIZE 256
#endif

/**
 * @brief Maximum decoder stream buffer size.
 *
 * Limit to prevent unbounded memory growth.
 */
#ifndef QPACK_DECODER_STREAM_MAX_BUFSIZE
#define QPACK_DECODER_STREAM_MAX_BUFSIZE (64 * 1024)
#endif

/* ============================================================================
 * OPAQUE TYPE
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK decoder stream.
 *
 * Manages decoder stream state and instruction buffer.
 */
typedef struct SocketQPACK_DecoderStream *SocketQPACK_DecoderStream_T;

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Create a new QPACK decoder stream.
 *
 * Creates a decoder stream with the specified stream ID. The stream is
 * initially in an uninitialized state and must be initialized before use.
 *
 * @param arena     Memory arena for allocations (must not be NULL)
 * @param stream_id QUIC unidirectional stream ID for this decoder stream
 * @return New decoder stream instance, or NULL on allocation failure
 *
 * @note The stream_id should be a client-initiated unidirectional stream
 *       (4*N+2 for client, 4*N+3 for server in QUIC terminology).
 *
 * @since 1.0.0
 */
extern SocketQPACK_DecoderStream_T
SocketQPACK_DecoderStream_new (Arena_T arena, uint64_t stream_id);

/**
 * @brief Initialize decoder stream for sending.
 *
 * Marks the stream as initialized and ready to send decoder instructions.
 * Each endpoint MUST initiate at most one decoder stream per direction.
 *
 * @param stream Decoder stream to initialize
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_ALREADY_INIT if already initialized
 *
 * @note RFC 9204 Section 4.2: The decoder stream SHOULD be established
 *       early in the connection.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_init (SocketQPACK_DecoderStream_T stream);

/**
 * @brief Check if stream type matches decoder stream.
 *
 * Validates that a received stream type byte equals QPACK_DECODER_STREAM_TYPE.
 *
 * @param type_byte Stream type byte received from peer
 * @return QPACK_STREAM_OK if type is 0x03,
 *         QPACK_STREAM_ERR_INVALID_TYPE otherwise
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_validate_type (uint8_t type_byte);

/**
 * @brief Validate that a stream ID represents the decoder stream.
 *
 * Verifies that a stream ID matches this decoder stream's ID.
 * Used to validate incoming stream data.
 *
 * @param stream    Decoder stream
 * @param stream_id Stream ID to validate
 * @return QPACK_STREAM_OK if stream_id matches,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_INVALID_TYPE if stream_id doesn't match
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_validate_id (SocketQPACK_DecoderStream_T stream,
                                       uint64_t stream_id);

/**
 * @brief Check if decoder stream is initialized.
 *
 * @param stream Decoder stream to check
 * @return true if initialized and ready for instructions, false otherwise
 *
 * @since 1.0.0
 */
extern bool
SocketQPACK_DecoderStream_is_open (SocketQPACK_DecoderStream_T stream);

/**
 * @brief Get the stream ID.
 *
 * @param stream Decoder stream
 * @return Stream ID, or 0 if stream is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_DecoderStream_get_id (SocketQPACK_DecoderStream_T stream);

/* ============================================================================
 * DECODER INSTRUCTIONS (RFC 9204 Section 4.4)
 * ============================================================================
 */

/**
 * @brief Write Section Acknowledgment instruction.
 *
 * RFC 9204 Section 4.4.1: After processing an encoded field section whose
 * Required Insert Count is not zero, the decoder emits a Section Acknowledgment
 * instruction. This signals that all dynamic table references in the field
 * section have been processed.
 *
 * @param stream    Decoder stream
 * @param stream_id Stream ID of the field section being acknowledged
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note This allows the encoder to safely evict entries from the dynamic table.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_write_section_ack (SocketQPACK_DecoderStream_T stream,
                                             uint64_t stream_id);

/**
 * @brief Write Stream Cancellation instruction.
 *
 * RFC 9204 Section 4.4.2: When a stream is reset or reading is abandoned,
 * the decoder emits a Stream Cancellation instruction. This indicates that
 * the field section(s) on that stream will not be processed.
 *
 * @param stream    Decoder stream
 * @param stream_id Stream ID being cancelled
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note This allows the encoder to know that pending references will never
 *       be acknowledged.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result SocketQPACK_DecoderStream_write_stream_cancel (
    SocketQPACK_DecoderStream_T stream, uint64_t stream_id);

/**
 * @brief Write Insert Count Increment instruction.
 *
 * RFC 9204 Section 4.4.3: The decoder informs the encoder that it has
 * received and processed entries added to the dynamic table. This increases
 * the Known Received Count at the encoder.
 *
 * @param stream    Decoder stream
 * @param increment Number of entries to increment (must be > 0)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL,
 *         QPACK_STREAM_ERR_NOT_INIT if stream not initialized,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_BUFFER_FULL if buffer cannot be grown
 *
 * @note An increment of 0 is an error per RFC 9204 Section 4.4.3.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_write_insert_count_inc (
    SocketQPACK_DecoderStream_T stream, uint64_t increment);

/* ============================================================================
 * BUFFER MANAGEMENT
 * ============================================================================
 */

/**
 * @brief Get accumulated instruction buffer for transmission.
 *
 * Returns a pointer to the internal buffer containing decoder instructions
 * ready to be sent on the QUIC stream. The buffer contains an unframed
 * sequence of decoder instructions.
 *
 * @param stream  Decoder stream
 * @param[out] len Output: buffer length in bytes (set to 0 if stream is NULL)
 * @return Pointer to instruction buffer, or NULL if empty or error
 *
 * @warning The returned pointer is only valid until the next write operation
 *          or reset_buffer call.
 *
 * @since 1.0.0
 */
extern const unsigned char *
SocketQPACK_DecoderStream_get_buffer (SocketQPACK_DecoderStream_T stream,
                                      size_t *len);

/**
 * @brief Reset instruction buffer after transmission.
 *
 * Clears the instruction buffer after successful transmission. Call this
 * after the QUIC stream has acknowledged the data.
 *
 * @param stream Decoder stream
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if stream is NULL
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_DecoderStream_reset_buffer (SocketQPACK_DecoderStream_T stream);

/**
 * @brief Get current buffer usage.
 *
 * @param stream Decoder stream
 * @return Number of bytes currently in the instruction buffer
 *
 * @since 1.0.0
 */
extern size_t
SocketQPACK_DecoderStream_buffer_size (SocketQPACK_DecoderStream_T stream);

/** @} */

#endif /* SOCKETQPACK_DECODER_STREAM_INCLUDED */
