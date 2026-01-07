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

/* ============================================================================
 * STREAM CANCELLATION INSTRUCTION DECODING (RFC 9204 Section 4.4.2)
 * ============================================================================
 */

/**
 * @brief Decoded Stream Cancellation instruction result.
 *
 * RFC 9204 Section 4.4.2: Contains the parsed stream ID from a
 * Stream Cancellation instruction.
 */
typedef struct
{
  uint64_t stream_id; /**< The cancelled stream ID */
} SocketQPACK_StreamCancel;

/**
 * @brief Decode Stream Cancellation instruction from input buffer.
 *
 * RFC 9204 Section 4.4.2: Decodes a Stream Cancellation instruction from
 * the decoder stream. The instruction has format:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 |     Stream ID (6+)    |
 * +---+---+-----------------------+
 *
 * @param input      Input buffer containing the instruction
 * @param input_len  Length of input buffer
 * @param[out] result Decoded instruction (must not be NULL)
 * @param[out] consumed Number of bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if any required parameter is NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if input is incomplete,
 *         QPACK_STREAM_ERR_INTERNAL on decoding error
 *
 * @note The first byte of input must have bits 7-6 equal to 01 (0x40 mask)
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_stream_cancel (const unsigned char *input,
                                  size_t input_len,
                                  SocketQPACK_StreamCancel *result,
                                  size_t *consumed);

/**
 * @brief Validate stream ID for Stream Cancellation instruction.
 *
 * RFC 9204 Section 4.4.2: Validates that a stream ID is valid for
 * cancellation. Stream ID 0 is reserved for the connection control stream
 * and should not be cancelled. Also provides a warning if the stream ID
 * is not found in tracking (stale cancellation).
 *
 * @param stream_id  Stream ID to validate
 * @return QPACK_STREAM_OK if valid,
 *         QPACK_STREAM_ERR_INVALID_INDEX if stream_id is 0 (reserved)
 *
 * @note This validation is for basic validity. Stream not found in tracking
 *       is a warning condition, not an error, per the RFC recommendation.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_stream_cancel_validate_id (uint64_t stream_id);

/**
 * @brief Release dynamic table references for a cancelled stream.
 *
 * RFC 9204 Section 4.4.2: When a stream is cancelled, all dynamic table
 * references associated with that stream should be released. This decrements
 * the reference count for each entry referenced by the stream.
 *
 * @param table     Dynamic table (may be NULL if no dynamic table)
 * @param stream_id Stream ID whose references should be released
 * @return QPACK_STREAM_OK on success (including when table is NULL),
 *         QPACK_STREAM_ERR_INTERNAL on reference tracking corruption
 *
 * @note If the stream has no outstanding references (not in tracking),
 *       this function succeeds silently as per RFC recommendation.
 * @note When an entry's reference count reaches 0, it becomes eligible
 *       for eviction on the next table update.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_stream_cancel_release_refs (SocketQPACK_Table_T table,
                                        uint64_t stream_id);

/**
 * @brief Check if a byte is a Stream Cancellation instruction.
 *
 * RFC 9204 Section 4.4.2: Stream Cancellation has bit pattern 01xxxxxx.
 *
 * @param first_byte First byte of the instruction
 * @return true if this is a Stream Cancellation instruction, false otherwise
 *
 * @since 1.0.0
 */
static inline bool
SocketQPACK_is_stream_cancel (unsigned char first_byte)
{
  /* Bit pattern: 01xxxxxx (bits 7-6 = 01) */
  return (first_byte & 0xC0) == QPACK_DINSTR_STREAM_CANCEL_MASK;
}

/* ============================================================================
 * INSERT COUNT INCREMENT PRIMITIVES (RFC 9204 Section 4.4.3)
 * ============================================================================
 */

/**
 * @brief Encode Insert Count Increment instruction to buffer.
 *
 * RFC 9204 Section 4.4.3: Encodes an increment instruction into the provided
 * output buffer. This is a low-level function for building decoder stream
 * data without using the stream abstraction.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 |     Increment (6+)    |
 * +---+---+-----------------------+
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param increment     Number of entries to increment (must be > 0)
 * @param[out] bytes_written Number of bytes written to output (must not be
 * NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if output or bytes_written is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_BUFFER_FULL if output buffer is too small
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_encode_insert_count_inc (unsigned char *output,
                                     size_t output_size,
                                     uint64_t increment,
                                     size_t *bytes_written);

/**
 * @brief Decode Insert Count Increment instruction from buffer.
 *
 * RFC 9204 Section 4.4.3: Decodes an increment instruction from the input
 * buffer. Returns the increment value which should be added to the
 * Known Received Count.
 *
 * @param input         Input buffer containing the instruction
 * @param input_len     Length of input buffer
 * @param[out] increment Decoded increment value (must not be NULL)
 * @param[out] consumed  Number of bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if any required parameter is NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if input is incomplete,
 *         QPACK_STREAM_ERR_INVALID_INDEX if decoded increment is 0,
 *         QPACK_STREAM_ERR_INTERNAL on decoding error
 *
 * @note The first byte of input must have bits 7-6 equal to 00
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_insert_count_inc (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *increment,
                                     size_t *consumed);

/**
 * @brief Apply Insert Count Increment to encoder state.
 *
 * RFC 9204 Section 4.4.3: Updates the Known Received Count based on the
 * received increment. This function is called by the encoder when it
 * receives an Insert Count Increment instruction from the decoder.
 *
 * @param known_received_count Current Known Received Count (updated in-place)
 * @param insert_count         Current Insert Count (total entries sent)
 * @param increment            Increment value from decoder (must be > 0)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if known_received_count is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_INVALID_INDEX if new count would exceed insert_count
 *
 * @note The encoder tracks Known Received Count to know which dynamic table
 *       entries have been acknowledged by the decoder. Entries with absolute
 *       index < Known Received Count are safe to reference.
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_apply_insert_count_inc (uint64_t *known_received_count,
                                    uint64_t insert_count,
                                    uint64_t increment);

/**
 * @brief Validate Insert Count Increment value.
 *
 * RFC 9204 Section 4.4.3: Validates that an increment value is valid:
 * - Increment must be non-zero
 * - Increment must not cause Known Received Count to exceed Insert Count
 *
 * @param known_received_count Current Known Received Count
 * @param insert_count         Current Insert Count (total entries sent)
 * @param increment            Increment value to validate
 * @return QPACK_STREAM_OK if valid,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_INVALID_INDEX if it would exceed insert_count
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_validate_insert_count_inc (uint64_t known_received_count,
                                       uint64_t insert_count,
                                       uint64_t increment);
/** @} */

#endif /* SOCKETQPACK_DECODER_STREAM_INCLUDED */
