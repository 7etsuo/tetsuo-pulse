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
 * DECODER INSTRUCTION DECODING (RFC 9204 Section 4.4)
 *
 * These functions decode decoder instructions received from the peer's
 * decoder stream. Used by the encoder to process acknowledgments.
 * ============================================================================
 */

/**
 * @brief Decoder instruction type enumeration.
 *
 * Identifies which decoder instruction was parsed from the stream.
 */
typedef enum
{
  QPACK_DINSTR_TYPE_SECTION_ACK,      /**< Section Acknowledgment (4.4.1) */
  QPACK_DINSTR_TYPE_STREAM_CANCEL,    /**< Stream Cancellation (4.4.2) */
  QPACK_DINSTR_TYPE_INSERT_COUNT_INC, /**< Insert Count Increment (4.4.3) */
  QPACK_DINSTR_TYPE_UNKNOWN           /**< Unknown/invalid instruction */
} SocketQPACK_DecoderInstrType;

/**
 * @brief Decoded decoder instruction.
 *
 * Contains the parsed result of a decoder instruction from the stream.
 */
typedef struct
{
  SocketQPACK_DecoderInstrType type; /**< Instruction type */
  uint64_t value;                    /**< Stream ID or increment value */
} SocketQPACK_DecoderInstruction;

/**
 * @brief Identify decoder instruction type from first byte.
 *
 * RFC 9204 Section 4.4: Determines the instruction type by examining
 * the bit pattern of the first byte:
 * - 1xxxxxxx: Section Acknowledgment
 * - 01xxxxxx: Stream Cancellation
 * - 00xxxxxx: Insert Count Increment
 *
 * @param first_byte First byte of the instruction
 * @return Instruction type
 *
 * @since 1.0.0
 */
extern SocketQPACK_DecoderInstrType
SocketQPACK_identify_decoder_instruction (uint8_t first_byte);

/**
 * @brief Decode Section Acknowledgment instruction.
 *
 * RFC 9204 Section 4.4.1: Decodes a Section Acknowledgment from the
 * decoder stream. The stream ID is extracted using a 7-bit prefix integer.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 |      Stream ID (7+)       |
 * +---+---------------------------+
 *
 * @param input      Input buffer containing the instruction
 * @param input_len  Length of input buffer
 * @param[out] stream_id Output: decoded stream ID (must not be NULL)
 * @param[out] consumed  Output: bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if output params are NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if more data needed,
 *         QPACK_STREAM_ERR_INTERNAL on decode error
 *
 * @note First byte must have bit 7 set (0x80 mask) to be valid
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_section_ack (const unsigned char *input,
                                size_t input_len,
                                uint64_t *stream_id,
                                size_t *consumed);

/**
 * @brief Decode Stream Cancellation instruction.
 *
 * RFC 9204 Section 4.4.2: Decodes a Stream Cancellation from the
 * decoder stream. The stream ID is extracted using a 6-bit prefix integer.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 |     Stream ID (6+)    |
 * +---+---+-----------------------+
 *
 * @param input      Input buffer containing the instruction
 * @param input_len  Length of input buffer
 * @param[out] stream_id Output: decoded stream ID (must not be NULL)
 * @param[out] consumed  Output: bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if output params are NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if more data needed,
 *         QPACK_STREAM_ERR_INTERNAL on decode error
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_stream_cancel (const unsigned char *input,
                                  size_t input_len,
                                  uint64_t *stream_id,
                                  size_t *consumed);

/**
 * @brief Validate stream ID for Stream Cancellation instruction.
 *
 * RFC 9204 Section 4.4.2: Validates that a stream ID is valid for
 * cancellation. Stream ID 0 is reserved for the connection control stream
 * and should not be cancelled.
 *
 * @param stream_id  Stream ID to validate
 * @return QPACK_STREAM_OK if valid,
 *         QPACK_STREAM_ERR_INVALID_INDEX if stream_id is 0 (reserved)
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_stream_cancel_validate_id (uint64_t stream_id);

/**
 * @brief Release dynamic table references for a cancelled stream.
 *
 * RFC 9204 Section 4.4.2: When a stream is cancelled, all dynamic table
 * references associated with that stream should be released.
 *
 * @param table     Dynamic table (may be NULL if no dynamic table)
 * @param stream_id Stream ID whose references should be released
 * @return QPACK_STREAM_OK on success (including when table is NULL),
 *         QPACK_STREAM_ERR_INTERNAL on reference tracking corruption
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_stream_cancel_release_refs (SocketQPACK_Table_T table,
                                        uint64_t stream_id);

/**
 * @brief Decode Insert Count Increment instruction.
 *
 * RFC 9204 Section 4.4.3: Decodes an Insert Count Increment from the
 * decoder stream. The increment value is extracted using a 6-bit prefix.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 |     Increment (6+)    |
 * +---+---+-----------------------+
 *
 * @param input      Input buffer containing the instruction
 * @param input_len  Length of input buffer
 * @param[out] increment Output: decoded increment value (must not be NULL)
 * @param[out] consumed  Output: bytes consumed from input (must not be NULL)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if output params are NULL,
 *         QPACK_STREAM_ERR_BUFFER_FULL if more data needed,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_INTERNAL on decode error
 *
 * @note An increment of 0 is an error per RFC 9204 Section 4.4.3
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_insert_count_inc (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *increment,
                                     size_t *consumed);

/**
 * @brief Encode Insert Count Increment instruction to buffer.
 *
 * RFC 9204 Section 4.4.3: Encodes an increment instruction into the provided
 * output buffer.
 *
 * @param output        Output buffer (must not be NULL)
 * @param output_size   Size of output buffer
 * @param increment     Number of entries to increment (must be > 0)
 * @param[out] bytes_written Number of bytes written to output
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
 * @brief Apply Insert Count Increment to encoder state.
 *
 * RFC 9204 Section 4.4.3: Updates the Known Received Count based on the
 * received increment.
 *
 * @param known_received_count Current Known Received Count (updated in-place)
 * @param insert_count         Current Insert Count (total entries sent)
 * @param increment            Increment value from decoder (must be > 0)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if known_received_count is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0,
 *         QPACK_STREAM_ERR_INVALID_INDEX if new count would exceed insert_count
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
 * RFC 9204 Section 4.4.3: Validates that an increment value is valid.
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

/**
 * @brief Decode next decoder instruction from buffer.
 *
 * Parses the next decoder instruction from the input buffer and returns
 * the instruction type and value. This is a convenience function that
 * identifies the instruction type and calls the appropriate decoder.
 *
 * @param input      Input buffer containing instruction(s)
 * @param input_len  Length of input buffer
 * @param[out] instr Output: decoded instruction (must not be NULL)
 * @param[out] consumed Output: bytes consumed (must not be NULL)
 * @return QPACK_STREAM_OK on success, error code on failure
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_decode_decoder_instruction (const unsigned char *input,
                                        size_t input_len,
                                        SocketQPACK_DecoderInstruction *instr,
                                        size_t *consumed);

/* ============================================================================
 * KNOWN RECEIVED COUNT MANAGEMENT (RFC 9204 Section 3.3)
 *
 * Tracks the encoder's view of which dynamic table entries the decoder
 * has acknowledged receiving.
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK acknowledgment state.
 *
 * Tracks Known Received Count and pending section acknowledgments
 * at the encoder side.
 */
typedef struct SocketQPACK_AckState *SocketQPACK_AckState_T;

/**
 * @brief Create a new QPACK acknowledgment state tracker.
 *
 * @param arena Memory arena for allocations (must not be NULL)
 * @return New acknowledgment state, or NULL on allocation failure
 *
 * @since 1.0.0
 */
extern SocketQPACK_AckState_T SocketQPACK_AckState_new (Arena_T arena);

/**
 * @brief Register a field section that needs acknowledgment.
 *
 * Called by the encoder when sending a field section that references
 * dynamic table entries. The encoder tracks the Required Insert Count
 * for each stream to update Known Received Count on acknowledgment.
 *
 * @param state     Acknowledgment state
 * @param stream_id Stream ID carrying the field section
 * @param required_insert_count Required Insert Count for this section
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if state is NULL
 *
 * @note Only sections with RIC > 0 should be registered
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_AckState_register_section (SocketQPACK_AckState_T state,
                                       uint64_t stream_id,
                                       uint64_t required_insert_count);

/**
 * @brief Process Section Acknowledgment from decoder.
 *
 * RFC 9204 Section 4.4.1: Updates the Known Received Count based on
 * the acknowledged section.
 *
 * @param state     Acknowledgment state
 * @param stream_id Stream ID from Section Acknowledgment
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if state is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if stream has no pending RIC
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_AckState_process_section_ack (SocketQPACK_AckState_T state,
                                          uint64_t stream_id);

/**
 * @brief Process Stream Cancellation from decoder.
 *
 * RFC 9204 Section 4.4.2: Removes the stream from pending acknowledgments
 * without updating Known Received Count.
 *
 * @param state     Acknowledgment state
 * @param stream_id Stream ID from Stream Cancellation
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if state is NULL
 *
 * @note Cancelling an unknown stream is not an error (idempotent)
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_AckState_process_stream_cancel (SocketQPACK_AckState_T state,
                                            uint64_t stream_id);

/**
 * @brief Process Insert Count Increment from decoder.
 *
 * RFC 9204 Section 4.4.3: Increases the Known Received Count by the
 * specified increment value.
 *
 * @param state     Acknowledgment state
 * @param increment Increment value (must be > 0)
 * @return QPACK_STREAM_OK on success,
 *         QPACK_STREAM_ERR_NULL_PARAM if state is NULL,
 *         QPACK_STREAM_ERR_INVALID_INDEX if increment is 0
 *
 * @since 1.0.0
 */
extern SocketQPACKStream_Result
SocketQPACK_AckState_process_insert_count_inc (SocketQPACK_AckState_T state,
                                               uint64_t increment);

/**
 * @brief Get the current Known Received Count.
 *
 * RFC 9204 Section 3.3: Returns the maximum insert count that has been
 * acknowledged by the decoder.
 *
 * @param state Acknowledgment state
 * @return Current Known Received Count, or 0 if state is NULL
 *
 * @since 1.0.0
 */
extern uint64_t
SocketQPACK_AckState_get_known_received_count (SocketQPACK_AckState_T state);

/**
 * @brief Check if an entry can be safely evicted.
 *
 * An entry can be evicted if its absolute index is less than the
 * Known Received Count.
 *
 * @param state     Acknowledgment state
 * @param abs_index Absolute index of entry to check
 * @return true if entry can be safely evicted, false otherwise
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_AckState_can_evict (SocketQPACK_AckState_T state,
                                            uint64_t abs_index);
/** @} */

#endif /* SOCKETQPACK_DECODER_STREAM_INCLUDED */
