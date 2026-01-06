/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression/decompression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * with Known Received Count tracking, and decoder stream instructions.
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
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Configuration Constants
 * ============================================================================
 */

#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

#ifndef SOCKETQPACK_MAX_BLOCKED_STREAMS
#define SOCKETQPACK_MAX_BLOCKED_STREAMS 100
#endif

#define SOCKETQPACK_STATIC_TABLE_SIZE 99
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Exceptions
 * ============================================================================
 */

extern const Except_T SocketQPACK_Error;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

typedef enum
{
  QPACK_OK = 0,
  QPACK_INCOMPLETE,
  QPACK_ERROR,
  QPACK_ERROR_INVALID_INDEX,
  QPACK_ERROR_INTEGER,
  QPACK_ERROR_TABLE_SIZE,
  QPACK_ERROR_STREAM_NOT_FOUND,
  QPACK_ERROR_INVALID_INSTRUCTION
} SocketQPACK_Result;

/* ============================================================================
 * Decoder Stream Instruction Types (RFC 9204 Section 4.4)
 * ============================================================================
 */

typedef enum
{
  QPACK_INSTRUCTION_SECTION_ACK = 0,     /**< Section Acknowledgment (4.4.1) */
  QPACK_INSTRUCTION_STREAM_CANCEL = 1,   /**< Stream Cancellation (4.4.2) */
  QPACK_INSTRUCTION_INSERT_COUNT_INC = 2 /**< Insert Count Increment (4.4.3) */
} SocketQPACK_InstructionType;

/* ============================================================================
 * Types
 * ============================================================================
 */

/**
 * @brief Decoded decoder stream instruction.
 */
typedef struct
{
  SocketQPACK_InstructionType type; /**< Instruction type */
  uint64_t stream_id;               /**< Stream ID (for SECTION_ACK, CANCEL) */
  uint64_t increment; /**< Increment value (for INSERT_COUNT_INC) */
} SocketQPACK_DecoderInstruction_T;

/**
 * @brief Opaque QPACK decoder state type.
 */
typedef struct SocketQPACK_DecoderState *SocketQPACK_DecoderState_T;

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * @brief Encode an integer with a given prefix size.
 *
 * Implements the integer encoding scheme from RFC 9204 Section 4.1.1,
 * which is based on HPACK (RFC 7541 Section 5.1).
 *
 * @param value       Value to encode.
 * @param prefix_bits Number of prefix bits (1-8).
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQPACK_int_encode (uint64_t value,
                                      int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode an integer with a given prefix size.
 *
 * Decodes a variable-length integer from the given buffer according to
 * RFC 9204 Section 4.1.1.
 *
 * @param input       Input buffer.
 * @param input_len   Size of input buffer.
 * @param prefix_bits Number of prefix bits (1-8).
 * @param value       Output: decoded value.
 * @param consumed    Output: bytes consumed.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * Decoder State Management
 * ============================================================================
 */

/**
 * @brief Create a new QPACK decoder state.
 *
 * @param arena Arena for memory allocation.
 *
 * @return New decoder state instance.
 */
extern SocketQPACK_DecoderState_T SocketQPACK_DecoderState_new (Arena_T arena);

/**
 * @brief Free a QPACK decoder state.
 *
 * @param state Pointer to decoder state (set to NULL after).
 */
extern void SocketQPACK_DecoderState_free (SocketQPACK_DecoderState_T *state);

/**
 * @brief Get the current Known Received Count.
 *
 * The Known Received Count (KRC) is the maximum Required Insert Count (RIC)
 * of all acknowledged sections. This value only increases over time.
 *
 * @param state Decoder state.
 *
 * @return Current Known Received Count.
 */
extern uint64_t SocketQPACK_DecoderState_get_known_received_count (
    SocketQPACK_DecoderState_T state);

/**
 * @brief Register a stream section with its Required Insert Count.
 *
 * Call this when sending a header section that references dynamic table
 * entries. The encoder uses this to track which streams have pending
 * acknowledgments.
 *
 * @param state     Decoder state.
 * @param stream_id Stream ID.
 * @param ric       Required Insert Count of the section.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result
SocketQPACK_DecoderState_register_stream (SocketQPACK_DecoderState_T state,
                                          uint64_t stream_id,
                                          uint64_t ric);

/* ============================================================================
 * Section Acknowledgment (RFC 9204 Section 4.4.1)
 * ============================================================================
 */

/**
 * @brief Decode a Section Acknowledgment instruction.
 *
 * Parses a Section Acknowledgment instruction from the decoder stream.
 * This instruction is sent by the decoder to acknowledge receipt of a
 * header section with non-zero Required Insert Count.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 |      Stream ID (7+)       |
 * +---+---------------------------+
 *
 * @param input       Input buffer containing the instruction.
 * @param input_len   Size of input buffer.
 * @param instruction Output: decoded instruction.
 * @param consumed    Output: bytes consumed.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result
SocketQPACK_decode_section_ack (const unsigned char *input,
                                size_t input_len,
                                SocketQPACK_DecoderInstruction_T *instruction,
                                size_t *consumed);

/**
 * @brief Encode a Section Acknowledgment instruction.
 *
 * Encodes a Section Acknowledgment for sending on the decoder stream.
 *
 * @param stream_id   Stream ID to acknowledge.
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQPACK_encode_section_ack (uint64_t stream_id,
                                              unsigned char *output,
                                              size_t output_size);

/**
 * @brief Validate and process a Section Acknowledgment.
 *
 * Validates that the acknowledged stream ID has pending sections with
 * non-zero Required Insert Count, and updates the Known Received Count.
 *
 * @param state       Decoder state.
 * @param instruction Decoded Section Acknowledgment instruction.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_validate_section_ack (
    SocketQPACK_DecoderState_T state,
    const SocketQPACK_DecoderInstruction_T *instruction);

/**
 * @brief Update Known Received Count after successful acknowledgment.
 *
 * Updates the decoder's Known Received Count to the maximum of the current
 * value and the acknowledged section's Required Insert Count.
 *
 * @param state     Decoder state.
 * @param ric       Required Insert Count of acknowledged section.
 */
extern void
SocketQPACK_update_known_received_count (SocketQPACK_DecoderState_T state,
                                         uint64_t ric);

/* ============================================================================
 * Decoder Stream Instruction Parsing
 * ============================================================================
 */

/**
 * @brief Decode a decoder stream instruction.
 *
 * Parses the next instruction from the decoder stream. The instruction
 * type is determined by the first byte:
 *   - 1xxxxxxx: Section Acknowledgment (stream ID with 7-bit prefix)
 *   - 01xxxxxx: Stream Cancellation (stream ID with 6-bit prefix)
 *   - 00xxxxxx: Insert Count Increment (increment with 6-bit prefix)
 *
 * @param input       Input buffer.
 * @param input_len   Size of input buffer.
 * @param instruction Output: decoded instruction.
 * @param consumed    Output: bytes consumed.
 *
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result SocketQPACK_decode_decoder_instruction (
    const unsigned char *input,
    size_t input_len,
    SocketQPACK_DecoderInstruction_T *instruction,
    size_t *consumed);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */
