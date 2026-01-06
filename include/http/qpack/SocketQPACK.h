/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.h
 * @brief QPACK header compression for HTTP/3 (RFC 9204).
 *
 * Implements QPACK algorithm with static table (99 entries), dynamic table
 * (FIFO eviction), and encoder/decoder instructions. Provides decoder stream
 * handling for Insert Count Increment, Section Acknowledgment, and Stream
 * Cancellation instructions.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended.
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

/**
 * @brief Default QPACK dynamic table size (RFC 9204 Section 3.2).
 */
#ifndef SOCKETQPACK_DEFAULT_TABLE_SIZE
#define SOCKETQPACK_DEFAULT_TABLE_SIZE 4096
#endif

/**
 * @brief Maximum QPACK dynamic table size.
 */
#ifndef SOCKETQPACK_MAX_TABLE_SIZE
#define SOCKETQPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum blocked streams (RFC 9204 Section 3.2.2).
 */
#ifndef SOCKETQPACK_MAX_BLOCKED_STREAMS
#define SOCKETQPACK_MAX_BLOCKED_STREAMS 100
#endif

/**
 * @brief QPACK static table size (RFC 9204 Appendix A).
 */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/**
 * @brief Entry overhead for dynamic table (RFC 9204 Section 3.2.1).
 */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/**
 * @brief Insert Count Increment instruction prefix bits (RFC 9204 Section
 * 4.4.3).
 */
#define SOCKETQPACK_INSERT_COUNT_INC_PREFIX 6

/**
 * @brief Insert Count Increment instruction pattern (RFC 9204 Section 4.4.3).
 */
#define SOCKETQPACK_INSERT_COUNT_INC_PATTERN 0x00

/**
 * @brief Insert Count Increment instruction mask.
 */
#define SOCKETQPACK_INSERT_COUNT_INC_MASK 0xC0

/**
 * @brief Exception type for QPACK errors.
 */
extern const Except_T SocketQPACK_Error;

/**
 * @brief QPACK operation result codes.
 */
typedef enum
{
  QPACK_OK = 0,                     /**< Success */
  QPACK_INCOMPLETE,                 /**< Need more data */
  QPACK_ERROR,                      /**< Generic error */
  QPACK_DECODER_STREAM_ERROR,       /**< Decoder stream protocol error */
  QPACK_ENCODER_STREAM_ERROR,       /**< Encoder stream protocol error */
  QPACK_DECOMPRESSION_FAILED,       /**< Header decompression failed */
  QPACK_ERROR_INVALID_INCREMENT,    /**< Increment value is zero or invalid */
  QPACK_ERROR_INCREMENT_OVERFLOW,   /**< Increment exceeds allowed range */
  QPACK_ERROR_INTEGER,              /**< Integer encoding/decoding error */
  QPACK_ERROR_TABLE_SIZE,           /**< Dynamic table size error */
} SocketQPACK_Result;

/**
 * @brief QPACK header field.
 */
typedef struct
{
  const char *name;   /**< Header name */
  size_t name_len;    /**< Header name length */
  const char *value;  /**< Header value */
  size_t value_len;   /**< Header value length */
  int never_index;    /**< Never index flag */
} SocketQPACK_Header;

/**
 * @brief Insert Count Increment instruction data (RFC 9204 Section 4.4.3).
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 |     Increment (6+)    |
 * +---+---+-----------------------+
 *
 * Pattern: 00xxxxxx (first 2 bits are 0)
 * Prefix length: 6 bits
 * Integer encoding: RFC 7541 Section 5.1 (variable-length)
 */
typedef struct
{
  size_t increment; /**< Known Received Count increment value (must be > 0) */
} SocketQPACK_InsertCountInc_T;

/**
 * @brief Opaque QPACK decoder type.
 */
typedef struct SocketQPACK_Decoder *SocketQPACK_Decoder_T;

/**
 * @brief QPACK decoder state.
 */
struct SocketQPACK_Decoder
{
  size_t known_received_count;       /**< Tracks received Insert Count
                                        Increments (RFC 9204 Section 2.1.4) */
  size_t dynamic_table_insert_count; /**< Total insertions sent by encoder */
  size_t max_table_capacity;         /**< Maximum dynamic table capacity */
  size_t current_table_capacity;     /**< Current dynamic table capacity */
  size_t max_blocked_streams;        /**< Maximum blocked streams */
  Arena_T arena;                     /**< Memory arena */
};

/**
 * @brief QPACK decoder configuration.
 */
typedef struct
{
  size_t max_table_capacity;   /**< Maximum dynamic table capacity */
  size_t max_blocked_streams;  /**< Maximum blocked streams */
} SocketQPACK_DecoderConfig;

/**
 * @brief Initialize decoder configuration with defaults.
 *
 * @param config  Configuration structure to initialize.
 */
extern void
SocketQPACK_decoder_config_defaults (SocketQPACK_DecoderConfig *config);

/**
 * @brief Create a new QPACK decoder.
 *
 * @param config  Decoder configuration (NULL for defaults).
 * @param arena   Memory arena for allocations.
 * @return New decoder instance.
 */
extern SocketQPACK_Decoder_T
SocketQPACK_Decoder_new (const SocketQPACK_DecoderConfig *config,
                         Arena_T arena);

/**
 * @brief Free a QPACK decoder.
 *
 * @param decoder  Pointer to decoder (set to NULL after).
 */
extern void SocketQPACK_Decoder_free (SocketQPACK_Decoder_T *decoder);

/**
 * @brief Get the current known received count.
 *
 * @param decoder  Decoder instance.
 * @return Current known received count.
 */
extern size_t
SocketQPACK_Decoder_get_known_received_count (SocketQPACK_Decoder_T decoder);

/**
 * @brief Set the dynamic table insert count (encoder's count).
 *
 * This should be called as the encoder inserts entries into the dynamic table.
 *
 * @param decoder  Decoder instance.
 * @param count    Total insert count from encoder.
 */
extern void
SocketQPACK_Decoder_set_insert_count (SocketQPACK_Decoder_T decoder,
                                      size_t count);

/* ============================================================================
 * Insert Count Increment Instruction (RFC 9204 Section 4.4.3)
 * ============================================================================
 */

/**
 * @brief Encode an Insert Count Increment instruction.
 *
 * Encodes the increment value into wire format for the decoder stream.
 *
 * Wire format (RFC 9204 Section 4.4.3):
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 |     Increment (6+)    |
 * +---+---+-----------------------+
 *
 * @param increment    Increment value (MUST be > 0).
 * @param output       Output buffer.
 * @param output_size  Output buffer size.
 * @return Number of bytes written, or -1 on error.
 */
extern ssize_t SocketQPACK_encode_insert_count_inc (size_t increment,
                                                    unsigned char *output,
                                                    size_t output_size);

/**
 * @brief Decode an Insert Count Increment instruction.
 *
 * Decodes wire format into an increment value. Does not update decoder state.
 *
 * @param input       Input buffer (starting at instruction byte).
 * @param input_len   Input buffer length.
 * @param increment   Output increment value.
 * @param consumed    Output bytes consumed.
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result
SocketQPACK_decode_insert_count_inc (const unsigned char *input,
                                     size_t input_len,
                                     size_t *increment,
                                     size_t *consumed);

/**
 * @brief Apply an Insert Count Increment to decoder state.
 *
 * Updates known_received_count in decoder state. Validates:
 * - Increment must be > 0
 * - known_received_count + increment must not exceed dynamic_table_insert_count
 *
 * @param decoder    Decoder instance.
 * @param increment  Increment value (from decode_insert_count_inc).
 * @return QPACK_OK on success, QPACK_DECODER_STREAM_ERROR on validation
 * failure.
 */
extern SocketQPACK_Result
SocketQPACK_Decoder_apply_increment (SocketQPACK_Decoder_T decoder,
                                     size_t increment);

/**
 * @brief Process a full Insert Count Increment instruction on decoder stream.
 *
 * Convenience function that decodes and applies in one step. Equivalent to:
 *   1. SocketQPACK_decode_insert_count_inc()
 *   2. SocketQPACK_Decoder_apply_increment()
 *
 * @param decoder    Decoder instance.
 * @param input      Input buffer (starting at instruction byte).
 * @param input_len  Input buffer length.
 * @param consumed   Output bytes consumed.
 * @return QPACK_OK on success, error code otherwise.
 */
extern SocketQPACK_Result
SocketQPACK_Decoder_process_insert_count_inc (SocketQPACK_Decoder_T decoder,
                                              const unsigned char *input,
                                              size_t input_len,
                                              size_t *consumed);

/**
 * @brief Check if a byte is an Insert Count Increment instruction.
 *
 * @param byte  First byte of instruction.
 * @return Non-zero if this is an Insert Count Increment instruction.
 */
static inline int
SocketQPACK_is_insert_count_inc (unsigned char byte)
{
  return (byte & SOCKETQPACK_INSERT_COUNT_INC_MASK)
         == SOCKETQPACK_INSERT_COUNT_INC_PATTERN;
}

/**
 * @brief Get string description of result code.
 *
 * @param result  Result code.
 * @return Human-readable string.
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */
