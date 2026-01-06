/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACKEncoderStream.h
 * @brief QPACK Encoder Stream Infrastructure (RFC 9204 Section 4.2).
 *
 * Implements the encoder stream which carries unframed encoder instructions
 * for QPACK header compression. The encoder stream is a unidirectional stream
 * of type 0x02 used by the encoder to update the decoder about changes to
 * the dynamic table.
 *
 * Thread Safety: Encoder stream instances are NOT thread-safe. One instance
 * per connection recommended.
 *
 * @defgroup qpack_encoder_stream QPACK Encoder Stream Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#ifndef SOCKETQPACKENCODERSTREAM_INCLUDED
#define SOCKETQPACKENCODERSTREAM_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @brief QPACK encoder stream type identifier (RFC 9204 Section 4.2).
 *
 * An encoder stream is a unidirectional stream of type 0x02.
 */
#define QPACK_ENCODER_STREAM_TYPE 0x02

/**
 * @brief Initial encoder stream buffer capacity.
 *
 * Conservative starting size for instruction accumulation. Buffer grows
 * as needed via arena allocation.
 */
#ifndef QPACK_ENCODER_STREAM_INITIAL_CAPACITY
#define QPACK_ENCODER_STREAM_INITIAL_CAPACITY 256
#endif

/**
 * @brief Maximum encoder stream buffer size.
 *
 * Prevents unbounded memory growth from accumulated instructions.
 */
#ifndef QPACK_ENCODER_STREAM_MAX_CAPACITY
#define QPACK_ENCODER_STREAM_MAX_CAPACITY (64 * 1024)
#endif

/**
 * @brief Result codes for QPACK encoder stream operations.
 */
typedef enum
{
  QPACK_ENCODER_STREAM_OK = 0,        /**< Operation succeeded */
  QPACK_ENCODER_STREAM_ERROR,         /**< Generic error */
  QPACK_ENCODER_STREAM_BUFFER_FULL,   /**< Buffer capacity exceeded */
  QPACK_ENCODER_STREAM_INVALID_PARAM, /**< Invalid parameter */
  QPACK_ENCODER_STREAM_ALREADY_INIT,  /**< Stream already initialized */
  QPACK_ENCODER_STREAM_NOT_INIT,      /**< Stream not initialized */
  QPACK_ENCODER_STREAM_CLOSED         /**< Stream closure attempted (error) */
} SocketQPACK_EncoderStream_Result;

/**
 * @brief Exception raised on encoder stream errors.
 */
extern const Except_T SocketQPACK_EncoderStream_Error;

/**
 * @brief Exception for critical stream closure (H3_CLOSED_CRITICAL_STREAM).
 *
 * RFC 9204 Section 4.2: The sender MUST NOT close the encoder stream
 * before the connection closes.
 */
extern const Except_T SocketQPACK_H3_ClosedCriticalStream;

/**
 * @brief Opaque encoder stream type.
 */
typedef struct SocketQPACK_EncoderStream *SocketQPACK_EncoderStream_T;

/**
 * @brief Create a new QPACK encoder stream.
 *
 * Allocates and initializes an encoder stream with the given QUIC stream ID.
 * The stream is marked as initialized and ready to buffer encoder instructions.
 *
 * @param arena     Arena for memory allocation (stream lifetime).
 * @param stream_id QUIC unidirectional stream ID for this encoder stream.
 *
 * @return New encoder stream instance, or NULL on allocation failure.
 *
 * @note RFC 9204 Section 4.2: Each endpoint MUST initiate at most one
 *       encoder stream. Use SocketQPACK_EncoderStream_is_initialized()
 *       to check if a stream already exists for this connection.
 *
 * @threadsafe No
 */
extern SocketQPACK_EncoderStream_T
SocketQPACK_EncoderStream_new (Arena_T arena, uint64_t stream_id);

/**
 * @brief Check if stream is initialized and active.
 *
 * @param stream Encoder stream instance.
 *
 * @return 1 if stream is initialized and open, 0 otherwise.
 */
extern int
SocketQPACK_EncoderStream_is_initialized (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Validate stream type matches encoder stream (0x02).
 *
 * Verifies that a received stream type identifier matches the expected
 * encoder stream type per RFC 9204 Section 4.2.
 *
 * @param stream_type Stream type value to validate.
 *
 * @return 1 if valid (equals QPACK_ENCODER_STREAM_TYPE), 0 otherwise.
 */
extern int SocketQPACK_EncoderStream_validate_type (uint64_t stream_type);

/**
 * @brief Get the QUIC stream ID for this encoder stream.
 *
 * @param stream Encoder stream instance.
 *
 * @return QUIC stream ID, or 0 if stream is NULL.
 */
extern uint64_t
SocketQPACK_EncoderStream_get_stream_id (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Write a Set Dynamic Table Capacity instruction.
 *
 * RFC 9204 Section 4.3.1: Encodes a dynamic table capacity update.
 *
 * Format: 0b001xxxxx (5-bit prefix integer)
 *
 * @param stream   Encoder stream instance.
 * @param capacity New dynamic table capacity.
 *
 * @return QPACK_ENCODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_capacity (SocketQPACK_EncoderStream_T stream,
                                          uint64_t capacity);

/**
 * @brief Write an Insert With Name Reference instruction.
 *
 * RFC 9204 Section 4.3.2: Inserts a header with name from static or
 * dynamic table reference and literal value.
 *
 * Format (static):  0b1xxxxxxx (6-bit prefix index, static bit = 1)
 * Format (dynamic): 0b0xxxxxxx (6-bit prefix index, static bit = 0)
 *
 * @param stream      Encoder stream instance.
 * @param is_static   1 if referencing static table, 0 for dynamic table.
 * @param name_index  Index of name in referenced table.
 * @param value       Header value bytes.
 * @param value_len   Length of header value.
 * @param use_huffman 1 to Huffman-encode value, 0 for literal.
 *
 * @return QPACK_ENCODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_insert_nameref (
    SocketQPACK_EncoderStream_T stream,
    int is_static,
    uint64_t name_index,
    const unsigned char *value,
    size_t value_len,
    int use_huffman);

/**
 * @brief Write an Insert With Literal Name instruction.
 *
 * RFC 9204 Section 4.3.3: Inserts a header with literal name and value.
 *
 * Format: 0b01xxxxxx (5-bit prefix for name length)
 *
 * @param stream           Encoder stream instance.
 * @param name             Header name bytes.
 * @param name_len         Length of header name.
 * @param value            Header value bytes.
 * @param value_len        Length of header value.
 * @param use_huffman_name 1 to Huffman-encode name, 0 for literal.
 * @param use_huffman_value 1 to Huffman-encode value, 0 for literal.
 *
 * @return QPACK_ENCODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_insert_literal (
    SocketQPACK_EncoderStream_T stream,
    const unsigned char *name,
    size_t name_len,
    const unsigned char *value,
    size_t value_len,
    int use_huffman_name,
    int use_huffman_value);

/**
 * @brief Write a Duplicate instruction.
 *
 * RFC 9204 Section 4.3.4: Duplicates an existing dynamic table entry
 * to add it again (refreshing it to the front).
 *
 * Format: 0b000xxxxx (5-bit prefix integer for relative index)
 *
 * @param stream        Encoder stream instance.
 * @param relative_index Relative index of entry to duplicate (0 = newest).
 *
 * @return QPACK_ENCODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_duplicate (SocketQPACK_EncoderStream_T stream,
                                           uint64_t relative_index);

/**
 * @brief Get the instruction buffer for transmission.
 *
 * Returns a pointer to the accumulated encoder instructions. The buffer
 * contents should be sent via QUIC STREAM frames to the peer.
 *
 * @param stream     Encoder stream instance.
 * @param buffer_len Output: length of buffer in bytes.
 *
 * @return Pointer to instruction buffer, or NULL if stream is NULL.
 *
 * @note The returned pointer is valid until the next write operation
 *       or buffer reset.
 */
extern const unsigned char *
SocketQPACK_EncoderStream_get_buffer (SocketQPACK_EncoderStream_T stream,
                                      size_t *buffer_len);

/**
 * @brief Reset the instruction buffer after transmission.
 *
 * Clears the buffer to prepare for accumulating new instructions.
 * Should be called after successfully sending the buffer contents.
 *
 * @param stream Encoder stream instance.
 */
extern void
SocketQPACK_EncoderStream_reset_buffer (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Mark stream as closed (triggers H3_CLOSED_CRITICAL_STREAM error).
 *
 * RFC 9204 Section 4.2: The sender MUST NOT close the encoder stream
 * before the connection closes. Calling this function indicates an
 * error condition.
 *
 * @param stream Encoder stream instance.
 *
 * @return QPACK_ENCODER_STREAM_CLOSED (always).
 *
 * @note This function is provided for error handling; the stream should
 *       never be closed during normal operation.
 */
extern SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_close (SocketQPACK_EncoderStream_T stream);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQPACK_EncoderStream_result_string (
    SocketQPACK_EncoderStream_Result result);

/** @} */

#endif /* SOCKETQPACKENCODERSTREAM_INCLUDED */
