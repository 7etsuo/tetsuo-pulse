/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACKDecoderStream.h
 * @brief QPACK Decoder Stream Infrastructure (RFC 9204 Section 4.2).
 *
 * Implements the decoder stream for QPACK header compression in HTTP/3.
 * The decoder stream is a unidirectional stream (type 0x03) used to send:
 *   - Section Acknowledgments
 *   - Stream Cancellations
 *   - Insert Count Increments
 *
 * Only one decoder stream is allowed per QPACK connection. Closure of the
 * decoder stream MUST be treated as a connection error of type
 * H3_CLOSED_CRITICAL_STREAM.
 *
 * Thread Safety: Decoder stream instances are NOT thread-safe.
 * Use external synchronization when sharing across threads.
 *
 * @defgroup qpack_decoder_stream QPACK Decoder Stream Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#ifndef SOCKETQPACKDECODERSTREAM_INCLUDED
#define SOCKETQPACKDECODERSTREAM_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Constants (RFC 9204 Section 4.2)
 * ============================================================================
 */

/**
 * @brief QPACK decoder stream type identifier.
 *
 * HTTP/3 unidirectional stream types use the lower 2 bits of stream ID.
 * The decoder stream is identified by type 0x03.
 */
#define QPACK_DECODER_STREAM_TYPE 0x03

/**
 * @brief Instruction bit patterns for decoder stream (RFC 9204 Section 4.4).
 *
 * Section Acknowledgment:     1xxxxxxx (prefix 7 bits)
 * Stream Cancellation:        01xxxxxx (prefix 6 bits)
 * Insert Count Increment:     00xxxxxx (prefix 6 bits)
 */
#define QPACK_INSTR_SECTION_ACK_PATTERN 0x80
#define QPACK_INSTR_SECTION_ACK_MASK 0x80
#define QPACK_INSTR_SECTION_ACK_PREFIX 7

#define QPACK_INSTR_STREAM_CANCEL_PATTERN 0x40
#define QPACK_INSTR_STREAM_CANCEL_MASK 0xC0
#define QPACK_INSTR_STREAM_CANCEL_PREFIX 6

#define QPACK_INSTR_INSERT_COUNT_INC_PATTERN 0x00
#define QPACK_INSTR_INSERT_COUNT_INC_MASK 0xC0
#define QPACK_INSTR_INSERT_COUNT_INC_PREFIX 6

/**
 * @brief Default send buffer size for decoder stream instructions.
 */
#define QPACK_DECODER_STREAM_DEFAULT_BUFFER_SIZE 4096

/* ============================================================================
 * Data Structures
 * ============================================================================
 */

/**
 * @brief Decoder stream states.
 *
 * Tracks the lifecycle of the decoder stream.
 */
typedef enum
{
  QPACK_DECODER_STREAM_STATE_IDLE = 0, /**< Not yet opened */
  QPACK_DECODER_STREAM_STATE_OPEN,     /**< Stream is open and active */
  QPACK_DECODER_STREAM_STATE_CLOSED    /**< Stream has been closed (error) */
} SocketQPACKDecoderStreamState;

/**
 * @brief Result codes for decoder stream operations.
 */
typedef enum
{
  QPACK_DECODER_STREAM_OK = 0,              /**< Operation succeeded */
  QPACK_DECODER_STREAM_ERROR_NULL,          /**< NULL pointer argument */
  QPACK_DECODER_STREAM_ERROR_INVALID_STATE, /**< Invalid stream state */
  QPACK_DECODER_STREAM_ERROR_BUFFER_FULL,   /**< Send buffer is full */
  QPACK_DECODER_STREAM_ERROR_DUPLICATE,     /**< Duplicate decoder stream */
  QPACK_DECODER_STREAM_ERROR_CLOSED,        /**< Stream unexpectedly closed */
  QPACK_DECODER_STREAM_ERROR_INVALID_TYPE,  /**< Invalid stream type */
  QPACK_DECODER_STREAM_ERROR_ENCODE         /**< Encoding error */
} SocketQPACKDecoderStream_Result;

/**
 * @brief Opaque decoder stream handle.
 */
typedef struct SocketQPACKDecoderStream *SocketQPACKDecoderStream_T;

/**
 * @brief QPACK Decoder Stream structure.
 *
 * Manages the state and send buffer for a QPACK decoder stream.
 */
struct SocketQPACKDecoderStream
{
  Arena_T arena; /**< Memory arena for allocations */

  uint64_t stream_id;                  /**< Unidirectional stream ID */
  SocketQPACKDecoderStreamState state; /**< Current stream state */

  /* Send buffer for batching instructions */
  unsigned char *send_buffer; /**< Instruction output buffer */
  size_t send_buffer_size;    /**< Total buffer capacity */
  size_t send_buffer_used;    /**< Bytes currently in buffer */

  /* Tracking counters */
  uint64_t max_acknowledged_section_id; /**< Highest acknowledged section */
  uint64_t known_received_count;        /**< Insert count known by encoder */
};

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new decoder stream.
 *
 * Allocates and initializes a decoder stream structure from the given arena.
 *
 * @param arena       Memory arena for allocation.
 * @param buffer_size Size of send buffer (0 for default).
 *
 * @return New decoder stream handle, or NULL on error.
 */
extern SocketQPACKDecoderStream_T
SocketQPACKDecoderStream_new (Arena_T arena, size_t buffer_size);

/**
 * @brief Initialize decoder stream with stream ID.
 *
 * Sets the stream ID and transitions to OPEN state.
 * The stream ID must be for a decoder stream type (0x03).
 *
 * @param stream    Decoder stream handle.
 * @param stream_id Unidirectional stream ID.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_open (SocketQPACKDecoderStream_T stream,
                               uint64_t stream_id);

/**
 * @brief Close the decoder stream.
 *
 * Transitions to CLOSED state. Further operations will fail.
 *
 * @param stream Decoder stream handle.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_close (SocketQPACKDecoderStream_T stream);

/**
 * @brief Reset the decoder stream for reuse.
 *
 * Clears send buffer and resets counters while preserving allocation.
 *
 * @param stream Decoder stream handle.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_reset (SocketQPACKDecoderStream_T stream);

/* ============================================================================
 * Instruction Functions (RFC 9204 Section 4.4)
 * ============================================================================
 */

/**
 * @brief Write Section Acknowledgment instruction.
 *
 * Acknowledges processing of a header block on the specified stream.
 * Format: 1xxxxxxx [encoded stream_id]
 *
 * @param stream           Decoder stream handle.
 * @param request_stream_id Stream ID of the acknowledged section.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_section_ack (SocketQPACKDecoderStream_T stream,
                                            uint64_t request_stream_id);

/**
 * @brief Write Stream Cancellation instruction.
 *
 * Signals that all references to the dynamic table for a stream are done.
 * Format: 01xxxxxx [encoded stream_id]
 *
 * @param stream           Decoder stream handle.
 * @param request_stream_id Stream ID being cancelled.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_stream_cancel (SocketQPACKDecoderStream_T stream,
                                              uint64_t request_stream_id);

/**
 * @brief Write Insert Count Increment instruction.
 *
 * Increases the Known Received Count at the encoder.
 * Format: 00xxxxxx [encoded increment]
 *
 * @param stream    Decoder stream handle.
 * @param increment Number of inserts to acknowledge.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_insert_count_inc (
    SocketQPACKDecoderStream_T stream, uint64_t increment);

/* ============================================================================
 * Buffer Management Functions
 * ============================================================================
 */

/**
 * @brief Get pending data from send buffer.
 *
 * Returns pointer to data waiting to be sent on the stream.
 *
 * @param stream  Decoder stream handle.
 * @param[out] len Length of pending data.
 *
 * @return Pointer to pending data, or NULL if none/error.
 */
extern const unsigned char *
SocketQPACKDecoderStream_get_pending (SocketQPACKDecoderStream_T stream,
                                      size_t *len);

/**
 * @brief Mark data as sent.
 *
 * Removes the specified number of bytes from the send buffer.
 *
 * @param stream Decoder stream handle.
 * @param len    Number of bytes sent.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_mark_sent (SocketQPACKDecoderStream_T stream,
                                    size_t len);

/**
 * @brief Clear the send buffer.
 *
 * Discards all pending instructions.
 *
 * @param stream Decoder stream handle.
 *
 * @return QPACK_DECODER_STREAM_OK on success, error code otherwise.
 */
extern SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_clear_buffer (SocketQPACKDecoderStream_T stream);

/**
 * @brief Get available space in send buffer.
 *
 * @param stream Decoder stream handle.
 *
 * @return Available bytes in buffer, or 0 on error.
 */
extern size_t
SocketQPACKDecoderStream_buffer_available (SocketQPACKDecoderStream_T stream);

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

/**
 * @brief Get current stream state.
 *
 * @param stream Decoder stream handle.
 *
 * @return Current state, or IDLE if stream is NULL.
 */
extern SocketQPACKDecoderStreamState
SocketQPACKDecoderStream_get_state (SocketQPACKDecoderStream_T stream);

/**
 * @brief Get stream ID.
 *
 * @param stream Decoder stream handle.
 *
 * @return Stream ID, or 0 if not open or NULL.
 */
extern uint64_t
SocketQPACKDecoderStream_get_stream_id (SocketQPACKDecoderStream_T stream);

/**
 * @brief Check if stream is open.
 *
 * @param stream Decoder stream handle.
 *
 * @return 1 if open, 0 otherwise.
 */
extern int SocketQPACKDecoderStream_is_open (SocketQPACKDecoderStream_T stream);

/**
 * @brief Get Known Received Count.
 *
 * Returns the insert count that has been acknowledged to the encoder.
 *
 * @param stream Decoder stream handle.
 *
 * @return Known received count, or 0 on error.
 */
extern uint64_t SocketQPACKDecoderStream_get_known_received_count (
    SocketQPACKDecoderStream_T stream);

/* ============================================================================
 * Validation Functions
 * ============================================================================
 */

/**
 * @brief Validate stream ID is for decoder stream type.
 *
 * Checks that the stream ID has the correct type bits for a decoder stream.
 * HTTP/3 unidirectional stream type is embedded in the stream ID.
 *
 * @param stream_id Stream ID to validate.
 *
 * @return 1 if valid decoder stream ID, 0 otherwise.
 */
extern int SocketQPACKDecoderStream_validate_stream_type (uint64_t stream_id);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get string representation of stream state.
 *
 * @param state Stream state.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQPACKDecoderStream_state_string (SocketQPACKDecoderStreamState state);

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code.
 *
 * @return Human-readable string.
 */
extern const char *
SocketQPACKDecoderStream_result_string (SocketQPACKDecoderStream_Result result);

/** @} */

#endif /* SOCKETQPACKDECODERSTREAM_INCLUDED */
