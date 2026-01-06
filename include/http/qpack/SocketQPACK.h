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
 * with absolute indexing, and three index conversion schemes as per RFC 9204
 * Sections 3.2.4-3.2.6.
 *
 * Known Received Count (KRC) - RFC 9204 Section 2.1.4:
 * The encoder tracks which dynamic table entries have been acknowledged by
 * the decoder. Only entries with absolute index < KRC can be safely referenced
 * in non-blocking representations.
 *
 * Thread Safety: Encoder/decoder instances are NOT thread-safe. One instance
 * per connection/thread recommended. Static functions are thread-safe.
 *
 * @since 1.0.0
 * @defgroup qpack QPACK Header Compression Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9204
 */

#ifndef SOCKETQPACK_INCLUDED
#define SOCKETQPACK_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * COMPILER ATTRIBUTES
 * ============================================================================
 */

#if defined(__GNUC__) || defined(__clang__)
#define QPACK_NONNULL(...) __attribute__ ((nonnull (__VA_ARGS__)))
#define QPACK_WARN_UNUSED __attribute__ ((warn_unused_result))
#else
#define QPACK_NONNULL(...)
#define QPACK_WARN_UNUSED
#endif

/* ============================================================================
 * CONFIGURATION CONSTANTS
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

/** RFC 9204 Section 3.2.1: Entry overhead is 32 bytes (same as HPACK) */
#define SOCKETQPACK_ENTRY_OVERHEAD 32

/** RFC 9204 Appendix A: Static table has 99 entries (0-indexed) */
#define SOCKETQPACK_STATIC_TABLE_SIZE 99

/* ============================================================================
 * ERROR CODES
 * ============================================================================
 */

/**
 * @brief QPACK operation result codes.
 *
 * RFC 9204 Section 2.2.3 specifies error handling requirements.
 *
 * @since 1.0.0
 */
typedef enum
{
  QPACK_OK = 0,            /**< Operation successful */
  QPACK_INCOMPLETE,        /**< Need more data to complete operation */
  QPACK_ERR_INVALID_INDEX, /**< Index out of valid range */
  QPACK_ERR_EVICTED_INDEX, /**< Referenced entry has been evicted */
  QPACK_ERR_FUTURE_INDEX,  /**< Index references not-yet-inserted entry */
  QPACK_ERR_BASE_OVERFLOW, /**< Base would exceed Insert Count */
  QPACK_ERR_TABLE_SIZE,    /**< Dynamic table size limit exceeded */
  QPACK_ERR_HEADER_SIZE,   /**< Individual header size limit exceeded */
  QPACK_ERR_HUFFMAN,       /**< Huffman decoding error */
  QPACK_ERR_INTEGER,       /**< Integer decoding error */
  QPACK_ERR_DECOMPRESSION, /**< Decompression failed (bomb protection) */
  QPACK_ERR_NULL_PARAM,    /**< NULL parameter passed to function */
  QPACK_ERR_INTERNAL       /**< Internal error */
} SocketQPACK_Result;

/* ============================================================================
 * OPAQUE TYPES
 * ============================================================================
 */

/**
 * @brief Opaque type for QPACK encoder.
 *
 * Manages header compression state including the dynamic table, Known Received
 * Count (KRC), and blocked stream tracking as per RFC 9204.
 *
 * @since 1.0.0
 */
typedef struct SocketQPACK_Encoder *SocketQPACK_Encoder_T;

/* ============================================================================
 * ENCODER CREATION/DESTRUCTION
 * ============================================================================
 */

/**
 * @brief Create a new QPACK encoder.
 *
 * Creates an encoder with the specified maximum dynamic table size. The
 * encoder's Known Received Count (KRC) is initialized to 0.
 *
 * @param arena      Memory arena for allocations
 * @param max_table_size Maximum dynamic table size in bytes (0 = disable)
 * @return New encoder instance, never NULL
 * @throws Mem_Failed on allocation failure
 *
 * @note The encoder is not thread-safe. Use one encoder per QUIC connection.
 *
 * @since 1.0.0
 */
extern QPACK_WARN_UNUSED QPACK_NONNULL (1) SocketQPACK_Encoder_T
    SocketQPACK_Encoder_new (Arena_T arena, size_t max_table_size);

/**
 * @brief Free encoder resources.
 *
 * Sets the encoder pointer to NULL after cleanup. Safe to call with NULL.
 *
 * @param encoder Pointer to encoder (will be set to NULL)
 *
 * @since 1.0.0
 */
extern void SocketQPACK_Encoder_free (SocketQPACK_Encoder_T *encoder);

/* ============================================================================
 * KNOWN RECEIVED COUNT (KRC) - RFC 9204 Section 2.1.4
 *
 * The KRC tracks the highest absolute index that the decoder has confirmed
 * receiving. Entries with index < KRC can be safely referenced without
 * blocking the decoder.
 * ============================================================================
 */

/**
 * @brief Get the current Known Received Count.
 *
 * RFC 9204 Section 2.1.4: The Known Received Count is the highest absolute
 * index that has been acknowledged by the decoder. The encoder can safely
 * reference entries with absolute index < KRC without causing the decoder
 * to block.
 *
 * @param encoder QPACK encoder instance
 * @return Current Known Received Count, or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern size_t
SocketQPACK_Encoder_known_received_count (SocketQPACK_Encoder_T encoder);

/**
 * @brief Check if an absolute index is acknowledged (safe to reference).
 *
 * RFC 9204 Section 2.1.4: An entry is considered acknowledged if its absolute
 * index is less than the Known Received Count. Acknowledged entries can be
 * referenced in non-blocking representations.
 *
 * @param encoder   QPACK encoder instance
 * @param abs_index Absolute index to check
 * @return true if index < KRC (acknowledged), false otherwise
 *
 * @note This is the primary function for determining whether to use a
 *       blocking or non-blocking representation when encoding headers.
 *
 * @since 1.0.0
 */
extern bool SocketQPACK_Encoder_is_acknowledged (SocketQPACK_Encoder_T encoder,
                                                 size_t abs_index);

/**
 * @brief Process a Section Acknowledgment decoder instruction.
 *
 * RFC 9204 Section 4.4.1 / Section 2.1.4: When the decoder acknowledges a
 * field section, it sends the Required Insert Count (RIC) of that section.
 * The encoder updates KRC to max(KRC, RIC) because any entry referenced by
 * the acknowledged section must have been received.
 *
 * @param encoder QPACK encoder instance
 * @param ric     Required Insert Count from the Section Acknowledgment
 * @return QPACK_OK on success
 *
 * @note KRC never decreases. If ric <= current KRC, this is a no-op.
 * @note ric is clamped to insert_count if it exceeds the current value.
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Encoder_on_section_ack (SocketQPACK_Encoder_T encoder, size_t ric);

/**
 * @brief Process an Insert Count Increment decoder instruction.
 *
 * RFC 9204 Section 4.4.3 / Section 2.1.4: The decoder sends an Insert Count
 * Increment instruction to inform the encoder that it has processed additional
 * dynamic table insertions. This increments the KRC by the specified amount.
 *
 * @param encoder   QPACK encoder instance
 * @param increment Number of entries to add to KRC (must be > 0)
 * @return QPACK_OK on success,
 *         QPACK_ERR_INVALID_INDEX if increment is 0 or would overflow
 *
 * @note The resulting KRC is clamped to insert_count if it would exceed it.
 *
 * @since 1.0.0
 */
extern SocketQPACK_Result
SocketQPACK_Encoder_on_insert_count_inc (SocketQPACK_Encoder_T encoder,
                                         size_t increment);

/* ============================================================================
 * ENCODER STATE QUERIES
 * ============================================================================
 */

/**
 * @brief Get the total number of insertions ever made.
 *
 * The insert count is a monotonically increasing counter that represents
 * the absolute index that will be assigned to the next inserted entry.
 *
 * @param encoder QPACK encoder instance
 * @return Total insertions (next absolute index), or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Encoder_insert_count (SocketQPACK_Encoder_T encoder);

/**
 * @brief Get the current dynamic table size in bytes.
 *
 * @param encoder QPACK encoder instance
 * @return Current size in bytes, or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Encoder_table_size (SocketQPACK_Encoder_T encoder);

/**
 * @brief Get the number of entries in the dynamic table.
 *
 * @param encoder QPACK encoder instance
 * @return Number of entries, or 0 if encoder is NULL
 *
 * @since 1.0.0
 */
extern size_t SocketQPACK_Encoder_entry_count (SocketQPACK_Encoder_T encoder);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Get human-readable string for QPACK result code.
 *
 * @param result Result code to describe
 * @return Static string describing the result (never NULL)
 *
 * @since 1.0.0
 */
extern const char *SocketQPACK_result_string (SocketQPACK_Result result);

/** @} */

#endif /* SOCKETQPACK_INCLUDED */
