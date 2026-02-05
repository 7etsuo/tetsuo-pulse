/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK structures and constants.
 * @internal
 *
 * Private implementation for QPACK (RFC 9204). Use SocketQPACK.h for public
 * API.
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/qpack/SocketQPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Average entry size estimate for capacity calculation */
#define QPACK_AVERAGE_ENTRY_SIZE 50

/** Minimum dynamic table capacity (entries, power of 2) */
#define QPACK_MIN_TABLE_CAPACITY 16

/** Default maximum blocked stream bytes (total queued across all streams) */
#define QPACK_DEFAULT_MAX_BLOCKED_BYTES (256 * 1024)

/** Initial capacity for blocked streams array */
#define QPACK_BLOCKED_INITIAL_CAPACITY 8

/** Maximum blocked sections per stream */
#define QPACK_MAX_SECTIONS_PER_STREAM 64

/* ============================================================================
 * FIELD LINE INSTRUCTION PATTERNS (RFC 9204 Section 4.5)
 *
 * Wire format patterns for field section instructions.
 * ============================================================================
 */

/**
 * @brief Literal Field Line with Literal Name instruction pattern.
 *
 * RFC 9204 Section 4.5.6:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 | N | H |NameLen(3+)|
 * +---+---+---+---+---+-----------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 */
#define QPACK_FIELD_LITERAL_LITERAL_PATTERN 0x20 /**< 001xxxxx pattern mask */
#define QPACK_FIELD_LITERAL_LITERAL_MASK 0xE0    /**< Top 3 bits mask */
#define QPACK_FIELD_LITERAL_NEVER_INDEX 0x10     /**< N bit (never index) */
#define QPACK_FIELD_LITERAL_NAME_HUFFMAN 0x08    /**< H bit for name */
#define QPACK_FIELD_LITERAL_NAME_PREFIX 3        /**< Name length prefix bits */
#define QPACK_FIELD_LITERAL_NAME_PREFIX_MASK \
  0x07                                         /**< Lower 3 bits for prefix */
#define QPACK_FIELD_LITERAL_VALUE_HUFFMAN 0x80 /**< H bit for value */
#define QPACK_FIELD_LITERAL_VALUE_PREFIX 7     /**< Value length prefix bits */

/* ============================================================================
 * INDEX METADATA (Internal)
 *
 * Tracks metadata for dynamic table entries as per RFC 9204 Section 3.2.4.
 * ============================================================================
 */

/**
 * @brief Metadata for a dynamic table entry.
 * @internal
 *
 * Tracks the absolute index assigned at insertion time. This index is
 * immutable for the lifetime of the entry and monotonically increases
 * across all insertions (RFC 9204 Section 3.2.4).
 */
struct QPACKIndexMetadata
{
  uint64_t abs_index;    /**< Absolute index (0 = first ever inserted) */
  uint64_t insert_count; /**< Insert Count at time of insertion */
  uint32_t ref_count;    /**< Reference count for tracking (future use) */
};

/* ============================================================================
 * DYNAMIC TABLE ENTRY
 * ============================================================================
 */

/**
 * @brief Dynamic table entry structure.
 * @internal
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
  struct QPACKIndexMetadata meta; /**< Index metadata per RFC 9204 3.2.4 */
} QPACK_DynamicEntry;

/* ============================================================================
 * DYNAMIC TABLE STRUCTURE
 * ============================================================================
 */

/**
 * @brief Per-stream dynamic table reference for accurate cancellation.
 * @internal
 *
 * Records which dynamic table entries a stream has referenced, so that
 * stream cancellation only releases that stream's references.
 */
typedef struct
{
  uint64_t stream_id; /**< HTTP/3 stream ID */
  uint64_t abs_index; /**< Absolute index of referenced entry */
} QPACK_StreamRef;

/** Default initial capacity for stream ref array */
#ifndef QPACK_STREAM_REF_INIT_CAP
#define QPACK_STREAM_REF_INIT_CAP 64
#endif

/** Maximum stream refs to prevent unbounded growth from malicious peers */
#ifndef QPACK_MAX_STREAM_REFS
#define QPACK_MAX_STREAM_REFS 4096
#endif

/**
 * @brief QPACK dynamic table implementation.
 * @internal
 *
 * Implements RFC 9204 Section 3.2.1-3.2.3 with absolute indexing.
 * Uses a circular buffer (ring buffer) for O(1) insertion and eviction.
 */
struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries; /**< Circular buffer of entries */
  size_t capacity;             /**< Buffer capacity (power of 2) */
  size_t head;                 /**< Index of oldest entry */
  size_t tail;                 /**< Index for next insertion */
  size_t count;                /**< Current number of entries */
  size_t size;                 /**< Current size in bytes */
  size_t max_size;             /**< Maximum size in bytes */

  /* RFC 9204 absolute indexing state */
  uint64_t insert_count;   /**< Total entries ever inserted (monotonic) */
  uint64_t dropped_count;  /**< Total entries evicted (oldest valid abs idx) */
  uint64_t known_received; /**< Known Received Count from decoder */

  /* Per-stream reference tracking for accurate cancellation */
  QPACK_StreamRef *stream_refs; /**< Array of (stream_id, abs_index) pairs */
  size_t stream_ref_count;      /**< Current number of references */
  size_t stream_ref_capacity;   /**< Array capacity */

  Arena_T arena; /**< Memory arena for allocations */
};

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

/**
 * @brief Calculate entry size per RFC 9204 Section 3.2.1.
 * @internal
 *
 * Entry size = name length + value length + 32 bytes overhead.
 *
 * @param name_len  Name length in bytes
 * @param value_len Value length in bytes
 * @return Entry size in bytes, or SIZE_MAX on overflow
 */
static inline size_t
qpack_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETQPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX;
}

/* ============================================================================
 * BLOCKED STREAM MANAGEMENT (RFC 9204 Sections 2.1.2, 2.2.1)
 * ============================================================================
 */

/**
 * @brief Queued field section waiting for dynamic table entries.
 * @internal
 *
 * RFC 9204 Section 2.2.1: When the Required Insert Count > Insert Count,
 * the field section cannot be decoded immediately and must be queued.
 */
typedef struct
{
  uint64_t required_insert_count; /**< RIC needed to decode this section */
  unsigned char *data;            /**< Compressed field section bytes */
  size_t data_len;                /**< Length of compressed data */
} SocketQPACK_BlockedSection;

/**
 * @brief Blocked stream state (decoder-side).
 * @internal
 *
 * RFC 9204 Section 2.2.1: Tracks all blocked field sections for a single
 * HTTP/3 stream. Sections are processed in FIFO order when unblocked.
 */
typedef struct
{
  uint64_t stream_id;                   /**< HTTP/3 stream identifier */
  SocketQPACK_BlockedSection *sections; /**< Array of blocked sections */
  size_t section_count;                 /**< Number of blocked sections */
  size_t section_alloc;                 /**< Allocated capacity */
  size_t total_bytes;                   /**< Total bytes across all sections */
  uint64_t min_required_insert_count;   /**< Minimum RIC across sections */
} SocketQPACK_BlockedStream;

/**
 * @brief Blocked stream manager (decoder-side).
 * @internal
 *
 * RFC 9204 Section 2.2.1: Manages all blocked streams for a QPACK decoder.
 * Provides efficient unblocking when the dynamic table insert count advances.
 * Stream lookup is O(n) but acceptable given SETTINGS_QPACK_BLOCKED_STREAMS
 * default of 100.
 */
struct SocketQPACK_BlockedManager
{
  Arena_T arena; /**< Memory arena for allocations */

  /* Blocked stream tracking */
  SocketQPACK_BlockedStream *streams; /**< Array of blocked streams */
  size_t stream_count;                /**< Number of blocked streams */
  size_t stream_alloc;                /**< Allocated capacity */

  /* Resource limits (RFC 9204 Section 5) */
  size_t max_blocked_streams; /**< SETTINGS_QPACK_BLOCKED_STREAMS */
  size_t max_blocked_bytes;   /**< Maximum total bytes in queues */
  size_t total_blocked_bytes; /**< Current total bytes queued */

  /* Statistics */
  uint64_t peak_blocked_count;  /**< Peak number of blocked streams */
  uint64_t total_unblock_count; /**< Total times streams unblocked */
};

/**
 * @brief Encoder-side blocked stream tracking.
 * @internal
 *
 * RFC 9204 Section 2.1.2: Encoder must track streams that would become
 * blocked if the referenced dynamic table entries aren't acknowledged.
 */
typedef struct
{
  uint64_t stream_id;             /**< Stream that references dynamic entry */
  uint64_t required_insert_count; /**< RIC of the blocking entry */
} SocketQPACK_EncoderBlockedRef;

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
