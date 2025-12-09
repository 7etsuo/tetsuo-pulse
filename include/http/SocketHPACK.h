/**
 * @file SocketHPACK.h
 * @ingroup http
 * @brief HPACK header compression/decompression module for HTTP/2 (RFC 7541).
 *
 * This module implements the full HPACK algorithm for efficient HTTP/2 header
 * field representation and transmission. It handles header compression to
 * reduce bandwidth and decompression with security safeguards.
 *
 * ## Key Components
 *
 * - **Static Table**: Fixed 61 entries of common headers (Appendix A).
 * - **Dynamic Table**: Growable table for repeated headers with eviction
 * policy.
 * - **Encoding Primitives**: Integer, string (literal/Huffman), indexing
 * modes.
 * - **Encoder/Decoder**: Stateful instances for block-level operations.
 *
 * ## Architecture Overview
 *
 * ```
 * +-------------------+     +-------------------+
 * |   HTTP/2 Layer    |     |   Application     |
 * | (SocketHTTP2)     |<--->| (Request/Response)|
 * +-------------------+     +-------------------+
 *           ^                        ^
 *           | Uses                   | Produces
 *           v                        v
 * +-------------------+     +-------------------+
 * |   HPACK Encoder   |     | HPACK Decoder     |
 * | - Table Mgmt      |     | - Table Updates   |
 * | - Header Encoding |     | - Header Decoding |
 * +-------------------+     +-------------------+
 *           ^                        ^
 *           | Shared                 | Shared
 *           v                        v
 * +-------------------+     +-------------------+
 * |   Dynamic Table   |<--->|   (Shared State)  |
 * | (FIFO Circular)   |     +-------------------+
 * +-------------------+               ^
 *           ^                         |
 *           | Static                  |
 *           v                         |
 * +-------------------+               |
 * |   Static Table    |<--------------+
 * | (61 Fixed Entries)|
 * +-------------------+
 * ```
 *
 * ## Module Dependencies
 *
 * - **Foundation**: Arena_T for memory, Except_T for errors.
 * - **HTTP Core**: SocketHTTP_Headers_T compatibility (optional integration).
 * - **Used By**: SocketHTTP2_Conn_T for frame processing.
 *
 * ## Thread Safety
 *
 * - Individual encoder/decoder instances: NOT thread-safe (internal state
 * mutation).
 * - Static functions (huffman_encode, int_encode): thread-safe.
 * - Dynamic table: NOT thread-safe; synchronize adds/gets.
 * - Recommendation: One encoder/decoder per connection/thread.
 *
 * ## Security Features
 *
 * - Configurable limits on table size, header sizes, list size.
 * - Decompression bomb protection via expansion ratio check.
 * - Validation of encoding primitives (Huffman padding, integer overflows).
 * - Automatic never-indexing for sensitive headers (e.g., authorization,
 * cookie).
 * - Limits on table size updates per block to prevent DoS.
 *
 * ## Performance Characteristics
 *
 * - Encoding/Decoding: O(n) linear in header block size.
 * - Table operations: O(1) add/get/evict via circular buffer.
 * - Huffman: DFA-based decoding for speed, optional encoding.
 *
 * ## Configuration Limits
 *
 * See defined constants:
 * - SOCKETHPACK_DEFAULT_TABLE_SIZE (4096 bytes)
 * - SOCKETHPACK_MAX_TABLE_SIZE (64KB)
 * - SOCKETHPACK_MAX_HEADER_SIZE (8KB)
 * - SOCKETHPACK_MAX_HEADER_LIST_SIZE (64KB)
 *
 * ## Integration Notes
 *
 * - Use with SocketHTTP2_Conn_new() for automatic setup.
 * - Manual use: Create encoder/decoder, manage table size via SETTINGS.
 * - Error handling: Check SocketHPACK_Result; use SocketHPACK_result_string()
 * for logging.
 * - Testing: Use test_hpack binary in build/ for validation.
 *
 * @defgroup hpack HPACK Header Compression Module
 * @ingroup http
 * @{
 *
 * @see SocketHTTP2.h for HTTP/2 protocol layer integration.
 * @see SocketHPACK_Encoder_new() primary entry for compression.
 * @see SocketHPACK_Decoder_new() primary entry for decompression.
 * @see @ref group__http for supporting HTTP types.
 * @see docs/HTTP-REFACTOR.md for refactoring notes.
 * @see docs/SECURITY.md#hpack for security deep dive.
 * @see https://tools.ietf.org/html/rfc7541 for full specification.
 */

#ifndef SOCKETHPACK_INCLUDED
#define SOCKETHPACK_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"

/* ============================================================================
 * Configuration Limits
 * ============================================================================
 */

/**
 * @brief Default dynamic table size in bytes (RFC 7541 default).
 * @ingroup http
 *
 * Used when no explicit table size is configured.
 */
#ifndef SOCKETHPACK_DEFAULT_TABLE_SIZE
#define SOCKETHPACK_DEFAULT_TABLE_SIZE 4096
#endif

/**
 * @brief Maximum allowable dynamic table size in bytes.
 * @ingroup http
 *
 * ENFORCEMENT: Table size updates are validated in
 * SocketHPACK_Decoder_decode(). Rejects updates exceeding
 * settings_max_table_size.
 * @see SocketHPACK_Decoder_set_table_size()
 */
#ifndef SOCKETHPACK_MAX_TABLE_SIZE
#define SOCKETHPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum size for individual header (name + value) in bytes.
 * @ingroup http
 */
#ifndef SOCKETHPACK_MAX_HEADER_SIZE
#define SOCKETHPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

/**
 * @brief Maximum total size for decoded header list in bytes.
 * @ingroup http
 */
#ifndef SOCKETHPACK_MAX_HEADER_LIST_SIZE
#define SOCKETHPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

/**
 * @brief Maximum allowed dynamic table size updates per header block.
 * @ingroup http
 *
 * Prevents excessive updates that could be used in attacks.
 */
#ifndef SOCKETHPACK_MAX_TABLE_UPDATES
#define SOCKETHPACK_MAX_TABLE_UPDATES 2
#endif

/**
 * @brief Size of the static table (RFC 7541 Appendix A).
 * @ingroup http
 *
 * Contains 61 predefined common header fields.
 */
#define SOCKETHPACK_STATIC_TABLE_SIZE 61

/**
 * @brief Overhead bytes per dynamic table entry (RFC 7541 Section 4.1).
 * @ingroup http
 *
 * 32 bytes minimum overhead for name/value storage and indexing.
 */
#define SOCKETHPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief SocketHPACK_Error - General HPACK operation failure
 * @ingroup http
 *
 * Raised when:
 * - Invalid header block encoding
 * - Huffman decoding error
 * - Integer overflow
 * - Size limits exceeded
 * - HPACK bomb detected
 */
extern const Except_T SocketHPACK_Error;

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief HPACK operation result codes.
 * @ingroup http
 */
typedef enum
{
  HPACK_OK = 0,              /**< Success */
  HPACK_INCOMPLETE,          /**< Need more data */
  HPACK_ERROR,               /**< Generic error */
  HPACK_ERROR_INVALID_INDEX, /**< Index out of range */
  HPACK_ERROR_HUFFMAN,       /**< Huffman decoding error */
  HPACK_ERROR_INTEGER,       /**< Integer overflow */
  HPACK_ERROR_TABLE_SIZE,    /**< Dynamic table size update invalid */
  HPACK_ERROR_HEADER_SIZE,   /**< Individual header too large */
  HPACK_ERROR_LIST_SIZE,     /**< Total header list too large */
  HPACK_ERROR_BOMB           /**< HPACK bomb detected */
} SocketHPACK_Result;

/* ============================================================================
 * Header Representation
 * ============================================================================
 */

/**
 * @brief HPACK header field representation.
 *
 * Represents a single header with optional never_index flag.
 * The never_index flag indicates sensitive data that should
 * never be added to the dynamic table.
 * @ingroup http
 */
typedef struct
{
  const char *name;  /**< Header name */
  size_t name_len;   /**< Name length in bytes */
  const char *value; /**< Header value */
  size_t value_len;  /**< Value length in bytes */
  int never_index;   /**< Sensitive - never add to dynamic table */
} SocketHPACK_Header;

/* ============================================================================
 * Dynamic Table
 * ============================================================================
 */

/**
 * @brief HPACK dynamic table (opaque type)
 * @ingroup http
 */
typedef struct SocketHPACK_Table *SocketHPACK_Table_T;

/**
 * @brief Create a new dynamic HPACK table for header compression.
 * @ingroup http
 *
 * Initializes a dynamic table used for storing header fields to reduce
 * redundancy in HTTP/2 header blocks (RFC 7541). The table supports eviction
 * of least recently used (oldest) entries when size limits are reached, using
 * a circular buffer for efficiency. All internal allocations (entries,
 * strings) are arena-managed for fast cleanup.
 *
 * @param[in] max_size Maximum allowed size for the table in bytes. Includes
 * SOCKETHPACK_ENTRY_OVERHEAD (32 bytes) per entry. Must be 0 <= max_size <=
 * SOCKETHPACK_MAX_TABLE_SIZE. Default recommendation:
 * SOCKETHPACK_DEFAULT_TABLE_SIZE (4096).
 * @param[in] arena Arena_T instance for all memory allocations. Table lifetime
 * is bound to this arena.
 *
 * @return Opaque pointer to new dynamic table instance.
 *
 * @throws SocketHPACK_Error If max_size invalid or internal initialization
 * fails.
 * @throws Arena_Failed If arena allocation fails (propagated).
 *
 * @threadsafe Yes - atomic creation; arena must be synchronized if shared
 * across threads.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketHPACK_Table_T table = NULL;
 * TRY {
 *     table = SocketHPACK_Table_new(SOCKETHPACK_DEFAULT_TABLE_SIZE, arena);
 *     assert(table != NULL);
 *     // Table ready for use in encoders/decoders
 * } EXCEPT(Arena_Failed, SocketHPACK_Error) {
 *     fprintf(stderr, "Failed to create table: %s\n",
 * Except_message(Except_stack)); return -1; } END_TRY;
 * // Use table...
 * SocketHPACK_Table_free(&table);
 * @endcode
 *
 * ## Advanced Configuration
 *
 * | max_size Value | Recommended For | Expected Entries | Compression Impact |
 * |----------------|-----------------|------------------|--------------------|
 * | 0 | Minimal memory | 0 | No dynamic compression |
 * | 4096 (default) | General use | ~10-20 | Good balance |
 * | 16384 | High-volume HTTP/2 | ~50-100 | Better ratios |
 * | 65536 (max) | Servers | ~200+ | Optimal but memory-intensive |
 *
 * @note Table starts empty (size=0, count=0). Populate during encoding or
 * manually.
 * @note Strings added to table are copied into arena; originals can be freed
 * after.
 * @note Use with SocketHPACK_Encoder_new() or SocketHPACK_Decoder_new() for
 * HTTP/2.
 *
 * @warning Large max_size increases memory footprint; monitor with
 * SocketHPACK_Table_size().
 * @warning Never pass NULL arena; will raise Arena_Failed.
 *
 * @complexity O(1) - constant time initialization and allocation
 *
 * @see SocketHPACK_Table_free() for paired cleanup
 * @see SocketHPACK_Table_add() to populate with headers
 * @see SocketHPACK_Table_set_max_size() for dynamic resizing
 * @see SocketHPACK_Encoder_new() for encoder integration
 * @see Arena.h for memory management details
 * @see docs/HTTP-REFACTOR.md for performance tuning
 * @see https://tools.ietf.org/html/rfc7541#section-4 for RFC specification
 */
extern SocketHPACK_Table_T SocketHPACK_Table_new (size_t max_size,
                                                  Arena_T arena);

/**
 * @brief Dispose of a dynamic table instance and release its resources.
 * @ingroup http
 *
 * Safely frees the dynamic table, returning all allocated memory to the arena.
 * The table pointer is set to NULL to prevent use-after-free errors.
 *
 * This function does not throw exceptions as it performs no allocations.
 * It is safe to call on already-NULL pointers (no-op).
 *
 * @param[in,out] table Pointer to the dynamic table instance. Set to NULL on
 * success.
 *
 * @threadsafe No - caller must ensure no concurrent access to the table or
 * arena.
 *
 * ## Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * TRY {
 *     SocketHPACK_Table_T table =
 * SocketHPACK_Table_new(SOCKETHPACK_DEFAULT_TABLE_SIZE, arena);
 *     // ... use table for encoding/decoding ...
 * } EXCEPT(SocketHPACK_Error) {
 *     // Handle error
 * } FINALLY {
 *     SocketHPACK_Table_free(&table);
 * } END_TRY;
 * Arena_dispose(&arena);
 * @endcode
 *
 * ## Important Notes
 *
 * - Always pair with SocketHPACK_Table_new() using the same arena for
 * lifecycle management.
 * - No individual header strings are freed; they remain in the arena until
 * Arena_clear() or Arena_dispose().
 * - In multi-threaded environments, synchronize access to shared arenas.
 *
 * @note This operation does not iterate over table entries; memory is managed
 * by the arena.
 *
 * @warning Failing to free tables can lead to arena exhaustion and memory
 * leaks.
 *
 * @complexity O(1) - constant time operation
 *
 * @see SocketHPACK_Table_new() for table creation
 * @see Arena_dispose() for complete resource cleanup
 * @see SocketHPACK_Encoder_free() and SocketHPACK_Decoder_free() for related
 * cleanup patterns
 * @see docs/HTTP.md for HTTP/2 header compression overview
 */
extern void SocketHPACK_Table_free (SocketHPACK_Table_T *table);

/**
 * @brief Update the maximum size of the dynamic table.
 * @ingroup http
 *
 * Changes the dynamic table's maximum capacity, potentially evicting the
 * oldest entries to fit within the new limit. This operation is typically
 * triggered by a HTTP/2 SETTINGS frame updating HEADER_TABLE_SIZE. Entries are
 * evicted from the oldest (highest index) until the table size is <= max_size.
 *
 * @param[in] table The dynamic table instance to update.
 * @param[in] max_size New maximum table size in bytes, including overhead per
 * entry. Must be >= 0 and <= SOCKETHPACK_MAX_TABLE_SIZE.
 *
 * @throws SocketHPACK_Error If max_size is invalid (negative or exceeds
 * maximum allowed).
 *
 * @threadsafe No - concurrent updates or accesses may lead to inconsistent
 * state or data races.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketHPACK_Table_T table = ...;  // Initialized table
 *
 * // Increase for better compression
 * TRY {
 *     SocketHPACK_Table_set_max_size(table, 16384);  // 16KB
 * } EXCEPT(SocketHPACK_Error) {
 *     SOCKET_LOG_ERROR_MSG("Failed to update table size: %s",
 * Socket_GetLastError());
 * }
 *
 * // Reduce size, evicting if necessary
 * SocketHPACK_Table_set_max_size(table, 2048);   // 2KB
 * @endcode
 *
 * ## Eviction Behavior
 *
 * | Condition | Action |
 * |-----------|--------|
 * | new_size >= current_size | No eviction |
 * | new_size < current_size | Evict oldest entries until compliant |
 * | new_size == 0 | Clear entire table |
 *
 * ## Query After Update
 *
 * After calling, verify with:
 * - SocketHPACK_Table_size(table) <= max_size
 * - SocketHPACK_Table_max_size(table) == max_size
 *
 * @note Affects compression efficiency; larger tables improve ratios but use
 * more memory.
 * @note Synchronized between encoder/decoder via SETTINGS frames in HTTP/2.
 *
 * @warning Frequent size changes can cause unnecessary evictions and
 * performance overhead.
 *
 * @complexity O(n) worst case - linear in number of entries if full eviction
 * needed
 * @complexity O(1) average - if no or few evictions
 *
 * @see SocketHPACK_Table_new() for initial configuration
 * @see SocketHPACK_Table_size() to get current usage
 * @see SocketHPACK_Table_count() for entry count changes
 * @see SocketHPACK_Decoder_set_table_size() for decoder synchronization
 * @see SocketHPACK_Encoder_set_table_size() for encoder updates
 * @see docs/HTTP.md#hpack-dynamic-table for HTTP/2 specifics
 */
extern void SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table,
                                            size_t max_size);

/**
 * @brief Query the current size of the dynamic table in bytes.
 * @ingroup http
 *
 * Returns the total size of all entries in the dynamic table, including the
 * 32-byte overhead per entry as per RFC 7541 Section 4.1. This value
 * represents memory usage and is always <= the maximum table size set via
 * SocketHPACK_Table_set_max_size().
 *
 * @param[in] table The dynamic table instance to query.
 *
 * @return Current table size in bytes (sum of name/value lengths +
 * SOCKETHPACK_ENTRY_OVERHEAD * entry count).
 *
 * @threadsafe No - concurrent table modifications (add/evict) may cause
 * inconsistent return values.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketHPACK_Table_T table = SocketHPACK_Table_new(4096, arena);
 * size_t size = SocketHPACK_Table_size(table);  // Initially 0
 *
 * // After adding entries
 * SocketHPACK_Table_add(table, ":method", 7, "GET", 3);
 * size = SocketHPACK_Table_size(table);  // ~42 bytes (value + name +
 * overhead)
 *
 * printf("Table size: %zu bytes\n", size);
 * @endcode
 *
 * ## Size Calculation
 *
 * Total size = \sum (name_len + value_len) + (count *
 * SOCKETHPACK_ENTRY_OVERHEAD)
 *
 * | Component | Description |
 * |-----------|-------------|
 * | Header Data | Sum of all name and value string lengths |
 * | Overhead | 32 bytes per entry for indexing and metadata |
 *
 * @note Size does not include static table; only dynamic entries.
 * @note Returns 0 for empty table.
 *
 * @complexity O(1) - maintained incrementally during add/evict operations
 *
 * @see SocketHPACK_Table_count() for entry count
 * @see SocketHPACK_Table_max_size() for capacity limit
 * @see SocketHPACK_Table_add() for adding entries that increase size
 * @see SocketHPACK_ENTRY_OVERHEAD for per-entry cost
 * @see docs/HTTP-REFACTOR.md#hpack-memory-management for tuning advice
 */
extern size_t SocketHPACK_Table_size (SocketHPACK_Table_T table);

/**
 * @brief Get number of entries
 * @ingroup http
 * @param table Dynamic table
 * @return Number of entries in the table
 * @threadsafe No
 */
extern size_t SocketHPACK_Table_count (SocketHPACK_Table_T table);

/**
 * @brief Get maximum table size
 * @ingroup http
 * @param table Dynamic table
 * @return Maximum size in bytes
 * @threadsafe No
 */
extern size_t SocketHPACK_Table_max_size (SocketHPACK_Table_T table);

/**
 * @brief Get entry by index
 * @ingroup http
 * @param table Dynamic table
 * @param index Entry index (1-based, relative to dynamic table start)
 * @param header Output header structure
 * @return HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range
 * @threadsafe No
 *
 * Retrieves an entry from the dynamic table by index.
 * Index 1 is the most recently added entry.
 */
extern SocketHPACK_Result SocketHPACK_Table_get (SocketHPACK_Table_T table,
                                                 size_t index,
                                                 SocketHPACK_Header *header);

/**
 * @brief Add entry to dynamic table
 * @ingroup http
 * @param table Dynamic table
 * @param name Header name
 * @param name_len Name length
 * @param value Header value
 * @param value_len Value length
 * @return HPACK_OK on success
 * @threadsafe No
 *
 * Adds a new entry to the dynamic table. May evict older entries
 * if the table size would exceed the maximum.
 */
extern SocketHPACK_Result
SocketHPACK_Table_add (SocketHPACK_Table_T table, const char *name,
                       size_t name_len, const char *value, size_t value_len);

/* ============================================================================
 * Encoder
 * ============================================================================
 */

/**
 * @brief HPACK encoder (opaque type)
 * @ingroup http
 */
typedef struct SocketHPACK_Encoder *SocketHPACK_Encoder_T;

/**
 * @brief Configuration for HPACK encoder instance.
 * @ingroup http
 *
 * Allows customization of table size, Huffman usage, and indexing behavior.
 */
typedef struct
{
  size_t max_table_size; /**< Maximum dynamic table size */
  int huffman_encode;    /**< Use Huffman encoding (default: 1) */
  int use_indexing;      /**< Add headers to dynamic table (default: 1) */
} SocketHPACK_EncoderConfig;

/**
 * @brief Initialize encoder config with defaults
 * @ingroup http
 * @param config Configuration structure to initialize
 * @threadsafe Yes
 */
extern void
SocketHPACK_encoder_config_defaults (SocketHPACK_EncoderConfig *config);

/**
 * @brief Create HPACK encoder instance.
 * @ingroup http
 * @param config Configuration (NULL for defaults).
 * @param arena Memory arena for allocations.
 * @return New encoder instance.
 * @throws SocketHPACK_Error on allocation failure.
 * @threadsafe Yes (arena must be thread-safe or thread-local).
 *
 * Creates a new HPACK encoder with the specified configuration.
 *
 * @see SocketHPACK_Encoder_free() for cleanup.
 * @see SocketHPACK_encoder_config_defaults() for default configuration.
 * @see SocketHPACK_Encoder_encode() for encoding headers.
 */
extern SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config,
                         Arena_T arena);

/**
 * @brief Free encoder
 * @ingroup http
 * @param encoder Pointer to encoder pointer (will be set to NULL)
 * @threadsafe No
 */
extern void SocketHPACK_Encoder_free (SocketHPACK_Encoder_T *encoder);

/**
 * @brief Encode header block
 * @ingroup http
 * @param encoder Encoder instance
 * @param headers Array of headers to encode
 * @param count Number of headers
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written, or -1 on error
 * @threadsafe No
 *
 * Encodes a header block using HPACK compression.
 */
extern ssize_t SocketHPACK_Encoder_encode (SocketHPACK_Encoder_T encoder,
                                           const SocketHPACK_Header *headers,
                                           size_t count, unsigned char *output,
                                           size_t output_size);

/**
 * @brief Signal table size change
 * @ingroup http
 * @param encoder Encoder
 * @param max_size New maximum size
 * @threadsafe No
 *
 * Signals that a dynamic table size update should be emitted
 * at the start of the next header block.
 */
extern void SocketHPACK_Encoder_set_table_size (SocketHPACK_Encoder_T encoder,
                                                size_t max_size);

/**
 * @brief Get encoder's dynamic table
 * @ingroup http
 * @param encoder Encoder
 * @return Dynamic table (for inspection/debugging)
 * @threadsafe No
 */
extern SocketHPACK_Table_T
SocketHPACK_Encoder_get_table (SocketHPACK_Encoder_T encoder);

/* ============================================================================
 * Decoder
 * ============================================================================
 */

/**
 * @brief HPACK decoder (opaque type)
 * @ingroup http
 */
typedef struct SocketHPACK_Decoder *SocketHPACK_Decoder_T;

/**
 * @brief Configuration for HPACK decoder instance.
 * @ingroup http
 *
 * Controls security limits like max header sizes and decompression bomb
 * prevention.
 */
typedef struct
{
  size_t max_table_size;       /**< Maximum dynamic table size */
  size_t max_header_size;      /**< Maximum individual header size */
  size_t max_header_list_size; /**< Maximum total decoded size */
  double max_expansion_ratio;  /**< Max decoded/encoded ratio to prevent
                                  decompression bombs (default: 10.0) */

} SocketHPACK_DecoderConfig;

/**
 * @brief Initialize decoder config with defaults
 * @ingroup http
 * @param config Configuration structure to initialize
 * @threadsafe Yes
 */
extern void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config);

/**
 * @brief Create HPACK decoder instance.
 * @ingroup http
 * @param config Configuration (NULL for defaults).
 * @param arena Memory arena for allocations.
 * @return New decoder instance.
 * @throws SocketHPACK_Error on allocation failure.
 * @threadsafe Yes (arena must be thread-safe or thread-local).
 *
 * Creates a new HPACK decoder with the specified configuration.
 *
 * @see SocketHPACK_Decoder_free() for cleanup.
 * @see SocketHPACK_decoder_config_defaults() for default configuration.
 * @see SocketHPACK_Decoder_decode() for decoding header blocks.
 * @see SocketHTTP2.h for HTTP/2 integration.
 */
extern SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config,
                         Arena_T arena);

/**
 * @brief Free decoder
 * @ingroup http
 * @param decoder Pointer to decoder pointer (will be set to NULL)
 * @threadsafe No
 */
extern void SocketHPACK_Decoder_free (SocketHPACK_Decoder_T *decoder);

/**
 * @brief Decode a complete HPACK header block into headers array.
 * @ingroup http
 *
 * Performs full decompression of an HPACK-encoded header block from HTTP/2
 * HEADERS or PUSH_PROMISE frames. Supports all HPACK representations: indexed
 * headers, literal headers (with/without indexing), dynamic table updates.
 * Single-pass decoding with validation against decoder config limits to
 * prevent security issues like decompression bombs. Decoded headers include
 * pseudo-headers (e.g., :method, :authority) and regular headers, preserving
 * block order. Name and value strings are null-terminated and allocated from
 * the arena for easy use.
 *
 * @param[in] decoder Initialized decoder with security configuration (max
 * sizes, expansion ratio).
 * @param[in] input Pointer to the encoded HPACK header block data.
 * @param[in] input_len Number of bytes in the input buffer.
 * @param[out] headers Pre-allocated array of SocketHPACK_Header to store
 * decoded results.
 * @param[in] max_headers Capacity of headers array (safety limit against
 * excessive headers).
 * @param[out] header_count Pointer to receive the number of decoded headers
 * written to array.
 * @param[in] arena Arena_T for allocating copies of header name and value
 * strings.
 *
 * @return SocketHPACK_Result indicating success or error:
 *         - HPACK_OK: Complete decode, *header_count populated.
 *         - HPACK_INCOMPLETE: Partial input; call again with more data.
 *         - HPACK_ERROR_*: Specific failure (e.g., HPACK_ERROR_INVALID_INDEX,
 * HPACK_ERROR_HUFFMAN).
 *
 * @throws SocketHPACK_Error On validation failures, limit violations, or
 * decoding errors.
 * @throws Arena_Failed If string allocations exceed arena capacity.
 *
 * @threadsafe No - modifies decoder state (table updates); requires external
 * synchronization for shared use.
 *
 * ## Basic Usage Pattern
 *
 * @code{.c}
 * // In HTTP/2 frame processing loop
 * SocketHPACK_Header headers[128];  // Reasonable max for most requests
 * size_t num_headers = 0;
 * const unsigned char *hpdata = frame->headers.payload;
 * size_t hplen = frame->headers.length;
 *
 * TRY {
 *     SocketHPACK_Result res = SocketHPACK_Decoder_decode(decoder, hpdata,
 * hplen, headers, 128, &num_headers, arena); if (res == HPACK_OK) {
 *         // Process headers
 *         for (size_t i = 0; i < num_headers; ++i) {
 *             if (headers[i].never_index) {
 *                 // Handle sensitive header (e.g., authorization)
 *             }
 *             // Convert to HTTP request/response as needed
 *         }
 *     } else if (res == HPACK_INCOMPLETE) {
 *         // Buffer more data and retry (rare for complete frames)
 *     } else {
 *         // Protocol error; consider GOAWAY or connection close
 *         SOCKET_LOG_ERROR_MSG("HPACK decode failed: %s",
 * SocketHPACK_result_string(res)); RAISE(SocketHTTP2_ProtocolError);
 *     }
 * } EXCEPT (SocketHPACK_Error) {
 *     // Log and handle
 * } END_TRY;
 * @endcode
 *
 * ## Error Codes and Recovery
 *
 * | Code | Typical Cause | Recommended Action |
 * |------|---------------|--------------------|
 * | HPACK_ERROR_INVALID_INDEX | Invalid table index | Peer error; send
 * RST_STREAM or GOAWAY | | HPACK_ERROR_HUFFMAN | Corrupt Huffman codes/padding
 * | Validate peer; close connection | | HPACK_ERROR_TABLE_SIZE | Invalid size
 * update > max | Protocol violation; reject update | | HPACK_ERROR_HEADER_SIZE
 * | Single header exceeds limit | Increase config or drop oversized | |
 * HPACK_ERROR_LIST_SIZE | Total size exceeds limit | Increase config or
 * truncate headers | | HPACK_ERROR_BOMB | Excessive expansion ratio | Tighten
 * max_expansion_ratio; ban peer IP |
 *
 * ## Security Considerations
 *
 * - Configurable limits prevent DoS via large headers or table updates.
 * - max_expansion_ratio guards against "HPACK bombs" where encoded is small
 * but decoded huge.
 * - never_index flag respected for sensitive headers (e.g., cookies, auth).
 * - Table size updates limited per block (SOCKETHPACK_MAX_TABLE_UPDATES).
 *
 * @note On success, *header_count <= max_headers; array not null-padded.
 * @note Pseudo-headers must appear before regular headers per RFC; order
 * preserved.
 * @note Supports Huffman decoding with padding validation (max 7 trailing
 * 1-bits).
 * @note Partial decodes (HPACK_INCOMPLETE) advance internal state; resume with
 * more input.
 * @note Arena strings lifetime ends with arena clear/dispose; copy if needed
 * longer.
 *
 * @warning Always validate *header_count before accessing headers array.
 * @warning Do not reuse headers array across calls without clearing or size
 * check.
 * @warning In production, log and monitor error rates for HPACK_ERROR_* codes.
 *
 * @complexity O(n + m) where n=input size, m=output headers (linear scan +
 * allocations)
 *
 * @see SocketHPACK_Decoder_new() for creating secure decoders
 * @see SocketHPACK_DecoderConfig for limit tuning
 * @see SocketHPACK_Header for output structure details
 * @see SocketHPACK_result_string() to get human-readable errors
 * @see SocketHTTP2.h for HTTP/2 frame integration
 * @see docs/SECURITY.md#hpack-security for attack mitigations
 * @see https://tools.ietf.org/html/rfc7541#section-6 for decoding spec
 */
extern SocketHPACK_Result
SocketHPACK_Decoder_decode (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            SocketHPACK_Header *headers, size_t max_headers,
                            size_t *header_count, Arena_T arena);

/**
 * @brief Handle SETTINGS table size update
 * @ingroup http
 * @param decoder Decoder
 * @param max_size New maximum size from SETTINGS frame
 * @threadsafe No
 */
extern void SocketHPACK_Decoder_set_table_size (SocketHPACK_Decoder_T decoder,
                                                size_t max_size);

/**
 * @brief Get decoder's dynamic table
 * @ingroup http
 * @param decoder Decoder
 * @return Dynamic table (for inspection/debugging)
 * @threadsafe No
 */
extern SocketHPACK_Table_T
SocketHPACK_Decoder_get_table (SocketHPACK_Decoder_T decoder);

/* ============================================================================
 * Huffman Coding
 * ============================================================================
 */

/**
 * @brief Huffman encode string
 * @ingroup http
 * @param input Input string
 * @param input_len Input length
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Encoded length, or -1 on error (buffer too small)
 * @threadsafe Yes
 *
 * Encodes a string using the HPACK Huffman table (RFC 7541 Appendix B).
 */
extern ssize_t SocketHPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Huffman decode string
 * @ingroup http
 * @param input Encoded input
 * @param input_len Input length
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Decoded length, or -1 on error
 * @threadsafe Yes
 *
 * Decodes a Huffman-encoded string using DFA-based decoding.
 * Validates padding (max 7 bits, all 1s).
 */
extern ssize_t SocketHPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * @brief Calculate encoded size
 * @ingroup http
 * @param input Input string
 * @param input_len Input length
 * @return Encoded size in bytes
 * @threadsafe Yes
 *
 * Calculates the size of the Huffman-encoded output in bytes.
 */
extern size_t SocketHPACK_huffman_encoded_size (const unsigned char *input,
                                                size_t input_len);

/* ============================================================================
 * Integer Coding (RFC 7541 Section 5.1)
 * ============================================================================
 */

/**
 * @brief Encode integer with prefix
 * @ingroup http
 * @param value Integer value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param output Output buffer
 * @param output_size Buffer size
 * @return Bytes written
 * @threadsafe Yes
 *
 * Encodes an integer using HPACK's variable-length encoding.
 */
extern size_t SocketHPACK_int_encode (uint64_t value, int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * @brief Decode integer with prefix
 * @ingroup http
 * @param input Input buffer
 * @param input_len Input length
 * @param prefix_bits Number of prefix bits (1-8)
 * @param value Output value
 * @param consumed Output bytes consumed
 * @return Result code
 * @threadsafe Yes
 *
 * Decodes an HPACK-encoded integer.
 */
extern SocketHPACK_Result
SocketHPACK_int_decode (const unsigned char *input, size_t input_len,
                        int prefix_bits, uint64_t *value, size_t *consumed);

/* ============================================================================
 * Static Table Lookup
 * ============================================================================
 */

/**
 * @brief Get entry from static table
 * @ingroup http
 * @param index Entry index (1-61)
 * @param header Output header structure
 * @return HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range
 * @threadsafe Yes
 *
 * Retrieves an entry from the static table by index.
 */
extern SocketHPACK_Result SocketHPACK_static_get (size_t index,
                                                  SocketHPACK_Header *header);

/**
 * @brief Find entry in static table
 * @ingroup http
 * @param name Header name
 * @param name_len Name length
 * @param value Header value (NULL to match name only)
 * @param value_len Value length
 * @return Index (1-61) on exact match, negative index if only name matches, 0
 * if not found
 * @threadsafe Yes
 *
 * Searches for an entry in the static table.
 */
extern int SocketHPACK_static_find (const char *name, size_t name_len,
                                    const char *value, size_t value_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Get error description
 * @ingroup http
 * @param result Result code
 * @return Static string describing the result
 * @threadsafe Yes
 */
extern const char *SocketHPACK_result_string (SocketHPACK_Result result);

/** @} */ /* hpack */

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

#endif /* SOCKETHPACK_INCLUDED */
