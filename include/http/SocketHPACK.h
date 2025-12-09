/**
 * @file SocketHPACK.h
 * @ingroup http
 * @brief HPACK header compression (RFC 7541) for HTTP/2.
 * @defgroup hpack HPACK Header Compression Module
 * @ingroup http
 * @{
 *
 * Provides HPACK header compression for HTTP/2, including:
 * - Static table (61 common headers per RFC 7541 Appendix A)
 * - Dynamic table with FIFO eviction
 * - Huffman encoding/decoding (RFC 7541 Appendix B)
 * - Variable-length integer encoding (RFC 7541 Section 5.1)
 *
 * Features:
 * - O(n) single-pass Huffman decoding via DFA
 * - O(1) dynamic table add/evict via circular buffer
 * - HPACK bomb prevention with configurable limits
 * - Thread-safe exception handling
 *
 * Thread safety: Encoder/decoder instances are NOT thread-safe.
 * Use one instance per thread or external synchronization.
 *
 * Security notes:
 * - Enforces maximum header size limits
 * - Validates Huffman padding (max 7 bits of 1s)
 * - Limits dynamic table size updates per header block
 * - Never indexes sensitive headers marked with never_index
 *
 * @see SocketHTTP2.h for HTTP/2 integration.
 * @see SocketHPACK_Encoder_new() for creating encoders.
 * @see SocketHPACK_Decoder_new() for creating decoders.
 * @see @ref group__http for core HTTP types and utilities.
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
 * @brief Create dynamic table.
 * @ingroup http
 * @param max_size Maximum table size in bytes (includes 32-byte overhead per entry).
 * @param arena Memory arena for allocations.
 * @return New table instance.
 * @throws SocketHPACK_Error on allocation failure.
 * @threadsafe Yes (arena must be thread-safe or thread-local).
 *
 * Creates a new dynamic table with the specified maximum size.
 * The table uses a circular buffer for O(1) FIFO operations.
 *
 * @see SocketHPACK_Table_free() for cleanup.
 * @see SocketHPACK_Table_set_max_size() for resizing after creation.
 */
extern SocketHPACK_Table_T SocketHPACK_Table_new (size_t max_size,
                                                  Arena_T arena);

/**
 * @brief Free dynamic table
 * @ingroup http
 * @param table Pointer to table pointer (will be set to NULL)
 * @threadsafe No
 *
 * Frees the dynamic table. Memory is returned to the arena.
 */
extern void SocketHPACK_Table_free (SocketHPACK_Table_T *table);

/**
 * @brief Update maximum table size
 * @ingroup http
 * @param table Dynamic table
 * @param max_size New maximum size in bytes
 * @threadsafe No
 *
 * Updates the maximum table size, evicting entries as needed.
 * This corresponds to a SETTINGS_HEADER_TABLE_SIZE update.
 */
extern void SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table,
                                            size_t max_size);

/**
 * @brief Get current table size in bytes
 * @ingroup http
 * @param table Dynamic table
 * @return Current size (sum of all entry sizes including overhead)
 * @threadsafe No
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
 * Controls security limits like max header sizes and decompression bomb prevention.
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
 * @brief Decode header block
 * @ingroup http
 * @param decoder Decoder instance
 * @param input Encoded header block
 * @param input_len Block length
 * @param headers Output array for decoded headers
 * @param max_headers Maximum headers to decode
 * @param header_count Output - number of headers decoded
 * @param arena Arena for header string allocation
 * @return Result code
 * @threadsafe No
 *
 * Decodes a complete HPACK header block in one call.
 * Header strings are allocated from the provided arena.
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
 * @return Index (1-61) on exact match, negative index if only name matches, 0 if not found
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
