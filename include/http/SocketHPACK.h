/**
 * SocketHPACK.h - HPACK Header Compression (RFC 7541)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
 * ============================================================================ */

/** Default dynamic table size (RFC 7541 default) */
#ifndef SOCKETHPACK_DEFAULT_TABLE_SIZE
#define SOCKETHPACK_DEFAULT_TABLE_SIZE 4096
#endif

/** Maximum dynamic table size */
#ifndef SOCKETHPACK_MAX_TABLE_SIZE
#define SOCKETHPACK_MAX_TABLE_SIZE (64 * 1024)
#endif

/** Maximum individual header size (name + value) */
#ifndef SOCKETHPACK_MAX_HEADER_SIZE
#define SOCKETHPACK_MAX_HEADER_SIZE (8 * 1024)
#endif

/** Maximum total decoded header list size */
#ifndef SOCKETHPACK_MAX_HEADER_LIST_SIZE
#define SOCKETHPACK_MAX_HEADER_LIST_SIZE (64 * 1024)
#endif

/** Maximum dynamic table size updates per header block */
#ifndef SOCKETHPACK_MAX_TABLE_UPDATES
#define SOCKETHPACK_MAX_TABLE_UPDATES 2
#endif

/** Static table size (RFC 7541 Appendix A) */
#define SOCKETHPACK_STATIC_TABLE_SIZE 61

/** HPACK entry overhead per RFC 7541 Section 4.1 */
#define SOCKETHPACK_ENTRY_OVERHEAD 32

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketHPACK_Error - General HPACK operation failure
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
 * ============================================================================ */

/**
 * HPACK operation result codes
 */
typedef enum
{
  HPACK_OK = 0,               /**< Success */
  HPACK_INCOMPLETE,           /**< Need more data */
  HPACK_ERROR,                /**< Generic error */
  HPACK_ERROR_INVALID_INDEX,  /**< Index out of range */
  HPACK_ERROR_HUFFMAN,        /**< Huffman decoding error */
  HPACK_ERROR_INTEGER,        /**< Integer overflow */
  HPACK_ERROR_TABLE_SIZE,     /**< Dynamic table size update invalid */
  HPACK_ERROR_HEADER_SIZE,    /**< Individual header too large */
  HPACK_ERROR_LIST_SIZE,      /**< Total header list too large */
  HPACK_ERROR_BOMB            /**< HPACK bomb detected */
} SocketHPACK_Result;

/* ============================================================================
 * Header Representation
 * ============================================================================ */

/**
 * HPACK header field
 *
 * Represents a single header with optional never_index flag.
 * The never_index flag indicates sensitive data that should
 * never be added to the dynamic table.
 */
typedef struct
{
  const char *name;   /**< Header name */
  size_t name_len;    /**< Name length in bytes */
  const char *value;  /**< Header value */
  size_t value_len;   /**< Value length in bytes */
  int never_index;    /**< Sensitive - never add to dynamic table */
} SocketHPACK_Header;

/* ============================================================================
 * Dynamic Table
 * ============================================================================ */

/**
 * HPACK dynamic table (opaque type)
 */
typedef struct SocketHPACK_Table *SocketHPACK_Table_T;

/**
 * SocketHPACK_Table_new - Create dynamic table
 * @max_size: Maximum table size in bytes (includes 32-byte overhead per entry)
 * @arena: Memory arena for allocations
 *
 * Creates a new dynamic table with the specified maximum size.
 * The table uses a circular buffer for O(1) FIFO operations.
 *
 * Returns: New table instance
 * Raises: SocketHPACK_Error on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHPACK_Table_T SocketHPACK_Table_new (size_t max_size,
                                                  Arena_T arena);

/**
 * SocketHPACK_Table_free - Free dynamic table
 * @table: Pointer to table pointer (will be set to NULL)
 *
 * Frees the dynamic table. Memory is returned to the arena.
 * Thread-safe: No
 */
extern void SocketHPACK_Table_free (SocketHPACK_Table_T *table);

/**
 * SocketHPACK_Table_set_max_size - Update maximum table size
 * @table: Dynamic table
 * @max_size: New maximum size in bytes
 *
 * Updates the maximum table size, evicting entries as needed.
 * This corresponds to a SETTINGS_HEADER_TABLE_SIZE update.
 *
 * Thread-safe: No
 */
extern void SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table,
                                            size_t max_size);

/**
 * SocketHPACK_Table_size - Get current table size in bytes
 * @table: Dynamic table
 *
 * Returns: Current size (sum of all entry sizes including overhead)
 * Thread-safe: No
 */
extern size_t SocketHPACK_Table_size (SocketHPACK_Table_T table);

/**
 * SocketHPACK_Table_count - Get number of entries
 * @table: Dynamic table
 *
 * Returns: Number of entries in the table
 * Thread-safe: No
 */
extern size_t SocketHPACK_Table_count (SocketHPACK_Table_T table);

/**
 * SocketHPACK_Table_max_size - Get maximum table size
 * @table: Dynamic table
 *
 * Returns: Maximum size in bytes
 * Thread-safe: No
 */
extern size_t SocketHPACK_Table_max_size (SocketHPACK_Table_T table);

/**
 * SocketHPACK_Table_get - Get entry by index
 * @table: Dynamic table
 * @index: Entry index (1-based, relative to dynamic table start)
 * @header: Output header structure
 *
 * Retrieves an entry from the dynamic table by index.
 * Index 1 is the most recently added entry.
 *
 * Returns: HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range
 * Thread-safe: No
 */
extern SocketHPACK_Result SocketHPACK_Table_get (SocketHPACK_Table_T table,
                                                 size_t index,
                                                 SocketHPACK_Header *header);

/**
 * SocketHPACK_Table_add - Add entry to dynamic table
 * @table: Dynamic table
 * @name: Header name
 * @name_len: Name length
 * @value: Header value
 * @value_len: Value length
 *
 * Adds a new entry to the dynamic table. May evict older entries
 * if the table size would exceed the maximum.
 *
 * Returns: HPACK_OK on success
 * Thread-safe: No
 */
extern SocketHPACK_Result SocketHPACK_Table_add (SocketHPACK_Table_T table,
                                                 const char *name,
                                                 size_t name_len,
                                                 const char *value,
                                                 size_t value_len);

/* ============================================================================
 * Encoder
 * ============================================================================ */

/**
 * HPACK encoder (opaque type)
 */
typedef struct SocketHPACK_Encoder *SocketHPACK_Encoder_T;

/**
 * Encoder configuration
 */
typedef struct
{
  size_t max_table_size; /**< Maximum dynamic table size */
  int huffman_encode;    /**< Use Huffman encoding (default: 1) */
  int use_indexing;      /**< Add headers to dynamic table (default: 1) */
} SocketHPACK_EncoderConfig;

/**
 * SocketHPACK_encoder_config_defaults - Initialize encoder config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes
 */
extern void
SocketHPACK_encoder_config_defaults (SocketHPACK_EncoderConfig *config);

/**
 * SocketHPACK_Encoder_new - Create encoder
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena for allocations
 *
 * Creates a new HPACK encoder with the specified configuration.
 *
 * Returns: New encoder instance
 * Raises: SocketHPACK_Error on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config,
                         Arena_T arena);

/**
 * SocketHPACK_Encoder_free - Free encoder
 * @encoder: Pointer to encoder pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHPACK_Encoder_free (SocketHPACK_Encoder_T *encoder);

/**
 * SocketHPACK_Encoder_encode - Encode header block
 * @encoder: Encoder instance
 * @headers: Array of headers to encode
 * @count: Number of headers
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Encodes a header block using HPACK compression.
 *
 * Returns: Bytes written, or -1 on error
 * Thread-safe: No
 */
extern ssize_t SocketHPACK_Encoder_encode (SocketHPACK_Encoder_T encoder,
                                           const SocketHPACK_Header *headers,
                                           size_t count, unsigned char *output,
                                           size_t output_size);

/**
 * SocketHPACK_Encoder_set_table_size - Signal table size change
 * @encoder: Encoder
 * @max_size: New maximum size
 *
 * Signals that a dynamic table size update should be emitted
 * at the start of the next header block.
 *
 * Thread-safe: No
 */
extern void SocketHPACK_Encoder_set_table_size (SocketHPACK_Encoder_T encoder,
                                                size_t max_size);

/**
 * SocketHPACK_Encoder_get_table - Get encoder's dynamic table
 * @encoder: Encoder
 *
 * Returns: Dynamic table (for inspection/debugging)
 * Thread-safe: No
 */
extern SocketHPACK_Table_T
SocketHPACK_Encoder_get_table (SocketHPACK_Encoder_T encoder);

/* ============================================================================
 * Decoder
 * ============================================================================ */

/**
 * HPACK decoder (opaque type)
 */
typedef struct SocketHPACK_Decoder *SocketHPACK_Decoder_T;

/**
 * Decoder configuration
 */
typedef struct
{
  size_t max_table_size;       /**< Maximum dynamic table size */
  size_t max_header_size;      /**< Maximum individual header size */
  size_t max_header_list_size; /**< Maximum total decoded size */
} SocketHPACK_DecoderConfig;

/**
 * SocketHPACK_decoder_config_defaults - Initialize decoder config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes
 */
extern void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config);

/**
 * SocketHPACK_Decoder_new - Create decoder
 * @config: Configuration (NULL for defaults)
 * @arena: Memory arena for allocations
 *
 * Creates a new HPACK decoder with the specified configuration.
 *
 * Returns: New decoder instance
 * Raises: SocketHPACK_Error on allocation failure
 * Thread-safe: Yes (arena must be thread-safe or thread-local)
 */
extern SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config,
                         Arena_T arena);

/**
 * SocketHPACK_Decoder_free - Free decoder
 * @decoder: Pointer to decoder pointer (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketHPACK_Decoder_free (SocketHPACK_Decoder_T *decoder);

/**
 * SocketHPACK_Decoder_decode - Decode header block
 * @decoder: Decoder instance
 * @input: Encoded header block
 * @input_len: Block length
 * @headers: Output array for decoded headers
 * @max_headers: Maximum headers to decode
 * @header_count: Output - number of headers decoded
 * @arena: Arena for header string allocation
 *
 * Decodes a complete HPACK header block in one call.
 * Header strings are allocated from the provided arena.
 *
 * Returns: Result code
 * Thread-safe: No
 */
extern SocketHPACK_Result
SocketHPACK_Decoder_decode (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            SocketHPACK_Header *headers, size_t max_headers,
                            size_t *header_count, Arena_T arena);

/**
 * SocketHPACK_Decoder_set_table_size - Handle SETTINGS table size update
 * @decoder: Decoder
 * @max_size: New maximum size from SETTINGS frame
 *
 * Thread-safe: No
 */
extern void SocketHPACK_Decoder_set_table_size (SocketHPACK_Decoder_T decoder,
                                                size_t max_size);

/**
 * SocketHPACK_Decoder_get_table - Get decoder's dynamic table
 * @decoder: Decoder
 *
 * Returns: Dynamic table (for inspection/debugging)
 * Thread-safe: No
 */
extern SocketHPACK_Table_T
SocketHPACK_Decoder_get_table (SocketHPACK_Decoder_T decoder);

/* ============================================================================
 * Huffman Coding
 * ============================================================================ */

/**
 * SocketHPACK_huffman_encode - Huffman encode string
 * @input: Input string
 * @input_len: Input length
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Encodes a string using the HPACK Huffman table (RFC 7541 Appendix B).
 *
 * Returns: Encoded length, or -1 on error (buffer too small)
 * Thread-safe: Yes
 */
extern ssize_t SocketHPACK_huffman_encode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * SocketHPACK_huffman_decode - Huffman decode string
 * @input: Encoded input
 * @input_len: Input length
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Decodes a Huffman-encoded string using DFA-based decoding.
 * Validates padding (max 7 bits, all 1s).
 *
 * Returns: Decoded length, or -1 on error
 * Thread-safe: Yes
 */
extern ssize_t SocketHPACK_huffman_decode (const unsigned char *input,
                                           size_t input_len,
                                           unsigned char *output,
                                           size_t output_size);

/**
 * SocketHPACK_huffman_encoded_size - Calculate encoded size
 * @input: Input string
 * @input_len: Input length
 *
 * Calculates the size of the Huffman-encoded output in bytes.
 *
 * Returns: Encoded size in bytes
 * Thread-safe: Yes
 */
extern size_t SocketHPACK_huffman_encoded_size (const unsigned char *input,
                                                size_t input_len);

/* ============================================================================
 * Integer Coding (RFC 7541 Section 5.1)
 * ============================================================================ */

/**
 * SocketHPACK_int_encode - Encode integer with prefix
 * @value: Integer value to encode
 * @prefix_bits: Number of prefix bits (1-8)
 * @output: Output buffer
 * @output_size: Buffer size
 *
 * Encodes an integer using HPACK's variable-length encoding.
 *
 * Returns: Bytes written
 * Thread-safe: Yes
 */
extern size_t SocketHPACK_int_encode (uint64_t value, int prefix_bits,
                                      unsigned char *output,
                                      size_t output_size);

/**
 * SocketHPACK_int_decode - Decode integer with prefix
 * @input: Input buffer
 * @input_len: Input length
 * @prefix_bits: Number of prefix bits (1-8)
 * @value: Output value
 * @consumed: Output bytes consumed
 *
 * Decodes an HPACK-encoded integer.
 *
 * Returns: Result code
 * Thread-safe: Yes
 */
extern SocketHPACK_Result SocketHPACK_int_decode (const unsigned char *input,
                                                  size_t input_len,
                                                  int prefix_bits,
                                                  uint64_t *value,
                                                  size_t *consumed);

/* ============================================================================
 * Static Table Lookup
 * ============================================================================ */

/**
 * SocketHPACK_static_get - Get entry from static table
 * @index: Entry index (1-61)
 * @header: Output header structure
 *
 * Retrieves an entry from the static table by index.
 *
 * Returns: HPACK_OK on success, HPACK_ERROR_INVALID_INDEX if out of range
 * Thread-safe: Yes
 */
extern SocketHPACK_Result SocketHPACK_static_get (size_t index,
                                                  SocketHPACK_Header *header);

/**
 * SocketHPACK_static_find - Find entry in static table
 * @name: Header name
 * @name_len: Name length
 * @value: Header value (NULL to match name only)
 * @value_len: Value length
 *
 * Searches for an entry in the static table.
 *
 * Returns: Index (1-61) on exact match, negative index if only name matches, 0 if not found
 * Thread-safe: Yes
 */
extern int SocketHPACK_static_find (const char *name, size_t name_len,
                                    const char *value, size_t value_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * SocketHPACK_result_string - Get error description
 * @result: Result code
 *
 * Returns: Static string describing the result
 * Thread-safe: Yes
 */
extern const char *SocketHPACK_result_string (SocketHPACK_Result result);

#endif /* SOCKETHPACK_INCLUDED */

