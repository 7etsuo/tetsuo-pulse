/**
 * @file SocketHPACK-private.h
 * @brief Internal HPACK header compression structures and constants.
 * @ingroup http
 * @ingroup hpack_private
 * @defgroup hpack_private HPACK Private Implementation Details
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * This header contains internal structures for the HPACK header compression implementation.
 * NOT for public consumption - use SocketHPACK.h instead.
 *
 * Key internals:
 * - Dynamic table circular buffer implementation
 * - Huffman encoding/decoding DFA tables and state machines
 * - Encoder/decoder internal structures
 * - HPACK integer encoding/decoding primitives
 * - Static table access functions
 * - Compression bomb prevention limits
 *
 * The implementation uses DFA-based Huffman decoding for O(n) single-pass
 * decompression with security hardening against compression bombs.
 *
 * @see SocketHPACK.h for public HPACK API.
 * @see SocketHTTP2.h for HTTP/2 integration.
 * @see SocketHTTP-private.h for core HTTP internal structures.
 * @see SocketHPACK_Encoder_new() for public encoder creation.
 * @see SocketHPACK_Decoder_new() for public decoder creation.
 */

#ifndef SOCKETHPACK_PRIVATE_INCLUDED
#define SOCKETHPACK_PRIVATE_INCLUDED

#include "http/SocketHPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/**
 * @brief Estimated average size of a dynamic HPACK table entry in bytes.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Used for initial capacity calculation to minimize resizes.
 */
#define HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50

/**
 * @brief Minimum capacity for dynamic table (power-of-2 for efficient modulo operations).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/**
 * @brief Total number of symbols in the HPACK Huffman table (ASCII 0-255 + End-of-String).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_SYMBOLS 257

/**
 * @brief End-of-String (EOS) symbol code in Huffman table.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_EOS 256

/**
 * @brief Maximum length of a Huffman code in bits (per RFC 7541).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_MAX_BITS 30

/**
 * @brief Number of states in the Huffman DFA decoder table.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_NUM_STATES 256

/**
 * @brief Special value indicating an invalid or error state in Huffman DFA.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_STATE_ERROR 0xFF

/**
 * @brief Special value marking an accept state in Huffman DFA transitions.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 */
#define HPACK_HUFFMAN_STATE_ACCEPT 0xFE

/* ============================================================================
 * Dynamic Table Entry
 * ============================================================================
 */

/**
 * @brief Entry in the HPACK dynamic table storing a header field name-value pair.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Stored in circular buffer. Strings are allocated from arena and managed by SocketHPACK_Table_T.
 *
 * @see SocketHPACK_Table_T
 * @see RFC 7541 Section 4.1
 */
typedef struct
{
  char *name;       /**< Header name (arena-allocated) */
  size_t name_len;  /**< Name length */
  char *value;      /**< Header value (arena-allocated) */
  size_t value_len; /**< Value length */
} HPACK_DynamicEntry;

/* ============================================================================
 * Dynamic Table Structure
 * ============================================================================
 */

/**
 * @brief Dynamic table for storing header fields in HPACK compression (RFC 7541).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Implements a circular buffer (ring buffer) for efficient eviction of oldest entries.
 * Indices follow HPACK convention: index 1 is most recent, increasing indices are older.
 * Supports dynamic resizing based on SETTINGS_HEADER_TABLE_SIZE.
 *
 * @see HPACK_DynamicEntry for individual entries.
 * @see hpack_table_evict() for eviction mechanism.
 * @see SocketHPACK_Encoder::table and SocketHPACK_Decoder::table for usage.
 */
struct SocketHPACK_Table
{
  HPACK_DynamicEntry *entries; /**< Ring buffer of dynamic entries */
  size_t capacity;             /**< Maximum number of entries (power-of-2) */
  size_t head;                 /**< Index of oldest entry */
  size_t tail;                 /**< Index for next insertion (one past newest) */
  size_t count;                /**< Current number of entries */
  size_t size;                 /**< Current total size in bytes (sum of entry sizes) */
  size_t max_size;             /**< Maximum allowed size in bytes (from settings) */
  Arena_T arena;               /**< Arena for allocating entries and strings */
};

/* ============================================================================
 * Encoder Structure
 * ============================================================================
 */

/**
 * @brief Internal structure for HPACK header encoder.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Manages dynamic table updates, Huffman encoding decisions, and indexing strategy.
 * Used by SocketHTTP2 for compressing outgoing headers.
 *
 * @see SocketHPACK_EncoderConfig for configuration options.
 * @see SocketHPACK_Table_T for dynamic table details.
 */
struct SocketHPACK_Encoder
{
  SocketHPACK_Table_T table;     /**< Dynamic table shared with decoder if symmetric */
  size_t pending_table_size;     /**< Pending dynamic table size update (0 if none) */
  int pending_table_size_update; /**< Flag indicating a table size update is queued */
  int huffman_encode;            /**< Flag to enable Huffman coding for strings */
  int use_indexing;              /**< Flag to enable dynamic table indexing */
  Arena_T arena;                 /**< Arena for temporary allocations during encoding */
};

/* ============================================================================
 * Decoder Structure
 * ============================================================================
 */

/**
 * @brief Internal structure for HPACK header decoder.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Handles decompression of HPACK-encoded headers with security checks against
 * decompression bombs (excessive expansion).
 * Used by SocketHTTP2 for processing incoming headers.
 *
 * @see SocketHPACK_DecoderConfig for configuration.
 * @see SocketHPACK_Table_T for dynamic table.
 * @warning Decompression bomb protection limits ratio of output to input bytes.
 */
struct SocketHPACK_Decoder
{
  SocketHPACK_Table_T table;      /**< Dynamic table for header field references */
  size_t max_header_size;         /**< Maximum size for a single decoded header field */
  size_t max_header_list_size;    /**< Maximum size for the entire header list */
  size_t settings_max_table_size; /**< Maximum dynamic table size from peer SETTINGS */
  Arena_T arena;                  /**< Arena for decoded header allocations */

  /* Decompression bomb protection */
  uint64_t decode_input_bytes;  /**< Cumulative input bytes processed in current session */
  uint64_t decode_output_bytes; /**< Cumulative output bytes produced in current session */
  double max_expansion_ratio;   /**< Maximum allowed output/input expansion ratio (default 10.0) */
};

/* ============================================================================
 * Static Table Entry
 * ============================================================================
 */

/**
 * @brief Structure for entries in the HPACK static table (RFC 7541 Table 2).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Contains 61 predefined HTTP header fields. Field order minimizes padding.
 * Strings are compile-time constants, no allocation needed.
 *
 * @see hpack_static_table for the full array of entries.
 * @see SocketHPACK_StaticEntry for public typedef (if exposed).
 */
typedef struct
{
  const char *name;  /**< Header field name (compile-time constant string) */
  const char *value; /**< Header field value (compile-time constant string) */
  uint8_t name_len;  /**< Length of name in bytes */
  uint8_t value_len; /**< Length of value in bytes */
} HPACK_StaticEntry;

/* ============================================================================
 * Huffman Tables (defined in SocketHPACK-huffman.c)
 * ============================================================================
 */

/**
 * @brief Entry in the HPACK Huffman encoding table for a specific symbol.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Maps a symbol (0-256) to its variable-length Huffman code.
 * Code is left-aligned in 32-bit field for easy bit manipulation.
 *
 * @see hpack_huffman_encode for the full table.
 * @see RFC 7541 Appendix B for Huffman code assignment.
 */
typedef struct
{
  uint32_t code; /**< Huffman code bits (left-aligned in 32-bit integer) */
  uint8_t bits;  /**< Number of valid bits in the code (1-30) */
} HPACK_HuffmanSymbol;

/**
 * @brief Transition entry in the Huffman decoding DFA table.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Defines state transition and output for a given input byte (nibble-indexed).
 * Supports efficient single-pass decoding with minimal branching.
 *
 * @see hpack_huffman_decode for the DFA table.
 * @see HPACK_DFA_* flags for behavior indicators.
 */
typedef struct
{
  uint8_t next_state; /**< Next state in DFA (or special values like error/accept) */
  uint8_t flags;      /**< Bit flags controlling output and error handling (HPACK_DFA_*) */
  uint8_t sym;        /**< Primary output symbol if accepting state reached */
} HPACK_HuffmanTransition;

/**
 * @brief Bit flags for Huffman DFA transition behavior.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Used in HPACK_HuffmanTransition::flags to indicate state outcomes.
 */
#define HPACK_DFA_ACCEPT 0x01 /**< Accepting state: one or more symbols emitted */
#define HPACK_DFA_EOS    0x02 /**< End-of-string symbol (256) emitted */
#define HPACK_DFA_ERROR  0x04 /**< Invalid transition: decoding error */
#define HPACK_DFA_SYM2   0x08 /**< Additional secondary symbol available in this transition */

/* External declarations for Huffman tables */
/**
 * @brief Precomputed Huffman encoding table for all 257 symbols.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Allows O(1) lookup of codes for fast encoding.
 * Defined in SocketHPACK-huffman.c.
 */
extern const HPACK_HuffmanSymbol hpack_huffman_encode[HPACK_HUFFMAN_SYMBOLS];
/**
 * @brief DFA table for Huffman decoding (state-machine transitions).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * 256 states x 16 nibbles = 4096 entries for byte-wise decoding.
 * Enables deterministic, branch-free decoding.
 * Defined in SocketHPACK-huffman.c.
 *
 * @see HPACK_HuffmanTransition for entry format.
 */
extern const HPACK_HuffmanTransition
    hpack_huffman_decode[HPACK_HUFFMAN_NUM_STATES][16];

/**
 * @brief Static table containing 61 predefined HTTP/2 header fields (RFC 7541, Appendix A).
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 *
 * Used for literal header representation without dynamic table indexing.
 * Entries indexed from 1 to 61; index 0 reserved.
 * Defined in SocketHPACK-table.c.
 *
 * @see HPACK_StaticEntry for structure.
 * @see SocketHPACK_get_static_entry() if public accessor exists.
 */
extern const HPACK_StaticEntry
    hpack_static_table[SOCKETHPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * Internal Functions
 * ============================================================================
 */

/**
 * @brief Evict oldest entries from dynamic table to free up required space.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 * @threadsafe No - modifies table state; requires external synchronization if shared.
 * @param table The dynamic table instance.
 * @param required_space Minimum bytes needed for new entry insertion.
 * @return Number of entries evicted (may be 0).
 * @throws SocketHPACK_Error if security checks fail during eviction (e.g., overflow).
 * @note Continues evicting until table->size + required_space <= table->max_size.
 * @note Calls SocketSecurity_check_add internally to prevent overflow.
 *
 * Used during encoder insertion when table exceeds capacity (called by SocketHPACK_Table_add).
 *
 * @see SocketHPACK_Table_T::size
 * @see SocketHPACK_Table_T::max_size
 * @see hpack_entry_size() for entry sizing.
 * @see SocketHPACK_Table_add() public function that triggers eviction.
 * @see @ref utilities for rate limiting and security modules.
 */
extern size_t hpack_table_evict (SocketHPACK_Table_T table,
                                 size_t required_space);

/**
 * @brief Compute the size of a dynamic table entry per RFC 7541 Section 4.1.
 * @ingroup http
 * @ingroup hpack_private
 * @internal
 * @threadsafe Yes - pure function with no side effects or shared state.
 * @param name_len Length of the header name in bytes.
 * @param value_len Length of the header value in bytes.
 * @return Total entry size = name_len + value_len + SOCKETHPACK_ENTRY_OVERHEAD (32 bytes),
 *         or SIZE_MAX if arithmetic overflow detected.
 * @note Uses SocketSecurity_check_add() to safely compute sum and prevent integer overflow.
 * @note Overhead accounts for indexing and management structures.
 *
 * Essential for table eviction and capacity checks.
 *
 * @see SocketSecurity_check_add()
 * @see hpack_table_evict()
 * @see SocketHPACK_Table_add() for usage in public table management.
 * @see SOCKETHPACK_ENTRY_OVERHEAD constant.
 * @see @ref foundation for security utilities like SocketSecurity_check_add().
 */
static inline size_t
hpack_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETHPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX; /* Overflow or invalid - caller should check */
}

/* @} */ /* hpack_private - closed earlier */
/* ============================================================================
 * Internal Functions
 * ============================================================================
 */

/**
 * @} */ /* hpack_private */

#endif /* SOCKETHPACK_PRIVATE_INCLUDED */
