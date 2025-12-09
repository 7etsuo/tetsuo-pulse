/**
 * SocketHTTP-private.h - Internal HTTP Core Structures
 *
 * Part of the Socket Library
 *
 * This header contains internal structures for the HTTP module.
 * NOT for public consumption - use SocketHTTP.h instead.
 */

#ifndef SOCKETHTTP_PRIVATE_INCLUDED
#define SOCKETHTTP_PRIVATE_INCLUDED

#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include <string.h> /* for strncasecmp */

/* ============================================================================
 * Header Collection Internals
 * ============================================================================
 */

/**
 * Hash table bucket count (prime for better distribution)
 * 31 provides good balance for typical header counts (10-30)
 */
#define SOCKETHTTP_HEADER_BUCKETS 31

/**
 * Single header entry in the collection
 */
typedef struct HeaderEntry
{
  char *name; /**< Header name (case-preserved, arena-allocated) */
  size_t name_len;
  char *value; /**< Header value (arena-allocated) */
  size_t value_len;

  struct HeaderEntry *hash_next; /**< Next entry in hash bucket chain */
  struct HeaderEntry *list_next; /**< Next entry in insertion order list */
  struct HeaderEntry *list_prev; /**< Previous entry in insertion order */
} HeaderEntry;

/**
 * Header collection internal structure
 *
 * Uses hash table with separate chaining for O(1) average lookup.
 * Maintains insertion order via doubly-linked list for iteration.
 */
struct SocketHTTP_Headers
{
  Arena_T arena;                                   /**< Memory arena */
  HeaderEntry *buckets[SOCKETHTTP_HEADER_BUCKETS]; /**< Hash table */
  HeaderEntry *first; /**< First header (insertion order) */
  HeaderEntry *last;  /**< Last header (insertion order) */
  size_t count;       /**< Total header count */
  size_t total_size;  /**< Total size of all headers */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * sockethttp_hash_name - Hash header name (case-insensitive)
 * @name: Header name
 * @len: Name length
 *
 * Uses djb2 hash on lowercased characters.
 *
 * Returns: Hash value in range [0, SOCKETHTTP_HEADER_BUCKETS)
 */

/**
 * sockethttp_name_equal - Compare header names (case-insensitive)
 * @a: First name
 * @a_len: First name length
 * @b: Second name
 * @b_len: Second name length
 *
 * Returns: 1 if equal (case-insensitive), 0 otherwise
 */
static inline int
sockethttp_name_equal (const char *a, size_t a_len, const char *b,
                       size_t b_len)
{
  if (a_len != b_len)
    return 0;
  return strncasecmp (a, b, a_len) == 0;
}

/* ============================================================================
 * URI Parser Internals
 * ============================================================================
 */

/**
 * URI parser state machine states
 */
typedef enum
{
  URI_STATE_START,
  URI_STATE_SCHEME,
  URI_STATE_SCHEME_COLON,
  URI_STATE_AUTHORITY_START,
  URI_STATE_AUTHORITY,
  URI_STATE_HOST,
  URI_STATE_HOST_IPV6,
  URI_STATE_PORT,
  URI_STATE_PATH,
  URI_STATE_QUERY,
  URI_STATE_FRAGMENT
} URIParserState;

/* ============================================================================
 * Character Classification Tables
 * ============================================================================
 */

/**
 * Token character table for RFC 9110
 * tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 */
extern const unsigned char sockethttp_tchar_table[256];

/**
 * Check if character is valid token character
 */
#define SOCKETHTTP_IS_TCHAR(c) (sockethttp_tchar_table[(unsigned char)(c)])

/**
 * Unreserved characters for URI per RFC 3986
 * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
extern const unsigned char sockethttp_uri_unreserved[256];

/**
 * Check if character is unreserved (doesn't need encoding)
 */
#define SOCKETHTTP_IS_UNRESERVED(c)                                           \
  (sockethttp_uri_unreserved[(unsigned char)(c)])

/**
 * Hex value table for percent decoding
 * Returns 0-15 for '0'-'9', 'a'-'f', 'A'-'F', or 255 for invalid
 */
extern const unsigned char sockethttp_hex_value[256];

/**
 * Get hex value or 255 if invalid
 */
#define SOCKETHTTP_HEX_VALUE(c) (sockethttp_hex_value[(unsigned char)(c)])

#endif /* SOCKETHTTP_PRIVATE_INCLUDED */
