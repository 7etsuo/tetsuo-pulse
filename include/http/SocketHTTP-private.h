/**
 * @file SocketHTTP-private.h
 * @brief Internal HTTP core structures and helper functions.
 * @ingroup http
 *
 * This header contains internal structures and helper functions for the HTTP
 * module. NOT for public consumption - use SocketHTTP.h instead.
 *
 * Contains:
 * - Header collection internal structures (hash table + linked list)
 * - URI parser state machine internals
 * - Internal helper functions for case-insensitive operations
 * - Private utility functions for HTTP processing
 *
 * Thread safety: Functions in this header are not thread-safe unless
 * documented.
 *
 * @see SocketHTTP.h for public API.
 * @see SocketHTTP1-private.h for HTTP/1.1 internal structures.
 * @see SocketHTTP2-private.h for HTTP/2 internal structures.
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
 * @brief Hash table bucket count for header collections (internal constant).
 * @internal
 * @ingroup http
 *
 * Fixed prime number (31) providing good distribution for typical HTTP header
 * counts (10-30). Balances low collision rate with minimal memory overhead.
 *
 * @see sockethttp_hash_name() for the hashing function used.
 * @threadsafe Yes - compile-time constant.
 * @see SocketHTTP_Headers::buckets for the hash table implementation.
 */
#define SOCKETHTTP_HEADER_BUCKETS 31

/**
 * @brief Individual HTTP header entry (name-value pair).
 * @internal
 * @ingroup http
 *
 * Internal node structure used by SocketHTTP_Headers_T for storing individual
 * headers in both hash table collision chains and insertion-order
 * doubly-linked list.
 *
 * Header names are stored case-preserved but looked up case-insensitively.
 * Both name and value are null-terminated C strings allocated from the
 * containing headers' arena.
 *
 * @note All fields are private; access via SocketHTTP_Headers_* public
 * functions only.
 * @see SocketHTTP_Headers_T for the containing collection.
 * @see sockethttp_name_equal() for case-insensitive name matching.
 * @see sockethttp_hash_name() for hash computation.
 */
typedef struct HeaderEntry
{
  char *name;       /**< Header name (case-preserved, null-terminated,
                       arena-allocated) */
  size_t name_len;  /**< Length of name excluding null terminator */
  char *value;      /**< Header value (null-terminated, arena-allocated) */
  size_t value_len; /**< Length of value excluding null terminator */

  struct HeaderEntry
      *hash_next; /**< Next entry in same hash bucket (collision resolution) */
  struct HeaderEntry
      *list_next; /**< Next entry in insertion-order doubly-linked list */
  struct HeaderEntry
      *list_prev; /**< Previous entry in insertion-order doubly-linked list */
} HeaderEntry;

/**
 * @brief Internal implementation of SocketHTTP_Headers_T header collection.
 * @internal
 * @ingroup http
 *
 * Private structure providing case-insensitive header lookup via hash table
 * (separate chaining) and ordered iteration via doubly-linked list.
 *
 * All memory allocations (entries, strings) from provided arena.
 * Not thread-safe; external locking required for concurrent access.
 *
 * @note Direct field access prohibited; use public SocketHTTP_Headers_*
 * functions.
 * @see SocketHTTP_Headers_T public opaque type.
 * @see HeaderEntry for individual header nodes.
 * @see sockethttp_hash_name() and sockethttp_name_equal() for internal lookup
 * logic.
 */
struct SocketHTTP_Headers
{
  Arena_T arena; /**< Arena for all allocations in this collection */
  HeaderEntry *buckets[SOCKETHTTP_HEADER_BUCKETS]; /**< Hash table buckets
                                                      (fixed-size array) */
  HeaderEntry *first; /**< Head of insertion-order doubly-linked list (or NULL
                         if empty) */
  HeaderEntry *last;  /**< Tail of insertion-order doubly-linked list (or NULL
                         if empty) */
  size_t count;       /**< Number of headers currently stored */
  size_t
      total_size; /**< Cumulative size of all header names + values (bytes) */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Hash HTTP header name for case-insensitive bucket lookup.
 * @internal
 * @ingroup http
 * @param name Pointer to null-terminated or length-bounded header name bytes.
 * @param len Exact byte length of name (excluding null if present).
 * @return Computed hash modulo SOCKETHTTP_HEADER_BUCKETS (0-30).
 * @threadsafe Yes - pure function, no side effects or shared state.
 *
 * Implements case-insensitive DJB2 hash variant: folds input to lowercase
 * during hashing for consistent header name bucketing per RFC 9110.
 * Designed for low collision rate with typical HTTP headers.
 *
 * @see SOCKETHTTP_HEADER_BUCKETS for table size.
 * @see sockethttp_name_equal() companion for equality checks.
 * @see SocketHTTP_Headers_get() for usage in public API.
 */
static inline unsigned sockethttp_hash_name (const char *name, size_t len);

/**
 * @brief Perform case-insensitive comparison of HTTP header names.
 * @internal
 * @ingroup http
 * @param a Pointer to first header name bytes.
 * @param a_len Byte length of first name.
 * @param b Pointer to second header name bytes.
 * @param b_len Byte length of second name.
 * @return 1 if names match case-insensitively and lengths equal, 0 otherwise.
 * @threadsafe Yes - pure function using standard library strncasecmp().
 *
 * Compares HTTP header field names per RFC 9110 §5.2 rule: field names
 * case-insensitive. Early length check avoids unnecessary strncasecmp call.
 * Used in hash table lookup collision resolution.
 *
 * @note Does not validate input as tokens; assumes pre-validated names.
 * @see sockethttp_hash_name() for complementary hashing.
 * @see strncasecmp(3) for implementation details.
 * @see SocketHTTP_Headers_get() and SocketHTTP_Headers_has() for usage.
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
 * @brief Internal states for DFA-based URI parser (RFC 3986 compliant).
 * @internal
 * @ingroup http
 *
 * State machine states used by SocketHTTP_URI_parse() for parsing URI
 * components: scheme://[userinfo@]host[:port]/path?query#fragment
 *
 * Handles generic syntax including IPv6 literals, percent-encoding, and
 * reserved chars. Invalid transitions lead to SocketHTTP_InvalidURI exception.
 *
 * @see SocketHTTP_URI_parse() public API.
 * @see SocketHTTP_URI for parsed result structure.
 * @see docs/HTTP.md for URI handling in HTTP context.
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
 * @brief Lookup table for valid HTTP token characters (tchar) per RFC 9110
 * §5.6.
 * @internal
 * @ingroup http
 *
 * Static array[256] where non-zero value indicates the character is a valid
 * token char for HTTP header field names and values (excluding separators like
 * :, ;, etc.).
 *
 * tchar ::= "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 *
 * Used for fast validation in header parsing and media type processing.
 *
 * @see SOCKETHTTP_IS_TCHAR() macro for usage.
 * @threadsafe Yes - static const array, read-only.
 * @see SocketHTTP_Headers_add() for header validation context.
 */
extern const unsigned char sockethttp_tchar_table[256];

/**
 * @brief Check if a character is a valid HTTP token character (tchar).
 * @internal
 * @ingroup http
 * @param c Character to validate (automatically promoted to unsigned char via
 * cast)
 * @return Non-zero if valid tchar per RFC 9110, zero otherwise.
 *
 * Fast O(1) table lookup used throughout HTTP parsing for validating
 * header field names, values, media type parameters, etc.
 *
 * @see sockethttp_tchar_table for the underlying validation table.
 * @threadsafe Yes - macro, pure function.
 * @see RFC 9110 §5.6 for complete tchar grammar.
 */
#define SOCKETHTTP_IS_TCHAR(c) (sockethttp_tchar_table[(unsigned char)(c)])

/**
 * @brief Lookup table for URI unreserved characters per RFC 3986 §2.3.
 * @internal
 * @ingroup http
 *
 * Static array[256] where non-zero value indicates characters that do not
 * require percent-encoding in URI components: ALPHA / DIGIT / "-" / "." / "_"
 * / "~"
 *
 * Used in URI encoding to identify safe characters and in decoding validation.
 *
 * @see SOCKETHTTP_IS_UNRESERVED() macro.
 * @threadsafe Yes - static const array, read-only.
 * @see SocketHTTP_URI_encode() and SocketHTTP_URI_decode().
 * @see RFC 3986 §2.3 for unreserved set definition.
 */
extern const unsigned char sockethttp_uri_unreserved[256];

/**
 * @brief Test if a character is URI unreserved (no percent-encoding required).
 * @internal
 * @ingroup http
 * @param c Character to test (promoted to unsigned char)
 * @return Non-zero if unreserved per RFC 3986, zero otherwise.
 *
 * Used in URI encoding to skip encoding for safe characters and in validation.
 *
 * @see sockethttp_uri_unreserved table.
 * @see SocketHTTP_URI_encode() for encoding context.
 * @threadsafe Yes - macro, pure function.
 * @see RFC 3986 §2.3 unreserved characters.
 */
#define SOCKETHTTP_IS_UNRESERVED(c)                                           \
  (sockethttp_uri_unreserved[(unsigned char)(c)])

/**
 * @brief Hexadecimal digit value lookup table for decoding and validation.
 * @internal
 * @ingroup http
 *
 * Static array[256] mapping ASCII characters to their hex value (0-15) for
 * valid digits, or 255 for invalid characters. Supports '0'-'9', 'a'-'f',
 * 'A'-'F'.
 *
 * Essential for percent-decoding (%XX sequences) in URIs and chunked encoding
 * sizes.
 *
 * @see SOCKETHTTP_HEX_VALUE() macro.
 * @see SocketHTTP_URI_decode() for URI percent-decoding usage.
 * @see SocketHTTP1 chunk size parsing in HTTP/1.1.
 */
extern const unsigned char sockethttp_hex_value[256];

/**
 * @brief Extract numeric value from hexadecimal digit character.
 * @internal
 * @ingroup http
 * @param c ASCII character to convert ('0'-'9', 'a'-'f', 'A'-'F')
 * @return 0-15 for valid hex digit, 255 for invalid input.
 *
 * Constant-time table lookup used in percent-decoding and hex parsing.
 * Invalid characters (non-hex) return 255 to simplify error checking.
 *
 * @see sockethttp_hex_value table.
 * @threadsafe Yes - static const array, read-only.
 * @threadsafe Yes - macro, pure function.
 * @see SocketHTTP_URI_decode() usage example.
 */
#define SOCKETHTTP_HEX_VALUE(c) (sockethttp_hex_value[(unsigned char)(c)])

#endif /* SOCKETHTTP_PRIVATE_INCLUDED */
