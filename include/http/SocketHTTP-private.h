/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTP-private.h
 * @brief Internal HTTP core structures and helper functions.
 * @ingroup http
 *
 * Internal structures and helpers for HTTP module. NOT for public consumption.
 * Contains header collection internals (hash table + linked list), URI parser
 * state machine, and character classification utilities.
 */

#ifndef SOCKETHTTP_PRIVATE_INCLUDED
#define SOCKETHTTP_PRIVATE_INCLUDED

#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include <string.h> /* for strncasecmp */

/**
 * @brief Hash table bucket count for header collections.
 * @internal
 *
 * Fixed prime (31) for good distribution with typical HTTP header counts
 * (10-30).
 */
#define SOCKETHTTP_HEADER_BUCKETS 31

/**
 * @brief Individual HTTP header entry (name-value pair).
 * @internal
 *
 * Node for hash table collision chains and insertion-order linked list.
 * Names are case-preserved but looked up case-insensitively.
 */
typedef struct HeaderEntry
{
  char *name;       /**< Header name (case-preserved, arena-allocated) */
  size_t name_len;  /**< Length of name excluding null */
  char *value;      /**< Header value (arena-allocated) */
  size_t value_len; /**< Length of value excluding null */
  unsigned hash;    /**< Cached hash bucket index */

  struct HeaderEntry *hash_next; /**< Next in hash bucket chain */
  struct HeaderEntry *list_next; /**< Next in insertion order */
  struct HeaderEntry *list_prev; /**< Previous in insertion order */
} HeaderEntry;

/**
 * @brief Internal implementation of SocketHTTP_Headers_T header collection.
 * @internal
 *
 * Case-insensitive header lookup via hash table (separate chaining) and
 * ordered iteration via doubly-linked list. All allocations from arena.
 * Not thread-safe.
 */
struct SocketHTTP_Headers
{
  Arena_T arena;                                    /**< Arena for allocations */
  HeaderEntry *buckets[SOCKETHTTP_HEADER_BUCKETS]; /**< Hash table buckets */
  HeaderEntry *first; /**< Head of insertion-order list */
  HeaderEntry *last;  /**< Tail of insertion-order list */
  size_t count;       /**< Number of headers stored */
  size_t total_size;  /**< Total size of names + values (bytes) */
};

/**
 * @brief Case-insensitive comparison of HTTP header names.
 * @internal
 *
 * RFC 9110 §5.2 compliant. Returns 1 if equal, 0 otherwise.
 */
static inline int
sockethttp_name_equal (const char *a, size_t a_len, const char *b,
                       size_t b_len)
{
  if (a_len != b_len)
    return 0;
  return strncasecmp (a, b, a_len) == 0;
}

/**
 * @brief Internal states for DFA-based URI parser (RFC 3986).
 * @internal
 *
 * Parses scheme://[userinfo@]host[:port]/path?query#fragment including IPv6
 * literals and percent-encoding.
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

/**
 * @brief Lookup table for valid HTTP token characters (tchar) per RFC 9110
 * §5.6.
 * @internal
 *
 * tchar ::= "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
 *           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 */
extern const unsigned char sockethttp_tchar_table[256];

/**
 * @brief Check if character is valid HTTP token character (RFC 9110 §5.6).
 * @internal
 */
#define SOCKETHTTP_IS_TCHAR(c) (sockethttp_tchar_table[(unsigned char)(c)])

/**
 * @brief Lookup table for URI unreserved characters per RFC 3986 §2.3.
 * @internal
 *
 * Characters not requiring percent-encoding: ALPHA / DIGIT / "-" / "." / "_" /
 * "~"
 */
extern const unsigned char sockethttp_uri_unreserved[256];

/**
 * @brief Test if character is URI unreserved (RFC 3986 §2.3).
 * @internal
 */
#define SOCKETHTTP_IS_UNRESERVED(c)                                           \
  (sockethttp_uri_unreserved[(unsigned char)(c)])

/**
 * @brief Hexadecimal digit value lookup table.
 * @internal
 *
 * Maps '0'-'9', 'a'-'f', 'A'-'F' to 0-15, invalid chars to 255.
 * Used for percent-decoding and chunked encoding.
 */
extern const unsigned char sockethttp_hex_value[256];

/**
 * @brief Extract hex digit value (0-15) or 255 if invalid.
 * @internal
 */
#define SOCKETHTTP_HEX_VALUE(c) (sockethttp_hex_value[(unsigned char)(c)])

/**
 * @brief Skip whitespace (space/tab) for OWS handling.
 * @internal
 */
static inline const char *
sockethttp_skip_whitespace (const char *p)
{
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

/**
 * @brief Skip delimiters (space/tab/comma) for list parsing.
 * @internal
 */
static inline const char *
sockethttp_skip_delimiters (const char *p)
{
  while (*p == ' ' || *p == '\t' || *p == ',')
    p++;
  return p;
}

/**
 * @brief Check if character is token boundary (NUL/comma/space/tab).
 * @internal
 */
static inline int
sockethttp_is_token_boundary (char c)
{
  return c == '\0' || c == ',' || c == ' ' || c == '\t';
}

#endif /* SOCKETHTTP_PRIVATE_INCLUDED */
