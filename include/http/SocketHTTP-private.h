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
#include <string.h>

#define SOCKETHTTP_HEADER_BUCKETS 32
#define SOCKETHTTP_HEADER_BUCKET_MASK (SOCKETHTTP_HEADER_BUCKETS - 1)

typedef struct HeaderEntry
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
  unsigned hash;
  struct HeaderEntry *hash_next;
  struct HeaderEntry *list_next;
  struct HeaderEntry *list_prev;
  int is_ref; /* 1 = zero-copy reference, 0 = owned copy */
} HeaderEntry;

struct SocketHTTP_Headers
{
  Arena_T arena;
  HeaderEntry *buckets[SOCKETHTTP_HEADER_BUCKETS];
  HeaderEntry *first;
  HeaderEntry *last;
  size_t count;
  size_t total_size;
};

static inline int
sockethttp_name_equal (const char *a, size_t a_len, const char *b,
                       size_t b_len)
{
  if (a_len != b_len)
    return 0;
  return strncasecmp (a, b, a_len) == 0;
}

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

extern const unsigned char sockethttp_tchar_table[256];
#define SOCKETHTTP_IS_TCHAR(c) (sockethttp_tchar_table[(unsigned char)(c)])

extern const unsigned char sockethttp_uri_unreserved[256];
#define SOCKETHTTP_IS_UNRESERVED(c)                                           \
  (sockethttp_uri_unreserved[(unsigned char)(c)])

extern const unsigned char sockethttp_hex_value[256];
#define SOCKETHTTP_HEX_VALUE(c) (sockethttp_hex_value[(unsigned char)(c)])

static inline const char *
sockethttp_skip_whitespace (const char *p)
{
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

static inline const char *
sockethttp_skip_delimiters (const char *p)
{
  while (*p == ' ' || *p == '\t' || *p == ',')
    p++;
  return p;
}

static inline int
sockethttp_is_token_boundary (char c)
{
  return c == '\0' || c == ',' || c == ' ' || c == '\t';
}

/* ============================================================================
 * HTTP PORT UTILITIES
 * ============================================================================
 */

/**
 * @brief Check if port is default for HTTP/HTTPS scheme.
 * @param port Port number (-1 for default, or explicit port).
 * @param is_https True if HTTPS/secure scheme, false for HTTP.
 * @return True if port is default (omit from Host header), false otherwise.
 *
 * Default ports:
 * - HTTP: 80 or -1 (unspecified)
 * - HTTPS: 443 or -1 (unspecified)
 *
 * Used to determine whether to include port in Host header per RFC 7230:
 * "A sender MUST NOT generate the port subcomponent in Host if the port
 *  is the default port for the request's scheme."
 */
static inline int
is_default_http_port (int port, int is_https)
{
  return port == -1 || port == (is_https ? 443 : 80);
}

/* ============================================================================
 * RFC 7230 WHITESPACE HANDLING
 * ============================================================================
 */

/**
 * @brief Skip optional whitespace (OWS) as defined by RFC 7230.
 * @param p Current position in string.
 * @param end End of string (exclusive).
 * @return New position after skipping SP (0x20) and HTAB (0x09) characters.
 *
 * OWS (Optional WhiteSpace) from RFC 7230 Section 3.2.3:
 *   OWS = *( SP / HTAB )
 *
 * Used for parsing HTTP headers and other protocol elements.
 */
static inline const char *
skip_ows (const char *p, const char *end)
{
  while (p < end && (*p == ' ' || *p == '\t'))
    p++;
  return p;
}

#endif /* SOCKETHTTP_PRIVATE_INCLUDED */
