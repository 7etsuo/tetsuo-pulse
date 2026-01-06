/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-static.c
 * @brief QPACK Static Table Implementation (RFC 9204 Section 3.1 + Appendix A)
 *
 * Contains the 99 predefined field line entries with 0-based indexing.
 * This is read-only data shared across all QPACK instances.
 */

#include "http/SocketQPACK.h"

#include <string.h>
#include <strings.h>

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 *
 * Key differences from HPACK (RFC 7541):
 * - QPACK uses 0-based indexing (index 0 is valid)
 * - HPACK uses 1-based indexing (index 1 is first)
 * - QPACK static table has 99 entries vs HPACK's 61 entries
 * - Table optimized for common HTTP/3 traffic patterns
 * ============================================================================
 */

/* clang-format off */
static const SocketQPACK_StaticEntry qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE] = {
  /* Index  0 */ { ":authority",                        10, "",                                         0 },
  /* Index  1 */ { ":path",                             5,  "/",                                        1 },
  /* Index  2 */ { "age",                               3,  "0",                                        1 },
  /* Index  3 */ { "content-disposition",               19, "",                                         0 },
  /* Index  4 */ { "content-length",                    14, "0",                                        1 },
  /* Index  5 */ { "cookie",                            6,  "",                                         0 },
  /* Index  6 */ { "date",                              4,  "",                                         0 },
  /* Index  7 */ { "etag",                              4,  "",                                         0 },
  /* Index  8 */ { "if-modified-since",                 17, "",                                         0 },
  /* Index  9 */ { "if-none-match",                     13, "",                                         0 },
  /* Index 10 */ { "last-modified",                     13, "",                                         0 },
  /* Index 11 */ { "link",                              4,  "",                                         0 },
  /* Index 12 */ { "location",                          8,  "",                                         0 },
  /* Index 13 */ { "referer",                           7,  "",                                         0 },
  /* Index 14 */ { "set-cookie",                        10, "",                                         0 },
  /* Index 15 */ { ":method",                           7,  "CONNECT",                                  7 },
  /* Index 16 */ { ":method",                           7,  "DELETE",                                   6 },
  /* Index 17 */ { ":method",                           7,  "GET",                                      3 },
  /* Index 18 */ { ":method",                           7,  "HEAD",                                     4 },
  /* Index 19 */ { ":method",                           7,  "OPTIONS",                                  7 },
  /* Index 20 */ { ":method",                           7,  "POST",                                     4 },
  /* Index 21 */ { ":method",                           7,  "PUT",                                      3 },
  /* Index 22 */ { ":scheme",                           7,  "http",                                     4 },
  /* Index 23 */ { ":scheme",                           7,  "https",                                    5 },
  /* Index 24 */ { ":status",                           7,  "103",                                      3 },
  /* Index 25 */ { ":status",                           7,  "200",                                      3 },
  /* Index 26 */ { ":status",                           7,  "304",                                      3 },
  /* Index 27 */ { ":status",                           7,  "404",                                      3 },
  /* Index 28 */ { ":status",                           7,  "503",                                      3 },
  /* Index 29 */ { "accept",                            6,  "*/*",                                      3 },
  /* Index 30 */ { "accept",                            6,  "application/dns-message",                  23 },
  /* Index 31 */ { "accept-encoding",                   15, "gzip, deflate, br",                        17 },
  /* Index 32 */ { "accept-ranges",                     13, "bytes",                                    5 },
  /* Index 33 */ { "access-control-allow-headers",      28, "cache-control",                            13 },
  /* Index 34 */ { "access-control-allow-headers",      28, "content-type",                             12 },
  /* Index 35 */ { "access-control-allow-origin",       27, "*",                                        1 },
  /* Index 36 */ { "cache-control",                     13, "max-age=0",                                9 },
  /* Index 37 */ { "cache-control",                     13, "max-age=2592000",                          15 },
  /* Index 38 */ { "cache-control",                     13, "max-age=604800",                           14 },
  /* Index 39 */ { "cache-control",                     13, "no-cache",                                 8 },
  /* Index 40 */ { "cache-control",                     13, "no-store",                                 8 },
  /* Index 41 */ { "cache-control",                     13, "public, max-age=31536000",                 24 },
  /* Index 42 */ { "content-encoding",                  16, "br",                                       2 },
  /* Index 43 */ { "content-encoding",                  16, "gzip",                                     4 },
  /* Index 44 */ { "content-type",                      12, "application/dns-message",                  23 },
  /* Index 45 */ { "content-type",                      12, "application/javascript",                   22 },
  /* Index 46 */ { "content-type",                      12, "application/json",                         16 },
  /* Index 47 */ { "content-type",                      12, "application/x-www-form-urlencoded",        33 },
  /* Index 48 */ { "content-type",                      12, "image/gif",                                9 },
  /* Index 49 */ { "content-type",                      12, "image/jpeg",                               10 },
  /* Index 50 */ { "content-type",                      12, "image/png",                                9 },
  /* Index 51 */ { "content-type",                      12, "text/css",                                 8 },
  /* Index 52 */ { "content-type",                      12, "text/html; charset=utf-8",                 24 },
  /* Index 53 */ { "content-type",                      12, "text/plain",                               10 },
  /* Index 54 */ { "content-type",                      12, "text/plain;charset=utf-8",                 24 },
  /* Index 55 */ { "range",                             5,  "bytes=0-",                                 8 },
  /* Index 56 */ { "strict-transport-security",         25, "max-age=31536000",                         16 },
  /* Index 57 */ { "strict-transport-security",         25, "max-age=31536000; includesubdomains",      35 },
  /* Index 58 */ { "strict-transport-security",         25, "max-age=31536000; includesubdomains; preload", 44 },
  /* Index 59 */ { "vary",                              4,  "accept-encoding",                          15 },
  /* Index 60 */ { "vary",                              4,  "origin",                                   6 },
  /* Index 61 */ { "x-content-type-options",            22, "nosniff",                                  7 },
  /* Index 62 */ { "x-xss-protection",                  16, "1; mode=block",                            13 },
  /* Index 63 */ { ":status",                           7,  "100",                                      3 },
  /* Index 64 */ { ":status",                           7,  "204",                                      3 },
  /* Index 65 */ { ":status",                           7,  "206",                                      3 },
  /* Index 66 */ { ":status",                           7,  "302",                                      3 },
  /* Index 67 */ { ":status",                           7,  "400",                                      3 },
  /* Index 68 */ { ":status",                           7,  "403",                                      3 },
  /* Index 69 */ { ":status",                           7,  "421",                                      3 },
  /* Index 70 */ { ":status",                           7,  "425",                                      3 },
  /* Index 71 */ { ":status",                           7,  "500",                                      3 },
  /* Index 72 */ { "accept-language",                   15, "",                                         0 },
  /* Index 73 */ { "access-control-allow-credentials",  32, "FALSE",                                    5 },
  /* Index 74 */ { "access-control-allow-credentials",  32, "TRUE",                                     4 },
  /* Index 75 */ { "access-control-allow-headers",      28, "*",                                        1 },
  /* Index 76 */ { "access-control-allow-methods",      28, "get",                                      3 },
  /* Index 77 */ { "access-control-allow-methods",      28, "get, post, options",                       18 },
  /* Index 78 */ { "access-control-allow-methods",      28, "options",                                  7 },
  /* Index 79 */ { "access-control-expose-headers",     29, "content-length",                           14 },
  /* Index 80 */ { "access-control-request-headers",    30, "content-type",                             12 },
  /* Index 81 */ { "access-control-request-method",     29, "get",                                      3 },
  /* Index 82 */ { "access-control-request-method",     29, "post",                                     4 },
  /* Index 83 */ { "alt-svc",                           7,  "clear",                                    5 },
  /* Index 84 */ { "authorization",                     13, "",                                         0 },
  /* Index 85 */ { "content-security-policy",           23, "script-src 'none'; object-src 'none'; base-uri 'none'", 53 },
  /* Index 86 */ { "early-data",                        10, "1",                                        1 },
  /* Index 87 */ { "expect-ct",                         9,  "",                                         0 },
  /* Index 88 */ { "forwarded",                         9,  "",                                         0 },
  /* Index 89 */ { "if-range",                          8,  "",                                         0 },
  /* Index 90 */ { "origin",                            6,  "",                                         0 },
  /* Index 91 */ { "purpose",                           7,  "prefetch",                                 8 },
  /* Index 92 */ { "server",                            6,  "",                                         0 },
  /* Index 93 */ { "timing-allow-origin",               19, "*",                                        1 },
  /* Index 94 */ { "upgrade-insecure-requests",         25, "1",                                        1 },
  /* Index 95 */ { "user-agent",                        10, "",                                         0 },
  /* Index 96 */ { "x-forwarded-for",                   15, "",                                         0 },
  /* Index 97 */ { "x-frame-options",                   15, "deny",                                     4 },
  /* Index 98 */ { "x-frame-options",                   15, "sameorigin",                               10 },
};
/* clang-format on */

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [SOCKETQPACK_OK] = "OK",
  [SOCKETQPACK_ERROR_INVALID_INDEX] = "Invalid index",
  [SOCKETQPACK_ERROR_NOT_FOUND] = "Not found",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result > SOCKETQPACK_ERROR_NOT_FOUND)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Static Table Lookup Functions
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_StaticEntry *entry_out)
{
  if (entry_out == NULL)
    return SOCKETQPACK_ERROR_INVALID_INDEX;

  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return SOCKETQPACK_ERROR_INVALID_INDEX;

  *entry_out = qpack_static_table[index];
  return SOCKETQPACK_OK;
}

/**
 * Case-insensitive name comparison for HTTP field names.
 * Returns 0 if equal, non-zero otherwise.
 */
static int
qpack_name_cmp (const char *a, size_t a_len, const char *b, size_t b_len)
{
  if (a_len != b_len)
    return 1;

  return strncasecmp (a, b, a_len);
}

int
SocketQPACK_static_find (const char *name,
                         size_t name_len,
                         const char *value,
                         size_t value_len)
{
  if (name == NULL || name_len == 0)
    return -1;

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const SocketQPACK_StaticEntry *entry = &qpack_static_table[i];

      /* Check name match (case-insensitive) */
      if (qpack_name_cmp (entry->name, entry->name_len, name, name_len) != 0)
        continue;

      /* Name matches - check value if provided */
      if (value == NULL)
        return (int)i; /* Name-only match requested */

      /* Check value match (case-sensitive) */
      if (entry->value_len == value_len
          && (value_len == 0 || memcmp (entry->value, value, value_len) == 0))
        {
          return (int)i; /* Exact match */
        }
    }

  return -1; /* No match found */
}

int
SocketQPACK_static_find_name (const char *name, size_t name_len)
{
  if (name == NULL || name_len == 0)
    return -1;

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const SocketQPACK_StaticEntry *entry = &qpack_static_table[i];

      if (qpack_name_cmp (entry->name, entry->name_len, name, name_len) == 0)
        return (int)i;
    }

  return -1;
}

size_t
SocketQPACK_static_name_len (size_t index)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return 0;

  return qpack_static_table[index].name_len;
}

size_t
SocketQPACK_static_value_len (size_t index)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return 0;

  return qpack_static_table[index].value_len;
}
