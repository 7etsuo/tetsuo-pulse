/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-static.c - QPACK Static Table (RFC 9204 Appendix A)
 *
 * The QPACK static table has 99 entries (indices 0-98), different from
 * HPACK's 61-entry table.
 */

#include <string.h>

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

/* ============================================================================
 * QPACK Static Table (RFC 9204 Appendix A)
 * ============================================================================
 *
 * 99 entries, indexed 0-98. Most common HTTP/3 headers.
 */

/* clang-format off */
static const QPACK_StaticEntry qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE] = {
  /*  0 */ { ":authority",                   "",                       10, 0 },
  /*  1 */ { ":path",                        "/",                       5, 1 },
  /*  2 */ { "age",                          "0",                       3, 1 },
  /*  3 */ { "content-disposition",          "",                       19, 0 },
  /*  4 */ { "content-length",               "0",                      14, 1 },
  /*  5 */ { "cookie",                       "",                        6, 0 },
  /*  6 */ { "date",                         "",                        4, 0 },
  /*  7 */ { "etag",                         "",                        4, 0 },
  /*  8 */ { "if-modified-since",            "",                       17, 0 },
  /*  9 */ { "if-none-match",                "",                       13, 0 },
  /* 10 */ { "last-modified",                "",                       13, 0 },
  /* 11 */ { "link",                         "",                        4, 0 },
  /* 12 */ { "location",                     "",                        8, 0 },
  /* 13 */ { "referer",                      "",                        7, 0 },
  /* 14 */ { "set-cookie",                   "",                       10, 0 },
  /* 15 */ { ":method",                      "CONNECT",                 7, 7 },
  /* 16 */ { ":method",                      "DELETE",                  7, 6 },
  /* 17 */ { ":method",                      "GET",                     7, 3 },
  /* 18 */ { ":method",                      "HEAD",                    7, 4 },
  /* 19 */ { ":method",                      "OPTIONS",                 7, 7 },
  /* 20 */ { ":method",                      "POST",                    7, 4 },
  /* 21 */ { ":method",                      "PUT",                     7, 3 },
  /* 22 */ { ":scheme",                      "http",                    7, 4 },
  /* 23 */ { ":scheme",                      "https",                   7, 5 },
  /* 24 */ { ":status",                      "103",                     7, 3 },
  /* 25 */ { ":status",                      "200",                     7, 3 },
  /* 26 */ { ":status",                      "304",                     7, 3 },
  /* 27 */ { ":status",                      "404",                     7, 3 },
  /* 28 */ { ":status",                      "503",                     7, 3 },
  /* 29 */ { "accept",                       "*/*",                     6, 3 },
  /* 30 */ { "accept",                       "application/dns-message", 6, 23 },
  /* 31 */ { "accept-encoding",              "gzip, deflate, br",      15, 17 },
  /* 32 */ { "accept-ranges",                "bytes",                  13, 5 },
  /* 33 */ { "access-control-allow-headers", "cache-control",          28, 13 },
  /* 34 */ { "access-control-allow-headers", "content-type",           28, 12 },
  /* 35 */ { "access-control-allow-origin",  "*",                      27, 1 },
  /* 36 */ { "cache-control",                "max-age=0",              13, 8 },
  /* 37 */ { "cache-control",                "max-age=2592000",        13, 15 },
  /* 38 */ { "cache-control",                "max-age=604800",         13, 14 },
  /* 39 */ { "cache-control",                "no-cache",               13, 8 },
  /* 40 */ { "cache-control",                "no-store",               13, 8 },
  /* 41 */ { "cache-control",                "public, max-age=31536000", 13, 24 },
  /* 42 */ { "content-encoding",             "br",                     16, 2 },
  /* 43 */ { "content-encoding",             "gzip",                   16, 4 },
  /* 44 */ { "content-type",                 "application/dns-message", 12, 23 },
  /* 45 */ { "content-type",                 "application/javascript", 12, 22 },
  /* 46 */ { "content-type",                 "application/json",       12, 16 },
  /* 47 */ { "content-type",                 "application/x-www-form-urlencoded", 12, 33 },
  /* 48 */ { "content-type",                 "image/gif",              12, 9 },
  /* 49 */ { "content-type",                 "image/jpeg",             12, 10 },
  /* 50 */ { "content-type",                 "image/png",              12, 9 },
  /* 51 */ { "content-type",                 "text/css",               12, 8 },
  /* 52 */ { "content-type",                 "text/html; charset=utf-8", 12, 24 },
  /* 53 */ { "content-type",                 "text/plain",             12, 10 },
  /* 54 */ { "content-type",                 "text/plain;charset=utf-8", 12, 24 },
  /* 55 */ { "range",                        "bytes=0-",                5, 8 },
  /* 56 */ { "strict-transport-security",    "max-age=31536000",       25, 16 },
  /* 57 */ { "strict-transport-security",    "max-age=31536000; includesubdomains", 25, 35 },
  /* 58 */ { "strict-transport-security",    "max-age=31536000; includesubdomains; preload", 25, 44 },
  /* 59 */ { "vary",                         "accept-encoding",         4, 15 },
  /* 60 */ { "vary",                         "origin",                  4, 6 },
  /* 61 */ { "x-content-type-options",       "nosniff",                22, 7 },
  /* 62 */ { "x-xss-protection",             "1; mode=block",          16, 13 },
  /* 63 */ { ":status",                      "100",                     7, 3 },
  /* 64 */ { ":status",                      "204",                     7, 3 },
  /* 65 */ { ":status",                      "206",                     7, 3 },
  /* 66 */ { ":status",                      "302",                     7, 3 },
  /* 67 */ { ":status",                      "400",                     7, 3 },
  /* 68 */ { ":status",                      "403",                     7, 3 },
  /* 69 */ { ":status",                      "421",                     7, 3 },
  /* 70 */ { ":status",                      "425",                     7, 3 },
  /* 71 */ { ":status",                      "500",                     7, 3 },
  /* 72 */ { "accept-language",              "",                       15, 0 },
  /* 73 */ { "access-control-allow-credentials", "FALSE",              32, 5 },
  /* 74 */ { "access-control-allow-credentials", "TRUE",               32, 4 },
  /* 75 */ { "access-control-allow-headers", "*",                      28, 1 },
  /* 76 */ { "access-control-allow-methods", "get",                    28, 3 },
  /* 77 */ { "access-control-allow-methods", "get, post, options",     28, 18 },
  /* 78 */ { "access-control-allow-methods", "options",                28, 7 },
  /* 79 */ { "access-control-expose-headers", "content-length",        29, 14 },
  /* 80 */ { "access-control-request-headers", "content-type",         30, 12 },
  /* 81 */ { "access-control-request-method", "get",                   29, 3 },
  /* 82 */ { "access-control-request-method", "post",                  29, 4 },
  /* 83 */ { "alt-svc",                      "clear",                   7, 5 },
  /* 84 */ { "authorization",                "",                       13, 0 },
  /* 85 */ { "content-security-policy",      "script-src 'none'; object-src 'none'; base-uri 'none'", 23, 52 },
  /* 86 */ { "early-data",                   "1",                      10, 1 },
  /* 87 */ { "expect-ct",                    "",                        9, 0 },
  /* 88 */ { "forwarded",                    "",                        9, 0 },
  /* 89 */ { "if-range",                     "",                        8, 0 },
  /* 90 */ { "origin",                       "",                        6, 0 },
  /* 91 */ { "purpose",                      "prefetch",                7, 8 },
  /* 92 */ { "server",                       "",                        6, 0 },
  /* 93 */ { "timing-allow-origin",          "*",                      19, 1 },
  /* 94 */ { "upgrade-insecure-requests",    "1",                      25, 1 },
  /* 95 */ { "user-agent",                   "",                       10, 0 },
  /* 96 */ { "x-forwarded-for",              "",                       15, 0 },
  /* 97 */ { "x-frame-options",              "deny",                   15, 4 },
  /* 98 */ { "x-frame-options",              "sameorigin",             15, 10 },
};
/* clang-format on */

/* ============================================================================
 * Static Table Functions
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header)
{
  if (header == NULL)
    return QPACK_ERROR;

  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_ERROR_INVALID_INDEX;

  const QPACK_StaticEntry *entry = &qpack_static_table[index];

  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return QPACK_OK;
}

int
SocketQPACK_static_find (const char *name,
                         size_t name_len,
                         const char *value,
                         size_t value_len)
{
  int name_match = -1;

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const QPACK_StaticEntry *entry = &qpack_static_table[i];

      /* Check name match */
      if (entry->name_len != name_len)
        continue;

      if (memcmp (entry->name, name, name_len) != 0)
        continue;

      /* Name matches - check if we have an exact match */
      if (name_match < 0)
        name_match = (int)i;

      /* Check value match */
      if (entry->value_len == value_len
          && (value_len == 0 || memcmp (entry->value, value, value_len) == 0))
        {
          /* Exact match - return positive index */
          return (int)i;
        }
    }

  /* Return negative index for name-only match, -1 for no match */
  return name_match >= 0 ? -name_match : -1;
}
