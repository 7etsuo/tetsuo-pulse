/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-table.c - QPACK Static Table (RFC 9204 Appendix A)
 *
 * QPACK static table with 99 pre-defined entries (indices 0-98).
 * This differs from HPACK which has 61 entries and 1-based indexing.
 */

#include <assert.h>
#include <string.h>

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 *
 * QPACK uses 0-based indexing with 99 entries (0-98).
 * This is the complete table from RFC 9204 Appendix A.
 * ============================================================================
 */

/* clang-format off */
const QPACK_StaticEntry qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE] = {
  /* Index 0: :authority */
  { ":authority", "", 10, 0 },
  /* Index 1: :path / */
  { ":path", "/", 5, 1 },
  /* Index 2: age 0 */
  { "age", "0", 3, 1 },
  /* Index 3: content-disposition */
  { "content-disposition", "", 19, 0 },
  /* Index 4: content-length 0 */
  { "content-length", "0", 14, 1 },
  /* Index 5: cookie */
  { "cookie", "", 6, 0 },
  /* Index 6: date */
  { "date", "", 4, 0 },
  /* Index 7: etag */
  { "etag", "", 4, 0 },
  /* Index 8: if-modified-since */
  { "if-modified-since", "", 17, 0 },
  /* Index 9: if-none-match */
  { "if-none-match", "", 13, 0 },
  /* Index 10: last-modified */
  { "last-modified", "", 13, 0 },
  /* Index 11: link */
  { "link", "", 4, 0 },
  /* Index 12: location */
  { "location", "", 8, 0 },
  /* Index 13: referer */
  { "referer", "", 7, 0 },
  /* Index 14: set-cookie */
  { "set-cookie", "", 10, 0 },
  /* Index 15: :method CONNECT */
  { ":method", "CONNECT", 7, 7 },
  /* Index 16: :method DELETE */
  { ":method", "DELETE", 7, 6 },
  /* Index 17: :method GET */
  { ":method", "GET", 7, 3 },
  /* Index 18: :method HEAD */
  { ":method", "HEAD", 7, 4 },
  /* Index 19: :method OPTIONS */
  { ":method", "OPTIONS", 7, 7 },
  /* Index 20: :method POST */
  { ":method", "POST", 7, 4 },
  /* Index 21: :method PUT */
  { ":method", "PUT", 7, 3 },
  /* Index 22: :scheme http */
  { ":scheme", "http", 7, 4 },
  /* Index 23: :scheme https */
  { ":scheme", "https", 7, 5 },
  /* Index 24: :status 103 */
  { ":status", "103", 7, 3 },
  /* Index 25: :status 200 */
  { ":status", "200", 7, 3 },
  /* Index 26: :status 304 */
  { ":status", "304", 7, 3 },
  /* Index 27: :status 404 */
  { ":status", "404", 7, 3 },
  /* Index 28: :status 503 */
  { ":status", "503", 7, 3 },
  /* Index 29: accept (wildcard) */
  { "accept", "*/*", 6, 3 },
  /* Index 30: accept application/dns-message */
  { "accept", "application/dns-message", 6, 23 },
  /* Index 31: accept-encoding gzip, deflate, br */
  { "accept-encoding", "gzip, deflate, br", 15, 17 },
  /* Index 32: accept-ranges bytes */
  { "accept-ranges", "bytes", 13, 5 },
  /* Index 33: access-control-allow-headers cache-control */
  { "access-control-allow-headers", "cache-control", 28, 13 },
  /* Index 34: access-control-allow-headers content-type */
  { "access-control-allow-headers", "content-type", 28, 12 },
  /* Index 35: access-control-allow-origin * */
  { "access-control-allow-origin", "*", 27, 1 },
  /* Index 36: cache-control max-age=0 */
  { "cache-control", "max-age=0", 13, 9 },
  /* Index 37: cache-control max-age=2592000 */
  { "cache-control", "max-age=2592000", 13, 15 },
  /* Index 38: cache-control max-age=604800 */
  { "cache-control", "max-age=604800", 13, 14 },
  /* Index 39: cache-control no-cache */
  { "cache-control", "no-cache", 13, 8 },
  /* Index 40: cache-control no-store */
  { "cache-control", "no-store", 13, 8 },
  /* Index 41: cache-control public, max-age=31536000 */
  { "cache-control", "public, max-age=31536000", 13, 24 },
  /* Index 42: content-encoding br */
  { "content-encoding", "br", 16, 2 },
  /* Index 43: content-encoding gzip */
  { "content-encoding", "gzip", 16, 4 },
  /* Index 44: content-type application/dns-message */
  { "content-type", "application/dns-message", 12, 23 },
  /* Index 45: content-type application/javascript */
  { "content-type", "application/javascript", 12, 22 },
  /* Index 46: content-type application/json */
  { "content-type", "application/json", 12, 16 },
  /* Index 47: content-type application/x-www-form-urlencoded */
  { "content-type", "application/x-www-form-urlencoded", 12, 33 },
  /* Index 48: content-type image/gif */
  { "content-type", "image/gif", 12, 9 },
  /* Index 49: content-type image/jpeg */
  { "content-type", "image/jpeg", 12, 10 },
  /* Index 50: content-type image/png */
  { "content-type", "image/png", 12, 9 },
  /* Index 51: content-type text/css */
  { "content-type", "text/css", 12, 8 },
  /* Index 52: content-type text/html; charset=utf-8 */
  { "content-type", "text/html; charset=utf-8", 12, 24 },
  /* Index 53: content-type text/plain */
  { "content-type", "text/plain", 12, 10 },
  /* Index 54: content-type text/plain;charset=utf-8 */
  { "content-type", "text/plain;charset=utf-8", 12, 24 },
  /* Index 55: range bytes=0- */
  { "range", "bytes=0-", 5, 8 },
  /* Index 56: strict-transport-security max-age=31536000 */
  { "strict-transport-security", "max-age=31536000", 25, 16 },
  /* Index 57: strict-transport-security max-age=31536000; includesubdomains */
  { "strict-transport-security", "max-age=31536000; includesubdomains", 25, 35 },
  /* Index 58: strict-transport-security max-age=31536000; includesubdomains; preload */
  { "strict-transport-security", "max-age=31536000; includesubdomains; preload", 25, 44 },
  /* Index 59: vary accept-encoding */
  { "vary", "accept-encoding", 4, 15 },
  /* Index 60: vary origin */
  { "vary", "origin", 4, 6 },
  /* Index 61: x-content-type-options nosniff */
  { "x-content-type-options", "nosniff", 22, 7 },
  /* Index 62: x-xss-protection 1; mode=block */
  { "x-xss-protection", "1; mode=block", 16, 13 },
  /* Index 63: :status 100 */
  { ":status", "100", 7, 3 },
  /* Index 64: :status 204 */
  { ":status", "204", 7, 3 },
  /* Index 65: :status 206 */
  { ":status", "206", 7, 3 },
  /* Index 66: :status 302 */
  { ":status", "302", 7, 3 },
  /* Index 67: :status 400 */
  { ":status", "400", 7, 3 },
  /* Index 68: :status 403 */
  { ":status", "403", 7, 3 },
  /* Index 69: :status 421 */
  { ":status", "421", 7, 3 },
  /* Index 70: :status 425 */
  { ":status", "425", 7, 3 },
  /* Index 71: :status 500 */
  { ":status", "500", 7, 3 },
  /* Index 72: accept-language */
  { "accept-language", "", 15, 0 },
  /* Index 73: access-control-allow-credentials FALSE */
  { "access-control-allow-credentials", "FALSE", 32, 5 },
  /* Index 74: access-control-allow-credentials TRUE */
  { "access-control-allow-credentials", "TRUE", 32, 4 },
  /* Index 75: access-control-allow-headers * */
  { "access-control-allow-headers", "*", 28, 1 },
  /* Index 76: access-control-allow-methods get */
  { "access-control-allow-methods", "get", 28, 3 },
  /* Index 77: access-control-allow-methods get, post, options */
  { "access-control-allow-methods", "get, post, options", 28, 18 },
  /* Index 78: access-control-allow-methods options */
  { "access-control-allow-methods", "options", 28, 7 },
  /* Index 79: access-control-expose-headers content-length */
  { "access-control-expose-headers", "content-length", 29, 14 },
  /* Index 80: access-control-request-headers content-type */
  { "access-control-request-headers", "content-type", 30, 12 },
  /* Index 81: access-control-request-method get */
  { "access-control-request-method", "get", 29, 3 },
  /* Index 82: access-control-request-method post */
  { "access-control-request-method", "post", 29, 4 },
  /* Index 83: alt-svc clear */
  { "alt-svc", "clear", 7, 5 },
  /* Index 84: authorization */
  { "authorization", "", 13, 0 },
  /* Index 85: content-security-policy script-src 'none'; object-src 'none'; base-uri 'none' */
  { "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'", 23, 52 },
  /* Index 86: early-data 1 */
  { "early-data", "1", 10, 1 },
  /* Index 87: expect-ct */
  { "expect-ct", "", 9, 0 },
  /* Index 88: forwarded */
  { "forwarded", "", 9, 0 },
  /* Index 89: if-range */
  { "if-range", "", 8, 0 },
  /* Index 90: origin */
  { "origin", "", 6, 0 },
  /* Index 91: purpose prefetch */
  { "purpose", "prefetch", 7, 8 },
  /* Index 92: server */
  { "server", "", 6, 0 },
  /* Index 93: timing-allow-origin * */
  { "timing-allow-origin", "*", 19, 1 },
  /* Index 94: upgrade-insecure-requests 1 */
  { "upgrade-insecure-requests", "1", 25, 1 },
  /* Index 95: user-agent */
  { "user-agent", "", 10, 0 },
  /* Index 96: x-forwarded-for */
  { "x-forwarded-for", "", 15, 0 },
  /* Index 97: x-frame-options deny */
  { "x-frame-options", "deny", 15, 4 },
  /* Index 98: x-frame-options sameorigin */
  { "x-frame-options", "sameorigin", 15, 10 },
};
/* clang-format on */

/* ============================================================================
 * Static Table Lookup Functions
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header)
{
  const QPACK_StaticEntry *entry;

  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_ERROR_INVALID_INDEX;

  if (header == NULL)
    return QPACK_ERROR;

  entry = &qpack_static_table[index];
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
  size_t i;
  int name_match_index = 0;

  if (name == NULL)
    return 0;

  for (i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const QPACK_StaticEntry *entry = &qpack_static_table[i];

      if (entry->name_len != name_len)
        continue;

      if (memcmp (entry->name, name, name_len) != 0)
        continue;

      /* Name matches - check value */
      if (value != NULL && entry->value_len == value_len
          && memcmp (entry->value, value, value_len) == 0)
        {
          /* Exact match - return positive (index + 1 for compatibility) */
          return (int)(i + 1);
        }

      /* Name-only match - remember first occurrence */
      if (name_match_index == 0)
        name_match_index = -((int)(i + 1));
    }

  return name_match_index;
}
