/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-table.c - QPACK Static and Dynamic Table (RFC 9204)
 *
 * Static table with 99 pre-defined entries (Appendix A), dynamic table with
 * circular buffer and absolute indexing.
 */

#include <assert.h>
#include <string.h>

#include "core/SocketUtil.h"
#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#define T SocketQPACK_DynamicTable_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketQPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 *
 * QPACK uses 0-based indexing (unlike HPACK's 1-based).
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
 * Internal Helpers
 * ============================================================================
 */

static int
qpack_validate_table (const SocketQPACK_DynamicTable_T table, const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK %s: NULL table pointer", func);
      return 0;
    }
  return 1;
}

static SocketQPACK_Result
qpack_validate_table_strict (const SocketQPACK_DynamicTable_T table,
                             const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK %s: NULL table pointer", func);
      return QPACK_ERROR;
    }
  return QPACK_OK;
}

static int
qpack_validate_search_params (const char *name, size_t name_len)
{
  if (name == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK find: NULL name pointer");
      return 0;
    }
  if (name_len == 0)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK find: zero name length");
      return 0;
    }
  return 1;
}

static SocketQPACK_Result
qpack_validate_header_ptr (SocketQPACK_Header *header, const char *func)
{
  if (header == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK %s: NULL output header pointer", func);
      return QPACK_ERROR;
    }
  return QPACK_OK;
}

/* Case-insensitive comparison with explicit lengths (ASCII, for HTTP headers)
 */
static int
qpack_strcasecmp (const char *a, size_t a_len, const char *b, size_t b_len)
{
  size_t min_len = (a_len < b_len) ? a_len : b_len;
  int cmp = strncasecmp (a, b, min_len);

  if (cmp != 0)
    return cmp;

  if (a_len < b_len)
    return -1;
  if (a_len > b_len)
    return 1;
  return 0;
}

/* Match entry against name and optionally value.
 * Returns: 1=exact match, 0=name-only match, -1=no match */
static int
qpack_match_entry (const char *entry_name,
                   size_t entry_name_len,
                   const char *entry_value,
                   size_t entry_value_len,
                   const char *name,
                   size_t name_len,
                   const char *value,
                   size_t value_len)
{
  if (entry_name_len != name_len)
    return -1;

  if (qpack_strcasecmp (entry_name, entry_name_len, name, name_len) != 0)
    return -1;

  if (value != NULL && entry_value_len == value_len
      && (value_len == 0 || memcmp (entry_value, value, value_len) == 0))
    {
      return 1;
    }

  return 0;
}

static SocketQPACK_Result
qpack_duplicate_header_strings (Arena_T arena,
                                const char *name,
                                size_t name_len,
                                const char *value,
                                size_t value_len,
                                char **name_out,
                                char **value_out)
{
  assert (arena != NULL);
  assert (name_out != NULL);
  assert (value_out != NULL);

  *name_out = arena_strndup (arena, name, name_len);
  if (*name_out == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: failed to allocate header name copy (length=%zu)",
          name_len);
      return QPACK_ERROR;
    }

  *value_out = arena_strndup (arena, value, value_len);
  if (*value_out == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: failed to allocate header value copy (length=%zu)",
          value_len);
      return QPACK_ERROR;
    }

  return QPACK_OK;
}

/* Calculate initial capacity (power-of-2) based on max_size */
static size_t
qpack_dynamic_initial_capacity (size_t max_size)
{
  size_t est_entries;

  if (max_size == 0)
    return QPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  est_entries = max_size / QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
  if (est_entries < QPACK_MIN_DYNAMIC_TABLE_CAPACITY)
    est_entries = QPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  return socket_util_round_up_pow2 (est_entries);
}

static void
qpack_table_clear (SocketQPACK_DynamicTable_T table)
{
  assert (table != NULL);
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  /* Note: insert_count and dropped_count are NOT reset */
}

static SocketQPACK_Result
qpack_dynamic_entry_init (Arena_T arena,
                          const char *name,
                          size_t name_len,
                          const char *value,
                          size_t value_len,
                          QPACK_DynamicEntry *entry)
{
  SocketQPACK_Result res;

  assert (arena != NULL);
  assert (entry != NULL);

  res = qpack_duplicate_header_strings (
      arena, name, name_len, value, value_len, &entry->name, &entry->value);
  if (res != QPACK_OK)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: qpack_dynamic_entry_init failed - "
                            "%s (name_len=%zu, value_len=%zu)",
                            SocketQPACK_result_string (res),
                            name_len,
                            value_len);
      return res;
    }

  entry->name_len = name_len;
  entry->value_len = value_len;
  return QPACK_OK;
}

static void
qpack_table_prepare_insertion (SocketQPACK_DynamicTable_T table,
                               size_t entry_size)
{
  assert (table != NULL);

  if (entry_size > table->max_size)
    {
      qpack_table_clear (table);
      return;
    }

  qpack_table_evict (table, entry_size);
}

/* ============================================================================
 * Dynamic Table Eviction
 * ============================================================================
 */

size_t
qpack_table_evict (SocketQPACK_DynamicTable_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      QPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size = qpack_entry_size (entry->name_len, entry->value_len);

      if (entry_size > table->size)
        {
          SOCKET_LOG_ERROR_MSG (
              "SocketQPACK: table corruption detected (entry_size=%zu > "
              "table_size=%zu), resetting table",
              entry_size,
              table->size);
          table->size = 0;
          table->count = 0;
          return evicted;
        }

      table->size -= entry_size;
      table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
      table->count--;
      table->dropped_count++;
      evicted++;
    }

  return evicted;
}

/* ============================================================================
 * Static Table Lookup
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_static_get (size_t index, SocketQPACK_Header *header)
{
  const QPACK_StaticEntry *entry;
  SocketQPACK_Result res;

  res = qpack_validate_header_ptr (header, "static_get");
  if (res != QPACK_OK)
    return res;

  /* QPACK uses 0-based indexing */
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK static_get: invalid index %zu (valid range 0-%zu)",
          index,
          (size_t)SOCKETQPACK_STATIC_TABLE_SIZE - 1);
      return QPACK_ERROR_INVALID_INDEX;
    }

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
  int name_match = 0;
  size_t i;

  if (!qpack_validate_search_params (name, name_len))
    return 0;

  for (i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const QPACK_StaticEntry *entry = &qpack_static_table[i];
      int match = qpack_match_entry (entry->name,
                                     entry->name_len,
                                     entry->value,
                                     entry->value_len,
                                     name,
                                     name_len,
                                     value,
                                     value_len);

      if (match == 1)
        return (int)(i + 1); /* Return positive for exact match */

      if (match == 0 && name_match == 0)
        name_match = -(int)(i + 1); /* Return negative for name-only match */
    }

  return name_match;
}

/* ============================================================================
 * Dynamic Table Implementation
 *
 * QPACK uses absolute indexing: entries are referenced by their insertion
 * order, starting from 0. This differs from HPACK's relative indexing.
 * ============================================================================
 */

SocketQPACK_DynamicTable_T
SocketQPACK_DynamicTable_new (size_t max_size, Arena_T arena)
{
  SocketQPACK_DynamicTable_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    SOCKET_RAISE_MSG (SocketQPACK,
                      SocketQPACK_Error,
                      "failed to allocate SocketQPACK_DynamicTable structure");

  initial_capacity = qpack_dynamic_initial_capacity (max_size);

  table->entries
      = CALLOC (arena, initial_capacity, sizeof (QPACK_DynamicEntry));
  if (table->entries == NULL)
    SOCKET_RAISE_MSG (
        SocketQPACK,
        SocketQPACK_Error,
        "failed to allocate SocketQPACK_DynamicTable entries array "
        "(capacity=%zu)",
        initial_capacity);

  table->capacity = initial_capacity;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_size = max_size;
  table->insert_count = 0;
  table->dropped_count = 0;
  table->arena = arena;

  return table;
}

void
SocketQPACK_DynamicTable_free (SocketQPACK_DynamicTable_T *table)
{
  if (table == NULL || *table == NULL)
    return;

  *table = NULL;
}

size_t
SocketQPACK_DynamicTable_size (SocketQPACK_DynamicTable_T table)
{
  if (!qpack_validate_table (table, "DynamicTable_size"))
    return 0;
  return table->size;
}

size_t
SocketQPACK_DynamicTable_count (SocketQPACK_DynamicTable_T table)
{
  if (!qpack_validate_table (table, "DynamicTable_count"))
    return 0;
  return table->count;
}

size_t
SocketQPACK_DynamicTable_max_size (SocketQPACK_DynamicTable_T table)
{
  if (!qpack_validate_table (table, "DynamicTable_max_size"))
    return 0;
  return table->max_size;
}

size_t
SocketQPACK_DynamicTable_insert_count (SocketQPACK_DynamicTable_T table)
{
  if (!qpack_validate_table (table, "DynamicTable_insert_count"))
    return 0;
  return table->insert_count;
}

void
SocketQPACK_DynamicTable_set_max_size (SocketQPACK_DynamicTable_T table,
                                       size_t max_size)
{
  if (!qpack_validate_table (table, "DynamicTable_set_max_size"))
    return;

  if (max_size > SOCKETQPACK_MAX_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK DynamicTable_set_max_size: clamping max_size from %zu "
          "to %zu",
          max_size,
          (size_t)SOCKETQPACK_MAX_TABLE_SIZE);
      max_size = SOCKETQPACK_MAX_TABLE_SIZE;
    }

  table->max_size = max_size;

  if (max_size == 0)
    qpack_table_clear (table);
  else
    qpack_table_evict (table, 0);
}

SocketQPACK_Result
SocketQPACK_DynamicTable_insert (SocketQPACK_DynamicTable_T table,
                                 const char *name,
                                 size_t name_len,
                                 const char *value,
                                 size_t value_len)
{
  size_t entry_size;
  QPACK_DynamicEntry *entry_ptr;
  SocketQPACK_Result res;

  res = qpack_validate_table_strict (table, "DynamicTable_insert");
  if (res != QPACK_OK)
    return res;

  if ((name == NULL && name_len != 0) || (value == NULL && value_len != 0))
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK DynamicTable_insert: invalid NULL string with non-zero "
          "length");
      return QPACK_ERROR;
    }

  entry_size = qpack_entry_size (name_len, value_len);
  qpack_table_prepare_insertion (table, entry_size);

  /* If entry is too large, it's already been handled (table cleared) */
  if (entry_size > table->max_size)
    {
      /* Entry too large - don't insert, but count it for absolute indexing */
      table->insert_count++;
      return QPACK_OK;
    }

  entry_ptr = &table->entries[table->tail];

  res = qpack_dynamic_entry_init (
      table->arena, name, name_len, value, value_len, entry_ptr);
  if (res != QPACK_OK)
    return res;

  table->tail = RINGBUF_WRAP (table->tail + 1, table->capacity);
  table->count++;
  table->size += entry_size;
  table->insert_count++;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_DynamicTable_get (SocketQPACK_DynamicTable_T table,
                              size_t index,
                              SocketQPACK_Header *header)
{
  SocketQPACK_Result res;

  res = qpack_validate_table_strict (table, "DynamicTable_get");
  if (res != QPACK_OK)
    return res;

  res = qpack_validate_header_ptr (header, "DynamicTable_get");
  if (res != QPACK_OK)
    return res;

  /* QPACK uses absolute indexing: index is the absolute insertion number.
   * We need to convert to relative position in the ring buffer.
   *
   * Valid range: [dropped_count, insert_count)
   * where dropped_count is the number of evicted entries.
   */
  if (index < table->dropped_count || index >= table->insert_count)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK DynamicTable_get: invalid absolute index %zu "
          "(valid range %zu-%zu)",
          index,
          table->dropped_count,
          table->insert_count > 0 ? table->insert_count - 1 : 0);
      return QPACK_ERROR_INVALID_INDEX;
    }

  /* Convert absolute index to ring buffer slot */
  size_t relative_index = index - table->dropped_count;
  if (relative_index >= table->count)
    return QPACK_ERROR_INVALID_INDEX;

  size_t slot = RINGBUF_WRAP (table->head + relative_index, table->capacity);

  QPACK_DynamicEntry *entry = &table->entries[slot];
  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return QPACK_OK;
}

#undef T
