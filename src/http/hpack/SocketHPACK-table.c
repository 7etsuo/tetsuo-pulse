/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHPACK-table.c - HPACK Static and Dynamic Table (RFC 7541 Section 2.3)
 *
 * Static table with 61 pre-defined entries, dynamic table with circular buffer.
 */

#include <assert.h>
#include <string.h>

#include "core/SocketUtil.h"
#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"

#define T SocketHPACK_Table_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HPACK"

/* clang-format off */
const HPACK_StaticEntry hpack_static_table[SOCKETHPACK_STATIC_TABLE_SIZE] = {
  /* Index 1: :authority */
  { ":authority", "", 10, 0 },
  /* Index 2: :method GET */
  { ":method", "GET", 7, 3 },
  /* Index 3: :method POST */
  { ":method", "POST", 7, 4 },
  /* Index 4: :path / */
  { ":path", "/", 5, 1 },
  /* Index 5: :path /index.html */
  { ":path", "/index.html", 5, 11 },
  /* Index 6: :scheme http */
  { ":scheme", "http", 7, 4 },
  /* Index 7: :scheme https */
  { ":scheme", "https", 7, 5 },
  /* Index 8: :status 200 */
  { ":status", "200", 7, 3 },
  /* Index 9: :status 204 */
  { ":status", "204", 7, 3 },
  /* Index 10: :status 206 */
  { ":status", "206", 7, 3 },
  /* Index 11: :status 304 */
  { ":status", "304", 7, 3 },
  /* Index 12: :status 400 */
  { ":status", "400", 7, 3 },
  /* Index 13: :status 404 */
  { ":status", "404", 7, 3 },
  /* Index 14: :status 500 */
  { ":status", "500", 7, 3 },
  /* Index 15: accept-charset */
  { "accept-charset", "", 14, 0 },
  /* Index 16: accept-encoding gzip, deflate */
  { "accept-encoding", "gzip, deflate", 15, 13 },
  /* Index 17: accept-language */
  { "accept-language", "", 15, 0 },
  /* Index 18: accept-ranges */
  { "accept-ranges", "", 13, 0 },
  /* Index 19: accept */
  { "accept", "", 6, 0 },
  /* Index 20: access-control-allow-origin */
  { "access-control-allow-origin", "", 27, 0 },
  /* Index 21: age */
  { "age", "", 3, 0 },
  /* Index 22: allow */
  { "allow", "", 5, 0 },
  /* Index 23: authorization */
  { "authorization", "", 13, 0 },
  /* Index 24: cache-control */
  { "cache-control", "", 13, 0 },
  /* Index 25: content-disposition */
  { "content-disposition", "", 19, 0 },
  /* Index 26: content-encoding */
  { "content-encoding", "", 16, 0 },
  /* Index 27: content-language */
  { "content-language", "", 16, 0 },
  /* Index 28: content-length */
  { "content-length", "", 14, 0 },
  /* Index 29: content-location */
  { "content-location", "", 16, 0 },
  /* Index 30: content-range */
  { "content-range", "", 13, 0 },
  /* Index 31: content-type */
  { "content-type", "", 12, 0 },
  /* Index 32: cookie */
  { "cookie", "", 6, 0 },
  /* Index 33: date */
  { "date", "", 4, 0 },
  /* Index 34: etag */
  { "etag", "", 4, 0 },
  /* Index 35: expect */
  { "expect", "", 6, 0 },
  /* Index 36: expires */
  { "expires", "", 7, 0 },
  /* Index 37: from */
  { "from", "", 4, 0 },
  /* Index 38: host */
  { "host", "", 4, 0 },
  /* Index 39: if-match */
  { "if-match", "", 8, 0 },
  /* Index 40: if-modified-since */
  { "if-modified-since", "", 17, 0 },
  /* Index 41: if-none-match */
  { "if-none-match", "", 13, 0 },
  /* Index 42: if-range */
  { "if-range", "", 8, 0 },
  /* Index 43: if-unmodified-since */
  { "if-unmodified-since", "", 19, 0 },
  /* Index 44: last-modified */
  { "last-modified", "", 13, 0 },
  /* Index 45: link */
  { "link", "", 4, 0 },
  /* Index 46: location */
  { "location", "", 8, 0 },
  /* Index 47: max-forwards */
  { "max-forwards", "", 12, 0 },
  /* Index 48: proxy-authenticate */
  { "proxy-authenticate", "", 18, 0 },
  /* Index 49: proxy-authorization */
  { "proxy-authorization", "", 19, 0 },
  /* Index 50: range */
  { "range", "", 5, 0 },
  /* Index 51: referer */
  { "referer", "", 7, 0 },
  /* Index 52: refresh */
  { "refresh", "", 7, 0 },
  /* Index 53: retry-after */
  { "retry-after", "", 11, 0 },
  /* Index 54: server */
  { "server", "", 6, 0 },
  /* Index 55: set-cookie */
  { "set-cookie", "", 10, 0 },
  /* Index 56: strict-transport-security */
  { "strict-transport-security", "", 25, 0 },
  /* Index 57: transfer-encoding */
  { "transfer-encoding", "", 17, 0 },
  /* Index 58: user-agent */
  { "user-agent", "", 10, 0 },
  /* Index 59: vary */
  { "vary", "", 4, 0 },
  /* Index 60: via */
  { "via", "", 3, 0 },
  /* Index 61: www-authenticate */
  { "www-authenticate", "", 16, 0 },
};
/* clang-format on */

static int
hpack_validate_table (const SocketHPACK_Table_T table, const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketHPACK %s: NULL table pointer", func);
      return 0;
    }
  return 1;
}

static SocketHPACK_Result
hpack_validate_table_strict (const SocketHPACK_Table_T table, const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK %s: NULL table pointer", func);
      return HPACK_ERROR;
    }
  return HPACK_OK;
}

static int
hpack_validate_search_params (const char *name, size_t name_len)
{
  if (name == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketHPACK find: NULL name pointer");
      return 0;
    }
  if (name_len == 0)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketHPACK find: zero name length");
      return 0;
    }
  return 1;
}

static SocketHPACK_Result
hpack_validate_header_ptr (SocketHPACK_Header *header, const char *func)
{
  if (header == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK %s: NULL output header pointer", func);
      return HPACK_ERROR;
    }
  return HPACK_OK;
}

static SocketHPACK_Result
hpack_validate_table_index (const SocketHPACK_Table_T table, size_t index)
{
  if (index == 0 || index > table->count)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketHPACK Table_get: invalid index %zu (valid range 1-%zu)",
          index,
          table->count);
      return HPACK_ERROR_INVALID_INDEX;
    }

  if (index - 1 >= table->capacity)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK Table_get: offset %zu exceeds capacity %zu",
          index - 1,
          table->capacity);
      return HPACK_ERROR_INVALID_INDEX;
    }

  return HPACK_OK;
}

static inline size_t
hpack_table_index_to_slot (const SocketHPACK_Table_T table, size_t index)
{
  size_t offset = index - 1;
  return RINGBUF_WRAP (table->tail + table->capacity - 1 - offset,
                       table->capacity);
}

static void
hpack_populate_header_from_dynamic (const HPACK_DynamicEntry *entry,
                                    SocketHPACK_Header *header)
{
  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;
}

/* Case-insensitive comparison with explicit lengths (ASCII, for HTTP headers)
 */
static int
hpack_strcasecmp (const char *a, size_t a_len, const char *b, size_t b_len)
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
hpack_match_entry (const char *entry_name,
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

  if (hpack_strcasecmp (entry_name, entry_name_len, name, name_len) != 0)
    return -1;

  if (value != NULL && entry_value_len == value_len
      && (value_len == 0 || memcmp (entry_value, value, value_len) == 0))
    {
      return 1;
    }

  return 0;
}

static SocketHPACK_Result
hpack_duplicate_header_strings (Arena_T arena,
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
          "SocketHPACK: failed to allocate header name copy (length=%zu)",
          name_len);
      return HPACK_ERROR;
    }

  *value_out = arena_strndup (arena, value, value_len);
  if (*value_out == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK: failed to allocate header value copy (length=%zu)",
          value_len);
      return HPACK_ERROR;
    }

  return HPACK_OK;
}

/* Calculate initial capacity (power-of-2) based on max_size */
static size_t
hpack_dynamic_initial_capacity (size_t max_size)
{
  size_t est_entries;

  if (max_size == 0)
    return HPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  est_entries = max_size / HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
  if (est_entries < HPACK_MIN_DYNAMIC_TABLE_CAPACITY)
    est_entries = HPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  return socket_util_round_up_pow2 (est_entries);
}

static void
hpack_table_clear (SocketHPACK_Table_T table)
{
  assert (table != NULL);
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
}

static SocketHPACK_Result
hpack_dynamic_entry_init (Arena_T arena,
                          const char *name,
                          size_t name_len,
                          const char *value,
                          size_t value_len,
                          HPACK_DynamicEntry *entry)
{
  SocketHPACK_Result res;

  assert (arena != NULL);
  assert (entry != NULL);

  res = hpack_duplicate_header_strings (
      arena, name, name_len, value, value_len, &entry->name, &entry->value);
  if (res != HPACK_OK)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK: hpack_dynamic_entry_init failed - "
                            "%s (name_len=%zu, value_len=%zu)",
                            SocketHPACK_result_string (res),
                            name_len,
                            value_len);
      return res;
    }

  entry->name_len = name_len;
  entry->value_len = value_len;
  return HPACK_OK;
}

static void
hpack_table_prepare_insertion (SocketHPACK_Table_T table, size_t entry_size)
{
  assert (table != NULL);

  if (entry_size > table->max_size)
    {
      hpack_table_clear (table);
      return;
    }

  hpack_table_evict (table, entry_size);
}

size_t
hpack_table_evict (SocketHPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      HPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size = hpack_entry_size (entry->name_len, entry->value_len);

      if (entry_size > table->size)
        {
          SOCKET_LOG_ERROR_MSG (
              "SocketHPACK: table corruption detected (entry_size=%zu > "
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
      evicted++;
    }

  return evicted;
}

SocketHPACK_Result
SocketHPACK_static_get (size_t index, SocketHPACK_Header *header)
{
  const HPACK_StaticEntry *entry;
  SocketHPACK_Result res;

  res = hpack_validate_header_ptr (header, "static_get");
  if (res != HPACK_OK)
    return res;

  if (index == 0 || index > SOCKETHPACK_STATIC_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketHPACK static_get: invalid index %zu (valid range 1-%zu)",
          index,
          (size_t)SOCKETHPACK_STATIC_TABLE_SIZE);
      return HPACK_ERROR_INVALID_INDEX;
    }

  entry = &hpack_static_table[index - 1];
  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return HPACK_OK;
}

int
SocketHPACK_static_find (const char *name,
                         size_t name_len,
                         const char *value,
                         size_t value_len)
{
  int name_match = 0;
  size_t i;

  if (!hpack_validate_search_params (name, name_len))
    return 0;

  for (i = 0; i < SOCKETHPACK_STATIC_TABLE_SIZE; i++)
    {
      const HPACK_StaticEntry *entry = &hpack_static_table[i];
      int match = hpack_match_entry (entry->name,
                                     entry->name_len,
                                     entry->value,
                                     entry->value_len,
                                     name,
                                     name_len,
                                     value,
                                     value_len);

      if (match == 1)
        return (int)(i + 1);

      if (match == 0 && name_match == 0)
        name_match = -(int)(i + 1);
    }

  return name_match;
}

SocketHPACK_Table_T
SocketHPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketHPACK_Table_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    SOCKET_RAISE_MSG (SocketHPACK,
                      SocketHPACK_Error,
                      "failed to allocate SocketHPACK_Table structure");

  initial_capacity = hpack_dynamic_initial_capacity (max_size);

  table->entries
      = CALLOC (arena, initial_capacity, sizeof (HPACK_DynamicEntry));
  if (table->entries == NULL)
    SOCKET_RAISE_MSG (
        SocketHPACK,
        SocketHPACK_Error,
        "failed to allocate SocketHPACK_Table entries array (capacity=%zu)",
        initial_capacity);

  table->capacity = initial_capacity;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_size = max_size;
  table->arena = arena;

  return table;
}

void
SocketHPACK_Table_free (SocketHPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;

  *table = NULL;
}

size_t
SocketHPACK_Table_size (SocketHPACK_Table_T table)
{
  if (!hpack_validate_table (table, "Table_size"))
    return 0;
  return table->size;
}

size_t
SocketHPACK_Table_count (SocketHPACK_Table_T table)
{
  if (!hpack_validate_table (table, "Table_count"))
    return 0;
  return table->count;
}

size_t
SocketHPACK_Table_max_size (SocketHPACK_Table_T table)
{
  if (!hpack_validate_table (table, "Table_max_size"))
    return 0;
  return table->max_size;
}

void
SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table, size_t max_size)
{
  if (!hpack_validate_table (table, "Table_set_max_size"))
    return;

  if (max_size > SOCKETHPACK_MAX_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketHPACK Table_set_max_size: clamping max_size from %zu to %zu",
          max_size,
          (size_t)SOCKETHPACK_MAX_TABLE_SIZE);
      max_size = SOCKETHPACK_MAX_TABLE_SIZE;
    }

  table->max_size = max_size;

  if (max_size == 0)
    hpack_table_clear (table);
  else
    hpack_table_evict (table, 0);
}

SocketHPACK_Result
SocketHPACK_Table_get (SocketHPACK_Table_T table,
                       size_t index,
                       SocketHPACK_Header *header)
{
  SocketHPACK_Result res;

  res = hpack_validate_table_strict (table, "Table_get");
  if (res != HPACK_OK)
    return res;

  res = hpack_validate_header_ptr (header, "Table_get");
  if (res != HPACK_OK)
    return res;

  res = hpack_validate_table_index (table, index);
  if (res != HPACK_OK)
    return res;

  size_t slot = hpack_table_index_to_slot (table, index);
  hpack_populate_header_from_dynamic (&table->entries[slot], header);

  return HPACK_OK;
}

SocketHPACK_Result
SocketHPACK_Table_add (SocketHPACK_Table_T table,
                       const char *name,
                       size_t name_len,
                       const char *value,
                       size_t value_len)
{
  size_t entry_size;
  HPACK_DynamicEntry *entry_ptr;
  SocketHPACK_Result res;

  res = hpack_validate_table_strict (table, "Table_add");
  if (res != HPACK_OK)
    return res;

  if ((name == NULL && name_len != 0) || (value == NULL && value_len != 0))
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK Table_add: invalid NULL string with non-zero length");
      return HPACK_ERROR;
    }

  entry_size = hpack_entry_size (name_len, value_len);
  hpack_table_prepare_insertion (table, entry_size);

  entry_ptr = &table->entries[table->tail];

  res = hpack_dynamic_entry_init (
      table->arena, name, name_len, value, value_len, entry_ptr);
  if (res != HPACK_OK)
    return res;

  table->tail = RINGBUF_WRAP (table->tail + 1, table->capacity);
  table->count++;
  table->size += entry_size;

  return HPACK_OK;
}

int
SocketHPACK_Table_find (SocketHPACK_Table_T table,
                        const char *name,
                        size_t name_len,
                        const char *value,
                        size_t value_len)
{
  int name_match = 0;
  size_t i;

  if (!hpack_validate_table (table, "Table_find"))
    return 0;

  if (!hpack_validate_search_params (name, name_len))
    return 0;

  for (i = 0; i < table->count; i++)
    {
      size_t slot = hpack_table_index_to_slot (table, i + 1);
      HPACK_DynamicEntry *entry = &table->entries[slot];
      int match = hpack_match_entry (entry->name,
                                     entry->name_len,
                                     entry->value,
                                     entry->value_len,
                                     name,
                                     name_len,
                                     value,
                                     value_len);

      if (match == 1)
        return (int)(i + 1);

      if (match == 0 && name_match == 0)
        name_match = -(int)(i + 1);
    }

  return name_match;
}

#undef T
