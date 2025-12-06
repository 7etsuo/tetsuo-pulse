/**
 * SocketHPACK-table.c - HPACK Static and Dynamic Table Implementation
 *
 * Part of the Socket Library
 *
 * Implements RFC 7541 Section 2.3 (Static Table) and Section 2.3.2 (Dynamic Table):
 * - Static table with 61 pre-defined header entries
 * - Dynamic table with circular buffer for O(1) FIFO operations
 * - Linear search for static table lookup (sufficient for 61 entries)
 *
 * Uses centralized utilities from SocketUtil.h for hash functions and
 * power-of-2 rounding to avoid code duplication.
 */

#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"

#include "core/SocketUtil.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Static Table (RFC 7541 Appendix A)
 *
 * Index 1-61. Entry sizes include 32-byte overhead per RFC 7541 Section 4.1.
 * Table is sorted by name for binary search, but indexed 1-based.
 * ============================================================================ */

/* clang-format off */
/* Static table entries: { name, value, name_len, value_len } */
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

/* ============================================================================
 * Static Table Lookup Functions
 * ============================================================================ */

SocketHPACK_Result
SocketHPACK_static_get (size_t index, SocketHPACK_Header *header)
{
  if (index < 1 || index > SOCKETHPACK_STATIC_TABLE_SIZE)
    return HPACK_ERROR_INVALID_INDEX;

  if (header == NULL)
    return HPACK_ERROR;

  const HPACK_StaticEntry *entry = &hpack_static_table[index - 1];
  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return HPACK_OK;
}

/**
 * Compare two strings case-insensitively
 * Returns: <0 if a<b, 0 if a==b, >0 if a>b
 */
static int
hpack_strcasecmp (const char *a, size_t a_len, const char *b, size_t b_len)
{
  size_t min_len = a_len < b_len ? a_len : b_len;
  size_t i;

  for (i = 0; i < min_len; i++)
    {
      unsigned char ca = (unsigned char)a[i];
      unsigned char cb = (unsigned char)b[i];

      /* Convert to lowercase */
      if (ca >= 'A' && ca <= 'Z')
        ca += 32;
      if (cb >= 'A' && cb <= 'Z')
        cb += 32;

      if (ca != cb)
        return (int)ca - (int)cb;
    }

  /* Equal up to min_len, shorter string is "less" */
  if (a_len < b_len)
    return -1;
  if (a_len > b_len)
    return 1;
  return 0;
}

int
SocketHPACK_static_find (const char *name, size_t name_len, const char *value,
                         size_t value_len)
{
  int name_match = 0;
  size_t i;

  if (name == NULL || name_len == 0)
    return 0;

  /* Linear search through static table */
  /* Could be optimized with hash table or binary search on sorted names */
  for (i = 0; i < SOCKETHPACK_STATIC_TABLE_SIZE; i++)
    {
      const HPACK_StaticEntry *entry = &hpack_static_table[i];

      /* Check name match (case-insensitive for HTTP headers) */
      if (entry->name_len == name_len
          && hpack_strcasecmp (entry->name, entry->name_len, name, name_len)
                 == 0)
        {
          /* Name matches */
          if (name_match == 0)
            name_match = -(int)(i + 1); /* First name match (negative) */

          /* Check value match (case-sensitive) */
          if (value != NULL && entry->value_len == value_len
              && (value_len == 0
                  || memcmp (entry->value, value, value_len) == 0))
            {
              /* Exact match */
              return (int)(i + 1);
            }
        }
    }

  /* Return negative of first name match, or 0 if not found */
  return name_match;
}

/* ============================================================================
 * Dynamic Table Implementation
 *
 * Uses circular buffer for O(1) FIFO operations.
 * Index 1 = most recently added entry
 * ============================================================================ */

/* Power-of-2 rounding uses socket_util_round_up_pow2() from SocketUtil.h */

SocketHPACK_Table_T
SocketHPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketHPACK_Table_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    return NULL;

  /* Estimate initial capacity based on max_size */
  /* Average entry size ~50 bytes (including overhead) */
  initial_capacity = max_size / 50;
  if (initial_capacity < 16)
    initial_capacity = 16;
  initial_capacity = socket_util_round_up_pow2 (initial_capacity);

  table->entries = CALLOC (arena, initial_capacity, sizeof (HPACK_DynamicEntry));
  if (table->entries == NULL)
    return NULL;

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

  /* Memory is managed by arena - just clear the pointer */
  *table = NULL;
}

size_t
SocketHPACK_Table_size (SocketHPACK_Table_T table)
{
  assert (table != NULL);
  return table->size;
}

size_t
SocketHPACK_Table_count (SocketHPACK_Table_T table)
{
  assert (table != NULL);
  return table->count;
}

size_t
SocketHPACK_Table_max_size (SocketHPACK_Table_T table)
{
  assert (table != NULL);
  return table->max_size;
}

/**
 * Evict oldest entries to make room
 */
size_t
hpack_table_evict (SocketHPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      /* Evict from head (oldest) */
      HPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size = hpack_entry_size (entry->name_len, entry->value_len);

      table->size -= entry_size;
      table->head = (table->head + 1) & (table->capacity - 1);
      table->count--;
      evicted++;
    }

  return evicted;
}

void
SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table, size_t max_size)
{
  assert (table != NULL);

  if (max_size > SOCKETHPACK_MAX_TABLE_SIZE)
    max_size = SOCKETHPACK_MAX_TABLE_SIZE;

  table->max_size = max_size;

  /* Evict entries if necessary */
  if (max_size == 0)
    {
      /* Clear the table */
      table->head = 0;
      table->tail = 0;
      table->count = 0;
      table->size = 0;
    }
  else
    {
      hpack_table_evict (table, 0);
    }
}

SocketHPACK_Result
SocketHPACK_Table_get (SocketHPACK_Table_T table, size_t index,
                       SocketHPACK_Header *header)
{
  size_t actual_index;
  HPACK_DynamicEntry *entry;

  assert (table != NULL);

  if (index < 1 || index > table->count)
    return HPACK_ERROR_INVALID_INDEX;

  if (header == NULL)
    return HPACK_ERROR;

  /* Index 1 = most recent (tail - 1) */
  /* Index n = oldest (head) */
  actual_index = (table->tail - index) & (table->capacity - 1);
  entry = &table->entries[actual_index];

  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return HPACK_OK;
}

SocketHPACK_Result
SocketHPACK_Table_add (SocketHPACK_Table_T table, const char *name,
                       size_t name_len, const char *value, size_t value_len)
{
  size_t entry_size;
  HPACK_DynamicEntry *entry;
  char *name_copy;
  char *value_copy;

  assert (table != NULL);
  assert (name != NULL || name_len == 0);
  assert (value != NULL || value_len == 0);

  entry_size = hpack_entry_size (name_len, value_len);

  /* If entry is larger than table, just clear the table */
  if (entry_size > table->max_size)
    {
      table->head = 0;
      table->tail = 0;
      table->count = 0;
      table->size = 0;
      return HPACK_OK;
    }

  /* Evict entries to make room */
  hpack_table_evict (table, entry_size);

  /* Allocate strings from arena */
  name_copy = ALLOC (table->arena, name_len + 1);
  if (name_copy == NULL)
    return HPACK_ERROR;

  value_copy = ALLOC (table->arena, value_len + 1);
  if (value_copy == NULL)
    return HPACK_ERROR;

  /* Copy strings */
  if (name_len > 0)
    memcpy (name_copy, name, name_len);
  name_copy[name_len] = '\0';

  if (value_len > 0)
    memcpy (value_copy, value, value_len);
  value_copy[value_len] = '\0';

  /* Add to tail */
  entry = &table->entries[table->tail];
  entry->name = name_copy;
  entry->name_len = name_len;
  entry->value = value_copy;
  entry->value_len = value_len;

  table->tail = (table->tail + 1) & (table->capacity - 1);
  table->count++;
  table->size += entry_size;

  return HPACK_OK;
}

/**
 * Find entry in dynamic table
 *
 * Returns: Index (1-based) for exact match, negative index for name match, 0 if
 * not found
 */
int
SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                        size_t name_len, const char *value, size_t value_len)
{
  int name_match = 0;
  size_t i;

  if (table == NULL || name == NULL || name_len == 0)
    return 0;

  for (i = 0; i < table->count; i++)
    {
      size_t actual_index = (table->tail - 1 - i) & (table->capacity - 1);
      HPACK_DynamicEntry *entry = &table->entries[actual_index];

      /* Check name match (case-insensitive) */
      if (entry->name_len == name_len
          && hpack_strcasecmp (entry->name, entry->name_len, name, name_len)
                 == 0)
        {
          /* Name matches */
          if (name_match == 0)
            name_match = -(int)(i + 1);

          /* Check value match (case-sensitive) */
          if (value != NULL && entry->value_len == value_len
              && (value_len == 0
                  || memcmp (entry->value, value, value_len) == 0))
            {
              return (int)(i + 1);
            }
        }
    }

  return name_match;
}

