/**
 * SocketHPACK-table.c - HPACK Static and Dynamic Table Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements RFC 7541 Section 2.3 (Static Table) and Section 2.3.2 (Dynamic
 * Table):
 * - Static table with 61 pre-defined header entries
 * - Dynamic table with circular buffer for O(1) FIFO operations
 * - Linear search for static table lookup (sufficient for 61 entries)
 *
 * Uses centralized utilities from SocketUtil.h for hash functions and
 * power-of-2 rounding to avoid code duplication.
 */

#include <assert.h>
#include <string.h>

#include "core/SocketUtil.h"
#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "HPACK"

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/* Use constants from SocketHPACK-private.h:
 * HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE
 * HPACK_MIN_DYNAMIC_TABLE_CAPACITY
 */

/* ============================================================================
 * Static Table (RFC 7541 Appendix A)
 *
 * Index 1-61. Entry sizes include 32-byte overhead per RFC 7541 Section 4.1.
 * Table is sorted by name for binary search, but indexed 1-based.
 * ============================================================================
 */

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
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * hpack_strcasecmp - Case-insensitive string comparison with explicit lengths
 * @a: First string
 * @a_len: Length of first string
 * @b: Second string
 * @b_len: Length of second string
 *
 * Compares two strings case-insensitively (ASCII only, suitable for HTTP
 * headers which are restricted to ASCII). Does not require null-termination.
 *
 * Returns: <0 if a<b, 0 if a==b, >0 if a>b
 * Thread-safe: Yes (no global state)
 */
static int
hpack_strcasecmp (const char *a, size_t a_len, const char *b, size_t b_len)
{
  size_t min_len = (a_len < b_len ? a_len : b_len);

  int cmp = strncasecmp (a, b, min_len);
  if (cmp != 0)
    return cmp;

  /* Prefixes match up to min_len; compare full lengths for lexicographical
   * order */
  return (a_len < b_len) ? -1 : (a_len > b_len ? 1 : 0);
}

/**
 * hpack_match_entry - Check if entry matches name and optionally value
 * @entry_name: Entry header name
 * @entry_name_len: Entry name length
 * @entry_value: Entry header value
 * @entry_value_len: Entry value length
 * @name: Search name
 * @name_len: Search name length
 * @value: Search value (NULL to match name only)
 * @value_len: Search value length
 *
 * Checks if an entry matches the given name (case-insensitive, ASCII) and
 * optionally the value (case-sensitive binary compare). Used internally by
 * static and dynamic table search functions to find exact or name-only
 * matches.
 *
 * Returns: 1 for exact match (name+value), 0 for name-only match, -1 for no
 * match Thread-safe: Yes (no global state)
 */
static int
hpack_match_entry (const char *entry_name, size_t entry_name_len,
                   const char *entry_value, size_t entry_value_len,
                   const char *name, size_t name_len, const char *value,
                   size_t value_len)
{
  /* Check name match (case-insensitive for HTTP headers) */
  if (entry_name_len != name_len)
    return -1;

  if (hpack_strcasecmp (entry_name, entry_name_len, name, name_len) != 0)
    return -1;

  /* Name matches - check value if provided */
  if (value != NULL && entry_value_len == value_len
      && (value_len == 0 || memcmp (entry_value, value, value_len) == 0))
    {
      return 1; /* Exact match */
    }

  return 0; /* Name-only match */
}

/* ============================================================================
 * Common Validation Helpers
 * ============================================================================
 */

/**
 * hpack_validate_search_params - Validate name parameters for search functions
 * @name: Header name
 * @name_len: Name length
 *
 * Logs debug message and returns 0 if invalid.
 * Returns: 1 if valid, 0 if invalid
 * Thread-safe: Yes
 */
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

/**
 * hpack_validate_index - Validate index for table get functions
 * @index: Requested index (1-based)
 * @max_idx: Maximum valid index
 * @func: Function name for logging
 *
 * Returns: HPACK_OK if valid, appropriate error otherwise
 * Thread-safe: Yes
 */
static SocketHPACK_Result
hpack_validate_index (size_t index, size_t max_idx, const char *func)
{
  if (index < 1 || index > max_idx)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketHPACK %s: invalid index %zu (valid range 1-%zu)", func, index,
          max_idx);
      return HPACK_ERROR_INVALID_INDEX;
    }
  return HPACK_OK;
}

/**
 * hpack_validate_header_ptr - Validate output header pointer
 * @header: Output header structure
 * @func: Function name for logging
 *
 * Returns: HPACK_OK if valid, HPACK_ERROR otherwise
 * Thread-safe: Yes
 */
static SocketHPACK_Result
hpack_validate_header_ptr (SocketHPACK_Header *header, const char *func)
{
  if (header == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK %s: NULL output header pointer",
                            func);
      return HPACK_ERROR;
    }
  return HPACK_OK;
}

/* ============================================================================
 * Dynamic Table Helper Functions
 * ============================================================================
 */

/* Forward declarations */
static void hpack_table_clear (SocketHPACK_Table_T table);
static SocketHPACK_Result hpack_duplicate_header_strings (
    Arena_T arena, const char *name, size_t name_len, const char *value,
    size_t value_len, char **name_out, char **value_out);

/**
 * hpack_dynamic_initial_capacity - Calculate initial circular buffer capacity
 * @max_size: Maximum table size in bytes
 *
 * Estimates number of entries based on average entry size, clamps to minimum,
 * and rounds up to power-of-2 for efficient circular buffer operations using
 * bitmask modulo.
 *
 * Returns: Initial capacity (>= HPACK_MIN_DYNAMIC_TABLE_CAPACITY, power of 2)
 * Thread-safe: Yes (no state)
 */
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

/**
 * hpack_table_prepare_insertion - Prepare dynamic table for new entry
 * insertion
 * @table: Dynamic table instance
 * @entry_size: Proposed new entry size (name + value + overhead)
 *
 * If entry_size exceeds max_size, clears the entire table.
 * Otherwise, evicts oldest entries from the head until sufficient space is
 * available.
 *
 * Returns: HPACK_OK (always succeeds, table may be cleared or entries evicted)
 * Thread-safe: No (modifies table state)
 */
static SocketHPACK_Result
hpack_table_prepare_insertion (SocketHPACK_Table_T table, size_t entry_size)
{
  assert (table != NULL);

  if (entry_size > table->max_size)
    {
      hpack_table_clear (table);
      return HPACK_OK;
    }

  hpack_table_evict (table, entry_size);
  return HPACK_OK;
}

/**
 * hpack_dynamic_entry_init - Initialize dynamic entry with duplicated strings
 * @arena: Arena for string allocations
 * @name: Source header name
 * @name_len: Name length
 * @value: Source header value
 * @value_len: Value length
 * @entry: Output entry structure to initialize
 *
 * Duplicates name and value strings into arena-allocated memory
 * (null-terminated). Logs error and returns HPACK_ERROR on allocation failure.
 *
 * Returns: HPACK_OK on success, HPACK_ERROR on allocation failure
 * Thread-safe: Yes (if arena is thread-safe)
 * Note: Entry strings owned by arena; valid until arena dispose.
 */
static SocketHPACK_Result
hpack_dynamic_entry_init (Arena_T arena, const char *name, size_t name_len,
                          const char *value, size_t value_len,
                          HPACK_DynamicEntry *entry)
{
  assert (arena != NULL);
  assert (entry != NULL);

  SocketHPACK_Result res = hpack_duplicate_header_strings (
      arena, name, name_len, value, value_len, &entry->name, &entry->value);
  if (res != HPACK_OK)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK: hpack_dynamic_entry_init failed - "
                            "%s (name_len=%zu, value_len=%zu)",
                            SocketHPACK_result_string (res), name_len,
                            value_len);
      return res;
    }

  entry->name_len = name_len;
  entry->value_len = value_len;
  return HPACK_OK;
}

/* ============================================================================
 * Static Table Lookup Functions
 * ============================================================================
 */

SocketHPACK_Result
SocketHPACK_static_get (size_t index, SocketHPACK_Header *header)
{
  SocketHPACK_Result res = hpack_validate_index (
      index, SOCKETHPACK_STATIC_TABLE_SIZE, "static_get");
  if (res != HPACK_OK)
    return res;

  res = hpack_validate_header_ptr (header, "static_get");
  if (res != HPACK_OK)
    return res;

  const HPACK_StaticEntry *entry = &hpack_static_table[index - 1];
  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return HPACK_OK;
}

int
SocketHPACK_static_find (const char *name, size_t name_len, const char *value,
                         size_t value_len)
{
  int name_match = 0;

  if (!hpack_validate_search_params (name, name_len))
    return 0;

  /* Linear search through static table (sufficient for 61 entries) */
  for (size_t i = 0; i < SOCKETHPACK_STATIC_TABLE_SIZE; i++)
    {
      const HPACK_StaticEntry *entry = &hpack_static_table[i];

      int match = hpack_match_entry (entry->name, entry->name_len,
                                     entry->value, entry->value_len, name,
                                     name_len, value, value_len);

      if (match == 1)
        return (int)(i + 1); /* Exact match - return positive index */

      if (match == 0 && name_match == 0)
        name_match = -(int)(i + 1); /* First name match - negative index */
    }

  return name_match;
}

/* ============================================================================
 * Dynamic Table Implementation
 *
 * Uses circular buffer for O(1) FIFO operations.
 * Index 1 = most recently added entry (tail-1)
 * Higher indices = older entries toward head
 * ============================================================================
 */

SocketHPACK_Table_T
SocketHPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketHPACK_Table_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    SOCKET_RAISE_MSG (SocketHPACK, SocketHPACK_Error,
                      "failed to allocate SocketHPACK_Table structure");

  /* Estimate initial capacity based on max_size and average entry size */
  initial_capacity = hpack_dynamic_initial_capacity (max_size);

  table->entries
      = CALLOC (arena, initial_capacity, sizeof (HPACK_DynamicEntry));
  if (table->entries == NULL)
    SOCKET_RAISE_MSG (
        SocketHPACK, SocketHPACK_Error,
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

  /* Memory is managed by arena - just clear the pointer */
  *table = NULL;
}

size_t
SocketHPACK_Table_size (SocketHPACK_Table_T table)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketHPACK Table_size: NULL table - returning 0");
      return 0;
    }
  return table->size;
}

size_t
SocketHPACK_Table_count (SocketHPACK_Table_T table)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketHPACK Table_count: NULL table - returning 0");
      return 0;
    }
  return table->count;
}

size_t
SocketHPACK_Table_max_size (SocketHPACK_Table_T table)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG (
          "SocketHPACK Table_max_size: NULL table - returning 0");
      return 0;
    }
  return table->max_size;
}

/**
 * hpack_table_evict - Evict oldest entries to make room for new entry
 * @table: Dynamic table
 * @required_space: Space needed for new entry (bytes, including overhead)
 *
 * Evicts entries from the head (oldest) of the circular buffer until there
 * is sufficient space for a new entry. Per RFC 7541 Section 4.4, entries
 * are evicted in FIFO order.
 *
 * Returns: Number of entries evicted
 * Thread-safe: No (caller must synchronize if needed)
 *
 * Note: This function is declared extern in SocketHPACK-private.h for use
 * by other HPACK implementation files.
 */
size_t
hpack_table_evict (SocketHPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      /* Evict from head (oldest entry) */
      HPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size = hpack_entry_size (entry->name_len, entry->value_len);

      table->size -= entry_size;
      table->head = (table->head + 1) & (table->capacity - 1);
      table->count--;
      evicted++;
    }

  return evicted;
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

/**
 * SocketHPACK_Table_set_max_size - Update maximum dynamic table size
 * @table: Dynamic table
 * @max_size: New maximum size in bytes
 *
 * Updates max_size and evicts entries if current size exceeds new limit.
 * If max_size == 0, clears the table entirely.
 * Clamped to SOCKETHPACK_MAX_TABLE_SIZE.
 *
 * Returns: void
 * Thread-safe: No (caller must synchronize)
 */
void
SocketHPACK_Table_set_max_size (SocketHPACK_Table_T table, size_t max_size)
{
  size_t orig_max = max_size;

  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK Table_set_max_size: NULL table pointer");
      return;
    }

  if (max_size > SOCKETHPACK_MAX_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketHPACK Table_set_max_size: clamping max_size from %zu to %zu",
          orig_max, SOCKETHPACK_MAX_TABLE_SIZE);
      max_size = SOCKETHPACK_MAX_TABLE_SIZE;
    }

  table->max_size = max_size;

  /* Evict or clear as necessary */
  if (max_size == 0)
    hpack_table_clear (table);
  else
    hpack_table_evict (table, 0);
}

SocketHPACK_Result
SocketHPACK_Table_get (SocketHPACK_Table_T table, size_t index,
                       SocketHPACK_Header *header)
{
  size_t actual_index;
  HPACK_DynamicEntry *entry;

  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK Table_get: NULL table pointer");
      return HPACK_ERROR;
    }

  SocketHPACK_Result res
      = hpack_validate_index (index, table->count, "Table_get");
  if (res != HPACK_OK)
    return res;

  res = hpack_validate_header_ptr (header, "Table_get");
  if (res != HPACK_OK)
    return res;

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

/**
 * hpack_duplicate_header_strings - Allocate and duplicate header name/value
 * strings from arena
 * @arena: Arena for allocation
 * @name: Source name (may be NULL if name_len == 0)
 * @name_len: Length of name
 * @value: Source value (may be NULL if value_len == 0)
 * @value_len: Length of value
 * @name_out: Output allocated name copy (null-terminated)
 * @value_out: Output allocated value copy (null-terminated)
 *
 * Duplicates strings with null-termination for safe usage.
 * On allocation failure, returns HPACK_ERROR (partial alloc not cleaned as
 * arena-managed).
 *
 * Returns: HPACK_OK or HPACK_ERROR
 * Thread-safe: Yes (if arena is)
 * Note: Strings owned by caller? No, arena lifetime.
 */
static char *
hpack_arena_alloc_dup (Arena_T arena, const char *src, size_t len,
                       const char *what)
{
  char *dup = ALLOC (arena, len + 1);
  if (dup == NULL)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK: failed to allocate header %s copy (length=%zu)", what,
          len);
      return NULL;
    }
  if (len > 0)
    memcpy (dup, src, len);
  dup[len] = '\0';
  return dup;
}

static SocketHPACK_Result
hpack_duplicate_header_strings (Arena_T arena, const char *name,
                                size_t name_len, const char *value,
                                size_t value_len, char **name_out,
                                char **value_out)
{
  assert (arena != NULL);
  assert (name_out != NULL);
  assert (value_out != NULL);

  *name_out = hpack_arena_alloc_dup (arena, name, name_len, "name");
  if (*name_out == NULL)
    return HPACK_ERROR;

  *value_out = hpack_arena_alloc_dup (arena, value, value_len, "value");
  if (*value_out == NULL)
    return HPACK_ERROR;

  return HPACK_OK;
}

SocketHPACK_Result
SocketHPACK_Table_add (SocketHPACK_Table_T table, const char *name,
                       size_t name_len, const char *value, size_t value_len)
{
  size_t entry_size;
  HPACK_DynamicEntry *entry_ptr;
  SocketHPACK_Result res;

  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketHPACK Table_add: NULL table pointer");
      return HPACK_ERROR;
    }

  if ((name == NULL && name_len != 0) || (value == NULL && value_len != 0))
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketHPACK Table_add: invalid NULL string with non-zero length");
      return HPACK_ERROR;
    }

  entry_size = hpack_entry_size (name_len, value_len);

  res = hpack_table_prepare_insertion (table, entry_size);
  if (res != HPACK_OK)
    return res;

  entry_ptr = &table->entries[table->tail];

  res = hpack_dynamic_entry_init (table->arena, name, name_len, value,
                                  value_len, entry_ptr);
  if (res != HPACK_OK)
    return res;

  table->tail = (table->tail + 1) & (table->capacity - 1);
  table->count++;
  table->size += entry_size;

  return HPACK_OK;
}

/**
 * SocketHPACK_Table_find - Find entry in dynamic table
 * @table: Dynamic table
 * @name: Header name to search for
 * @name_len: Name length
 * @value: Header value (NULL to match name only)
 * @value_len: Value length
 *
 * Searches for an entry in the dynamic table. The search starts from the
 * most recently added entry (index 1) to older entries.
 *
 * Returns: Positive index (1-based) for exact match, negative index if only
 *          name matches, 0 if not found
 * Thread-safe: No
 */
int
SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                        size_t name_len, const char *value, size_t value_len)
{
  int name_match = 0;

  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketHPACK Table_find: NULL table pointer");
      return 0;
    }

  if (!hpack_validate_search_params (name, name_len))
    return 0;

  for (size_t i = 0; i < table->count; i++)
    {
      size_t actual_index = (table->tail - 1 - i) & (table->capacity - 1);
      HPACK_DynamicEntry *entry = &table->entries[actual_index];

      int match = hpack_match_entry (entry->name, entry->name_len,
                                     entry->value, entry->value_len, name,
                                     name_len, value, value_len);

      if (match == 1)
        return (int)(i + 1); /* Exact match - return positive index */

      if (match == 0 && name_match == 0)
        name_match = -(int)(i + 1); /* First name match - negative index */
    }

  return name_match;
}
