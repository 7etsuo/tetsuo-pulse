/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-headers.c - HTTP Header Collection
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements HTTP header collection with O(1) average case
 * case-insensitive lookup using hash table with separate chaining.
 */



#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Overhead for null terminators in header entry size calculation */
#define HEADER_ENTRY_NULL_OVERHEAD 2

/** Maximum chain length per bucket to prevent hash collision DoS attacks */
#define SOCKETHTTP_MAX_CHAIN_LEN 10

/**
 * Maximum chain length to traverse during search operations.
 * Set to 2x the insertion limit to allow searching existing entries
 * even when bucket is at capacity.
 */
#define SOCKETHTTP_MAX_CHAIN_SEARCH_LEN (SOCKETHTTP_MAX_CHAIN_LEN * 2)

/**
 * VALIDATE_HEADERS_NAME - Validate headers and name parameters.
 * @headers: Headers collection (may be NULL).
 * @name: Header name (may be NULL).
 * @retval: Value to return if validation fails.
 *
 * Common validation pattern for public header functions.
 */
#define VALIDATE_HEADERS_NAME(headers, name, retval)                          \
  do                                                                          \
    {                                                                         \
      if (!(headers) || !(name))                                              \
        return (retval);                                                      \
    }                                                                         \
  while (0)

/* ============================================================================
 * Internal Helper Functions - Hash Table Operations
 * ============================================================================
 */

/**
 * find_entry_with_prev - Find header entry and track predecessor
 * @headers: Header collection
 * @name: Header name to find
 * @name_len: Length of name
 * @prev_ptr_out: Output pointer to predecessor's hash_next pointer (for O(1) unlink)
 *
 * Returns: Entry pointer or NULL if not found
 * On success, *prev_ptr_out points to the hash_next pointer that points to entry
 */
static HeaderEntry *
find_entry_with_prev (SocketHTTP_Headers_T headers, const char *name,
                      size_t name_len, HeaderEntry ***prev_ptr_out)
{
  unsigned bucket = socket_util_hash_djb2_ci_len (name, name_len,
                                                  SOCKETHTTP_HEADER_BUCKETS);
  HeaderEntry **pp = &headers->buckets[bucket];

  /* SECURITY: Limit traversal to prevent hash collision DoS */
  int chain_len = 0;
  while (*pp)
    {
      chain_len++;
      if (chain_len > SOCKETHTTP_MAX_CHAIN_SEARCH_LEN)
        {
          SOCKET_LOG_WARN_MSG (
              "SocketHTTP",
              "Excessive hash chain length %d in bucket %u - potential DoS",
              chain_len, bucket);
          return NULL;
        }
      if (sockethttp_name_equal ((*pp)->name, (*pp)->name_len, name, name_len))
        {
          if (prev_ptr_out)
            *prev_ptr_out = pp;
          return *pp;
        }
      pp = &(*pp)->hash_next;
    }
  return NULL;
}

/**
 * find_entry - Find header entry by name (case-insensitive)
 * @headers: Header collection
 * @name: Header name to find
 * @name_len: Length of name
 *
 * Returns: Entry pointer or NULL if not found
 */
static HeaderEntry *
find_entry (SocketHTTP_Headers_T headers, const char *name, size_t name_len)
{
  return find_entry_with_prev (headers, name, name_len, NULL);
}

/**
 * add_to_bucket - Add entry to hash bucket
 * @headers: Header collection
 * @entry: Entry to add (must have entry->hash pre-computed)
 *
 * Returns: 0 on success, -1 if bucket chain too long (DoS protection)
 */
static int
add_to_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  /* Use cached hash from entry (computed during add_n) */
  unsigned bucket = entry->hash;

  /* SECURITY: Check current chain length to prevent hash collision DoS */
  int chain_len = 0;
  for (HeaderEntry *curr = headers->buckets[bucket]; curr;
       curr = curr->hash_next)
    {
      chain_len++;
      if (chain_len >= SOCKETHTTP_MAX_CHAIN_LEN)
        return -1; /* Bucket too crowded - potential DoS */
    }

  entry->hash_next = headers->buckets[bucket];
  headers->buckets[bucket] = entry;
  return 0;
}

/**
 * unlink_from_bucket_fast - O(1) unlink entry using predecessor pointer
 * @entry: Entry to remove
 * @prev_ptr: Pointer to hash_next that points to entry (from find_entry_with_prev)
 */
static void
unlink_from_bucket_fast (HeaderEntry *entry, HeaderEntry **prev_ptr)
{
  *prev_ptr = entry->hash_next;
}

/**
 * remove_from_bucket - Remove entry from hash bucket (O(n) traversal)
 * @headers: Header collection
 * @entry: Entry to remove (uses cached entry->hash)
 *
 * Note: Prefer unlink_from_bucket_fast() when predecessor is known from find.
 */
static void
remove_from_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  /* Use cached hash from entry */
  unsigned bucket = entry->hash;
  HeaderEntry **pp = &headers->buckets[bucket];

  while (*pp)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

/* ============================================================================
 * Internal Helper Functions - List Operations
 * ============================================================================
 */

/**
 * add_to_list - Add entry to insertion-order list
 * @headers: Header collection
 * @entry: Entry to add
 */
static void
add_to_list (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  entry->list_prev = headers->last;
  entry->list_next = NULL;

  if (headers->last)
    headers->last->list_next = entry;
  else
    headers->first = entry;

  headers->last = entry;
}

/**
 * remove_from_list - Remove entry from insertion-order list
 * @headers: Header collection
 * @entry: Entry to remove
 */
static void
remove_from_list (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  if (entry->list_prev)
    entry->list_prev->list_next = entry->list_next;
  else
    headers->first = entry->list_next;

  if (entry->list_next)
    entry->list_next->list_prev = entry->list_prev;
  else
    headers->last = entry->list_prev;
}

static int
remove_one_n (SocketHTTP_Headers_T headers, const char *name, size_t name_len)
{
  HeaderEntry **prev_ptr = NULL;
  HeaderEntry *entry = find_entry_with_prev (headers, name, name_len, &prev_ptr);
  if (!entry)
    return 0;

  size_t delta_temp;
  size_t delta;
  if (!SocketSecurity_check_add (entry->name_len, entry->value_len,
                                 &delta_temp)
      || !SocketSecurity_check_add (delta_temp, HEADER_ENTRY_NULL_OVERHEAD,
                                    &delta))
    {
      /* Invalid entry sizes, reset total */
      headers->total_size = 0;
      SOCKET_LOG_WARN_MSG ("SocketHTTP",
                           "Invalid header entry sizes in remove");
    }
  else if (delta > headers->total_size)
    {
      headers->total_size = 0;
      SOCKET_LOG_WARN_MSG ("SocketHTTP",
                           "Header total_size underflow in remove");
    }
  else
    {
      headers->total_size -= delta;
    }

  /* Use fast O(1) unlink since we tracked predecessor during find */
  unlink_from_bucket_fast (entry, prev_ptr);
  remove_from_list (headers, entry);
  headers->count--;

  return 1;
}

/* ============================================================================
 * Internal Helper Functions - Token Matching
 * ============================================================================
 */

/* skip_token_delimiters - Use shared sockethttp_skip_delimiters */
#define skip_token_delimiters sockethttp_skip_delimiters

/**
 * extract_token_bounds - Find end of current token
 * @start: Start of token
 * @end: Output pointer to one past end of token
 *
 * Returns: Length of token
 */
static size_t
extract_token_bounds (const char *start, const char **end)
{
  const char *p = start;
  while (*p && *p != ',' && *p != ' ' && *p != '\t')
    p++;
  *end = p;
  return (size_t)(p - start);
}


/* ============================================================================
 * Internal Helper Functions - Header Entry Allocation
 * ============================================================================
 */

/**
 * validate_header_limits - Check header count and size limits
 * @headers: Header collection
 * @entry_size: Size of new entry
 *
 * Returns: 0 if within limits, -1 if exceeded
 */
static int
validate_header_limits (SocketHTTP_Headers_T headers, size_t entry_size)
{
  size_t new_count;
  if (!SocketSecurity_check_add (headers->count, 1, &new_count)
      || new_count > SOCKETHTTP_MAX_HEADERS)
    return -1;

  size_t new_total;
  if (!SocketSecurity_check_add (headers->total_size, entry_size, &new_total)
      || new_total > SOCKETHTTP_MAX_HEADER_SIZE)
    return -1;
  return 0;
}

/**
 * allocate_string_copy - Allocate and copy a string to arena
 * @arena: Memory arena
 * @src: Source string (may be NULL)
 * @len: String length (0 for empty)
 *
 * Returns: Null-terminated copy or NULL on allocation failure.
 * If src is NULL or len is 0, returns empty string.
 */
static char *
allocate_string_copy (Arena_T arena, const char *src, size_t len)
{
  size_t alloc_size = (src && len > 0) ? len + 1 : 1;
  char *copy = ALLOC (arena, alloc_size);
  if (!copy)
    return NULL;
  if (src && len > 0)
    memcpy (copy, src, len);
  copy[alloc_size - 1] = '\0';
  return copy;
}

/**
 * allocate_entry_name - Allocate and copy header name
 * @arena: Memory arena
 * @entry: Entry to populate
 * @name: Header name
 * @name_len: Name length
 *
 * Returns: 0 on success, -1 on failure
 */
static int
allocate_entry_name (Arena_T arena, HeaderEntry *entry, const char *name,
                     size_t name_len)
{
  char *name_copy = allocate_string_copy (arena, name, name_len);
  if (!name_copy)
    return -1;
  entry->name = name_copy;
  entry->name_len = name_len;
  return 0;
}

/**
 * allocate_entry_value - Allocate and copy header value
 * @arena: Memory arena
 * @entry: Entry to populate
 * @value: Header value (may be NULL)
 * @value_len: Value length
 *
 * Returns: 0 on success, -1 on failure
 */
static int
allocate_entry_value (Arena_T arena, HeaderEntry *entry, const char *value,
                      size_t value_len)
{
  char *value_copy = allocate_string_copy (arena, value, value_len);
  if (!value_copy)
    return -1;
  entry->value = value_copy;
  entry->value_len = (value && value_len > 0) ? value_len : 0;
  return 0;
}

/* ============================================================================
 * Header Collection Lifecycle
 * ============================================================================
 */

SocketHTTP_Headers_T
SocketHTTP_Headers_new (Arena_T arena)
{
  if (!arena)
    return NULL;

  SocketHTTP_Headers_T headers = CALLOC (arena, 1, sizeof (*headers));
  if (!headers)
    return NULL;

  headers->arena = arena;
  /* count, total_size, first, last, buckets are zero-initialized by CALLOC */

  return headers;
}

void
SocketHTTP_Headers_clear (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return;

  /* Clear hash table buckets */
  for (int i = 0; i < SOCKETHTTP_HEADER_BUCKETS; i++)
    headers->buckets[i] = NULL;

  /* Clear list and counters */
  headers->first = NULL;
  headers->last = NULL;
  headers->count = 0;
  headers->total_size = 0;

  /* Note: Memory is arena-allocated, actual freeing happens on Arena_dispose
   */
}

/* ============================================================================
 * Adding Headers
 * ============================================================================
 */

int
SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers, const char *name,
                          size_t name_len, const char *value, size_t value_len)
{
  VALIDATE_HEADERS_NAME (headers, name, -1);

  if (!SocketHTTP_header_name_valid (name, name_len))
    return -1;

  if (!SocketHTTP_header_value_valid (value, value_len))
    return -1;

  size_t temp_size;
  if (!SocketSecurity_check_add (name_len, value_len, &temp_size))
    return -1;
  size_t entry_size;
  if (!SocketSecurity_check_add (temp_size, HEADER_ENTRY_NULL_OVERHEAD,
                                 &entry_size))
    return -1;
  if (validate_header_limits (headers, entry_size) < 0)
    return -1;

  HeaderEntry *entry = ALLOC (headers->arena, sizeof (*entry));
  if (!entry)
    return -1;

  if (allocate_entry_name (headers->arena, entry, name, name_len) < 0)
    return -1;

  /* Cache hash bucket index to avoid recomputation in bucket operations */
  entry->hash = socket_util_hash_djb2_ci_len (name, name_len,
                                              SOCKETHTTP_HEADER_BUCKETS);

  if (allocate_entry_value (headers->arena, entry, value, value_len) < 0)
    return -1;

  if (add_to_bucket (headers, entry) < 0)
    return -1;

  add_to_list (headers, entry);
  headers->count++;
  headers->total_size += entry_size;

  return 0;
}

int
SocketHTTP_Headers_add (SocketHTTP_Headers_T headers, const char *name,
                        const char *value)
{
  if (!name)
    return -1;
  size_t name_len = strlen (name);
  size_t value_len = value ? strlen (value) : 0;
  return SocketHTTP_Headers_add_n (headers, name, name_len, value, value_len);
}

int
SocketHTTP_Headers_set (SocketHTTP_Headers_T headers, const char *name,
                        const char *value)
{
  VALIDATE_HEADERS_NAME (headers, name, -1);

  SocketHTTP_Headers_remove_all (headers, name);
  return SocketHTTP_Headers_add (headers, name, value);
}

/* ============================================================================
 * Retrieving Headers
 * ============================================================================
 */

const char *
SocketHTTP_Headers_get (SocketHTTP_Headers_T headers, const char *name)
{
  VALIDATE_HEADERS_NAME (headers, name, NULL);

  size_t name_len = strlen (name);
  HeaderEntry *entry = find_entry (headers, name, name_len);

  return entry ? entry->value : NULL;
}

int
SocketHTTP_Headers_get_int (SocketHTTP_Headers_T headers, const char *name,
                            int64_t *value)
{
  if (!headers || !name || !value)
    return -1;

  const char *str = SocketHTTP_Headers_get (headers, name);
  if (!str)
    return -1;

  const char *p = str;
  /* Skip leading whitespace */
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0')
    return -1;

  /* Parse optional sign */
  int negative = 0;
  if (*p == '-')
    {
      negative = 1;
      p++;
    }
  else if (*p == '+')
    {
      p++;
    }

  /* Parse digits with overflow protection */
  if (!(*p >= '0' && *p <= '9'))
    return -1;
  int64_t result = 0;
  while (*p >= '0' && *p <= '9')
    {
      int digit = *p - '0';
      if (result > (INT64_MAX - digit) / 10)
        return -1; /* Overflow */
      result = result * 10 + digit;
      p++;
    }

  /* Skip trailing whitespace */
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != '\0')
    return -1;

  *value = negative ? -result : result;
  return 0;
}

size_t
SocketHTTP_Headers_get_all (SocketHTTP_Headers_T headers, const char *name,
                            const char **values, size_t max_values)
{
  if (!headers || !name || !values || max_values == 0)
    return 0;

  size_t name_len = strlen (name);
  size_t found = 0;

  HeaderEntry *entry = headers->first;
  while (entry && found < max_values)
    {
      if (sockethttp_name_equal (entry->name, entry->name_len, name, name_len))
        values[found++] = entry->value;
      entry = entry->list_next;
    }

  return found;
}

/* ============================================================================
 * Checking Headers
 * ============================================================================
 */

int
SocketHTTP_Headers_has (SocketHTTP_Headers_T headers, const char *name)
{
  VALIDATE_HEADERS_NAME (headers, name, 0);

  size_t name_len = strlen (name);
  return find_entry (headers, name, name_len) != NULL;
}

int
SocketHTTP_Headers_contains (SocketHTTP_Headers_T headers, const char *name,
                             const char *token)
{
  if (!headers || !name || !token)
    return 0;

  const char *header_value = SocketHTTP_Headers_get (headers, name);
  if (!header_value)
    return 0;

  size_t token_len = strlen (token);
  if (token_len == 0)
    return 0;

  const char *p = header_value;
  while (*p)
    {
      p = skip_token_delimiters (p);
      if (*p == '\0')
        break;

      const char *end;
      size_t len = extract_token_bounds (p, &end);

      if (sockethttp_name_equal (p, len, token, token_len))
        return 1;

      p = end;
    }

  return 0;
}

/* ============================================================================
 * Removing Headers
 * ============================================================================
 */

int
SocketHTTP_Headers_remove (SocketHTTP_Headers_T headers, const char *name)
{
  VALIDATE_HEADERS_NAME (headers, name, 0);

  size_t name_len = strlen (name);
  return remove_one_n (headers, name, name_len);
}

int
SocketHTTP_Headers_remove_all (SocketHTTP_Headers_T headers, const char *name)
{
  VALIDATE_HEADERS_NAME (headers, name, 0);

  size_t name_len = strlen (name);
  int removed = 0;
  while (remove_one_n (headers, name, name_len))
    removed++;

  return removed;
}

/* ============================================================================
 * Iteration
 * ============================================================================
 */

size_t
SocketHTTP_Headers_count (SocketHTTP_Headers_T headers)
{
  return headers ? headers->count : 0;
}

const SocketHTTP_Header *
SocketHTTP_Headers_at (SocketHTTP_Headers_T headers, size_t index)
{
  if (!headers || index >= headers->count)
    return NULL;

  /* Linear scan - could optimize with array if needed */
  HeaderEntry *entry = headers->first;
  for (size_t i = 0; i < index && entry; i++)
    entry = entry->list_next;

  if (!entry)
    return NULL;

  /* Cast is safe because HeaderEntry starts with same fields as
   * SocketHTTP_Header */
  return (const SocketHTTP_Header *)entry;
}

int
SocketHTTP_Headers_iterate (SocketHTTP_Headers_T headers,
                            SocketHTTP_HeaderCallback callback, void *userdata)
{
  if (!headers || !callback)
    return 0;

  HeaderEntry *entry = headers->first;
  while (entry)
    {
      int result = callback (entry->name, entry->name_len, entry->value,
                             entry->value_len, userdata);
      if (result != 0)
        return result;
      entry = entry->list_next;
    }

  return 0;
}
