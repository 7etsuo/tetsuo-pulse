/**
 * SocketHTTP-headers.c - HTTP Header Collection
 *
 * Part of the Socket Library
 *
 * Implements HTTP header collection with O(1) average case
 * case-insensitive lookup using hash table with separate chaining.
 */

#include "http/SocketHTTP.h"
#include "http/SocketHTTP-private.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Module-Specific Error Handling
 * ============================================================================ */

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP);

#define RAISE_HTTP_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHTTP, e)

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Overhead for null terminators in header entry size calculation */
#define HEADER_ENTRY_NULL_OVERHEAD 2

/* ============================================================================
 * Internal Helper Functions - String Operations
 * ============================================================================ */

/**
 * arena_strdup_n - Allocate and copy string into arena
 * @arena: Memory arena
 * @str: Source string
 * @len: Length to copy
 *
 * Returns: Arena-allocated null-terminated copy, or NULL on failure
 */
static char *
arena_strdup_n (Arena_T arena, const char *str, size_t len)
{
  char *copy = ALLOC (arena, len + 1);
  if (!copy)
    return NULL;
  memcpy (copy, str, len);
  copy[len] = '\0';
  return copy;
}

/* ============================================================================
 * Internal Helper Functions - Hash Table Operations
 * ============================================================================ */

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
  unsigned bucket = sockethttp_hash_name (name, name_len);
  HeaderEntry *entry = headers->buckets[bucket];

  while (entry)
    {
      if (sockethttp_name_equal (entry->name, entry->name_len, name, name_len))
        return entry;
      entry = entry->hash_next;
    }
  return NULL;
}

/**
 * add_to_bucket - Add entry to hash bucket
 * @headers: Header collection
 * @entry: Entry to add
 */
static void
add_to_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  unsigned bucket = sockethttp_hash_name (entry->name, entry->name_len);
  entry->hash_next = headers->buckets[bucket];
  headers->buckets[bucket] = entry;
}

/**
 * remove_from_bucket - Remove entry from hash bucket
 * @headers: Header collection
 * @entry: Entry to remove
 */
static void
remove_from_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  unsigned bucket = sockethttp_hash_name (entry->name, entry->name_len);
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
 * ============================================================================ */

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

/* ============================================================================
 * Internal Helper Functions - Integer Parsing
 * ============================================================================ */

/**
 * skip_leading_whitespace - Skip leading whitespace characters
 * @p: Pointer to current position (updated on return)
 *
 * Returns: Pointer to first non-whitespace character
 */
static const char *
skip_leading_whitespace (const char *p)
{
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

/**
 * parse_sign - Parse optional sign character
 * @p: Pointer to current position (updated)
 *
 * Returns: 1 if negative sign found, 0 otherwise
 */
static int
parse_sign (const char **p)
{
  if (**p == '-')
    {
      (*p)++;
      return 1;
    }
  if (**p == '+')
    (*p)++;
  return 0;
}

/**
 * parse_digits - Parse digits into int64_t with overflow protection
 * @p: Pointer to current position (updated)
 * @result: Output value
 *
 * Returns: 0 on success, -1 if no digits or overflow
 */
static int
parse_digits (const char **p, int64_t *result)
{
  if (!isdigit ((unsigned char)**p))
    return -1;

  *result = 0;
  while (isdigit ((unsigned char)**p))
    {
      int digit = **p - '0';
      if (*result > (INT64_MAX - digit) / 10)
        return -1; /* Overflow */
      *result = *result * 10 + digit;
      (*p)++;
    }
  return 0;
}

/* ============================================================================
 * Internal Helper Functions - Token Matching
 * ============================================================================ */

/**
 * skip_token_delimiters - Skip whitespace and comma delimiters
 * @p: Pointer to current position
 *
 * Returns: Pointer to start of next token or end of string
 */
static const char *
skip_token_delimiters (const char *p)
{
  while (*p == ' ' || *p == '\t' || *p == ',')
    p++;
  return p;
}

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

/**
 * token_equal_ci - Case-insensitive token comparison
 * @token: Token from header value
 * @token_len: Token length
 * @target: Target token to match
 * @target_len: Target length
 *
 * Returns: 1 if equal (case-insensitive), 0 otherwise
 */
static int
token_equal_ci (const char *token, size_t token_len, const char *target,
                size_t target_len)
{
  return sockethttp_name_equal (token, token_len, target, target_len);
}

/* ============================================================================
 * Internal Helper Functions - Header Entry Allocation
 * ============================================================================ */

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
  if (headers->count >= SOCKETHTTP_MAX_HEADERS)
    return -1;
  if (headers->total_size + entry_size > SOCKETHTTP_MAX_HEADER_SIZE)
    return -1;
  return 0;
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
  entry->name = arena_strdup_n (arena, name, name_len);
  if (!entry->name)
    return -1;
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
  if (value && value_len > 0)
    entry->value = arena_strdup_n (arena, value, value_len);
  else
    entry->value = arena_strdup_n (arena, "", 0);

  if (!entry->value)
    return -1;
  entry->value_len = value_len;
  return 0;
}

/* ============================================================================
 * Header Collection Lifecycle
 * ============================================================================ */

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

  /* Note: Memory is arena-allocated, actual freeing happens on Arena_dispose */
}

/* ============================================================================
 * Adding Headers
 * ============================================================================ */

int
SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers, const char *name,
                          size_t name_len, const char *value, size_t value_len)
{
  if (!headers || !name)
    return -1;

  if (!SocketHTTP_header_name_valid (name, name_len))
    return -1;

  if (!SocketHTTP_header_value_valid (value, value_len))
    return -1;

  size_t entry_size = name_len + value_len + HEADER_ENTRY_NULL_OVERHEAD;
  if (validate_header_limits (headers, entry_size) < 0)
    return -1;

  HeaderEntry *entry = ALLOC (headers->arena, sizeof (*entry));
  if (!entry)
    return -1;

  if (allocate_entry_name (headers->arena, entry, name, name_len) < 0)
    return -1;

  if (allocate_entry_value (headers->arena, entry, value, value_len) < 0)
    return -1;

  add_to_bucket (headers, entry);
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
  if (!headers || !name)
    return -1;

  SocketHTTP_Headers_remove_all (headers, name);
  return SocketHTTP_Headers_add (headers, name, value);
}

/* ============================================================================
 * Retrieving Headers
 * ============================================================================ */

const char *
SocketHTTP_Headers_get (SocketHTTP_Headers_T headers, const char *name)
{
  if (!headers || !name)
    return NULL;

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

  const char *p = skip_leading_whitespace (str);
  if (*p == '\0')
    return -1;

  int negative = parse_sign (&p);

  int64_t result;
  if (parse_digits (&p, &result) < 0)
    return -1;

  p = skip_leading_whitespace (p);
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
 * ============================================================================ */

int
SocketHTTP_Headers_has (SocketHTTP_Headers_T headers, const char *name)
{
  if (!headers || !name)
    return 0;

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

      if (token_equal_ci (p, len, token, token_len))
        return 1;

      p = end;
    }

  return 0;
}

/* ============================================================================
 * Removing Headers
 * ============================================================================ */

int
SocketHTTP_Headers_remove (SocketHTTP_Headers_T headers, const char *name)
{
  if (!headers || !name)
    return 0;

  size_t name_len = strlen (name);
  HeaderEntry *entry = find_entry (headers, name, name_len);

  if (!entry)
    return 0;

  headers->total_size
      -= (entry->name_len + entry->value_len + HEADER_ENTRY_NULL_OVERHEAD);

  remove_from_bucket (headers, entry);
  remove_from_list (headers, entry);
  headers->count--;

  /* Note: Entry memory is arena-allocated, not individually freed */

  return 1;
}

int
SocketHTTP_Headers_remove_all (SocketHTTP_Headers_T headers, const char *name)
{
  if (!headers || !name)
    return 0;

  int removed = 0;
  while (SocketHTTP_Headers_remove (headers, name))
    removed++;

  return removed;
}

/* ============================================================================
 * Iteration
 * ============================================================================ */

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
