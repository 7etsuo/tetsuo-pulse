/**
 * SocketHTTP-headers.c - HTTP Header Collection
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Allocate and copy string into arena (null-terminated)
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

/**
 * Find header entry by name (case-insensitive)
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
 * Add entry to hash bucket
 */
static void
add_to_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  unsigned bucket = sockethttp_hash_name (entry->name, entry->name_len);
  entry->hash_next = headers->buckets[bucket];
  headers->buckets[bucket] = entry;
}

/**
 * Remove entry from hash bucket
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

/**
 * Add entry to insertion-order list
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
 * Remove entry from insertion-order list
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
  headers->count = 0;
  headers->total_size = 0;
  headers->first = NULL;
  headers->last = NULL;

  /* Buckets are zero-initialized by CALLOC */

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

  /* Clear list pointers */
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

  /* Validate name */
  if (!SocketHTTP_header_name_valid (name, name_len))
    return -1;

  /* Validate value */
  if (!SocketHTTP_header_value_valid (value, value_len))
    return -1;

  /* Check limits */
  if (headers->count >= SOCKETHTTP_MAX_HEADERS)
    return -1;

  size_t entry_size = name_len + value_len + 2; /* +2 for null terminators */
  if (headers->total_size + entry_size > SOCKETHTTP_MAX_HEADER_SIZE)
    return -1;

  /* Allocate entry */
  HeaderEntry *entry = ALLOC (headers->arena, sizeof (*entry));
  if (!entry)
    return -1;

  /* Copy name */
  entry->name = arena_strdup_n (headers->arena, name, name_len);
  if (!entry->name)
    return -1;
  entry->name_len = name_len;

  /* Copy value */
  if (value && value_len > 0)
    {
      entry->value = arena_strdup_n (headers->arena, value, value_len);
      if (!entry->value)
        return -1;
    }
  else
    {
      /* Empty value */
      entry->value = arena_strdup_n (headers->arena, "", 0);
      if (!entry->value)
        return -1;
    }
  entry->value_len = value_len;

  /* Add to data structures */
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

  /* Remove all existing headers with this name */
  SocketHTTP_Headers_remove_all (headers, name);

  /* Add new header */
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

  /* Parse integer (handling leading/trailing whitespace) */
  const char *p = str;
  while (*p == ' ' || *p == '\t')
    p++;

  if (*p == '\0')
    return -1;

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

  if (!isdigit ((unsigned char)*p))
    return -1;

  int64_t result = 0;
  while (isdigit ((unsigned char)*p))
    {
      int digit = *p - '0';
      /* Overflow check */
      if (result > (INT64_MAX - digit) / 10)
        return -1;
      result = result * 10 + digit;
      p++;
    }

  /* Skip trailing whitespace */
  while (*p == ' ' || *p == '\t')
    p++;

  /* Should be at end of string */
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

  /* Search through all entries in insertion order */
  HeaderEntry *entry = headers->first;
  while (entry && found < max_values)
    {
      if (sockethttp_name_equal (entry->name, entry->name_len, name, name_len))
        {
          values[found++] = entry->value;
        }
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

  const char *value = SocketHTTP_Headers_get (headers, name);
  if (!value)
    return 0;

  size_t token_len = strlen (token);
  if (token_len == 0)
    return 0;

  /* Search for token in comma-separated list */
  const char *p = value;
  while (*p)
    {
      /* Skip leading whitespace and commas */
      while (*p == ' ' || *p == '\t' || *p == ',')
        p++;

      if (*p == '\0')
        break;

      /* Find end of this token */
      const char *start = p;
      while (*p && *p != ',' && *p != ' ' && *p != '\t')
        p++;

      size_t len = (size_t)(p - start);

      /* Case-insensitive comparison */
      if (len == token_len)
        {
          int match = 1;
          for (size_t i = 0; i < len; i++)
            {
              char a = start[i];
              char b = token[i];
              if (a >= 'A' && a <= 'Z')
                a = a + ('a' - 'A');
              if (b >= 'A' && b <= 'Z')
                b = b + ('a' - 'A');
              if (a != b)
                {
                  match = 0;
                  break;
                }
            }
          if (match)
            return 1;
        }
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

  /* Update total size */
  headers->total_size -= (entry->name_len + entry->value_len + 2);

  /* Remove from data structures */
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

