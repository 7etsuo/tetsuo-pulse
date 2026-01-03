/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP-headers.c - HTTP Header Collection
 *
 * O(1) case-insensitive lookup using hash table with separate chaining.
 */

#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP.h"

#include <stdint.h>
#include <time.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define HEADER_ENTRY_NULL_OVERHEAD 2
#define SOCKETHTTP_MAX_CHAIN_LEN 10
#define SOCKETHTTP_MAX_CHAIN_SEARCH_LEN (SOCKETHTTP_MAX_CHAIN_LEN * 2)
#define SOCKETHTTP_MAX_DOS_WARNINGS 3 /* Hard fail after this many warnings */

#define VALIDATE_HEADERS_NAME(headers, name, retval) \
  do                                                 \
    {                                                \
      if (!(headers) || !(name))                     \
        return (retval);                             \
    }                                                \
  while (0)

/* ============================================================================
 * Hash Table Implementation
 * ============================================================================
 */

/* Random hash seed for DoS protection - initialized once at startup */
static uint32_t header_hash_seed = 0;

__attribute__ ((constructor)) static void
init_header_hash_seed (void)
{
  if (SocketCrypto_random_bytes (&header_hash_seed, sizeof (header_hash_seed))
      != 0)
    {
      /* Fallback: combine multiple entropy sources for better unpredictability
       */
      uint32_t time_seed = (uint32_t)time (NULL);
      uint32_t pid_seed = (uint32_t)getpid ();
      /* Use stack address for ASLR entropy */
      uintptr_t stack_addr = (uintptr_t)&header_hash_seed;
      uint32_t stack_seed = (uint32_t)(stack_addr ^ (stack_addr >> 32));

      header_hash_seed = time_seed ^ pid_seed ^ stack_seed;

      SOCKET_LOG_WARN_MSG ("Crypto RNG unavailable - using weaker entropy "
                           "sources for hash seed");
    }
}

static HeaderEntry *
find_entry_with_prev (SocketHTTP_Headers_T headers,
                      const char *name,
                      size_t name_len,
                      HeaderEntry ***prev_ptr_out)
{
  unsigned bucket
      = socket_util_hash_djb2_seeded_ci_len (
            name, name_len, SOCKETHTTP_HEADER_BUCKETS, header_hash_seed)
        & SOCKETHTTP_HEADER_BUCKET_MASK;
  HeaderEntry **pp = &headers->buckets[bucket];

  int chain_len = 0;
  while (*pp)
    {
      chain_len++;

      /* Early exit if chain is too long */
      if (chain_len > SOCKETHTTP_MAX_CHAIN_SEARCH_LEN)
        {
          headers->dos_chain_warnings++;
          SOCKET_LOG_WARN_MSG (
              "Excessive hash chain length %d in bucket %u - potential DoS "
              "(warning %d/%d)",
              chain_len,
              bucket,
              headers->dos_chain_warnings,
              SOCKETHTTP_MAX_DOS_WARNINGS);

          /* Hard fail after threshold to prevent resource exhaustion */
          if (headers->dos_chain_warnings >= SOCKETHTTP_MAX_DOS_WARNINGS)
            {
              SOCKET_LOG_ERROR_MSG (
                  "DoS threshold exceeded - rejecting connection");
            }
          return NULL;
        }

      /* Check for name match */
      if (sockethttp_name_equal ((*pp)->name, (*pp)->name_len, name, name_len))
        {
          /* Handle optional prev_ptr_out */
          if (prev_ptr_out)
            *prev_ptr_out = pp;
          return *pp;
        }

      pp = &(*pp)->hash_next;
    }
  return NULL;
}

static HeaderEntry *
find_entry (SocketHTTP_Headers_T headers, const char *name, size_t name_len)
{
  return find_entry_with_prev (headers, name, name_len, NULL);
}

static int
add_to_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
  unsigned bucket = entry->hash;

  int chain_len = 0;
  for (HeaderEntry *curr = headers->buckets[bucket]; curr;
       curr = curr->hash_next)
    {
      chain_len++;
      if (chain_len >= SOCKETHTTP_MAX_CHAIN_LEN)
        return -1;
    }

  entry->hash_next = headers->buckets[bucket];
  headers->buckets[bucket] = entry;
  return 0;
}

static void
unlink_from_bucket_fast (HeaderEntry *entry, HeaderEntry **prev_ptr)
{
  *prev_ptr = entry->hash_next;
}

static void
remove_from_bucket (SocketHTTP_Headers_T headers, HeaderEntry *entry)
{
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
 * List Operations
 * ============================================================================
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
  HeaderEntry *entry
      = find_entry_with_prev (headers, name, name_len, &prev_ptr);
  if (!entry)
    return 0;

  size_t delta_temp;
  size_t delta;
  if (!SocketSecurity_check_add (entry->name_len, entry->value_len, &delta_temp)
      || !SocketSecurity_check_add (
          delta_temp, HEADER_ENTRY_NULL_OVERHEAD, &delta))
    {
      headers->total_size = 0;
      SOCKET_LOG_WARN_MSG ("Invalid header entry sizes in remove");
    }
  else if (delta > headers->total_size)
    {
      headers->total_size = 0;
      SOCKET_LOG_WARN_MSG ("Header total_size underflow in remove");
    }
  else
    {
      headers->total_size -= delta;
    }

  unlink_from_bucket_fast (entry, prev_ptr);
  remove_from_list (headers, entry);
  headers->count--;

  return 1;
}

/* ============================================================================
 * Token Matching
 * ============================================================================
 */

#define skip_token_delimiters sockethttp_skip_delimiters

static size_t
extract_token_bounds (const char *start, const char **end)
{
  const char *p = start;
  while (!sockethttp_is_token_boundary (*p))
    p++;
  *end = p;
  return (size_t)(p - start);
}

/* ============================================================================
 * Header Entry Allocation
 * ============================================================================
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

static int
allocate_entry_name (Arena_T arena,
                     HeaderEntry *entry,
                     const char *name,
                     size_t name_len)
{
  char *name_copy = arena_strndup (arena, name, name_len);
  if (!name_copy)
    return -1;
  entry->name = name_copy;
  entry->name_len = name_len;
  return 0;
}

static int
allocate_entry_value (Arena_T arena,
                      HeaderEntry *entry,
                      const char *value,
                      size_t value_len)
{
  char *value_copy = arena_strndup (arena, value, value_len);
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
  return headers;
}

void
SocketHTTP_Headers_clear (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return;

  for (int i = 0; i < SOCKETHTTP_HEADER_BUCKETS; i++)
    headers->buckets[i] = NULL;

  headers->first = NULL;
  headers->last = NULL;
  headers->count = 0;
  headers->total_size = 0;
  headers->dos_chain_warnings = 0;
}

/* ============================================================================
 * Adding Headers
 * ============================================================================
 */

int
SocketHTTP_Headers_add_n (SocketHTTP_Headers_T headers,
                          const char *name,
                          size_t name_len,
                          const char *value,
                          size_t value_len)
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
  if (!SocketSecurity_check_add (
          temp_size, HEADER_ENTRY_NULL_OVERHEAD, &entry_size))
    return -1;
  if (validate_header_limits (headers, entry_size) < 0)
    return -1;

  HeaderEntry *entry = ALLOC (headers->arena, sizeof (*entry));
  if (!entry)
    return -1;

  if (allocate_entry_name (headers->arena, entry, name, name_len) < 0)
    return -1;

  entry->hash = socket_util_hash_djb2_seeded_ci_len (
                    name, name_len, SOCKETHTTP_HEADER_BUCKETS, header_hash_seed)
                & SOCKETHTTP_HEADER_BUCKET_MASK;

  if (allocate_entry_value (headers->arena, entry, value, value_len) < 0)
    return -1;

  entry->is_ref = 0;

  if (add_to_bucket (headers, entry) < 0)
    return -1;

  add_to_list (headers, entry);
  headers->count++;
  headers->total_size += entry_size;

  return 0;
}

int
SocketHTTP_Headers_add_ref (SocketHTTP_Headers_T headers,
                            const char *name,
                            size_t name_len,
                            const char *value,
                            size_t value_len)
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
  if (!SocketSecurity_check_add (
          temp_size, HEADER_ENTRY_NULL_OVERHEAD, &entry_size))
    return -1;
  if (validate_header_limits (headers, entry_size) < 0)
    return -1;

  HeaderEntry *entry = ALLOC (headers->arena, sizeof (*entry));
  if (!entry)
    return -1;

  /* Store references directly - NO COPY */
  entry->name = (char *)name;
  entry->name_len = name_len;
  entry->value = (char *)value;
  entry->value_len = value_len;
  entry->is_ref = 1;

  entry->hash = socket_util_hash_djb2_seeded_ci_len (
                    name, name_len, SOCKETHTTP_HEADER_BUCKETS, header_hash_seed)
                & SOCKETHTTP_HEADER_BUCKET_MASK;

  if (add_to_bucket (headers, entry) < 0)
    return -1;

  add_to_list (headers, entry);
  headers->count++;
  headers->total_size += entry_size;

  return 0;
}

int
SocketHTTP_Headers_materialize (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return -1;

  for (HeaderEntry *e = headers->first; e != NULL; e = e->list_next)
    {
      if (!e->is_ref)
        continue;

      /* Copy name */
      char *name_copy = arena_strndup (headers->arena, e->name, e->name_len);
      if (!name_copy)
        return -1;

      /* Copy value */
      char *value_copy = arena_strndup (headers->arena, e->value, e->value_len);
      if (!value_copy)
        return -1;

      e->name = name_copy;
      e->value = value_copy;
      e->is_ref = 0;
    }

  return 0;
}

int
SocketHTTP_Headers_add (SocketHTTP_Headers_T headers,
                        const char *name,
                        const char *value)
{
  if (!name)
    return -1;
  size_t name_len = strlen (name);
  size_t value_len = value ? strlen (value) : 0;
  return SocketHTTP_Headers_add_n (headers, name, name_len, value, value_len);
}

int
SocketHTTP_Headers_set (SocketHTTP_Headers_T headers,
                        const char *name,
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
SocketHTTP_Headers_get_n (SocketHTTP_Headers_T headers,
                          const char *name,
                          size_t name_len)
{
  VALIDATE_HEADERS_NAME (headers, name, NULL);

  HeaderEntry *entry = find_entry (headers, name, name_len);

  return entry ? entry->value : NULL;
}

const char *
SocketHTTP_Headers_get (SocketHTTP_Headers_T headers, const char *name)
{
  if (!name)
    return NULL;
  return SocketHTTP_Headers_get_n (headers, name, strlen (name));
}

int
SocketHTTP_Headers_get_int (SocketHTTP_Headers_T headers,
                            const char *name,
                            int64_t *value)
{
  if (!headers || !name || !value)
    return -1;

  const char *str = SocketHTTP_Headers_get (headers, name);
  if (!str)
    return -1;

  const char *p = sockethttp_skip_whitespace (str);
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

  if (!(*p >= '0' && *p <= '9'))
    return -1;
  uint64_t result = 0;
  while (*p >= '0' && *p <= '9')
    {
      int digit = *p - '0';
      if (result > (UINT64_MAX - digit) / 10)
        return -1;
      result = result * 10 + digit;
      p++;
    }

  p = sockethttp_skip_whitespace (p);
  if (*p != '\0')
    return -1;

  if (negative)
    {
      if (result > ((uint64_t)INT64_MAX + 1))
        return -1;
      *value = -(int64_t)result;
    }
  else
    {
      if (result > (uint64_t)INT64_MAX)
        return -1;
      *value = (int64_t)result;
    }

  return 0;
}

size_t
SocketHTTP_Headers_get_all_n (SocketHTTP_Headers_T headers,
                              const char *name,
                              size_t name_len,
                              const char **values,
                              size_t max_values)
{
  if (!headers || !name || !values || max_values == 0)
    return 0;

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

size_t
SocketHTTP_Headers_get_all (SocketHTTP_Headers_T headers,
                            const char *name,
                            const char **values,
                            size_t max_values)
{
  if (!name)
    return 0;
  return SocketHTTP_Headers_get_all_n (
      headers, name, strlen (name), values, max_values);
}

/* ============================================================================
 * Checking Headers
 * ============================================================================
 */

int
SocketHTTP_Headers_has_n (SocketHTTP_Headers_T headers,
                          const char *name,
                          size_t name_len)
{
  VALIDATE_HEADERS_NAME (headers, name, 0);

  return find_entry (headers, name, name_len) != NULL;
}

int
SocketHTTP_Headers_has (SocketHTTP_Headers_T headers, const char *name)
{
  if (!name)
    return 0;
  return SocketHTTP_Headers_has_n (headers, name, strlen (name));
}

int
SocketHTTP_Headers_contains_n (SocketHTTP_Headers_T headers,
                               const char *name,
                               size_t name_len,
                               const char *token,
                               size_t token_len)
{
  if (!headers || !name || !token || token_len == 0)
    return 0;

  const char *header_value = SocketHTTP_Headers_get_n (headers, name, name_len);
  if (!header_value)
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

int
SocketHTTP_Headers_contains (SocketHTTP_Headers_T headers,
                             const char *name,
                             const char *token)
{
  if (!name || !token)
    return 0;
  return SocketHTTP_Headers_contains_n (
      headers, name, strlen (name), token, strlen (token));
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

  HeaderEntry *entry = headers->first;
  for (size_t i = 0; i < index && entry; i++)
    entry = entry->list_next;

  if (!entry)
    return NULL;

  return (const SocketHTTP_Header *)entry;
}

int
SocketHTTP_Headers_iterate (SocketHTTP_Headers_T headers,
                            SocketHTTP_HeaderCallback callback,
                            void *userdata)
{
  if (!headers || !callback)
    return 0;

  HeaderEntry *entry = headers->first;
  while (entry)
    {
      int result = callback (entry->name,
                             entry->name_len,
                             entry->value,
                             entry->value_len,
                             userdata);
      if (result != 0)
        return result;
      entry = entry->list_next;
    }

  return 0;
}
