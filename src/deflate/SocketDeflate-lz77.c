/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-lz77.c
 * @brief RFC 1951 LZ77 string matcher for DEFLATE compression.
 *
 * Implements hash-table-based string matching per RFC 1951 Section 4.
 * Uses a 15-bit hash on 3-byte sequences with chained collision resolution.
 *
 * Key features:
 * - 32KB window with 32K-entry hash table
 * - Position+1 storage to distinguish position 0 from "no match"
 * - Configurable chain limits for speed/compression tradeoff
 * - Lazy matching optimization for improved compression
 */

#include "deflate/SocketDeflate.h"

#include "core/Arena.h"

#include <string.h>

/**
 * LZ77 matcher state structure.
 *
 * The hash table uses position+1 storage:
 * - head[hash] == 0 means no position has this hash
 * - head[hash] == N means position N-1 has this hash
 * - prev[pos] == 0 means end of chain
 * - prev[pos] == M means position M-1 has same hash
 */
struct SocketDeflate_Matcher
{
  /* Hash table: head[hash] = most recent position + 1 (0 = no match) */
  uint16_t head[DEFLATE_HASH_SIZE];

  /* Chain links: prev[pos % WINDOW_SIZE] = previous position + 1 (0 = end) */
  uint16_t prev[DEFLATE_WINDOW_SIZE];

  /* Input window */
  const uint8_t *window; /* Input data pointer */
  size_t window_size;    /* Actual data size */

  /* Configuration */
  int chain_limit; /* Max chain traversal */
  int good_length; /* Length threshold to reduce lazy search */
  int nice_length; /* Stop search if match >= this */

  Arena_T arena;
};

/*
 * Hash 3 bytes into 15-bit value.
 *
 * Uses XOR with bit shifts for good distribution.
 * The shifts (10, 5, 0) spread the byte values across
 * the 15-bit hash space.
 */
static inline uint32_t
deflate_hash3 (const uint8_t *s)
{
  return ((uint32_t)s[0] << 10) ^ ((uint32_t)s[1] << 5) ^ s[2];
}

/*
 * Public API Implementation
 */

SocketDeflate_Matcher_T
SocketDeflate_Matcher_new (Arena_T arena)
{
  SocketDeflate_Matcher_T matcher;

  matcher = ALLOC (arena, sizeof (*matcher));

  /* Initialize hash table to "no match" */
  memset (matcher->head, 0, sizeof (matcher->head));

  /* Initialize chain links to "end of chain" */
  memset (matcher->prev, 0, sizeof (matcher->prev));

  /* No input yet */
  matcher->window = NULL;
  matcher->window_size = 0;

  /* Set default limits */
  matcher->chain_limit = DEFLATE_CHAIN_LIMIT;
  matcher->good_length = DEFLATE_GOOD_LENGTH;
  matcher->nice_length = DEFLATE_NICE_LENGTH;

  matcher->arena = arena;

  return matcher;
}

void
SocketDeflate_Matcher_init (SocketDeflate_Matcher_T matcher,
                            const uint8_t *data,
                            size_t size)
{
  /* Clear hash table */
  memset (matcher->head, 0, sizeof (matcher->head));
  memset (matcher->prev, 0, sizeof (matcher->prev));

  /* Set input window */
  matcher->window = data;
  matcher->window_size = size;
}

void
SocketDeflate_Matcher_set_limits (SocketDeflate_Matcher_T matcher,
                                  int chain_limit,
                                  int good_len,
                                  int nice_len)
{
  if (chain_limit > 0)
    matcher->chain_limit = chain_limit;
  if (good_len > 0)
    matcher->good_length = good_len;
  if (nice_len > 0)
    matcher->nice_length = nice_len;
}

void
SocketDeflate_Matcher_insert (SocketDeflate_Matcher_T matcher, size_t pos)
{
  uint32_t hash;
  size_t wrapped_pos;

  /* Need at least 3 bytes for hash */
  if (pos + DEFLATE_MIN_MATCH > matcher->window_size)
    return;

  hash = deflate_hash3 (matcher->window + pos) & (DEFLATE_HASH_SIZE - 1);
  wrapped_pos = pos & (DEFLATE_WINDOW_SIZE - 1);

  /* Link to previous position with same hash */
  matcher->prev[wrapped_pos] = matcher->head[hash];

  /* Update head to current position+1 */
  matcher->head[hash] = (uint16_t)(pos + 1);
}

/*
 * Get next position in hash chain.
 */
static uint16_t
get_next_in_chain (SocketDeflate_Matcher_T matcher, size_t cur)
{
  return matcher->prev[cur & (DEFLATE_WINDOW_SIZE - 1)];
}

/*
 * Check if candidate at cmp matches scan for at least min bytes.
 * Returns 0 if quick-reject, else extends and returns match length.
 */
static size_t
try_match (const uint8_t *scan,
           const uint8_t *scan_end,
           const uint8_t *cmp,
           size_t best_len)
{
  /* Quick reject: byte at best_len doesn't match */
  if (best_len >= DEFLATE_MIN_MATCH && cmp[best_len] != scan[best_len])
    return 0;

  /* Check first 3 bytes */
  if (cmp[0] != scan[0] || cmp[1] != scan[1] || cmp[2] != scan[2])
    return 0;

  /* Extend match forward */
  const uint8_t *s = scan + DEFLATE_MIN_MATCH;
  const uint8_t *c = cmp + DEFLATE_MIN_MATCH;

  while (s < scan_end && *s == *c)
    {
      s++;
      c++;
    }

  return s - scan;
}

int
SocketDeflate_Matcher_find (SocketDeflate_Matcher_T matcher,
                            size_t pos,
                            SocketDeflate_Match *match)
{
  uint32_t hash;
  uint16_t cur_plus1;
  size_t best_len = DEFLATE_MIN_MATCH - 1;
  size_t best_dist = 0;
  size_t max_len;
  const uint8_t *window;
  const uint8_t *scan;
  const uint8_t *scan_end;

  /* Need at least 3 bytes for minimum match */
  if (pos + DEFLATE_MIN_MATCH > matcher->window_size)
    return 0;

  window = matcher->window;
  hash = deflate_hash3 (window + pos) & (DEFLATE_HASH_SIZE - 1);
  cur_plus1 = matcher->head[hash];

  if (cur_plus1 == 0)
    return 0;

  /* Maximum match length at this position */
  max_len = matcher->window_size - pos;
  if (max_len > DEFLATE_MAX_MATCH)
    max_len = DEFLATE_MAX_MATCH;

  scan = window + pos;
  scan_end = scan + max_len;

  /* Traverse hash chain */
  for (int chain_count = 0; chain_count < matcher->chain_limit; chain_count++)
    {
      if (cur_plus1 == 0)
        break;

      size_t cur = cur_plus1 - 1;
      size_t dist = pos - cur;

      if (dist > DEFLATE_WINDOW_SIZE || dist == 0)
        break;

      size_t len = try_match (scan, scan_end, window + cur, best_len);

      if (len > best_len)
        {
          best_len = len;
          best_dist = dist;

          if (len >= (size_t)matcher->nice_length)
            break;
        }

      cur_plus1 = get_next_in_chain (matcher, cur);
    }

  if (best_len >= DEFLATE_MIN_MATCH)
    {
      match->length = (uint16_t)best_len;
      match->distance = (uint16_t)best_dist;
      return 1;
    }

  return 0;
}

int
SocketDeflate_Matcher_should_defer (SocketDeflate_Matcher_T matcher,
                                    size_t pos,
                                    unsigned int cur_len)
{
  SocketDeflate_Match lookahead;

  /*
   * If current match is already "good enough", don't bother
   * looking ahead. This saves time for long matches.
   */
  if (cur_len >= (unsigned int)matcher->good_length)
    return 0;

  /*
   * Check if position+1 has a longer match.
   * If so, we should defer (emit literal at pos, then use
   * the longer match at pos+1).
   */
  if (pos + 1 + DEFLATE_MIN_MATCH <= matcher->window_size)
    {
      if (SocketDeflate_Matcher_find (matcher, pos + 1, &lookahead))
        {
          if (lookahead.length > cur_len)
            return 1;
        }
    }

  return 0;
}
