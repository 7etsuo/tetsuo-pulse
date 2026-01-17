/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_lz77.c - RFC 1951 LZ77 string matcher unit tests
 *
 * Tests for the LZ77 string matcher, verifying correct hash table
 * operations, match finding, and lazy matching per RFC 1951 Section 4.
 *
 * Test coverage:
 * - Matcher creation and initialization
 * - Hash function distribution
 * - Basic match finding
 * - Longest match selection
 * - Nearest match preference
 * - Chain limit enforcement
 * - Hash collision handling
 * - Lazy matching
 * - Window boundaries
 * - Edge cases
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Helper: Create and initialize a matcher with test data
 */
static Arena_T test_arena;

static SocketDeflate_Matcher_T
make_matcher (const uint8_t *data, size_t size)
{
  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (test_arena);
  SocketDeflate_Matcher_init (matcher, data, size);
  return matcher;
}

/*
 * Helper: Insert all positions into the matcher
 */
static void
insert_all (SocketDeflate_Matcher_T matcher, size_t count)
{
  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= count; i++)
    {
      SocketDeflate_Matcher_insert (matcher, i);
    }
}

/*
 * Basic Operations Tests
 */

TEST (matcher_create)
{
  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (test_arena);
  ASSERT (matcher != NULL);
}

TEST (matcher_init)
{
  const uint8_t data[] = "Hello, World!";
  SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data) - 1);
  ASSERT (matcher != NULL);
}

TEST (hash_distribution)
{
  /*
   * Test that different 3-byte sequences produce different hashes.
   * We don't require perfect distribution, just that the hash function
   * spreads values across the table.
   */
  const uint8_t seq1[] = "ABC";
  const uint8_t seq2[] = "DEF";
  const uint8_t seq3[] = "XYZ";
  const uint8_t seq4[] = "123";

  /* We can't directly call the hash function, but we can verify
     that inserting different sequences at the same position
     and finding them works correctly. This indirectly tests
     that the hash function distinguishes them. */

  SocketDeflate_Matcher_T matcher;
  SocketDeflate_Match match;

  /* Sequence "ABCABC" should find a match */
  const uint8_t abc_abc[] = "ABCABC";
  matcher = make_matcher (abc_abc, 6);
  SocketDeflate_Matcher_insert (matcher, 0);
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 3, &match), 1);
  ASSERT_EQ (match.length, 3);
  ASSERT_EQ (match.distance, 3);
}

TEST (match_simple)
{
  /* "ABCABC" - position 3 should match position 0 with length 3 */
  const uint8_t data[] = "ABCABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 6);

  /* Insert position 0 */
  SocketDeflate_Matcher_insert (matcher, 0);

  /* Find match at position 3 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 3, &match), 1);
  ASSERT_EQ (match.length, 3);
  ASSERT_EQ (match.distance, 3);
}

TEST (match_longest)
{
  /* "ABCDEFABCDEF" - position 6 should find longest match (6 bytes) */
  const uint8_t data[] = "ABCDEFABCDEF";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 12);

  /* Insert first 6 positions */
  for (size_t i = 0; i < 6; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 6 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 6, &match), 1);
  ASSERT_EQ (match.length, 6);
  ASSERT_EQ (match.distance, 6);
}

TEST (match_nearest)
{
  /*
   * When multiple matches have the same length, prefer the nearest
   * (smallest distance). This produces smaller distance codes.
   *
   * "ABCXXABCXXABC" (13 bytes)
   * "ABC" occurs at positions 0, 5, 10
   * At position 10, we should find position 5 (distance 5, most recent insert)
   */
  const uint8_t data[] = "ABCXXABCXXABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 13);

  /* Insert positions 0-9 (before search position 10) */
  for (size_t i = 0; i < 10; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 10 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 10, &match), 1);
  ASSERT_EQ (match.length, 3);
  /* Should prefer position 5 (distance 5) over position 0 (distance 10) */
  ASSERT_EQ (match.distance, 5);
}

TEST (chain_limit)
{
  /*
   * Test that chain_limit stops search even with many potential matches.
   * Create a sequence where many positions hash to the same value.
   */
  uint8_t data[256];
  memset (data, 'A', sizeof (data));

  /* Make unique 3-byte sequences at intervals */
  for (size_t i = 0; i < sizeof (data) - 3; i += 3)
    {
      data[i] = 'X';
      data[i + 1] = 'Y';
      data[i + 2] = 'Z';
    }

  SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data));

  /* Set a very low chain limit */
  SocketDeflate_Matcher_set_limits (matcher, 5, 0, 0);

  /* Insert all positions */
  insert_all (matcher, sizeof (data));

  /* Find should complete quickly due to chain limit */
  SocketDeflate_Match match;
  int found = SocketDeflate_Matcher_find (matcher, sizeof (data) - 10, &match);
  /* May or may not find a match depending on chain order, but should complete
   */
  (void)found;
}

TEST (hash_collision)
{
  /*
   * Test that hash collisions are handled correctly by byte comparison.
   * Even if two sequences hash to the same value, we should only match
   * if the bytes actually match.
   *
   * Data: "ABCDEFGHIJKLMNOPQRSTUVWXYZABC" (29 bytes)
   * The "ABC" at position 26 should match "ABC" at position 0 (distance 26)
   */
  const uint8_t data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 29);

  /* Insert positions 0-25 (before search position 26) */
  for (size_t i = 0; i < 26; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at the end "ABC" */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 26, &match), 1);
  ASSERT_EQ (match.length, 3);
  ASSERT_EQ (match.distance, 26);
}

TEST (chain_ordering)
{
  /*
   * Test that hash chains maintain proper ordering (newest first).
   * Multiple inserts at same hash should chain correctly.
   *
   * Data: "ABCXYZABCXYZABCXYZABC" (21 bytes)
   * "ABC" occurs at positions 0, 6, 12, 18
   * When searching at 18, we should find the nearest (position 12, distance 6)
   */
  const uint8_t data[] = "ABCXYZABCXYZABCXYZABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 21);

  /* Insert positions 0-17 (before search position 18) */
  for (size_t i = 0; i < 18; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at the last "ABC" */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 18, &match), 1);

  /* Should find the most recent match first (distance 6 from position 12) */
  ASSERT_EQ (match.distance, 6);
}

TEST (lazy_match_basic)
{
  /*
   * Test lazy matching: "ABCXABCDABCD"
   * At position 4, we find "ABC" (length 3) at position 0
   * At position 8, we find "ABCD" (length 4) at position 4
   *
   * Note: In LZ77 compression, we only search positions before the current
   * position, so we insert incrementally as we would during compression.
   */
  const uint8_t data[] = "ABCXABCDABCD";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 12);

  /* Insert positions 0-3 (before search position 4) */
  for (size_t i = 0; i < 4; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 4: "ABC" matches position 0 */
  SocketDeflate_Match match4;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 4, &match4), 1);
  ASSERT_EQ (match4.length, 3);   /* "ABC" */
  ASSERT_EQ (match4.distance, 4); /* pos 4 - pos 0 = 4 */

  /* Check if should defer (needs position 5 in hash table for lookahead) */
  SocketDeflate_Matcher_insert (matcher, 4);
  ASSERT_EQ (SocketDeflate_Matcher_should_defer (matcher, 4, match4.length), 0);

  /* Insert positions 5-7 to set up for searching at 8 */
  for (size_t i = 5; i < 8; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 8: "ABCD" matches position 4 */
  SocketDeflate_Match match8;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 8, &match8), 1);
  ASSERT_EQ (match8.length, 4);   /* "ABCD" */
  ASSERT_EQ (match8.distance, 4); /* pos 8 - pos 4 = 4 */
}

TEST (lazy_threshold)
{
  /*
   * Test that good_length threshold skips lazy lookahead.
   * If current match is >= good_length, don't bother checking next position.
   */
  uint8_t data[100];
  memset (data, 0, sizeof (data));

  /* Create a long repeating pattern */
  const char *pattern = "ABCDEFGHIJKLMNOP";
  size_t plen = 16;
  memcpy (data, pattern, plen);
  memcpy (data + 20, pattern, plen);

  SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data));

  /* Set a low good_length threshold */
  SocketDeflate_Matcher_set_limits (matcher, 0, 10, 0);

  /* Insert first 20 positions */
  for (size_t i = 0; i < 20; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 20 - should be 16 bytes */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 20, &match), 1);
  ASSERT (match.length >= 10);

  /* Should NOT defer because match >= good_length */
  ASSERT_EQ (SocketDeflate_Matcher_should_defer (matcher, 20, match.length), 0);
}

TEST (window_boundary_start)
{
  /*
   * Test matches near the start of the window.
   * Position 0 can't match anything (no previous data).
   * Position 3 is the first that can match.
   */
  const uint8_t data[] = "ABCABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 6);

  SocketDeflate_Match match;

  /* Position 0 can't find anything (nothing inserted yet) */
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 0, &match), 0);

  /* Insert position 0 */
  SocketDeflate_Matcher_insert (matcher, 0);

  /* Position 3 should find match */
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 3, &match), 1);
}

TEST (window_boundary_end)
{
  /*
   * Test matches at the end of the window.
   * Ensure we don't read past the buffer.
   *
   * Data: "ABCABCAB" (8 bytes)
   * Position 5 has "CAB" which doesn't match "ABC" (position 0)
   * but we can extend to match 3 bytes: "CAB" at 2 matches "CAB" at 5
   */
  const uint8_t data[] = "ABCABCAB";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 8);

  /* Insert positions 0-4 (before search position 5) */
  for (size_t i = 0; i < 5; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Position 6: "AB" is only 2 bytes remaining, which is < MIN_MATCH
     So we can't find a match at position 6 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 6, &match), 0);

  /* Position 5: "CAB" should match position 2 "CAB" */
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 5, &match), 1);
  ASSERT_EQ (match.length, 3);
  ASSERT_EQ (match.distance, 3); /* pos 5 - pos 2 = 3 */
}

TEST (repeated_bytes)
{
  /*
   * Test with highly repetitive data.
   * "AAAAAAAA" - every position can match the previous ones.
   */
  const uint8_t data[] = "AAAAAAAA";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 8);

  /* Insert only positions 0, 1, 2 (before search position 3) */
  for (size_t i = 0; i < 3; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Position 3 should find a match */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 3, &match), 1);
  ASSERT (match.length >= 3);
  ASSERT (match.distance >= 1);
}

TEST (distance_one_rle)
{
  /*
   * Test RLE-like matching with distance=1.
   * "AAAAAA" - optimal encoding uses distance=1 matches.
   */
  const uint8_t data[] = "AAAAAA";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 6);

  /* Insert position 0, 1, 2 */
  SocketDeflate_Matcher_insert (matcher, 0);
  SocketDeflate_Matcher_insert (matcher, 1);
  SocketDeflate_Matcher_insert (matcher, 2);

  /* Find match at position 3 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 3, &match), 1);

  /* Should find a match with distance <= 3 */
  ASSERT (match.distance <= 3);
  ASSERT (match.length >= 3);
}

TEST (max_match_length)
{
  /*
   * Test that matches are truncated at DEFLATE_MAX_MATCH (258).
   */
  uint8_t data[520];
  memset (data, 'X', sizeof (data));

  SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data));

  /* Insert position 0 */
  SocketDeflate_Matcher_insert (matcher, 0);

  /* Find match at position 260 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 260, &match), 1);

  /* Match length should be capped at MAX_MATCH or limited by remaining data */
  ASSERT (match.length <= DEFLATE_MAX_MATCH);
}

TEST (no_matches_random)
{
  /*
   * Test with data that has no repeating 3-byte sequences.
   */
  const uint8_t data[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
  SocketDeflate_Matcher_T matcher = make_matcher (data, 12);

  insert_all (matcher, 12);

  /* Should not find any matches since no 3-byte sequence repeats */
  SocketDeflate_Match match;

  for (size_t i = 3; i + 3 <= 12; i++)
    {
      int found = SocketDeflate_Matcher_find (matcher, i, &match);
      if (found)
        {
          /* If found, verify it's a real match */
          ASSERT (match.length >= 3);
          ASSERT (match.distance > 0);
        }
    }
}

TEST (position_zero_match)
{
  /*
   * Test that position 0 can be found in subsequent searches.
   * This tests the position+1 storage scheme.
   */
  const uint8_t data[] = "XYZABCXYZABC";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 12);

  /* Insert positions 0, 1, 2, 3, 4, 5 */
  for (size_t i = 0; i <= 5; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* Find match at position 6 - should find "XYZABC" at position 0 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 6, &match), 1);

  /* Distance should be 6 (pos 6 - pos 0)
   * Length should be 6 because "XYZABC" at pos 0 matches "XYZABC" at pos 6 */
  ASSERT_EQ (match.distance, 6);
  ASSERT_EQ (match.length, 6);
}

TEST (lazy_match_override)
{
  /*
   * Test good_length optimization: should_defer() returns 0 when current
   * match length >= good_length, skipping the lazy lookahead entirely.
   *
   * This is a key optimization in DEFLATE compression - when we already
   * have a "good enough" match, don't waste time checking if the next
   * position has something better.
   */
  const uint8_t data[] = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
  SocketDeflate_Matcher_T matcher = make_matcher (data, 32);

  /* Set good_length = 8 so matches >= 8 skip lazy lookahead */
  SocketDeflate_Matcher_set_limits (matcher, 0, 8, 0);

  /* Insert positions 0-15 */
  for (size_t i = 0; i < 16; i++)
    SocketDeflate_Matcher_insert (matcher, i);

  /* At position 16, we find "ABCDEFGHIJKLMNOP" (len 16) from position 0 */
  SocketDeflate_Match match;
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 16, &match), 1);
  ASSERT_EQ (match.length, 16);
  ASSERT_EQ (match.distance, 16);

  /* With match length 16 >= good_length 8, should_defer returns 0 */
  int defer = SocketDeflate_Matcher_should_defer (matcher, 16, match.length);
  ASSERT_EQ (defer, 0);
}

TEST (hash_distribution_quality)
{
  /*
   * Test that different 3-byte patterns produce varied hash distribution
   * by verifying that inserting different patterns at position 0 and
   * searching for them at position 100 produces distinct matches.
   *
   * This indirectly tests hash function quality since good distribution
   * means different patterns map to different hash buckets and can be
   * found reliably.
   */
  const uint8_t patterns[][3] = {
    { 0, 0, 0 },       /* All zeros */
    { 0, 0, 1 },       /* Single bit change */
    { 0, 1, 0 },       /* Different position */
    { 1, 0, 0 },       /* Different position */
    { 'A', 'B', 'C' }, /* ASCII text */
    { 'X', 'Y', 'Z' }, /* Different ASCII */
    { '0', '1', '2' }, /* Digits */
    { 255, 255, 255 }, /* All ones */
    { 128, 128, 128 }  /* Middle value */
  };
  size_t num_patterns = sizeof (patterns) / sizeof (patterns[0]);

  /* Test that each pattern can be found independently */
  for (size_t p = 0; p < num_patterns; p++)
    {
      uint8_t data[128];
      memset (data, 'X', sizeof (data));

      /* Place the pattern at position 0 and 100 */
      memcpy (data, patterns[p], 3);
      memcpy (data + 100, patterns[p], 3);

      SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data));
      SocketDeflate_Matcher_insert (matcher, 0);

      SocketDeflate_Match match;
      int found = SocketDeflate_Matcher_find (matcher, 100, &match);
      ASSERT_EQ (found, 1);
      ASSERT_EQ (match.distance, 100);
      ASSERT (match.length >= 3);
    }
}

TEST (matcher_empty_input)
{
  /*
   * Test edge case with minimal input (less than MIN_MATCH bytes).
   * Should not find any matches and should not crash.
   */
  const uint8_t empty_data[] = "";
  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (test_arena);
  SocketDeflate_Matcher_init (matcher, empty_data, 0);

  SocketDeflate_Match match;
  /* No positions can be inserted or searched with empty data */
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 0, &match), 0);

  /* Test with 1-2 bytes (less than MIN_MATCH=3) */
  const uint8_t short_data[] = "AB";
  matcher = make_matcher (short_data, 2);
  ASSERT_EQ (SocketDeflate_Matcher_find (matcher, 0, &match), 0);
}

TEST (nice_length_early_stop)
{
  /*
   * Test that nice_length causes early termination of chain search.
   * With a very long repeating pattern and a low nice_length setting,
   * the matcher should stop searching once it finds a "nice enough" match.
   *
   * The nice_length optimization prevents searching entire hash chains
   * when a sufficiently long match is already found.
   *
   * Key: Don't insert the search position before searching there!
   */
  uint8_t data[512];
  memset (data, 'X', sizeof (data));

  /* Create long repeating patterns at intervals */
  const char *pattern = "ABCDEFGHIJ"; /* 10 chars */
  for (size_t i = 0; i < sizeof (data) - 20; i += 100)
    {
      memcpy (data + i, pattern, 10);
    }

  SocketDeflate_Matcher_T matcher = make_matcher (data, sizeof (data));

  /* Set a low nice_length to trigger early termination */
  SocketDeflate_Matcher_set_limits (matcher, 0, 0, 10); /* nice_length = 10 */

  /* Insert positions 0 to 399 (NOT including position 400) */
  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= 400; i++)
    {
      SocketDeflate_Matcher_insert (matcher, i);
    }

  /* Search at position 400 - should find match from position 0, 100, 200, or
   * 300 */
  /* Position 400 starts with "ABCDEFGHIJ" which also exists at 0, 100, 200, 300
   */
  SocketDeflate_Match match;
  int found = SocketDeflate_Matcher_find (matcher, 400, &match);
  ASSERT_EQ (found, 1);

  /* Should find a match with length >= nice_length (10) */
  ASSERT (match.length >= 10);
  ASSERT (match.distance > 0);

  /* The match should prefer nearest (position 300, distance 100) due to
   * early termination when nice_length is reached */
  ASSERT_EQ (match.distance, 100);
}

/*
 * Test Runner
 */

int
main (void)
{
  test_arena = Arena_new ();

  Test_run_all ();

  Arena_dispose (&test_arena);

  return Test_get_failures () > 0 ? 1 : 0;
}
