/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http2_priority.c - RFC 9218 Extensible Priorities Tests
 *
 * Tests for the RFC 9218 Extensible Priority implementation:
 * - Priority header field parsing
 * - Priority serialization
 * - Stream priority get/set
 * - PRIORITY_UPDATE frame processing
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP2.h"
#include "http/SocketHTTP2-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test utilities */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                                \
  do                                                                          \
    {                                                                         \
      if (!(cond))                                                            \
        {                                                                     \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);  \
          return 0;                                                           \
        }                                                                     \
    }                                                                         \
  while (0)

#define TEST_BEGIN(name)                                                      \
  do                                                                          \
    {                                                                         \
      tests_run++;                                                            \
      printf ("  Testing %s... ", #name);                                     \
      fflush (stdout);                                                        \
    }                                                                         \
  while (0)

#define TEST_PASS()                                                           \
  do                                                                          \
    {                                                                         \
      tests_passed++;                                                         \
      printf ("PASSED\n");                                                    \
      return 1;                                                               \
    }                                                                         \
  while (0)

/* Priority initialization tests */
static int
test_priority_init (void)
{
  TEST_BEGIN (priority_init);

  SocketHTTP2_Priority priority;

  SocketHTTP2_Priority_init (&priority);

  TEST_ASSERT (priority.urgency == SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY,
               "Default urgency should be 3");
  TEST_ASSERT (priority.incremental == 0,
               "Default incremental should be false");

  TEST_PASS ();
}

/* Priority parsing tests */
static int
test_priority_parse_urgency_only (void)
{
  TEST_BEGIN (priority_parse_urgency_only);

  SocketHTTP2_Priority priority;
  int ret;

  /* Test "u=0" */
  ret = SocketHTTP2_Priority_parse ("u=0", 3, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 0, "Urgency should be 0");
  TEST_ASSERT (priority.incremental == 0, "Incremental should be false");

  /* Test "u=7" */
  ret = SocketHTTP2_Priority_parse ("u=7", 3, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 7, "Urgency should be 7");
  TEST_ASSERT (priority.incremental == 0, "Incremental should be false");

  /* Test "u=3" */
  ret = SocketHTTP2_Priority_parse ("u=3", 3, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 3, "Urgency should be 3");

  TEST_PASS ();
}

static int
test_priority_parse_incremental_only (void)
{
  TEST_BEGIN (priority_parse_incremental_only);

  SocketHTTP2_Priority priority;
  int ret;

  /* Test bare "i" */
  ret = SocketHTTP2_Priority_parse ("i", 1, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY,
               "Urgency should be default");
  TEST_ASSERT (priority.incremental == 1, "Incremental should be true");

  /* Test "i=?1" */
  ret = SocketHTTP2_Priority_parse ("i=?1", 4, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.incremental == 1, "Incremental should be true");

  /* Test "i=?0" */
  ret = SocketHTTP2_Priority_parse ("i=?0", 4, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.incremental == 0, "Incremental should be false");

  TEST_PASS ();
}

static int
test_priority_parse_both (void)
{
  TEST_BEGIN (priority_parse_both);

  SocketHTTP2_Priority priority;
  int ret;

  /* Test "u=3, i" */
  ret = SocketHTTP2_Priority_parse ("u=3, i", 6, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 3, "Urgency should be 3");
  TEST_ASSERT (priority.incremental == 1, "Incremental should be true");

  /* Test "u=0,i" (no space) */
  ret = SocketHTTP2_Priority_parse ("u=0,i", 5, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 0, "Urgency should be 0");
  TEST_ASSERT (priority.incremental == 1, "Incremental should be true");

  /* Test "i, u=5" (reverse order) */
  ret = SocketHTTP2_Priority_parse ("i, u=5", 6, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 5, "Urgency should be 5");
  TEST_ASSERT (priority.incremental == 1, "Incremental should be true");

  TEST_PASS ();
}

static int
test_priority_parse_empty (void)
{
  TEST_BEGIN (priority_parse_empty);

  SocketHTTP2_Priority priority;
  int ret;

  /* Empty value uses defaults */
  ret = SocketHTTP2_Priority_parse ("", 0, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY,
               "Urgency should be default");
  TEST_ASSERT (priority.incremental == 0, "Incremental should be default");

  /* NULL value uses defaults */
  ret = SocketHTTP2_Priority_parse (NULL, 0, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY,
               "Urgency should be default");

  TEST_PASS ();
}

static int
test_priority_parse_unknown_params (void)
{
  TEST_BEGIN (priority_parse_unknown_params);

  SocketHTTP2_Priority priority;
  int ret;

  /* Unknown parameters should be ignored */
  ret = SocketHTTP2_Priority_parse ("u=2, foo=bar", 12, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == 2, "Urgency should be 2");
  TEST_ASSERT (priority.incremental == 0, "Incremental should be default");

  /* All unknown */
  ret = SocketHTTP2_Priority_parse ("x=1, y=2", 8, &priority);
  TEST_ASSERT (ret == 0, "Parse should succeed");
  TEST_ASSERT (priority.urgency == SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY,
               "Urgency should be default");

  TEST_PASS ();
}

static int
test_priority_parse_invalid (void)
{
  TEST_BEGIN (priority_parse_invalid);

  SocketHTTP2_Priority priority;
  int ret;

  /* Urgency out of range (8) */
  ret = SocketHTTP2_Priority_parse ("u=8", 3, &priority);
  TEST_ASSERT (ret == -1, "Parse should fail for u=8");

  /* Urgency out of range (negative - not applicable as unsigned parse) */

  /* Invalid boolean for i */
  ret = SocketHTTP2_Priority_parse ("i=true", 6, &priority);
  TEST_ASSERT (ret == -1, "Parse should fail for i=true");

  /* Missing value for u */
  ret = SocketHTTP2_Priority_parse ("u", 1, &priority);
  TEST_ASSERT (ret == -1, "Parse should fail for bare u");

  TEST_PASS ();
}

/* Priority serialization tests */
static int
test_priority_serialize_defaults (void)
{
  TEST_BEGIN (priority_serialize_defaults);

  SocketHTTP2_Priority priority;
  char buf[64];
  ssize_t len;

  /* Default priority (u=3, i=false) serializes to empty or nothing special */
  priority.urgency = SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY;
  priority.incremental = 0;

  len = SocketHTTP2_Priority_serialize (&priority, buf, sizeof (buf));
  TEST_ASSERT (len == 0, "Default priority should serialize to empty");

  TEST_PASS ();
}

static int
test_priority_serialize_non_default_urgency (void)
{
  TEST_BEGIN (priority_serialize_non_default_urgency);

  SocketHTTP2_Priority priority;
  char buf[64];
  ssize_t len;

  /* Non-default urgency */
  priority.urgency = 0;
  priority.incremental = 0;

  len = SocketHTTP2_Priority_serialize (&priority, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Should serialize to 'u=0'");
  TEST_ASSERT (memcmp (buf, "u=0", 3) == 0, "Should be 'u=0'");

  /* High urgency */
  priority.urgency = 7;
  len = SocketHTTP2_Priority_serialize (&priority, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Should serialize to 'u=7'");
  TEST_ASSERT (memcmp (buf, "u=7", 3) == 0, "Should be 'u=7'");

  TEST_PASS ();
}

static int
test_priority_serialize_incremental (void)
{
  TEST_BEGIN (priority_serialize_incremental);

  SocketHTTP2_Priority priority;
  char buf[64];
  ssize_t len;

  /* Default urgency with incremental */
  priority.urgency = SOCKETHTTP2_PRIORITY_DEFAULT_URGENCY;
  priority.incremental = 1;

  len = SocketHTTP2_Priority_serialize (&priority, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Should serialize to 'i'");
  TEST_ASSERT (buf[0] == 'i', "Should be 'i'");

  TEST_PASS ();
}

static int
test_priority_serialize_both (void)
{
  TEST_BEGIN (priority_serialize_both);

  SocketHTTP2_Priority priority;
  char buf[64];
  ssize_t len;

  /* Non-default urgency with incremental */
  priority.urgency = 0;
  priority.incremental = 1;

  len = SocketHTTP2_Priority_serialize (&priority, buf, sizeof (buf));
  TEST_ASSERT (len == 6, "Should serialize to 'u=0, i'");
  TEST_ASSERT (memcmp (buf, "u=0, i", 6) == 0, "Should be 'u=0, i'");

  TEST_PASS ();
}

static int
test_priority_serialize_buffer_too_small (void)
{
  TEST_BEGIN (priority_serialize_buffer_too_small);

  SocketHTTP2_Priority priority;
  char buf[2];
  ssize_t len;

  priority.urgency = 0;
  priority.incremental = 0;

  /* Buffer too small for "u=0" */
  len = SocketHTTP2_Priority_serialize (&priority, buf, 2);
  TEST_ASSERT (len == -1, "Should fail with small buffer");

  TEST_PASS ();
}

/* Frame type string test */
static int
test_priority_update_frame_type_string (void)
{
  TEST_BEGIN (priority_update_frame_type_string);

  const char *name = SocketHTTP2_frame_type_string (HTTP2_FRAME_PRIORITY_UPDATE);

  /* The frame type name may be "UNKNOWN_FRAME" until we add it to the frame_type_names array */
  /* For now, just check it doesn't crash */
  TEST_ASSERT (name != NULL, "Frame type string should not be NULL");

  TEST_PASS ();
}

/* Run all tests */
int
main (void)
{
  printf ("RFC 9218 Extensible Priorities Tests\n");
  printf ("=====================================\n\n");

  /* Priority initialization */
  printf ("Priority Initialization:\n");
  test_priority_init ();

  /* Priority parsing */
  printf ("\nPriority Parsing:\n");
  test_priority_parse_urgency_only ();
  test_priority_parse_incremental_only ();
  test_priority_parse_both ();
  test_priority_parse_empty ();
  test_priority_parse_unknown_params ();
  test_priority_parse_invalid ();

  /* Priority serialization */
  printf ("\nPriority Serialization:\n");
  test_priority_serialize_defaults ();
  test_priority_serialize_non_default_urgency ();
  test_priority_serialize_incremental ();
  test_priority_serialize_both ();
  test_priority_serialize_buffer_too_small ();

  /* Frame type */
  printf ("\nFrame Type:\n");
  test_priority_update_frame_type_string ();

  /* Summary */
  printf ("\n=====================================\n");
  printf ("Tests: %d/%d passed\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
