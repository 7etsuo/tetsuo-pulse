/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketevent.c - SocketEvent unit tests
 * Tests for the SocketEvent registration and unregistration module.
 * Covers registration, unregistration, error conditions, and edge cases.
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "core/SocketEvent.h"
#include "test/Test.h"

/* Test event handler that does nothing */
static void
test_callback (void *userdata, const SocketEventRecord *event)
{
  (void)userdata;
  (void)event;
}

/* Another test callback for duplicate testing */
static void
test_callback2 (void *userdata, const SocketEventRecord *event)
{
  (void)userdata;
  (void)event;
}

/* Test basic registration succeeds */
TEST (socketevent_register_basic)
{
  int result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, 0);

  /* Clean up */
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, 0);
}

/* Test registration with userdata */
TEST (socketevent_register_with_userdata)
{
  int dummy_data = 42;
  int result = SocketEvent_register (test_callback, &dummy_data);
  ASSERT_EQ (result, 0);

  /* Clean up */
  result = SocketEvent_unregister (test_callback, &dummy_data);
  ASSERT_EQ (result, 0);
}

/* Test registration with NULL callback fails */
TEST (socketevent_register_null_callback_fails)
{
  int result = SocketEvent_register (NULL, NULL);
  ASSERT_EQ (result, -1);
}

/* Test duplicate registration fails */
TEST (socketevent_register_duplicate_fails)
{
  int result;

  /* Register first time - should succeed */
  result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, 0);

  /* Register again with same callback and userdata - should fail */
  result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, -1);

  /* Clean up */
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, 0);
}

/* Test same callback with different userdata is allowed */
TEST (socketevent_register_same_callback_different_userdata)
{
  int dummy1 = 1;
  int dummy2 = 2;
  int result;

  /* Register with first userdata */
  result = SocketEvent_register (test_callback, &dummy1);
  ASSERT_EQ (result, 0);

  /* Register same callback with different userdata - should succeed */
  result = SocketEvent_register (test_callback, &dummy2);
  ASSERT_EQ (result, 0);

  /* Clean up both */
  result = SocketEvent_unregister (test_callback, &dummy1);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (test_callback, &dummy2);
  ASSERT_EQ (result, 0);
}

/* Test different callbacks with same userdata is allowed */
TEST (socketevent_register_different_callbacks_same_userdata)
{
  int dummy = 42;
  int result;

  /* Register first callback */
  result = SocketEvent_register (test_callback, &dummy);
  ASSERT_EQ (result, 0);

  /* Register different callback with same userdata - should succeed */
  result = SocketEvent_register (test_callback2, &dummy);
  ASSERT_EQ (result, 0);

  /* Clean up both */
  result = SocketEvent_unregister (test_callback, &dummy);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (test_callback2, &dummy);
  ASSERT_EQ (result, 0);
}

/* Test handler limit is enforced (SOCKET_EVENT_MAX_HANDLERS = 8) */
TEST (socketevent_register_limit_reached)
{
  int dummy[10];
  int i;
  int result;

  /* Register up to the limit (8 handlers) */
  for (i = 0; i < 8; i++)
    {
      dummy[i] = i;
      result = SocketEvent_register (test_callback, &dummy[i]);
      ASSERT_EQ (result, 0);
    }

  /* 9th registration should fail */
  dummy[8] = 8;
  result = SocketEvent_register (test_callback, &dummy[8]);
  ASSERT_EQ (result, -1);

  /* Clean up all registered handlers */
  for (i = 0; i < 8; i++)
    {
      result = SocketEvent_unregister (test_callback, &dummy[i]);
      ASSERT_EQ (result, 0);
    }
}

/* Test unregister with NULL callback fails */
TEST (socketevent_unregister_null_callback_fails)
{
  int result = SocketEvent_unregister (NULL, NULL);
  ASSERT_EQ (result, -1);
}

/* Test unregister non-existent handler fails */
TEST (socketevent_unregister_not_registered_fails)
{
  int result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, -1);
}

/* Test unregister with wrong userdata fails */
TEST (socketevent_unregister_wrong_userdata_fails)
{
  int dummy1 = 1;
  int dummy2 = 2;
  int result;

  /* Register with dummy1 */
  result = SocketEvent_register (test_callback, &dummy1);
  ASSERT_EQ (result, 0);

  /* Try to unregister with dummy2 - should fail */
  result = SocketEvent_unregister (test_callback, &dummy2);
  ASSERT_EQ (result, -1);

  /* Unregister with correct userdata */
  result = SocketEvent_unregister (test_callback, &dummy1);
  ASSERT_EQ (result, 0);
}

/* Test multiple register/unregister cycles */
TEST (socketevent_multiple_register_unregister_cycles)
{
  int i;
  int result;

  for (i = 0; i < 5; i++)
    {
      result = SocketEvent_register (test_callback, NULL);
      ASSERT_EQ (result, 0);

      result = SocketEvent_unregister (test_callback, NULL);
      ASSERT_EQ (result, 0);
    }
}

/* Test unregister after reaching limit frees slot */
TEST (socketevent_unregister_frees_slot)
{
  int dummy[10];
  int i;
  int result;

  /* Fill to limit */
  for (i = 0; i < 8; i++)
    {
      dummy[i] = i;
      result = SocketEvent_register (test_callback, &dummy[i]);
      ASSERT_EQ (result, 0);
    }

  /* Unregister one */
  result = SocketEvent_unregister (test_callback, &dummy[0]);
  ASSERT_EQ (result, 0);

  /* Should be able to register a new one */
  dummy[8] = 8;
  result = SocketEvent_register (test_callback, &dummy[8]);
  ASSERT_EQ (result, 0);

  /* Clean up */
  for (i = 1; i < 8; i++)
    {
      result = SocketEvent_unregister (test_callback, &dummy[i]);
      ASSERT_EQ (result, 0);
    }
  result = SocketEvent_unregister (test_callback, &dummy[8]);
  ASSERT_EQ (result, 0);
}

/* Test double unregister fails */
TEST (socketevent_double_unregister_fails)
{
  int result;

  /* Register */
  result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, 0);

  /* First unregister succeeds */
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, 0);

  /* Second unregister fails */
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, -1);
}

/* Test registration and unregistration with multiple different callbacks */
TEST (socketevent_multiple_different_callbacks)
{
  int result;

  /* Register both callbacks */
  result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, 0);
  result = SocketEvent_register (test_callback2, NULL);
  ASSERT_EQ (result, 0);

  /* Unregister in different order */
  result = SocketEvent_unregister (test_callback2, NULL);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, 0);
}

/* Test all combinations of NULL/non-NULL for userdata */
TEST (socketevent_userdata_combinations)
{
  int dummy = 42;
  int result;

  /* NULL callback, NULL userdata - fails */
  result = SocketEvent_register (NULL, NULL);
  ASSERT_EQ (result, -1);

  /* NULL callback, non-NULL userdata - fails */
  result = SocketEvent_register (NULL, &dummy);
  ASSERT_EQ (result, -1);

  /* Valid callback, NULL userdata - succeeds */
  result = SocketEvent_register (test_callback, NULL);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (test_callback, NULL);
  ASSERT_EQ (result, 0);

  /* Valid callback, non-NULL userdata - succeeds */
  result = SocketEvent_register (test_callback, &dummy);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (test_callback, &dummy);
  ASSERT_EQ (result, 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
