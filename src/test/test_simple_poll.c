/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_poll.c - Simple poll module unit tests
 */

#include <assert.h>

#include "simple/SocketSimple-poll.h"
#include "test/Test.h"

/* Test that SOCKET_POLL_TIMEOUT_USE_DEFAULT is defined */
TEST (poll_timeout_constant_defined)
{
  /* Verify the constant compiles and has expected value */
  int timeout = SOCKET_POLL_TIMEOUT_USE_DEFAULT;
  ASSERT_EQ (timeout, -2);
}

/* Test poll instance creation and timeout setting */
TEST (poll_timeout_default_usage)
{
  SocketSimple_Poll_T poll = Socket_simple_poll_new (64);
  ASSERT_NOT_NULL (poll);

  /* Set a custom default timeout */
  int result = Socket_simple_poll_set_timeout (poll, 5000);
  ASSERT_EQ (result, 0);

  Socket_simple_poll_free (&poll);
  ASSERT_NULL (poll);
}

/* Test framework boilerplate */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
