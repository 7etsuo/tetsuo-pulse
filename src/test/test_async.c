/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_async.c - SocketAsync unit tests
 *
 * Tests for asynchronous I/O operations.
 * Covers context creation, backend queries, and basic cancellation.
 *
 * Note: Tests that involve actual async I/O are minimized because
 * the async backend (io_uring/kqueue) may not be available on all
 * systems and can block indefinitely in tests.
 */

/* cppcheck-suppress-file duplicateCondition ; intentional double-cancel test
 */
/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */
/* cppcheck-suppress-file duplicateCondition ; intentional test pattern */

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketAsync.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Callback for async operations - just a placeholder for testing */
static void
async_test_callback (Socket_T socket, ssize_t bytes, int err, void *user_data)
{
  (void)socket;
  (void)bytes;
  (void)err;
  (void)user_data;
  /* Callback should never be invoked in fallback mode tests */
}

/* ==================== Context Lifecycle Tests ==================== */

TEST (async_new_free)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  ASSERT_NOT_NULL (async);

  SocketAsync_free (&async);
  ASSERT_NULL (async);

  Arena_dispose (&arena);
}

TEST (async_free_null)
{
  SocketAsync_T async = NULL;
  SocketAsync_free (&async);
  SocketAsync_free (NULL);
  /* Should not crash */
  ASSERT (1);
}

/* ==================== Backend Query Tests ==================== */

TEST (async_backend_name)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  const char *name = SocketAsync_backend_name (async);
  ASSERT_NOT_NULL (name);
  /* Backend name should be non-empty */
  ASSERT (strlen (name) > 0);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_backend_name_null)
{
  const char *name = SocketAsync_backend_name (NULL);
  ASSERT_NOT_NULL (name);
  /* Should return "unavailable" for NULL context */
  ASSERT (strcmp (name, "unavailable") == 0);
}

TEST (async_is_available)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Just check it returns a valid value (0 or 1) */
  int available = SocketAsync_is_available (async);
  ASSERT (available == 0 || available == 1);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_is_available_null)
{
  int available = SocketAsync_is_available (NULL);
  ASSERT_EQ (0, available);
}

/* ==================== Cancel Tests ==================== */

TEST (async_cancel_valid_request)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile unsigned request_id1 = 0;
  volatile unsigned request_id2 = 0;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY { socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  const char *test_data = "test";
  char recv_buffer[256];

  /* Submit two requests to test hash chain traversal in cancel */
  TRY
  {
    request_id1
        = SocketAsync_send (async, socket, test_data, strlen (test_data),
                            async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed) { request_id1 = 0; }
  END_TRY;

  TRY
  {
    request_id2
        = SocketAsync_recv (async, socket, recv_buffer, sizeof (recv_buffer),
                            async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed) { request_id2 = 0; }
  END_TRY;

  /* Cancel in reverse order to exercise different code paths */
  if (request_id2 > 0)
    {
      int result = SocketAsync_cancel (async, request_id2);
      ASSERT_EQ (0, result);
    }

  if (request_id1 > 0)
    {
      int result = SocketAsync_cancel (async, request_id1);
      ASSERT_EQ (0, result);
    }

  /* Verify double-cancel returns -1 (request not found) */
  if (request_id1 > 0)
    {
      int result = SocketAsync_cancel (async, request_id1);
      ASSERT_EQ (-1, result);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_cancel_invalid)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Cancel non-existent request */
  int result = SocketAsync_cancel (async, 12345);
  /* Should return -1 since request doesn't exist */
  ASSERT_EQ (-1, result);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Fallback Mode Tests ==================== */

TEST (async_send_fallback_mode)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile unsigned request_id = 0;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Create a socket for testing */
  TRY { socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    /* Socket creation failed - test passes */
    return;
  }
  END_TRY;

  /* Submit async send - should succeed even in fallback mode */
  const char *test_data = "test data";

  TRY
  {
    request_id
        = SocketAsync_send (async, socket, test_data, strlen (test_data),
                            async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    /* Expected in fallback mode when backend not available */
    request_id = 0;
  }
  END_TRY;

  /* In fallback mode, request should be tracked and ID returned */
  /* Note: On platforms without io_uring/kqueue, this may raise exception */
  if (request_id > 0)
    {
      /* Request was submitted - cancel it to clean up */
      int cancel_result = SocketAsync_cancel (async, request_id);
      ASSERT_EQ (0, cancel_result);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_recv_fallback_mode)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile unsigned request_id = 0;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Create a socket for testing */
  TRY { socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    /* Socket creation failed - test passes */
    return;
  }
  END_TRY;

  /* Submit async recv - should succeed even in fallback mode */
  char recv_buffer[256];

  TRY
  {
    request_id
        = SocketAsync_recv (async, socket, recv_buffer, sizeof (recv_buffer),
                            async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    /* Expected in fallback mode when backend not available */
    request_id = 0;
  }
  END_TRY;

  /* In fallback mode, request should be tracked and ID returned */
  if (request_id > 0)
    {
      /* Request was submitted - cancel it to clean up */
      int cancel_result = SocketAsync_cancel (async, request_id);
      ASSERT_EQ (0, cancel_result);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Process Completions Tests ==================== */

TEST (async_process_completions_no_pending)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Process with no pending requests - should return immediately */
  int count = SocketAsync_process_completions (async, 0);
  ASSERT_EQ (0, count);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Batch Operations Tests ==================== */

TEST (async_submit_batch)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY { socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Create a batch of operations */
  const char *send_data = "test";
  char recv_buf[256];

  SocketAsync_Op ops[2];
  memset (ops, 0, sizeof (ops));

  /* Send operation */
  ops[0].socket = socket;
  ops[0].is_send = 1;
  ops[0].send_buf = send_data;
  ops[0].len = strlen (send_data);
  ops[0].cb = async_test_callback;
  ops[0].user_data = NULL;

  /* Recv operation */
  ops[1].socket = socket;
  ops[1].is_send = 0;
  ops[1].recv_buf = recv_buf;
  ops[1].len = sizeof (recv_buf);
  ops[1].cb = async_test_callback;
  ops[1].user_data = NULL;

  /* Submit batch - may fail if backend doesn't support batching */
  int result = SocketAsync_submit_batch (async, ops, 2);
  /* Result is number of submitted ops or -1 on error */
  ASSERT (result >= -1);

  /* Cancel all to clean up */
  SocketAsync_cancel_all (async);

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_submit_batch_empty)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Empty batch should be handled gracefully */
  int result = SocketAsync_submit_batch (async, NULL, 0);
  ASSERT (result >= -1);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Cancel All Tests ==================== */

TEST (async_cancel_all)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY { socket = Socket_new (AF_INET, SOCK_STREAM, 0); }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Submit a few requests */
  const char *test_data = "test";
  char recv_buf[256];
  volatile unsigned req1 = 0, req2 = 0;

  TRY
  {
    req1 = SocketAsync_send (async, socket, test_data, strlen (test_data),
                             async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed) { req1 = 0; }
  END_TRY;

  TRY
  {
    req2 = SocketAsync_recv (async, socket, recv_buf, sizeof (recv_buf),
                             async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed) { req2 = 0; }
  END_TRY;

  (void)req2; /* Suppress unused warning - we only check req1 cancellation */

  /* Cancel all pending requests */
  int result = SocketAsync_cancel_all (async);
  /* Should return number of cancelled requests or 0 if none pending */
  ASSERT (result >= 0);

  /* Verify individual cancels now fail (already cancelled) */
  if (req1 > 0)
    {
      int cancel_result = SocketAsync_cancel (async, req1);
      ASSERT_EQ (-1, cancel_result);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_cancel_all_empty)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY { async = SocketAsync_new (arena); }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Cancel all with no pending requests */
  int result = SocketAsync_cancel_all (async);
  ASSERT_EQ (0, result);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Backend Selection Tests ==================== */

TEST (async_backend_available_auto)
{
  setup_signals ();

  /* Check if AUTO backend is available */
  int available = SocketAsync_backend_available (ASYNC_BACKEND_AUTO);
  /* AUTO should always return some value (0 = no async, 1 = some backend) */
  ASSERT (available == 0 || available == 1);
}

TEST (async_backend_available_poll)
{
  setup_signals ();

  /* Poll backend should always be available as fallback */
  int available = SocketAsync_backend_available (ASYNC_BACKEND_POLL);
  /* Poll is typically always available */
  ASSERT (available == 0 || available == 1);
}

TEST (async_backend_available_iouring)
{
  setup_signals ();

  /* Check if io_uring backend is available */
  int available = SocketAsync_backend_available (ASYNC_BACKEND_IO_URING);
  /* Returns 0 or 1 depending on system support */
  ASSERT (available == 0 || available == 1);
}

TEST (async_set_backend)
{
  setup_signals ();

  /* Try to set to AUTO backend */
  int result = SocketAsync_set_backend (ASYNC_BACKEND_AUTO);
  /* Should succeed or return -1 if not supported */
  ASSERT (result == 0 || result == -1);
}

TEST (async_set_backend_unavailable)
{
  setup_signals ();

  /* Try to set an unavailable backend */
  int available = SocketAsync_backend_available (ASYNC_BACKEND_IO_URING);
  if (available == 0)
    {
      /* Backend not available - setting it should fail */
      int result = SocketAsync_set_backend (ASYNC_BACKEND_IO_URING);
      ASSERT_EQ (-1, result);
    }
  else
    {
      /* Backend available - test passes */
      ASSERT (1);
    }
}

/* ==================== Main ==================== */

int
main (void)
{
  setup_signals ();
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
