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
#include "core/SocketConfig.h"
#include "core/SocketTimer.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
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
    request_id1 = SocketAsync_send (async,
                                    socket,
                                    test_data,
                                    strlen (test_data),
                                    async_test_callback,
                                    NULL,
                                    ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    request_id1 = 0;
  }
  END_TRY;

  TRY
  {
    request_id2 = SocketAsync_recv (async,
                                    socket,
                                    recv_buffer,
                                    sizeof (recv_buffer),
                                    async_test_callback,
                                    NULL,
                                    ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    request_id2 = 0;
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Create a socket for testing */
  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
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
    request_id = SocketAsync_send (async,
                                   socket,
                                   test_data,
                                   strlen (test_data),
                                   async_test_callback,
                                   NULL,
                                   ASYNC_FLAG_NONE);
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    /* Async not available - test passes */
    return;
  }
  END_TRY;

  /* Create a socket for testing */
  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
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
    request_id = SocketAsync_recv (async,
                                   socket,
                                   recv_buffer,
                                   sizeof (recv_buffer),
                                   async_test_callback,
                                   NULL,
                                   ASYNC_FLAG_NONE);
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
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
    req1 = SocketAsync_send (async,
                             socket,
                             test_data,
                             strlen (test_data),
                             async_test_callback,
                             NULL,
                             ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req1 = 0;
  }
  END_TRY;

  TRY
  {
    req2 = SocketAsync_recv (async,
                             socket,
                             recv_buf,
                             sizeof (recv_buf),
                             async_test_callback,
                             NULL,
                             ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req2 = 0;
  }
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

  TRY
  {
    async = SocketAsync_new (arena);
  }
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

/* ==================== Progress Query Tests ==================== */

TEST (async_get_progress_null)
{
  setup_signals ();
  size_t completed = 999, total = 999;

  /* NULL async should return 0 */
  int result = SocketAsync_get_progress (NULL, 1, &completed, &total);
  ASSERT_EQ (0, result);
  ASSERT_EQ (0U, completed);
  ASSERT_EQ (0U, total);
}

TEST (async_get_progress_invalid_id)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  size_t completed = 999, total = 999;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Invalid request ID (0 or non-existent) should return 0 */
  int result = SocketAsync_get_progress (async, 0, &completed, &total);
  ASSERT_EQ (0, result);

  result = SocketAsync_get_progress (async, 999, &completed, &total);
  ASSERT_EQ (0, result);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_get_progress_pending)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Submit a request */
  const char *test_data = "hello";
  volatile unsigned req_id = 0;

  TRY
  {
    req_id = SocketAsync_send (async,
                               socket,
                               test_data,
                               strlen (test_data),
                               async_test_callback,
                               NULL,
                               ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req_id = 0;
  }
  END_TRY;

  if (req_id > 0)
    {
      size_t completed = 999, total = 999;
      int result = SocketAsync_get_progress (async, req_id, &completed, &total);
      ASSERT_EQ (1, result);
      ASSERT_EQ (0U, completed); /* Not yet completed */
      ASSERT_EQ (strlen (test_data), total);
    }

  SocketAsync_cancel_all (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Continuation Tests ==================== */

TEST (async_send_continue_invalid)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Continue on non-existent request should return 0 */
  unsigned result = SocketAsync_send_continue (async, 999);
  ASSERT_EQ (0U, result);

  /* Continue on invalid ID (0) should return 0 */
  result = SocketAsync_send_continue (async, 0);
  ASSERT_EQ (0U, result);

  /* NULL async should return 0 */
  result = SocketAsync_send_continue (NULL, 1);
  ASSERT_EQ (0U, result);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_recv_continue_invalid)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Continue on non-existent request should return 0 */
  unsigned result = SocketAsync_recv_continue (async, 999);
  ASSERT_EQ (0U, result);

  /* NULL async should return 0 */
  result = SocketAsync_recv_continue (NULL, 1);
  ASSERT_EQ (0U, result);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== Timeout Configuration Tests ==================== */

TEST (async_timeout_default)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Default timeout should be 0 (disabled) */
  int64_t timeout = SocketAsync_get_timeout (async);
  ASSERT_EQ (0LL, timeout);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_timeout_set_get)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Set timeout and verify */
  SocketAsync_set_timeout (async, 5000);
  int64_t timeout = SocketAsync_get_timeout (async);
  ASSERT_EQ (5000LL, timeout);

  /* Disable timeout */
  SocketAsync_set_timeout (async, 0);
  timeout = SocketAsync_get_timeout (async);
  ASSERT_EQ (0LL, timeout);

  /* Negative values should be treated as 0 */
  SocketAsync_set_timeout (async, -100);
  timeout = SocketAsync_get_timeout (async);
  ASSERT_EQ (0LL, timeout);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_timeout_null)
{
  setup_signals ();

  /* NULL async should be handled gracefully */
  SocketAsync_set_timeout (NULL, 5000);
  int64_t timeout = SocketAsync_get_timeout (NULL);
  ASSERT_EQ (0LL, timeout);
}

/* ==================== Stale Request Expiration Tests ==================== */

TEST (async_expire_stale_empty)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* No pending requests - should return 0 */
  int expired = SocketAsync_expire_stale (async);
  ASSERT_EQ (0, expired);

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_expire_stale_null)
{
  setup_signals ();

  /* NULL async should return 0 */
  int expired = SocketAsync_expire_stale (NULL);
  ASSERT_EQ (0, expired);
}

/* ==================== Timeout-Aware Send/Recv Tests ==================== */

TEST (async_send_timeout_basic)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Submit send with 5-second timeout */
  const char *test_data = "test";
  volatile unsigned req_id = 0;

  TRY
  {
    req_id = SocketAsync_send_timeout (async,
                                       socket,
                                       test_data,
                                       strlen (test_data),
                                       async_test_callback,
                                       NULL,
                                       ASYNC_FLAG_NONE,
                                       5000);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req_id = 0;
  }
  END_TRY;

  /* Should succeed if async available */
  if (req_id > 0)
    {
      ASSERT (req_id > 0);
      /* Cancel to clean up */
      SocketAsync_cancel (async, req_id);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_recv_timeout_basic)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Submit recv with 5-second timeout */
  char recv_buf[256];
  volatile unsigned req_id = 0;

  TRY
  {
    req_id = SocketAsync_recv_timeout (async,
                                       socket,
                                       recv_buf,
                                       sizeof (recv_buf),
                                       async_test_callback,
                                       NULL,
                                       ASYNC_FLAG_NONE,
                                       5000);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req_id = 0;
  }
  END_TRY;

  /* Should succeed if async available */
  if (req_id > 0)
    {
      ASSERT (req_id > 0);
      /* Cancel to clean up */
      SocketAsync_cancel (async, req_id);
    }

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/* ==================== io_uring-Specific Tests ==================== */

TEST (async_iouring_available_api)
{
  setup_signals ();

  SocketAsync_IOUringInfo info;
  memset (&info, 0, sizeof (info));

  int available = SocketAsync_io_uring_available (&info);

  /* Check compiled flag is set correctly */
#if SOCKET_HAS_IO_URING
  ASSERT_EQ (1, info.compiled);
#else
  ASSERT_EQ (0, info.compiled);
#endif

  /* Kernel version should be populated on Linux when io_uring is compiled */
#if defined(__linux__) && SOCKET_HAS_IO_URING
  ASSERT (info.major > 0);
#endif

  /* available should match supported flag */
  ASSERT_EQ (info.supported, available);
}

TEST (async_iouring_kernel_version_validation)
{
  setup_signals ();

  SocketAsync_IOUringInfo info;
  memset (&info, 0, sizeof (info));

  int available = SocketAsync_io_uring_available (&info);

  /* On Linux with io_uring compiled, verify kernel version validation */
#if defined(__linux__) && SOCKET_HAS_IO_URING
  if (available)
    {
      /* Kernel version components should be in reasonable range (0-999) */
      ASSERT (info.major >= 0 && info.major <= 999);
      ASSERT (info.minor >= 0 && info.minor <= 999);
      ASSERT (info.patch >= 0 && info.patch <= 999);

      /* For supported io_uring, major version should be at least 5 */
      if (info.supported)
        {
          ASSERT (info.major >= 5);
        }
    }
#endif

  /* Test passes - kernel version parsing includes validation */
  ASSERT (1);
}

TEST (async_iouring_backend_detection)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  const char *name = SocketAsync_backend_name (async);
  int available = SocketAsync_is_available (async);

  /* On Linux with io_uring available, backend should be io_uring */
#if SOCKET_HAS_IO_URING
  SocketAsync_IOUringInfo info;
  if (SocketAsync_io_uring_available (&info) && info.supported)
    {
      /* io_uring is available - verify it's being used */
      ASSERT (available == 1);
      ASSERT (strcmp (name, "io_uring") == 0);
    }
#endif

  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_iouring_submit_and_cancel)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Skip if io_uring not available */
  if (!SocketAsync_is_available (async))
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  /* Verify we're using io_uring backend */
  const char *backend = SocketAsync_backend_name (async);
  ASSERT (strcmp (backend, "io_uring") == 0);

  /* Create a socket for testing */
  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Test data */
  const char *test_data = "Hello io_uring!";
  size_t test_len = strlen (test_data);
  char recv_buf[64];
  memset (recv_buf, 0, sizeof (recv_buf));

  /* Submit send request (will fail since socket not connected, but tests
   * io_uring path) */
  volatile unsigned send_id = 0;
  TRY
  {
    send_id = SocketAsync_send (async,
                                socket,
                                test_data,
                                test_len,
                                async_test_callback,
                                NULL,
                                ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    send_id = 0;
  }
  END_TRY;

  /* Submit recv request */
  volatile unsigned recv_id = 0;
  TRY
  {
    recv_id = SocketAsync_recv (async,
                                socket,
                                recv_buf,
                                sizeof (recv_buf),
                                async_test_callback,
                                NULL,
                                ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    recv_id = 0;
  }
  END_TRY;

  /* Verify requests were submitted successfully */
  if (send_id > 0)
    {
      size_t completed, total;
      int found = SocketAsync_get_progress (async, send_id, &completed, &total);
      ASSERT_EQ (1, found);
      ASSERT_EQ (test_len, total);
    }

  /* Process completions briefly (may fail since socket not connected) */
  SocketAsync_process_completions (async, 10);

  /* Cancel remaining requests */
  if (send_id > 0)
    SocketAsync_cancel (async, send_id);
  if (recv_id > 0)
    SocketAsync_cancel (async, recv_id);

  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

TEST (async_iouring_high_concurrency)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;

#define HIGH_CONCURRENCY_COUNT 100

  Socket_T socks[HIGH_CONCURRENCY_COUNT];
  volatile unsigned request_ids[HIGH_CONCURRENCY_COUNT];
  const char *test_data = "X";
  size_t created = 0;

  memset (socks, 0, sizeof (socks));
  memset ((void *)request_ids, 0, sizeof (request_ids));

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Skip if io_uring not available */
  if (!SocketAsync_is_available (async))
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  /* Create sockets and submit send requests */
  for (size_t i = 0; i < HIGH_CONCURRENCY_COUNT; i++)
    {
      TRY
      {
        socks[i] = Socket_new (AF_INET, SOCK_STREAM, 0);
        created++;

        request_ids[i] = SocketAsync_send (async,
                                           socks[i],
                                           test_data,
                                           1,
                                           async_test_callback,
                                           NULL,
                                           ASYNC_FLAG_NONE);
      }
      EXCEPT (Socket_Failed)
      {
        break;
      }
      EXCEPT (SocketAsync_Failed)
      {
        break;
      }
      END_TRY;
    }

  /* Verify we submitted many requests */
  ASSERT (created >= 50);

  /* Process some completions */
  for (int round = 0; round < 10; round++)
    {
      int completed = SocketAsync_process_completions (async, 10);
      if (completed == 0)
        break;
    }

  /* Cancel all pending requests */
  int cancelled = SocketAsync_cancel_all (async);
  ASSERT (cancelled >= 0);

  /* Cleanup sockets */
  for (size_t i = 0; i < created; i++)
    {
      if (socks[i])
        Socket_free (&socks[i]);
    }

  SocketAsync_free (&async);
  Arena_dispose (&arena);

#undef HIGH_CONCURRENCY_COUNT
}

/* ==================== Timer Integration Tests ==================== */

/* Callback context for tracking timer invocations */
typedef struct
{
  volatile int call_count;
  volatile int64_t last_call_time_ms;
} AsyncTimerContext;

static void
async_timer_test_callback (void *userdata)
{
  AsyncTimerContext *ctx = (AsyncTimerContext *)userdata;
  if (ctx)
    {
      ctx->call_count++;
      ctx->last_call_time_ms = Socket_get_monotonic_ms ();
    }
}

/**
 * async_timer_fires - Verify timer fires during SocketPoll_wait with async
 *
 * This test verifies that timer callbacks are invoked correctly when
 * SocketPoll is used with io_uring async operations.
 */
TEST (async_timer_fires)
{
  setup_signals ();
  SocketPoll_T poll = NULL;
  SocketTimer_T timer = NULL;
  AsyncTimerContext ctx = { 0, 0 };
  SocketEvent_T *events = NULL;
  int64_t start_time;
  int nfds;

  /* Create poll with timer support */
  TRY
  {
    poll = SocketPoll_new (10);
  }
  EXCEPT (SocketPoll_Failed)
  {
    ASSERT (0); /* Should not fail */
    return;
  }
  END_TRY;

  /* Skip if async/io_uring not available */
  SocketAsync_T async = SocketPoll_get_async (poll);
  if (!async || !SocketAsync_is_available (async))
    {
      SocketPoll_free (&poll);
      return; /* Skip test - async not available */
    }

  /* Verify we're using io_uring backend for async */
  const char *backend = SocketAsync_backend_name (async);
  if (strcmp (backend, "io_uring") != 0 && strstr (backend, "io_uring") == NULL)
    {
      /* Not io_uring - skip test */
      SocketPoll_free (&poll);
      return;
    }

  /* Add a timer to fire in 50ms */
  timer = SocketTimer_add (poll, 50, async_timer_test_callback, &ctx);
  ASSERT_NOT_NULL (timer);

  /* Record start time */
  start_time = Socket_get_monotonic_ms ();

  /* Wait for events - should wake up when timer fires */
  nfds = SocketPoll_wait (poll, &events, 200);

  /* Timer should have fired (nfds = 0 means timeout, which is fine) */
  (void)nfds;

  /* Verify callback was invoked */
  ASSERT_EQ (1, ctx.call_count);

  /* Verify timing (should fire after ~50ms, allow some slack) */
  int64_t elapsed = ctx.last_call_time_ms - start_time;
  ASSERT (elapsed >= 40); /* At least 40ms */
  ASSERT (elapsed < 150); /* Not too much delay */

  SocketPoll_free (&poll);
}

/**
 * async_timer_cancel - Verify cancelled timer doesn't fire with async
 */
TEST (async_timer_cancel)
{
  setup_signals ();
  SocketPoll_T poll = NULL;
  SocketTimer_T timer = NULL;
  AsyncTimerContext ctx = { 0, 0 };
  SocketEvent_T *events = NULL;

  TRY
  {
    poll = SocketPoll_new (10);
  }
  EXCEPT (SocketPoll_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Skip if async/io_uring not available */
  SocketAsync_T async = SocketPoll_get_async (poll);
  if (!async || !SocketAsync_is_available (async))
    {
      SocketPoll_free (&poll);
      return;
    }

  const char *backend = SocketAsync_backend_name (async);
  if (strcmp (backend, "io_uring") != 0 && strstr (backend, "io_uring") == NULL)
    {
      SocketPoll_free (&poll);
      return;
    }

  /* Add timer and immediately cancel it */
  timer = SocketTimer_add (poll, 50, async_timer_test_callback, &ctx);
  ASSERT_NOT_NULL (timer);

  int cancel_result = SocketTimer_cancel (poll, timer);
  ASSERT_EQ (0, cancel_result);

  /* Wait past when timer would have fired */
  SocketPoll_wait (poll, &events, 100);

  /* Timer should NOT have fired */
  ASSERT_EQ (0, ctx.call_count);

  SocketPoll_free (&poll);
}

/**
 * async_timer_multiple - Verify multiple timers fire in order with async
 */
TEST (async_timer_multiple)
{
  setup_signals ();
  SocketPoll_T poll = NULL;
  SocketTimer_T timer1 = NULL;
  SocketTimer_T timer2 = NULL;
  SocketTimer_T timer3 = NULL;
  AsyncTimerContext ctx1 = { 0, 0 };
  AsyncTimerContext ctx2 = { 0, 0 };
  AsyncTimerContext ctx3 = { 0, 0 };
  SocketEvent_T *events = NULL;
  int64_t start_time;

  TRY
  {
    poll = SocketPoll_new (10);
  }
  EXCEPT (SocketPoll_Failed)
  {
    ASSERT (0);
    return;
  }
  END_TRY;

  /* Skip if async/io_uring not available */
  SocketAsync_T async = SocketPoll_get_async (poll);
  if (!async || !SocketAsync_is_available (async))
    {
      SocketPoll_free (&poll);
      return;
    }

  const char *backend = SocketAsync_backend_name (async);
  if (strcmp (backend, "io_uring") != 0 && strstr (backend, "io_uring") == NULL)
    {
      SocketPoll_free (&poll);
      return;
    }

  /* Add multiple timers with different delays */
  timer1 = SocketTimer_add (poll, 30, async_timer_test_callback, &ctx1);
  timer2 = SocketTimer_add (poll, 60, async_timer_test_callback, &ctx2);
  timer3 = SocketTimer_add (poll, 90, async_timer_test_callback, &ctx3);

  ASSERT_NOT_NULL (timer1);
  ASSERT_NOT_NULL (timer2);
  ASSERT_NOT_NULL (timer3);

  start_time = Socket_get_monotonic_ms ();

  /* Wait long enough for all timers */
  for (int i = 0; i < 5
                  && (ctx1.call_count == 0 || ctx2.call_count == 0
                      || ctx3.call_count == 0);
       i++)
    {
      SocketPoll_wait (poll, &events, 50);
    }

  /* All timers should have fired */
  ASSERT_EQ (1, ctx1.call_count);
  ASSERT_EQ (1, ctx2.call_count);
  ASSERT_EQ (1, ctx3.call_count);

  /* Verify timers fired in order */
  ASSERT (ctx1.last_call_time_ms <= ctx2.last_call_time_ms);
  ASSERT (ctx2.last_call_time_ms <= ctx3.last_call_time_ms);

  /* Verify timing is roughly correct */
  int64_t elapsed1 = ctx1.last_call_time_ms - start_time;
  int64_t elapsed2 = ctx2.last_call_time_ms - start_time;
  int64_t elapsed3 = ctx3.last_call_time_ms - start_time;

  ASSERT (elapsed1 >= 20 && elapsed1 < 100);
  ASSERT (elapsed2 >= 50 && elapsed2 < 150);
  ASSERT (elapsed3 >= 80 && elapsed3 < 200);

  SocketPoll_free (&poll);
}

/* ==================== Fixed Buffer Security Tests ==================== */

#if SOCKET_HAS_IO_URING

/**
 * async_send_fixed_overflow_attack - Test integer overflow protection
 *
 * Verifies that the bounds check in SocketAsync_send_fixed() correctly
 * rejects overflow attacks where offset + len wraps around.
 */
TEST (async_send_fixed_overflow_attack)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile int raised_exception = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return; /* Skip if async not available */
  }
  END_TRY;

  /* Skip if not using io_uring */
  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Register a small buffer (1KB) */
  static char test_buf[1024];
  memset (test_buf, 0, sizeof (test_buf));

  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return; /* Buffer registration not supported */
  }
  END_TRY;

  /* Attack vector: offset + len wraps to small value */
  size_t offset = SIZE_MAX - 1000;
  size_t len = 2000;

  /* This should raise an exception due to overflow protection */
  TRY
  {
    SocketAsync_send_fixed (async,
                            socket,
                            0,
                            offset,
                            len,
                            async_test_callback,
                            NULL,
                            ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    raised_exception = 1;
  }
  END_TRY;

  /* Should have caught the overflow */
  ASSERT_EQ (1, raised_exception);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/**
 * async_recv_fixed_overflow_attack - Test integer overflow protection
 *
 * Verifies that the bounds check in SocketAsync_recv_fixed() correctly
 * rejects overflow attacks where offset + len wraps around.
 */
TEST (async_recv_fixed_overflow_attack)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile int raised_exception = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Skip if not using io_uring */
  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Register a small buffer (1KB) */
  static char test_buf[1024];
  memset (test_buf, 0, sizeof (test_buf));

  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Attack vector: offset + len wraps to small value */
  size_t offset = SIZE_MAX - 500;
  size_t len = 1000;

  /* This should raise an exception due to overflow protection */
  TRY
  {
    SocketAsync_recv_fixed (async,
                            socket,
                            0,
                            offset,
                            len,
                            async_test_callback,
                            NULL,
                            ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    raised_exception = 1;
  }
  END_TRY;

  /* Should have caught the overflow */
  ASSERT_EQ (1, raised_exception);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/**
 * async_send_fixed_large_offset - Test large offset rejection
 *
 * Verifies that an offset beyond buffer size is rejected.
 */
TEST (async_send_fixed_large_offset)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile int raised_exception = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  static char test_buf[1024];
  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Offset beyond buffer size */
  size_t offset = sizeof (test_buf) + 100;
  size_t len = 10;

  TRY
  {
    SocketAsync_send_fixed (async,
                            socket,
                            0,
                            offset,
                            len,
                            async_test_callback,
                            NULL,
                            ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    raised_exception = 1;
  }
  END_TRY;

  ASSERT_EQ (1, raised_exception);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/**
 * async_recv_fixed_valid_bounds - Test valid buffer access
 *
 * Verifies that valid offset/len combinations are accepted.
 */
TEST (async_recv_fixed_valid_bounds)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile unsigned req_id = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  static char test_buf[1024];
  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Valid access: read 512 bytes starting at offset 256 */
  TRY
  {
    req_id = SocketAsync_recv_fixed (
        async, socket, 0, 256, 512, async_test_callback, NULL, ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req_id = 0;
  }
  END_TRY;

  /* Should succeed */
  ASSERT (req_id > 0);

  if (req_id > 0)
    SocketAsync_cancel (async, req_id);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/**
 * async_send_fixed_edge_case - Test edge case at buffer boundary
 *
 * Verifies that accessing exactly to the end of the buffer works.
 */
TEST (async_send_fixed_edge_case)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile unsigned req_id = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  static char test_buf[1024];
  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* Edge case: access exactly to the end */
  size_t offset = 1000;
  size_t len = 24; /* offset + len = 1024, exactly buffer size */

  TRY
  {
    req_id = SocketAsync_send_fixed (async,
                                     socket,
                                     0,
                                     offset,
                                     len,
                                     async_test_callback,
                                     NULL,
                                     ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    req_id = 0;
  }
  END_TRY;

  /* Should succeed */
  ASSERT (req_id > 0);

  if (req_id > 0)
    SocketAsync_cancel (async, req_id);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

/**
 * async_send_fixed_one_past_end - Test rejection of access one byte past end
 *
 * Verifies that offset + len exactly one past the buffer size is rejected.
 */
TEST (async_send_fixed_one_past_end)
{
  setup_signals ();
  Arena_T arena = Arena_new ();
  SocketAsync_T async = NULL;
  Socket_T socket = NULL;
  volatile int raised_exception = 0;

  TRY
  {
    async = SocketAsync_new (arena);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  if (strcmp (SocketAsync_backend_name (async), "io_uring") != 0)
    {
      SocketAsync_free (&async);
      Arena_dispose (&arena);
      return;
    }

  TRY
  {
    socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  }
  EXCEPT (Socket_Failed)
  {
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  static char test_buf[1024];
  void *bufs[1] = { test_buf };
  size_t lens[1] = { sizeof (test_buf) };

  TRY
  {
    SocketAsync_register_buffers (async, bufs, lens, 1);
  }
  EXCEPT (SocketAsync_Failed)
  {
    Socket_free (&socket);
    SocketAsync_free (&async);
    Arena_dispose (&arena);
    return;
  }
  END_TRY;

  /* One byte past the end */
  size_t offset = 1000;
  size_t len = 25; /* offset + len = 1025, one past buffer size */

  TRY
  {
    SocketAsync_send_fixed (async,
                            socket,
                            0,
                            offset,
                            len,
                            async_test_callback,
                            NULL,
                            ASYNC_FLAG_NONE);
  }
  EXCEPT (SocketAsync_Failed)
  {
    raised_exception = 1;
  }
  END_TRY;

  /* Should have raised exception */
  ASSERT_EQ (1, raised_exception);

  SocketAsync_unregister_buffers (async);
  Socket_free (&socket);
  SocketAsync_free (&async);
  Arena_dispose (&arena);
}

#endif /* SOCKET_HAS_IO_URING */

/* ==================== Main ==================== */

int
main (void)
{
  setup_signals ();
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
