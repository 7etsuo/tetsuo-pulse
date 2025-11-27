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

/* ==================== Main ==================== */

int
main (void)
{
  setup_signals ();
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
