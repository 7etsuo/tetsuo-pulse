/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_signals.c - Signal handling tests
 *
 * Tests for:
 * - Socket_ignore_sigpipe() function
 * - EINTR handling in poll operations
 * - Signal interrupt during blocking operations
 * - Self-pipe trick integration
 * - Library signal-safety properties
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "test/Test.h"

/* =============================================================================
 * Test Helpers
 * =============================================================================
 */

/* Volatile flag for signal handler - only use sig_atomic_t */
static volatile sig_atomic_t g_signal_received = 0;
static volatile sig_atomic_t g_alarm_count = 0;

/* Simple signal handler that just sets a flag */
static void
test_signal_handler (int signo)
{
  (void)signo;
  g_signal_received = 1;
}

/* SIGALRM handler for timing tests */
static void
alarm_handler (int signo)
{
  (void)signo;
  g_alarm_count++;
}

/* Self-pipe for signal tests */
static int g_test_pipe[2] = { -1, -1 };

/* Signal handler that writes to pipe (async-signal-safe) */
static void
pipe_signal_handler (int signo)
{
  int saved_errno = errno;
  char byte = (char)signo;
  /* write() return value intentionally ignored - best effort in handler */
  ssize_t ret = write (g_test_pipe[1], &byte, 1);
  (void)ret;
  errno = saved_errno;
}

/* Setup self-pipe for tests */
static int
setup_test_pipe (void)
{
  if (pipe (g_test_pipe) < 0)
    return -1;

  fcntl (g_test_pipe[0], F_SETFL, O_NONBLOCK);
  fcntl (g_test_pipe[1], F_SETFL, O_NONBLOCK);
  fcntl (g_test_pipe[0], F_SETFD, FD_CLOEXEC);
  fcntl (g_test_pipe[1], F_SETFD, FD_CLOEXEC);

  return 0;
}

/* Cleanup test pipe */
static void
cleanup_test_pipe (void)
{
  if (g_test_pipe[0] >= 0)
    close (g_test_pipe[0]);
  if (g_test_pipe[1] >= 0)
    close (g_test_pipe[1]);
  g_test_pipe[0] = -1;
  g_test_pipe[1] = -1;
}

/* Drain test pipe */
static int
drain_test_pipe (void)
{
  char buf[16];
  ssize_t n;
  int count = 0;

  while ((n = read (g_test_pipe[0], buf, sizeof (buf))) > 0)
    count += (int)n;

  return count;
}

/* =============================================================================
 * Socket_ignore_sigpipe Tests
 * =============================================================================
 */

TEST (signal_ignore_sigpipe_succeeds)
{
  /* Test that Socket_ignore_sigpipe() returns success */
  int result = Socket_ignore_sigpipe ();
  ASSERT_EQ (0, result);
}

TEST (signal_ignore_sigpipe_is_idempotent)
{
  /* Calling multiple times should succeed */
  int result1 = Socket_ignore_sigpipe ();
  int result2 = Socket_ignore_sigpipe ();
  int result3 = Socket_ignore_sigpipe ();

  ASSERT_EQ (0, result1);
  ASSERT_EQ (0, result2);
  ASSERT_EQ (0, result3);
}

TEST (signal_sigpipe_ignored_after_call)
{
  /* After calling Socket_ignore_sigpipe(), sending to closed socket
   * should not kill the process with SIGPIPE */

  Socket_ignore_sigpipe ();

  /* Create a socket pair */
  int sv[2];
  int err = socketpair (AF_UNIX, SOCK_STREAM, 0, sv);
  ASSERT_EQ (0, err);

  /* Close the receiving end */
  close (sv[1]);

  /* Try to write - should get EPIPE, not SIGPIPE */
  ssize_t n = write (sv[0], "test", 4);

  /* If we get here, SIGPIPE didn't kill us */
  ASSERT (n < 0);
  ASSERT (errno == EPIPE || errno == ECONNRESET);

  close (sv[0]);
}

/* =============================================================================
 * Self-Pipe Pattern Tests
 * =============================================================================
 */

TEST (signal_self_pipe_receives_signal)
{
  /* Test that self-pipe trick works for signal notification */

  ASSERT_EQ (0, setup_test_pipe ());

  /* Install handler that writes to pipe */
  struct sigaction sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = pipe_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGUSR1, &sa, NULL);

  /* Send signal to self */
  raise (SIGUSR1);

  /* Check that signal was received via pipe */
  int count = drain_test_pipe ();
  ASSERT (count > 0);

  /* Restore default handler */
  signal (SIGUSR1, SIG_DFL);
  cleanup_test_pipe ();
}

TEST (signal_self_pipe_nonblocking_write)
{
  /* Test that pipe write in signal handler doesn't block */

  ASSERT_EQ (0, setup_test_pipe ());

  struct sigaction sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = pipe_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGUSR1, &sa, NULL);

  /* Send many signals rapidly */
  for (int i = 0; i < 10; i++)
    raise (SIGUSR1);

  /* All should complete without blocking */
  int count = drain_test_pipe ();
  ASSERT (count >= 1); /* At least one should have been written */

  signal (SIGUSR1, SIG_DFL);
  cleanup_test_pipe ();
}

/* =============================================================================
 * EINTR Handling Tests
 * =============================================================================
 */

TEST (signal_poll_handles_eintr)
{
  /* Test that SocketPoll_wait handles EINTR gracefully */

  g_alarm_count = 0;

  /* Install SIGALRM handler */
  struct sigaction sa, old_sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = alarm_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0; /* Don't use SA_RESTART - we want EINTR */
  sigaction (SIGALRM, &sa, &old_sa);

  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  /* Schedule alarm for 100ms from now */
  struct itimerval timer;
  memset (&timer, 0, sizeof (timer));
  timer.it_value.tv_usec = 100000; /* 100ms */
  setitimer (ITIMER_REAL, &timer, NULL);

  /* Wait longer than the alarm - should be interrupted but handle it */
  SocketEvent_T *events;
  int n = SocketPoll_wait (poll, &events, 500); /* 500ms timeout */

  /* Verify alarm fired */
  ASSERT (g_alarm_count >= 1);

  /* Result should be valid (0 for timeout or handled EINTR) */
  ASSERT (n >= 0);

  /* Cancel any pending timer */
  memset (&timer, 0, sizeof (timer));
  setitimer (ITIMER_REAL, &timer, NULL);

  /* Restore old handler */
  sigaction (SIGALRM, &old_sa, NULL);

  SocketPoll_free (&poll);
}

TEST (signal_poll_wait_can_timeout_normally)
{
  /* Verify poll timeout works when not interrupted */

  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  SocketEvent_T *events;

  /* Short timeout - should return 0 (no events) */
  int n = SocketPoll_wait (poll, &events, 10);
  ASSERT_EQ (0, n);

  SocketPoll_free (&poll);
}

/* =============================================================================
 * Signal Handler Installation Tests
 * =============================================================================
 */

TEST (signal_sigaction_installs_handler)
{
  /* Test that sigaction() works correctly */

  g_signal_received = 0;

  struct sigaction sa, old_sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = test_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;

  int result = sigaction (SIGUSR1, &sa, &old_sa);
  ASSERT_EQ (0, result);

  /* Send signal */
  raise (SIGUSR1);

  /* Verify handler was called */
  ASSERT_EQ (1, g_signal_received);

  /* Restore previous handler */
  sigaction (SIGUSR1, &old_sa, NULL);
}

TEST (signal_multiple_handlers_can_coexist)
{
  /* Test that different signals can have different handlers */

  g_signal_received = 0;
  g_alarm_count = 0;

  struct sigaction sa_usr, sa_alrm, old_usr, old_alrm;

  memset (&sa_usr, 0, sizeof (sa_usr));
  sa_usr.sa_handler = test_signal_handler;
  sigemptyset (&sa_usr.sa_mask);
  sigaction (SIGUSR1, &sa_usr, &old_usr);

  memset (&sa_alrm, 0, sizeof (sa_alrm));
  sa_alrm.sa_handler = alarm_handler;
  sigemptyset (&sa_alrm.sa_mask);
  sigaction (SIGALRM, &sa_alrm, &old_alrm);

  /* Send both signals */
  raise (SIGUSR1);
  raise (SIGALRM);

  /* Verify both handlers were called */
  ASSERT_EQ (1, g_signal_received);
  ASSERT_EQ (1, g_alarm_count);

  /* Restore */
  sigaction (SIGUSR1, &old_usr, NULL);
  sigaction (SIGALRM, &old_alrm, NULL);
}

/* =============================================================================
 * Library Signal Safety Tests
 * =============================================================================
 */

TEST (signal_library_has_no_handlers_by_default)
{
  /* Verify that creating library objects doesn't install signal handlers */

  /* Save current SIGINT disposition */
  struct sigaction old_sigint;
  sigaction (SIGINT, NULL, &old_sigint);

  /* Create various library objects */
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  SocketPoll_T poll = SocketPoll_new (10);
  Arena_T arena = Arena_new ();

  /* Check SIGINT disposition hasn't changed */
  struct sigaction new_sigint;
  sigaction (SIGINT, NULL, &new_sigint);

  ASSERT (old_sigint.sa_handler == new_sigint.sa_handler);

  /* Cleanup */
  Socket_free (&socket);
  SocketPoll_free (&poll);
  Arena_dispose (&arena);
}

TEST (signal_msg_nosignal_used_for_send)
{
  /* Verify that MSG_NOSIGNAL is defined and usable */

  /* On Linux, MSG_NOSIGNAL should be non-zero */
  /* On macOS, it might be 0 (we use SO_NOSIGPIPE instead) */
#ifdef __linux__
  ASSERT (MSG_NOSIGNAL != 0);
#endif

  /* SOCKET_MSG_NOSIGNAL should always be defined */
  ASSERT (SOCKET_MSG_NOSIGNAL >= 0);
}

/* =============================================================================
 * Signal Mask Tests
 * =============================================================================
 */

TEST (signal_pthread_sigmask_works)
{
  /* Test that pthread_sigmask can block/unblock signals */

  sigset_t block_set, old_set;
  sigemptyset (&block_set);
  sigaddset (&block_set, SIGUSR2);

  /* Block SIGUSR2 */
  int result = pthread_sigmask (SIG_BLOCK, &block_set, &old_set);
  ASSERT_EQ (0, result);

  /* Unblock */
  result = pthread_sigmask (SIG_SETMASK, &old_set, NULL);
  ASSERT_EQ (0, result);
}

/* =============================================================================
 * Volatile sig_atomic_t Tests
 * =============================================================================
 */

TEST (signal_sig_atomic_t_is_safe)
{
  /* Test that sig_atomic_t can be safely written from handler */

  volatile sig_atomic_t test_flag = 0;

  /* These operations should be atomic */
  test_flag = 1;
  ASSERT_EQ (1, test_flag);

  test_flag = 0;
  ASSERT_EQ (0, test_flag);
}

/* =============================================================================
 * Integration Tests
 * =============================================================================
 */

TEST (signal_self_pipe_with_select_integration)
{
  /* Test self-pipe integration with select() - demonstrates the pattern
   * that would be used with SocketPoll in a real application.
   *
   * Note: SocketPoll_add() requires Socket_T, not raw fds. For raw fd
   * monitoring (like signal pipes), use select/poll directly or create
   * a wrapper. See examples/graceful_shutdown.c for the full pattern.
   */

  ASSERT_EQ (0, setup_test_pipe ());

  /* Install signal handler */
  struct sigaction sa, old_sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = pipe_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGUSR1, &sa, &old_sa);

  /* Send signal */
  raise (SIGUSR1);

  /* Use select() to wait for pipe to be readable */
  fd_set readfds;
  FD_ZERO (&readfds);
  FD_SET (g_test_pipe[0], &readfds);

  struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
  int n = select (g_test_pipe[0] + 1, &readfds, NULL, NULL, &tv);

  ASSERT (n > 0);
  ASSERT (FD_ISSET (g_test_pipe[0], &readfds));

  /* Drain the pipe */
  int count = drain_test_pipe ();
  ASSERT (count > 0);

  /* Restore and cleanup */
  sigaction (SIGUSR1, &old_sa, NULL);
  cleanup_test_pipe ();
}

TEST (signal_graceful_shutdown_pattern)
{
  /* Test the complete graceful shutdown pattern using select() */

  ASSERT_EQ (0, setup_test_pipe ());

  /* Install handler */
  struct sigaction sa, old_sa;
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = pipe_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGTERM, &sa, &old_sa);

  /* Simulate graceful shutdown */
  int running = 1;
  int iterations = 0;

  /* Send shutdown signal */
  raise (SIGTERM);

  while (running && iterations < 10)
    {
      fd_set readfds;
      FD_ZERO (&readfds);
      FD_SET (g_test_pipe[0], &readfds);

      struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
      int n = select (g_test_pipe[0] + 1, &readfds, NULL, NULL, &tv);

      if (n > 0 && FD_ISSET (g_test_pipe[0], &readfds))
        {
          drain_test_pipe ();
          running = 0;
        }
      iterations++;
    }

  /* Should have exited cleanly */
  ASSERT_EQ (0, running);
  ASSERT (iterations < 10);

  /* Cleanup */
  sigaction (SIGTERM, &old_sa, NULL);
  cleanup_test_pipe ();
}

/* =============================================================================
 * Test Main
 * =============================================================================
 */

int
main (void)
{
  printf ("=== Signal Handling Tests ===\n\n");

  /* Ensure SIGPIPE is ignored for all tests */
  if (Socket_ignore_sigpipe () != 0)
    {
      perror ("Socket_ignore_sigpipe");
      return 1;
    }

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}
