/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketerror.c - SocketError module unit tests
 * Tests for the SocketError thread-local error message handling module.
 * Covers error message retrieval and thread-local storage behavior.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "core/SocketUtil.h"
#include "test/Test.h"

typedef struct
{
  int called;
  SocketLogLevel level;
  const char *component;
  char message[SOCKET_ERROR_BUFSIZE];
} LogProbe;

static void
log_capture_callback (void *userdata,
                      SocketLogLevel level,
                      const char *component,
                      const char *message)
{
  LogProbe *probe = (LogProbe *)userdata;

  if (!probe)
    return;

  probe->called++;
  probe->level = level;
  probe->component = component;

  if (message)
    strncpy (probe->message, message, sizeof (probe->message) - 1);
}

TEST (socketlog_custom_callback_receives_errors)
{
  LogProbe probe = { 0 };

  SocketLog_setcallback (log_capture_callback, &probe);
  SOCKET_ERROR_MSG ("Observability logging test message");

  ASSERT_EQ (1, probe.called);
  ASSERT_EQ (SOCKET_LOG_ERROR, probe.level);
  ASSERT_NOT_NULL (probe.component);
  ASSERT (strstr (probe.message, "Observability logging test message") != NULL);

  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_level_names)
{
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_TRACE));
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_DEBUG));
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_INFO));
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_WARN));
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_ERROR));
  ASSERT_NOT_NULL (SocketLog_levelname (SOCKET_LOG_FATAL));
  ASSERT_NOT_NULL (SocketLog_levelname ((SocketLogLevel)999));
}

TEST (socketlog_callback_replacement)
{
  LogProbe probe1 = { 0 };
  LogProbe probe2 = { 0 };

  SocketLog_setcallback (log_capture_callback, &probe1);
  SocketLog_emit (SOCKET_LOG_INFO, "TestComponent", "Message 1");
  ASSERT_EQ (1, probe1.called);
  ASSERT_EQ (0, probe2.called);

  SocketLog_setcallback (log_capture_callback, &probe2);
  SocketLog_emit (SOCKET_LOG_INFO, "TestComponent", "Message 2");
  ASSERT_EQ (1, probe1.called);
  ASSERT_EQ (1, probe2.called);

  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_getcallback_returns_default)
{
  void *userdata = NULL;
  SocketLogCallback callback;

  SocketLog_setcallback (NULL, NULL);
  callback = SocketLog_getcallback (&userdata);
  ASSERT_NOT_NULL (callback);
}

TEST (socketlog_emitf_formats_messages)
{
  LogProbe probe = { 0 };

  SocketLog_setcallback (log_capture_callback, &probe);
  SocketLog_emitf (
      SOCKET_LOG_WARN, "TestComponent", "Formatted: %d %s", 42, "test");

  ASSERT_EQ (1, probe.called);
  ASSERT_EQ (SOCKET_LOG_WARN, probe.level);
  ASSERT (strstr (probe.message, "Formatted: 42 test") != NULL);

  SocketLog_setcallback (NULL, NULL);
}

/* Test that Socket_GetLastError returns empty string initially */
TEST (socketerror_initial_empty)
{
  socket_error_buf[0] = '\0';
  socket_last_errno = 0;
  const char *error = Socket_GetLastError ();
  ASSERT_NOT_NULL (error);
  ASSERT_EQ (strlen (error), 0);
}

/* Test that error buffer is thread-local
 * Note: This test verifies the basic functionality. True thread-local
 * behavior would require execution in multiple threads, which is
 * tested in test_threadsafety.c */
TEST (socketerror_returns_buffer)
{
  socket_error_buf[0] = '\0';
  socket_last_errno = 0;
  const char *error1 = Socket_GetLastError ();
  const char *error2 = Socket_GetLastError ();

  /* Should return same buffer pointer */
  ASSERT_EQ (error1, error2);

  /* Should be empty initially */
  ASSERT_EQ (strlen (error1), 0);
}

/* Test that Socket_GetLastError returns valid pointer */
TEST (socketerror_valid_pointer)
{
  const char *error = Socket_GetLastError ();

  /* Should not be NULL */
  ASSERT_NOT_NULL (error);

  /* Should be a valid string (may be empty) */
  /* Reading from the buffer should not crash */
  size_t len = strlen (error);
  ASSERT (len < SOCKET_ERROR_BUFSIZE);
}

TEST (socketerror_geterrno_returns_captured_value)
{
  int saved_errno = errno;

  errno = ECONNREFUSED;
  SOCKET_ERROR_FMT ("Test error with errno capture");
  ASSERT_EQ (ECONNREFUSED, Socket_geterrno ());

  errno = ETIMEDOUT;
  SOCKET_ERROR_MSG ("Test error message");
  ASSERT_EQ (ETIMEDOUT, Socket_geterrno ());

  errno = saved_errno;
}

TEST (socketerror_geterrorcode_maps_errno_correctly)
{
  int saved_errno = errno;

  errno = ECONNREFUSED;
  SOCKET_ERROR_FMT ("Connection refused test");
  ASSERT_EQ (SOCKET_ERROR_ECONNREFUSED, Socket_geterrorcode ());

  errno = ETIMEDOUT;
  SOCKET_ERROR_FMT ("Timeout test");
  ASSERT_EQ (SOCKET_ERROR_ETIMEDOUT, Socket_geterrorcode ());

  errno = EADDRINUSE;
  SOCKET_ERROR_FMT ("Address in use test");
  ASSERT_EQ (SOCKET_ERROR_EADDRINUSE, Socket_geterrorcode ());

  errno = ENOMEM;
  SOCKET_ERROR_FMT ("Out of memory test");
  ASSERT_EQ (SOCKET_ERROR_ENOMEM, Socket_geterrorcode ());

  errno = EAGAIN;
  SOCKET_ERROR_FMT ("Would block test");
  ASSERT_EQ (SOCKET_ERROR_EAGAIN, Socket_geterrorcode ());

  errno = 0;
  SOCKET_ERROR_FMT ("No error test");
  ASSERT_EQ (SOCKET_ERROR_NONE, Socket_geterrorcode ());

  errno = saved_errno;
}

TEST (socketerror_geterrorcode_unknown_errno)
{
  int saved_errno = errno;

  errno = 99999;
  SOCKET_ERROR_FMT ("Unknown errno test");
  ASSERT_EQ (SOCKET_ERROR_UNKNOWN, Socket_geterrorcode ());

  errno = saved_errno;
}

TEST (socketerror_geterrno_thread_local)
{
  int saved_errno = errno;

  errno = ECONNREFUSED;
  SOCKET_ERROR_FMT ("Thread local test 1");
  int errno1 = Socket_geterrno ();

  errno = ETIMEDOUT;
  SOCKET_ERROR_FMT ("Thread local test 2");
  int errno2 = Socket_geterrno ();

  ASSERT_EQ (ECONNREFUSED, errno1);
  ASSERT_EQ (ETIMEDOUT, errno2);

  errno = saved_errno;
}

/* ============================================================================
 * SocketError_is_retryable_errno tests
 * ============================================================================
 */

TEST (socketerror_retryable_network_errors)
{
  /* Basic network errors - should be retryable */
  ASSERT_EQ (1, SocketError_is_retryable_errno (EAGAIN));
#ifdef EWOULDBLOCK
  ASSERT_EQ (1, SocketError_is_retryable_errno (EWOULDBLOCK));
#endif
  ASSERT_EQ (1, SocketError_is_retryable_errno (EALREADY));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNREFUSED));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNRESET));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EHOSTUNREACH));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EINPROGRESS));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EINTR));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENOTCONN));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETUNREACH));
  ASSERT_EQ (1, SocketError_is_retryable_errno (EPIPE));
  ASSERT_EQ (1, SocketError_is_retryable_errno (ECONNABORTED));
}

TEST (socketerror_retryable_platform_specific)
{
  /* Platform-specific network errors */
#ifdef ENETDOWN
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETDOWN));
#endif
#ifdef ENETRESET
  ASSERT_EQ (1, SocketError_is_retryable_errno (ENETRESET));
#endif
}

TEST (socketerror_retryable_timeout)
{
  /* Timeout errors should be retryable */
  ASSERT_EQ (1, SocketError_is_retryable_errno (ETIMEDOUT));
}

TEST (socketerror_non_retryable_config)
{
  /* Configuration errors - not retryable */
  ASSERT_EQ (0, SocketError_is_retryable_errno (EINVAL));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EACCES));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EADDRINUSE));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EADDRNOTAVAIL));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EAFNOSUPPORT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EBADF));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EFAULT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EISCONN));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOTSOCK));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EOPNOTSUPP));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPROTONOSUPPORT));
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPERM));
}

TEST (socketerror_non_retryable_platform_specific)
{
  /* Platform-specific non-retryable errors */
#ifdef EPROTO
  ASSERT_EQ (0, SocketError_is_retryable_errno (EPROTO));
#endif
}

TEST (socketerror_non_retryable_resource)
{
  /* Resource exhaustion - not retryable */
  ASSERT_EQ (0, SocketError_is_retryable_errno (EMFILE));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOMEM));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOBUFS));
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENFILE));
#ifdef ENOSPC
  ASSERT_EQ (0, SocketError_is_retryable_errno (ENOSPC));
#endif
}

TEST (socketerror_retryable_edge_cases)
{
  /* Edge cases */
  ASSERT_EQ (0, SocketError_is_retryable_errno (0));
  ASSERT_EQ (0, SocketError_is_retryable_errno (99999));
  ASSERT_EQ (0, SocketError_is_retryable_errno (-1));
}

TEST (socketerror_categorize_network)
{
  /* Network category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ECONNREFUSED));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ECONNRESET));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ENETUNREACH));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EHOSTUNREACH));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EAGAIN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EINPROGRESS));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (ENOTCONN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_NETWORK,
             SocketError_categorize_errno (EPIPE));
}

TEST (socketerror_categorize_protocol)
{
  /* Protocol category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EINVAL));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EAFNOSUPPORT));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EBADF));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EISCONN));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (ENOTSOCK));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EOPNOTSUPP));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_PROTOCOL,
             SocketError_categorize_errno (EPROTONOSUPPORT));
}

TEST (socketerror_categorize_application)
{
  /* Application category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EACCES));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EADDRINUSE));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EADDRNOTAVAIL));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_APPLICATION,
             SocketError_categorize_errno (EPERM));
}

TEST (socketerror_categorize_timeout)
{
  /* Timeout category */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_TIMEOUT,
             SocketError_categorize_errno (ETIMEDOUT));
}

TEST (socketerror_categorize_resource)
{
  /* Resource category errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (EMFILE));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENOMEM));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENOBUFS));
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_RESOURCE,
             SocketError_categorize_errno (ENFILE));
}

TEST (socketerror_categorize_unknown)
{
  /* Unknown category for unmapped errors */
  ASSERT_EQ (SOCKET_ERROR_CATEGORY_UNKNOWN,
             SocketError_categorize_errno (99999));
}

TEST (socketerror_category_name)
{
  /* Verify category names */
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_NETWORK),
                  "NETWORK")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_PROTOCOL),
                  "PROTOCOL")
          == 0);
  ASSERT (
      strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_APPLICATION),
              "APPLICATION")
      == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_TIMEOUT),
                  "TIMEOUT")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_RESOURCE),
                  "RESOURCE")
          == 0);
  ASSERT (strcmp (SocketError_category_name (SOCKET_ERROR_CATEGORY_UNKNOWN),
                  "UNKNOWN")
          == 0);

  /* Out of range */
  ASSERT (strcmp (SocketError_category_name ((SocketErrorCategory)999),
                  "UNKNOWN")
          == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
