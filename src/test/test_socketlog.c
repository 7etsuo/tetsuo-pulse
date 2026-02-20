/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketlog.c - Comprehensive unit tests for SocketLog module
 * Tests all 13 public API functions plus integration scenarios:
 * - Callback management (setcallback, getcallback)
 * - Log level filtering (setlevel, getlevel, levelname)
 * - Message emission (emit, emitf, emitfv)
 * - Thread-local context (setcontext, getcontext, clearcontext)
 * - Structured logging (setstructuredcallback, emit_structured)
 * - Buffer truncation, thread safety, platform differences
 */

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketLog.h"
#include "test/Test.h"

/* Test callback state */
typedef struct
{
  int call_count;
  SocketLogLevel last_level;
  char last_component[256];
  char last_message[SOCKET_LOG_BUFFER_SIZE];
  void *userdata_received;
} TestCallbackState;

static TestCallbackState test_state = { 0 };
static pthread_mutex_t test_state_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Test structured callback state */
typedef struct
{
  int call_count;
  SocketLogLevel last_level;
  char last_component[256];
  char last_message[SOCKET_LOG_BUFFER_SIZE];
  size_t last_field_count;
  SocketLogField last_fields[10];
  int context_present;
  SocketLogContext last_context;
} TestStructuredState;

static TestStructuredState structured_state = { 0 };

static void
reset_test_state (void)
{
  memset (&test_state, 0, sizeof (test_state));
  memset (&structured_state, 0, sizeof (structured_state));
}

static void
test_callback (void *userdata,
               SocketLogLevel level,
               const char *component,
               const char *message)
{
  pthread_mutex_lock (&test_state_mutex);

  test_state.call_count++;
  test_state.last_level = level;
  test_state.userdata_received = userdata;

  if (component)
    {
      strncpy (test_state.last_component,
               component,
               sizeof (test_state.last_component) - 1);
      test_state.last_component[sizeof (test_state.last_component) - 1] = '\0';
    }
  else
    {
      test_state.last_component[0] = '\0';
    }

  if (message)
    {
      strncpy (test_state.last_message,
               message,
               sizeof (test_state.last_message) - 1);
      test_state.last_message[sizeof (test_state.last_message) - 1] = '\0';
    }
  else
    {
      test_state.last_message[0] = '\0';
    }

  pthread_mutex_unlock (&test_state_mutex);
}

static void
test_structured_callback (void *userdata,
                          SocketLogLevel level,
                          const char *component,
                          const char *message,
                          const SocketLogField *fields,
                          size_t field_count,
                          const SocketLogContext *context)
{
  structured_state.call_count++;
  structured_state.last_level = level;

  if (component)
    {
      strncpy (structured_state.last_component,
               component,
               sizeof (structured_state.last_component) - 1);
      structured_state
          .last_component[sizeof (structured_state.last_component) - 1]
          = '\0';
    }

  if (message)
    {
      strncpy (structured_state.last_message,
               message,
               sizeof (structured_state.last_message) - 1);
      structured_state.last_message[sizeof (structured_state.last_message) - 1]
          = '\0';
    }

  structured_state.last_field_count = field_count < 10 ? field_count : 10;
  for (size_t i = 0; i < structured_state.last_field_count; i++)
    {
      /* Store pointers instead of copying - fields are const char* */
      structured_state.last_fields[i].key = fields[i].key;
      structured_state.last_fields[i].value = fields[i].value;
    }

  if (context)
    {
      structured_state.context_present = 1;
      memcpy (
          &structured_state.last_context, context, sizeof (SocketLogContext));
    }
  else
    {
      structured_state.context_present = 0;
    }

  (void)userdata;
}

TEST (socketlog_levelname_valid_levels)
{
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_TRACE), "TRACE") == 0);
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_DEBUG), "DEBUG") == 0);
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_INFO), "INFO") == 0);
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_WARN), "WARN") == 0);
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_ERROR), "ERROR") == 0);
  ASSERT (strcmp (SocketLog_levelname (SOCKET_LOG_FATAL), "FATAL") == 0);
}

TEST (socketlog_levelname_invalid_levels)
{
  ASSERT (strcmp (SocketLog_levelname (-1), "UNKNOWN") == 0);
  ASSERT (strcmp (SocketLog_levelname (999), "UNKNOWN") == 0);
}

TEST (socketlog_setlevel_getlevel_roundtrip)
{
  /* Save original level */
  SocketLogLevel original = SocketLog_getlevel ();

  /* Test setting various levels */
  SocketLog_setlevel (SOCKET_LOG_TRACE);
  ASSERT_EQ (SocketLog_getlevel (), SOCKET_LOG_TRACE);

  SocketLog_setlevel (SOCKET_LOG_DEBUG);
  ASSERT_EQ (SocketLog_getlevel (), SOCKET_LOG_DEBUG);

  SocketLog_setlevel (SOCKET_LOG_FATAL);
  ASSERT_EQ (SocketLog_getlevel (), SOCKET_LOG_FATAL);

  /* Restore original */
  SocketLog_setlevel (original);
}

TEST (socketlog_level_filtering)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_setlevel (SOCKET_LOG_WARN);

  /* These should be filtered out */
  SocketLog_emit (SOCKET_LOG_TRACE, "test", "trace message");
  SocketLog_emit (SOCKET_LOG_DEBUG, "test", "debug message");
  SocketLog_emit (SOCKET_LOG_INFO, "test", "info message");
  ASSERT_EQ (test_state.call_count, 0);

  /* These should pass through */
  SocketLog_emit (SOCKET_LOG_WARN, "test", "warn message");
  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_message, "warn message") == 0);

  SocketLog_emit (SOCKET_LOG_ERROR, "test", "error message");
  ASSERT_EQ (test_state.call_count, 2);

  SocketLog_emit (SOCKET_LOG_FATAL, "test", "fatal message");
  ASSERT_EQ (test_state.call_count, 3);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
  SocketLog_setlevel (SOCKET_LOG_INFO);
}

TEST (socketlog_setcallback_receives_messages)
{
  reset_test_state ();
  void *userdata = (void *)0x12345678;

  SocketLog_setcallback (test_callback, userdata);
  SocketLog_emit (SOCKET_LOG_INFO, "TestComponent", "Test message");

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT_EQ (test_state.last_level, SOCKET_LOG_INFO);
  ASSERT (strcmp (test_state.last_component, "TestComponent") == 0);
  ASSERT (strcmp (test_state.last_message, "Test message") == 0);
  ASSERT_EQ (test_state.userdata_received, userdata);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_getcallback_returns_default_when_null)
{
  SocketLog_setcallback (NULL, NULL);

  void *userdata = NULL;
  SocketLogCallback cb = SocketLog_getcallback (&userdata);

  ASSERT_NOT_NULL (cb);
  /* Default logger should be returned when no custom callback set */
}

TEST (socketlog_getcallback_returns_custom_callback)
{
  void *test_userdata = (void *)0xABCDEF;
  SocketLog_setcallback (test_callback, test_userdata);

  void *retrieved_userdata = NULL;
  SocketLogCallback cb = SocketLog_getcallback (&retrieved_userdata);

  ASSERT_EQ (cb, test_callback);
  ASSERT_EQ (retrieved_userdata, test_userdata);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_callback_with_null_component)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_emit (SOCKET_LOG_INFO, NULL, "message with no component");

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_component, "") == 0);
  ASSERT (strcmp (test_state.last_message, "message with no component") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_callback_with_null_message)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_emit (SOCKET_LOG_INFO, "TestComponent", NULL);

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_component, "TestComponent") == 0);
  ASSERT (strcmp (test_state.last_message, "") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_emitf_basic_formatting)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_emitf (
      SOCKET_LOG_INFO, "Test", "Value: %d, String: %s", 42, "hello");

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_message, "Value: 42, String: hello") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_emitf_buffer_truncation)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  /* Create a format string that will overflow SOCKET_LOG_BUFFER_SIZE (1024) */
  char long_string[SOCKET_LOG_BUFFER_SIZE + 100];
  memset (long_string, 'A', sizeof (long_string) - 1);
  long_string[sizeof (long_string) - 1] = '\0';

  SocketLog_emitf (SOCKET_LOG_INFO, "Test", "%s", long_string);

  ASSERT_EQ (test_state.call_count, 1);
  size_t msg_len = strlen (test_state.last_message);
  ASSERT_EQ (msg_len, SOCKET_LOG_BUFFER_SIZE - 1);

  /* Check for truncation suffix */
  const char *suffix
      = test_state.last_message + msg_len - SOCKET_LOG_TRUNCATION_SUFFIX_LEN;
  ASSERT (strcmp (suffix, SOCKET_LOG_TRUNCATION_SUFFIX) == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

/* Helper for testing emitfv with NULL format */
static void
test_emitfv_null_helper (SocketLogLevel level,
                         const char *component,
                         const char *fmt,
                         ...)
{
  va_list args;
  va_start (args, fmt);
  SocketLog_emitfv (level, component, fmt, args);
  va_end (args);
}

TEST (socketlog_emitfv_null_format_string)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  /* emitfv with NULL format should call emit with NULL message */
  test_emitfv_null_helper (SOCKET_LOG_INFO, "Test", NULL);

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_message, "") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_setcontext_getcontext_roundtrip)
{
  SocketLogContext ctx = { 0 };
  strncpy (ctx.trace_id, "trace-12345", sizeof (ctx.trace_id) - 1);
  strncpy (ctx.request_id, "req-67890", sizeof (ctx.request_id) - 1);
  ctx.connection_fd = 42;

  SocketLog_setcontext (&ctx);

  const SocketLogContext *retrieved = SocketLog_getcontext ();
  ASSERT_NOT_NULL (retrieved);
  ASSERT (strcmp (retrieved->trace_id, "trace-12345") == 0);
  ASSERT (strcmp (retrieved->request_id, "req-67890") == 0);
  ASSERT_EQ (retrieved->connection_fd, 42);

  /* Cleanup */
  SocketLog_clearcontext ();
}

TEST (socketlog_clearcontext_resets_all_fields)
{
  SocketLogContext ctx = { 0 };
  strncpy (ctx.trace_id, "trace-12345", sizeof (ctx.trace_id) - 1);
  strncpy (ctx.request_id, "req-67890", sizeof (ctx.request_id) - 1);
  ctx.connection_fd = 42;

  SocketLog_setcontext (&ctx);
  SocketLog_clearcontext ();

  const SocketLogContext *retrieved = SocketLog_getcontext ();
  ASSERT_NULL (retrieved);
}

TEST (socketlog_setcontext_null_clears_context)
{
  SocketLogContext ctx = { 0 };
  strncpy (ctx.trace_id, "trace-12345", sizeof (ctx.trace_id) - 1);
  ctx.connection_fd = 42;

  SocketLog_setcontext (&ctx);
  ASSERT_NOT_NULL (SocketLog_getcontext ());

  SocketLog_setcontext (NULL);
  ASSERT_NULL (SocketLog_getcontext ());
}

TEST (socketlog_context_null_termination_enforcement)
{
  SocketLogContext ctx;

  /* Fill with non-null bytes */
  memset (&ctx, 'X', sizeof (ctx));
  /* Set some data but don't null-terminate */
  memcpy (ctx.trace_id, "trace", 5);
  memcpy (ctx.request_id, "request", 7);
  ctx.connection_fd = 10;

  SocketLog_setcontext (&ctx);

  const SocketLogContext *retrieved = SocketLog_getcontext ();
  ASSERT_NOT_NULL (retrieved);

  /* Check that null termination was enforced */
  ASSERT_EQ (retrieved->trace_id[SOCKET_LOG_ID_SIZE - 1], '\0');
  ASSERT_EQ (retrieved->request_id[SOCKET_LOG_ID_SIZE - 1], '\0');
}

TEST (socketlog_emit_structured_with_callback)
{
  reset_test_state ();
  SocketLog_setstructuredcallback (test_structured_callback, NULL);

  SocketLogField fields[]
      = { { "fd", "42" }, { "bytes", "1024" }, { "peer", "192.168.1.1" } };

  SocketLog_emit_structured (
      SOCKET_LOG_INFO, "Socket", "Connection established", fields, 3);

  ASSERT_EQ (structured_state.call_count, 1);
  ASSERT_EQ (structured_state.last_level, SOCKET_LOG_INFO);
  ASSERT (strcmp (structured_state.last_component, "Socket") == 0);
  ASSERT (strcmp (structured_state.last_message, "Connection established")
          == 0);
  ASSERT_EQ (structured_state.last_field_count, 3);

  /* Cleanup */
  SocketLog_setstructuredcallback (NULL, NULL);
}

TEST (socketlog_emit_structured_fallback_to_default)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_setstructuredcallback (NULL, NULL);

  SocketLogField fields[] = { { "key1", "value1" }, { "key2", "value2" } };

  SocketLog_emit_structured (SOCKET_LOG_INFO, "Test", "Message", fields, 2);

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_component, "Test") == 0);

  /* Message should contain formatted fields */
  ASSERT_NOT_NULL (strstr (test_state.last_message, "key1=value1"));
  ASSERT_NOT_NULL (strstr (test_state.last_message, "key2=value2"));

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_structured_callback_receives_context)
{
  reset_test_state ();
  SocketLog_setstructuredcallback (test_structured_callback, NULL);

  SocketLogContext ctx = { 0 };
  strncpy (ctx.trace_id, "trace-abc", sizeof (ctx.trace_id) - 1);
  ctx.connection_fd = 99;
  SocketLog_setcontext (&ctx);

  SocketLogField fields[] = { { "key", "value" } };
  SocketLog_emit_structured (SOCKET_LOG_INFO, "Test", "Msg", fields, 1);

  ASSERT_EQ (structured_state.call_count, 1);
  ASSERT_EQ (structured_state.context_present, 1);
  ASSERT (strcmp (structured_state.last_context.trace_id, "trace-abc") == 0);
  ASSERT_EQ (structured_state.last_context.connection_fd, 99);

  /* Cleanup */
  SocketLog_clearcontext ();
  SocketLog_setstructuredcallback (NULL, NULL);
}

TEST (socketlog_structured_with_null_fields)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  /* NULL fields with count > 0 should be handled gracefully */
  SocketLog_emit_structured (SOCKET_LOG_INFO, "Test", "Message", NULL, 0);

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_message, "Message") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_structured_fallback_escapes_injection_chars)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);
  SocketLog_setstructuredcallback (NULL, NULL);

  SocketLogField fields[] = { { "user\nname", "line1\r\nline2=ok" } };

  SocketLog_emit_structured (SOCKET_LOG_INFO, "Test", "Msg", fields, 1);

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT_NOT_NULL (
      strstr (test_state.last_message, "user\\nname=line1\\r\\nline2\\=ok"));
  ASSERT_NULL (strchr (test_state.last_message, '\n'));
  ASSERT_NULL (strchr (test_state.last_message, '\r'));

  SocketLog_setcallback (NULL, NULL);
  SocketLog_setstructuredcallback (NULL, NULL);
}

TEST (socketlog_structured_field_with_null_key_value)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  SocketLogField fields[] = {
    { "valid", "field" },
    { NULL, "value" },     /* NULL key - formatting stops here */
    { "key", NULL },       /* NULL value - never reached */
    { "another", "valid" } /* Never reached */
  };

  SocketLog_emit_structured (SOCKET_LOG_INFO, "Test", "Msg", fields, 4);

  ASSERT_EQ (test_state.call_count, 1);

  /* Should contain first valid field only - formatting stops at first NULL */
  ASSERT_NOT_NULL (strstr (test_state.last_message, "valid=field"));
  /* Fields after the NULL are not included */
  ASSERT_NULL (strstr (test_state.last_message, "another=valid"));

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

typedef struct
{
  int thread_id;
  int iterations;
} ThreadTestArgs;

static void *
thread_log_worker (void *arg)
{
  ThreadTestArgs *args = (ThreadTestArgs *)arg;

  for (int i = 0; i < args->iterations; i++)
    {
      SocketLog_emitf (SOCKET_LOG_INFO,
                       "Thread",
                       "Thread %d iteration %d",
                       args->thread_id,
                       i);
    }

  return NULL;
}

TEST (socketlog_concurrent_logging)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  const int num_threads = 4;
  const int iterations_per_thread = 10;
  pthread_t threads[num_threads];
  ThreadTestArgs args[num_threads];

  for (int i = 0; i < num_threads; i++)
    {
      args[i].thread_id = i;
      args[i].iterations = iterations_per_thread;
      pthread_create (&threads[i], NULL, thread_log_worker, &args[i]);
    }

  for (int i = 0; i < num_threads; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* All messages should have been logged */
  ASSERT_EQ (test_state.call_count, num_threads * iterations_per_thread);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

static void *
thread_context_worker (void *arg)
{
  int thread_id = *(int *)arg;

  SocketLogContext ctx = { 0 };
  snprintf (ctx.trace_id, sizeof (ctx.trace_id), "thread-%d-trace", thread_id);
  snprintf (
      ctx.request_id, sizeof (ctx.request_id), "thread-%d-req", thread_id);
  ctx.connection_fd = thread_id * 100;

  SocketLog_setcontext (&ctx);

  /* Verify context is isolated to this thread */
  const SocketLogContext *retrieved = SocketLog_getcontext ();
  ASSERT_NOT_NULL (retrieved);

  char expected_trace[SOCKET_LOG_ID_SIZE];
  char expected_request[SOCKET_LOG_ID_SIZE];
  snprintf (
      expected_trace, sizeof (expected_trace), "thread-%d-trace", thread_id);
  snprintf (
      expected_request, sizeof (expected_request), "thread-%d-req", thread_id);

  ASSERT (strcmp (retrieved->trace_id, expected_trace) == 0);
  ASSERT (strcmp (retrieved->request_id, expected_request) == 0);
  ASSERT_EQ (retrieved->connection_fd, thread_id * 100);

  SocketLog_clearcontext ();

  return NULL;
}

TEST (socketlog_context_isolation_across_threads)
{
  const int num_threads = 8;
  pthread_t threads[num_threads];
  int thread_ids[num_threads];

  for (int i = 0; i < num_threads; i++)
    {
      thread_ids[i] = i;
      pthread_create (&threads[i], NULL, thread_context_worker, &thread_ids[i]);
    }

  for (int i = 0; i < num_threads; i++)
    {
      pthread_join (threads[i], NULL);
    }
}

TEST (socketlog_large_structured_field_array)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  /* Create many fields to test truncation */
  SocketLogField fields[100];
  for (int i = 0; i < 100; i++)
    {
      static char keys[100][20];
      static char values[100][20];
      snprintf (keys[i], sizeof (keys[i]), "key%d", i);
      snprintf (values[i], sizeof (values[i]), "value%d", i);
      fields[i].key = keys[i];
      fields[i].value = values[i];
    }

  SocketLog_emit_structured (
      SOCKET_LOG_INFO, "Test", "Many fields", fields, 100);

  ASSERT_EQ (test_state.call_count, 1);

  /* Message should be truncated but still valid */
  size_t msg_len = strlen (test_state.last_message);
  ASSERT (msg_len > 0);
  ASSERT (msg_len <= SOCKET_LOG_BUFFER_SIZE);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

TEST (socketlog_empty_strings)
{
  reset_test_state ();
  SocketLog_setcallback (test_callback, NULL);

  SocketLog_emit (SOCKET_LOG_INFO, "", "");

  ASSERT_EQ (test_state.call_count, 1);
  ASSERT (strcmp (test_state.last_component, "") == 0);
  ASSERT (strcmp (test_state.last_message, "") == 0);

  /* Cleanup */
  SocketLog_setcallback (NULL, NULL);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
