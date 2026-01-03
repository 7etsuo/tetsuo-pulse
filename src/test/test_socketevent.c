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

/* ============================================================================
 * POLL WAKEUP EVENT TESTS
 * ============================================================================
 */

/* Test context for poll wakeup event verification */
typedef struct
{
  int called;
  SocketEventType type;
  const char *component;
  int nfds;
  int timeout_ms;
} PollWakeupContext;

/* Callback for poll wakeup event verification */
static void
poll_wakeup_callback (void *userdata, const SocketEventRecord *event)
{
  PollWakeupContext *ctx = (PollWakeupContext *)userdata;

  if (ctx != NULL && event != NULL)
    {
      ctx->called = 1;
      ctx->type = event->type;
      ctx->component = event->component;
      ctx->nfds = event->data.poll.nfds;
      ctx->timeout_ms = event->data.poll.timeout_ms;
    }
}

/* Test emit_poll_wakeup with no registered handlers (should not crash) */
TEST (socketevent_emit_poll_wakeup_no_handlers)
{
  /* Should complete without crashing */
  SocketEvent_emit_poll_wakeup (0, 1000);
  SocketEvent_emit_poll_wakeup (10, -1);
  SocketEvent_emit_poll_wakeup (5, 0);
}

/* Test emit_poll_wakeup with single registered handler */
TEST (socketevent_emit_poll_wakeup_single_handler)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  /* Register handler */
  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* Emit event with zero file descriptors */
  SocketEvent_emit_poll_wakeup (0, 1000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.type, SOCKET_EVENT_POLL_WAKEUP);
  ASSERT_EQ (ctx.nfds, 0);
  ASSERT_EQ (ctx.timeout_ms, 1000);

  /* Verify component string */
  ASSERT_NOT_NULL (ctx.component);
  ASSERT_EQ (strcmp (ctx.component, "SocketPoll"), 0);

  /* Clean up */
  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with multiple registered handlers */
TEST (socketevent_emit_poll_wakeup_multiple_handlers)
{
  PollWakeupContext ctx1 = { 0, 0, NULL, 0, 0 };
  PollWakeupContext ctx2 = { 0, 0, NULL, 0, 0 };
  PollWakeupContext ctx3 = { 0, 0, NULL, 0, 0 };
  int result;

  /* Register three handlers */
  result = SocketEvent_register (poll_wakeup_callback, &ctx1);
  ASSERT_EQ (result, 0);
  result = SocketEvent_register (poll_wakeup_callback, &ctx2);
  ASSERT_EQ (result, 0);
  result = SocketEvent_register (poll_wakeup_callback, &ctx3);
  ASSERT_EQ (result, 0);

  /* Emit event with multiple fds */
  SocketEvent_emit_poll_wakeup (42, 5000);

  /* All handlers should receive the event */
  ASSERT_EQ (ctx1.called, 1);
  ASSERT_EQ (ctx1.type, SOCKET_EVENT_POLL_WAKEUP);
  ASSERT_EQ (ctx1.nfds, 42);
  ASSERT_EQ (ctx1.timeout_ms, 5000);

  ASSERT_EQ (ctx2.called, 1);
  ASSERT_EQ (ctx2.type, SOCKET_EVENT_POLL_WAKEUP);
  ASSERT_EQ (ctx2.nfds, 42);
  ASSERT_EQ (ctx2.timeout_ms, 5000);

  ASSERT_EQ (ctx3.called, 1);
  ASSERT_EQ (ctx3.type, SOCKET_EVENT_POLL_WAKEUP);
  ASSERT_EQ (ctx3.nfds, 42);
  ASSERT_EQ (ctx3.timeout_ms, 5000);

  /* Clean up */
  result = SocketEvent_unregister (poll_wakeup_callback, &ctx1);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (poll_wakeup_callback, &ctx2);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (poll_wakeup_callback, &ctx3);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with nfds=0 (no file descriptors) */
TEST (socketevent_emit_poll_wakeup_zero_fds)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_poll_wakeup (0, 100);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 0);
  ASSERT_EQ (ctx.timeout_ms, 100);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with positive nfds values */
TEST (socketevent_emit_poll_wakeup_positive_fds)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* Test various positive nfds values */
  SocketEvent_emit_poll_wakeup (1, 1000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 1);

  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (100, 2000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 100);

  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (10000, 3000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 10000);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with timeout_ms=-1 (infinite timeout) */
TEST (socketevent_emit_poll_wakeup_infinite_timeout)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_poll_wakeup (5, -1);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 5);
  ASSERT_EQ (ctx.timeout_ms, -1);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with timeout_ms=0 (non-blocking) */
TEST (socketevent_emit_poll_wakeup_nonblocking_timeout)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_poll_wakeup (3, 0);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 3);
  ASSERT_EQ (ctx.timeout_ms, 0);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with positive timeout values */
TEST (socketevent_emit_poll_wakeup_positive_timeout)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* Test various timeout values */
  SocketEvent_emit_poll_wakeup (2, 1);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.timeout_ms, 1);

  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (2, 1000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.timeout_ms, 1000);

  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (2, 60000);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.timeout_ms, 60000);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_poll_wakeup with various nfds and timeout combinations */
TEST (socketevent_emit_poll_wakeup_combinations)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* Zero fds, infinite timeout */
  SocketEvent_emit_poll_wakeup (0, -1);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 0);
  ASSERT_EQ (ctx.timeout_ms, -1);

  /* Zero fds, zero timeout */
  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (0, 0);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 0);
  ASSERT_EQ (ctx.timeout_ms, 0);

  /* Many fds, infinite timeout */
  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (1000, -1);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 1000);
  ASSERT_EQ (ctx.timeout_ms, -1);

  /* Many fds, zero timeout */
  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (1000, 0);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 1000);
  ASSERT_EQ (ctx.timeout_ms, 0);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test that poll events use correct union member (data.poll) */
TEST (socketevent_emit_poll_wakeup_uses_poll_union)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* Emit with distinctive values */
  SocketEvent_emit_poll_wakeup (123, 456);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.type, SOCKET_EVENT_POLL_WAKEUP);
  /* Verify we got the poll-specific data */
  ASSERT_EQ (ctx.nfds, 123);
  ASSERT_EQ (ctx.timeout_ms, 456);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test multiple emit calls with same handler */
TEST (socketevent_emit_poll_wakeup_multiple_emits)
{
  PollWakeupContext ctx = { 0, 0, NULL, 0, 0 };
  int result;

  result = SocketEvent_register (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);

  /* First emit */
  SocketEvent_emit_poll_wakeup (10, 100);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 10);
  ASSERT_EQ (ctx.timeout_ms, 100);

  /* Second emit with different values */
  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (20, 200);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 20);
  ASSERT_EQ (ctx.timeout_ms, 200);

  /* Third emit */
  ctx.called = 0;
  SocketEvent_emit_poll_wakeup (30, 300);
  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.nfds, 30);
  ASSERT_EQ (ctx.timeout_ms, 300);

  result = SocketEvent_unregister (poll_wakeup_callback, &ctx);
  ASSERT_EQ (result, 0);
}

||||||| parent of 9d1edeed (test(core): Add comprehensive tests for SocketEvent_emit_accept)
/* ============================================================================
 * SocketEvent_emit_accept Tests
 * ============================================================================
 */

/* Test context for verifying emit_accept event data */
typedef struct
{
  int called;
  SocketEventType type;
  const char *component;
  int fd;
  const char *peer_addr;
  int peer_port;
  const char *local_addr;
  int local_port;
} AcceptEventContext;

static void
accept_event_handler (void *userdata, const SocketEventRecord *event)
{
  AcceptEventContext *ctx = (AcceptEventContext *)userdata;
  ctx->called++;
  ctx->type = event->type;
  ctx->component = event->component;
  ctx->fd = event->data.connection.fd;
  ctx->peer_addr = event->data.connection.peer_addr;
  ctx->peer_port = event->data.connection.peer_port;
  ctx->local_addr = event->data.connection.local_addr;
  ctx->local_port = event->data.connection.local_port;
}

/* Test emit_accept with no handlers registered (should not crash) */
TEST (socketevent_emit_accept_no_handlers)
{
  /* This should not crash even without registered handlers */
  SocketEvent_emit_accept (42, "192.168.1.100", 54321, "192.168.1.1", 80);
}

/* Test emit_accept dispatches to single registered handler */
TEST (socketevent_emit_accept_single_handler)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (42, "192.168.1.100", 54321, "192.168.1.1", 80);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.type, SOCKET_EVENT_ACCEPTED);
  ASSERT_EQ (ctx.fd, 42);
  ASSERT_EQ (strcmp (ctx.peer_addr, "192.168.1.100"), 0);
  ASSERT_EQ (ctx.peer_port, 54321);
  ASSERT_EQ (strcmp (ctx.local_addr, "192.168.1.1"), 0);
  ASSERT_EQ (ctx.local_port, 80);
  ASSERT_EQ (strcmp (ctx.component, "Socket"), 0);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept dispatches to multiple registered handlers */
TEST (socketevent_emit_accept_multiple_handlers)
{
  AcceptEventContext ctx1 = { 0 };
  AcceptEventContext ctx2 = { 0 };
  AcceptEventContext ctx3 = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx1);
  ASSERT_EQ (result, 0);
  result = SocketEvent_register (accept_event_handler, &ctx2);
  ASSERT_EQ (result, 0);
  result = SocketEvent_register (accept_event_handler, &ctx3);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (99, "10.0.0.5", 12345, "10.0.0.1", 443);

  /* All handlers should be called */
  ASSERT_EQ (ctx1.called, 1);
  ASSERT_EQ (ctx2.called, 1);
  ASSERT_EQ (ctx3.called, 1);

  /* Verify all received same event data */
  ASSERT_EQ (ctx1.fd, 99);
  ASSERT_EQ (ctx2.fd, 99);
  ASSERT_EQ (ctx3.fd, 99);
  ASSERT_EQ (ctx1.peer_port, 12345);
  ASSERT_EQ (ctx2.peer_port, 12345);
  ASSERT_EQ (ctx3.peer_port, 12345);

  result = SocketEvent_unregister (accept_event_handler, &ctx1);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (accept_event_handler, &ctx2);
  ASSERT_EQ (result, 0);
  result = SocketEvent_unregister (accept_event_handler, &ctx3);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with NULL peer_addr */
TEST (socketevent_emit_accept_null_peer_addr)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (10, NULL, 8080, "127.0.0.1", 80);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 10);
  ASSERT_NULL (ctx.peer_addr);
  ASSERT_EQ (ctx.peer_port, 8080);
  ASSERT_EQ (strcmp (ctx.local_addr, "127.0.0.1"), 0);
  ASSERT_EQ (ctx.local_port, 80);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with NULL local_addr */
TEST (socketevent_emit_accept_null_local_addr)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (20, "203.0.113.5", 9090, NULL, 22);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 20);
  ASSERT_EQ (strcmp (ctx.peer_addr, "203.0.113.5"), 0);
  ASSERT_EQ (ctx.peer_port, 9090);
  ASSERT_NULL (ctx.local_addr);
  ASSERT_EQ (ctx.local_port, 22);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with both addresses NULL */
TEST (socketevent_emit_accept_both_addrs_null)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (30, NULL, 1234, NULL, 5678);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 30);
  ASSERT_NULL (ctx.peer_addr);
  ASSERT_EQ (ctx.peer_port, 1234);
  ASSERT_NULL (ctx.local_addr);
  ASSERT_EQ (ctx.local_port, 5678);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with negative fd */
TEST (socketevent_emit_accept_negative_fd)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (-1, "192.168.1.1", 80, "192.168.1.2", 443);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, -1);
  ASSERT_EQ (ctx.peer_port, 80);
  ASSERT_EQ (ctx.local_port, 443);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with zero port values */
TEST (socketevent_emit_accept_zero_ports)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (50, "0.0.0.0", 0, "0.0.0.0", 0);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 50);
  ASSERT_EQ (ctx.peer_port, 0);
  ASSERT_EQ (ctx.local_port, 0);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with maximum valid port values */
TEST (socketevent_emit_accept_max_ports)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (60, "192.168.1.1", 65535, "192.168.1.2", 65535);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 60);
  ASSERT_EQ (ctx.peer_port, 65535);
  ASSERT_EQ (ctx.local_port, 65535);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with IPv6 addresses */
TEST (socketevent_emit_accept_ipv6)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (70, "2001:db8::1", 8080, "2001:db8::2", 443);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 70);
  ASSERT_EQ (strcmp (ctx.peer_addr, "2001:db8::1"), 0);
  ASSERT_EQ (ctx.peer_port, 8080);
  ASSERT_EQ (strcmp (ctx.local_addr, "2001:db8::2"), 0);
  ASSERT_EQ (ctx.local_port, 443);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept called multiple times increments call count */
TEST (socketevent_emit_accept_multiple_calls)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (1, "192.168.1.1", 80, "192.168.1.2", 80);
  SocketEvent_emit_accept (2, "192.168.1.3", 81, "192.168.1.4", 81);
  SocketEvent_emit_accept (3, "192.168.1.5", 82, "192.168.1.6", 82);

  ASSERT_EQ (ctx.called, 3);
  /* Context should have last emit's data */
  ASSERT_EQ (ctx.fd, 3);
  ASSERT_EQ (ctx.peer_port, 82);
  ASSERT_EQ (ctx.local_port, 82);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept event type is always SOCKET_EVENT_ACCEPTED */
TEST (socketevent_emit_accept_correct_event_type)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (100, "192.168.1.1", 80, "192.168.1.2", 443);

  ASSERT_EQ (ctx.type, SOCKET_EVENT_ACCEPTED);
  ASSERT_NE (ctx.type, SOCKET_EVENT_CONNECTED);
  ASSERT_NE (ctx.type, SOCKET_EVENT_DNS_TIMEOUT);
  ASSERT_NE (ctx.type, SOCKET_EVENT_POLL_WAKEUP);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept component is always "Socket" */
TEST (socketevent_emit_accept_correct_component)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (110, "192.168.1.1", 80, "192.168.1.2", 443);

  ASSERT_EQ (strcmp (ctx.component, "Socket"), 0);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

/* Test emit_accept with empty string addresses */
TEST (socketevent_emit_accept_empty_addrs)
{
  AcceptEventContext ctx = { 0 };
  int result;

  result = SocketEvent_register (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);

  SocketEvent_emit_accept (120, "", 80, "", 443);

  ASSERT_EQ (ctx.called, 1);
  ASSERT_EQ (ctx.fd, 120);
  ASSERT_EQ (strcmp (ctx.peer_addr, ""), 0);
  ASSERT_EQ (strcmp (ctx.local_addr, ""), 0);

  result = SocketEvent_unregister (accept_event_handler, &ctx);
  ASSERT_EQ (result, 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
