/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_flow.c
 * @brief Unit tests for QUIC Flow Control (RFC 9000 Section 4).
 */

#include "quic/SocketQUICFlow.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Connection-Level Flow Control Tests
 * ============================================================================
 */

TEST (flow_new)
{
  Arena_T arena;
  SocketQUICFlow_T fc;

  arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  fc = SocketQUICFlow_new (arena);
  ASSERT_NOT_NULL (fc);

  /* Check defaults */
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW, fc->recv_max_data);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW, fc->send_max_data);
  ASSERT_EQ (0, fc->recv_consumed);
  ASSERT_EQ (0, fc->send_consumed);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_MAX_STREAMS_BIDI, fc->max_streams_bidi);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_MAX_STREAMS_UNI, fc->max_streams_uni);
  ASSERT_EQ (0, fc->streams_bidi_count);
  ASSERT_EQ (0, fc->streams_uni_count);

  Arena_dispose (&arena);
}

TEST (flow_init_custom)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = Arena_alloc (arena, sizeof (*fc), __FILE__, __LINE__);

  res = SocketQUICFlow_init (fc, 2048, 4096, 50, 100);
  ASSERT_EQ (QUIC_FLOW_OK, res);

  ASSERT_EQ (2048, fc->recv_max_data);
  ASSERT_EQ (4096, fc->send_max_data);
  ASSERT_EQ (50, fc->max_streams_bidi);
  ASSERT_EQ (100, fc->max_streams_uni);

  Arena_dispose (&arena);
}

TEST (flow_init_null)
{
  SocketQUICFlow_Result res;

  res = SocketQUICFlow_init (NULL, 1024, 1024, 10, 10);
  ASSERT_EQ (QUIC_FLOW_ERROR_NULL, res);
}

TEST (flow_init_overflow)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = Arena_alloc (arena, sizeof (*fc), __FILE__, __LINE__);

  /* Try to set window larger than max */
  res = SocketQUICFlow_init (fc, QUIC_FLOW_MAX_WINDOW + 1, 1024, 10, 10);
  ASSERT_EQ (QUIC_FLOW_ERROR_OVERFLOW, res);

  Arena_dispose (&arena);
}

TEST (flow_can_send_basic)
{
  Arena_T arena;
  SocketQUICFlow_T fc;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Initially should be able to send up to send_max_data */
  ASSERT (SocketQUICFlow_can_send (fc, 1024));
  ASSERT (SocketQUICFlow_can_send (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW));
  ASSERT (!SocketQUICFlow_can_send (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW + 1));

  Arena_dispose (&arena);
}

TEST (flow_consume_send_basic)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Consume some bytes */
  res = SocketQUICFlow_consume_send (fc, 1024);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (1024, fc->send_consumed);

  /* Consume more */
  res = SocketQUICFlow_consume_send (fc, 2048);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (3072, fc->send_consumed);

  Arena_dispose (&arena);
}

TEST (flow_consume_send_blocked)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Try to consume more than available */
  res = SocketQUICFlow_consume_send (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW + 1);
  ASSERT_EQ (QUIC_FLOW_ERROR_BLOCKED, res);

  /* Consumed should not change on error */
  ASSERT_EQ (0, fc->send_consumed);

  Arena_dispose (&arena);
}

TEST (flow_consume_recv_basic)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_consume_recv (fc, 512);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (512, fc->recv_consumed);

  Arena_dispose (&arena);
}

TEST (flow_consume_recv_blocked)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_consume_recv (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW + 1);
  ASSERT_EQ (QUIC_FLOW_ERROR_BLOCKED, res);

  Arena_dispose (&arena);
}

TEST (flow_update_send_max)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Increase send window */
  res = SocketQUICFlow_update_send_max (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW * 2);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW * 2, fc->send_max_data);

  Arena_dispose (&arena);
}

TEST (flow_update_send_max_decrease)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Try to decrease send window (not allowed per RFC 9000) */
  res = SocketQUICFlow_update_send_max (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW / 2);
  ASSERT_EQ (QUIC_FLOW_ERROR_INVALID, res);

  Arena_dispose (&arena);
}

TEST (flow_update_recv_max)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_update_recv_max (fc, QUIC_FLOW_DEFAULT_CONN_WINDOW * 2);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW * 2, fc->recv_max_data);

  Arena_dispose (&arena);
}

TEST (flow_send_window)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  uint64_t window;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Initial window */
  window = SocketQUICFlow_send_window (fc);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW, window);

  /* Consume some bytes */
  SocketQUICFlow_consume_send (fc, 1024);
  window = SocketQUICFlow_send_window (fc);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW - 1024, window);

  Arena_dispose (&arena);
}

TEST (flow_recv_window)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  uint64_t window;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  window = SocketQUICFlow_recv_window (fc);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW, window);

  SocketQUICFlow_consume_recv (fc, 512);
  window = SocketQUICFlow_recv_window (fc);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW - 512, window);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Stream-Level Flow Control Tests
 * ============================================================================
 */

TEST (flow_stream_new)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 4);

  ASSERT_NOT_NULL (fs);
  ASSERT_EQ (4, fs->stream_id);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW, fs->recv_max_data);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW, fs->send_max_data);
  ASSERT_EQ (0, fs->recv_consumed);
  ASSERT_EQ (0, fs->send_consumed);

  Arena_dispose (&arena);
}

TEST (flow_stream_init_custom)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = Arena_alloc (arena, sizeof (*fs), __FILE__, __LINE__);

  res = SocketQUICFlowStream_init (fs, 8, 512, 1024);
  ASSERT_EQ (QUIC_FLOW_OK, res);

  ASSERT_EQ (8, fs->stream_id);
  ASSERT_EQ (512, fs->recv_max_data);
  ASSERT_EQ (1024, fs->send_max_data);

  Arena_dispose (&arena);
}

TEST (flow_stream_can_send)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 0);

  ASSERT (SocketQUICFlowStream_can_send (fs, 1024));
  ASSERT (SocketQUICFlowStream_can_send (fs, QUIC_FLOW_DEFAULT_STREAM_WINDOW));
  ASSERT (!SocketQUICFlowStream_can_send (fs,
                                          QUIC_FLOW_DEFAULT_STREAM_WINDOW + 1));

  Arena_dispose (&arena);
}

TEST (flow_stream_consume_send)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 4);

  res = SocketQUICFlowStream_consume_send (fs, 256);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (256, fs->send_consumed);

  res = SocketQUICFlowStream_consume_send (fs, 128);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (384, fs->send_consumed);

  Arena_dispose (&arena);
}

TEST (flow_stream_consume_send_blocked)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 0);

  res = SocketQUICFlowStream_consume_send (fs,
                                           QUIC_FLOW_DEFAULT_STREAM_WINDOW + 1);
  ASSERT_EQ (QUIC_FLOW_ERROR_BLOCKED, res);

  Arena_dispose (&arena);
}

TEST (flow_stream_consume_recv)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 8);

  res = SocketQUICFlowStream_consume_recv (fs, 100);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (100, fs->recv_consumed);

  Arena_dispose (&arena);
}

TEST (flow_stream_update_send_max)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 4);

  res = SocketQUICFlowStream_update_send_max (fs,
                                              QUIC_FLOW_DEFAULT_STREAM_WINDOW
                                                  * 2);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW * 2, fs->send_max_data);

  Arena_dispose (&arena);
}

TEST (flow_stream_update_send_max_decrease)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 4);

  /* Try to decrease (not allowed) */
  res = SocketQUICFlowStream_update_send_max (fs,
                                              QUIC_FLOW_DEFAULT_STREAM_WINDOW
                                                  / 2);
  ASSERT_EQ (QUIC_FLOW_ERROR_INVALID, res);

  Arena_dispose (&arena);
}

TEST (flow_stream_send_window)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  uint64_t window;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 0);

  window = SocketQUICFlowStream_send_window (fs);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW, window);

  SocketQUICFlowStream_consume_send (fs, 100);
  window = SocketQUICFlowStream_send_window (fs);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW - 100, window);

  Arena_dispose (&arena);
}

TEST (flow_stream_recv_window)
{
  Arena_T arena;
  SocketQUICFlowStream_T fs;
  uint64_t window;

  arena = Arena_new ();
  fs = SocketQUICFlowStream_new (arena, 4);

  window = SocketQUICFlowStream_recv_window (fs);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW, window);

  SocketQUICFlowStream_consume_recv (fs, 200);
  window = SocketQUICFlowStream_recv_window (fs);
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW - 200, window);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Stream Count Management Tests
 * ============================================================================
 */

TEST (flow_update_max_streams_bidi)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_update_max_streams_bidi (fc, 200);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (200, fc->max_streams_bidi);

  Arena_dispose (&arena);
}

TEST (flow_update_max_streams_uni)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_update_max_streams_uni (fc, 150);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (150, fc->max_streams_uni);

  Arena_dispose (&arena);
}

TEST (flow_can_open_stream_bidi)
{
  Arena_T arena;
  SocketQUICFlow_T fc;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Initially should be able to open streams */
  ASSERT (SocketQUICFlow_can_open_stream_bidi (fc));

  Arena_dispose (&arena);
}

TEST (flow_open_stream_bidi)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_open_stream_bidi (fc);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (1, fc->streams_bidi_count);

  res = SocketQUICFlow_open_stream_bidi (fc);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (2, fc->streams_bidi_count);

  Arena_dispose (&arena);
}

TEST (flow_open_stream_bidi_blocked)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;
  int i;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Open up to the limit */
  for (i = 0; i < QUIC_FLOW_DEFAULT_MAX_STREAMS_BIDI; i++)
    {
      res = SocketQUICFlow_open_stream_bidi (fc);
      ASSERT_EQ (QUIC_FLOW_OK, res);
    }

  /* Try to open one more (should be blocked) */
  res = SocketQUICFlow_open_stream_bidi (fc);
  ASSERT_EQ (QUIC_FLOW_ERROR_BLOCKED, res);

  Arena_dispose (&arena);
}

TEST (flow_open_stream_uni)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  res = SocketQUICFlow_open_stream_uni (fc);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (1, fc->streams_uni_count);

  Arena_dispose (&arena);
}

TEST (flow_close_stream_bidi)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Open a stream */
  SocketQUICFlow_open_stream_bidi (fc);
  ASSERT_EQ (1, fc->streams_bidi_count);

  /* Close it */
  res = SocketQUICFlow_close_stream_bidi (fc);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (0, fc->streams_bidi_count);

  Arena_dispose (&arena);
}

TEST (flow_close_stream_bidi_underflow)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  /* Try to close when count is already 0 */
  res = SocketQUICFlow_close_stream_bidi (fc);
  ASSERT_EQ (QUIC_FLOW_ERROR_INVALID, res);

  Arena_dispose (&arena);
}

TEST (flow_close_stream_uni)
{
  Arena_T arena;
  SocketQUICFlow_T fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  fc = SocketQUICFlow_new (arena);

  SocketQUICFlow_open_stream_uni (fc);
  res = SocketQUICFlow_close_stream_uni (fc);
  ASSERT_EQ (QUIC_FLOW_OK, res);
  ASSERT_EQ (0, fc->streams_uni_count);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

TEST (flow_connection_and_stream)
{
  Arena_T arena;
  SocketQUICFlow_T conn_fc;
  SocketQUICFlowStream_T stream_fc;
  SocketQUICFlow_Result res;

  arena = Arena_new ();
  conn_fc = SocketQUICFlow_new (arena);
  stream_fc = SocketQUICFlowStream_new (arena, 4);

  /* Check both connection and stream limits for send */
  size_t bytes_to_send = 1024;

  /* Both should allow */
  ASSERT (SocketQUICFlow_can_send (conn_fc, bytes_to_send));
  ASSERT (SocketQUICFlowStream_can_send (stream_fc, bytes_to_send));

  /* Consume on both */
  res = SocketQUICFlow_consume_send (conn_fc, bytes_to_send);
  ASSERT_EQ (QUIC_FLOW_OK, res);

  res = SocketQUICFlowStream_consume_send (stream_fc, bytes_to_send);
  ASSERT_EQ (QUIC_FLOW_OK, res);

  /* Check windows reduced correctly */
  ASSERT_EQ (QUIC_FLOW_DEFAULT_CONN_WINDOW - bytes_to_send,
             SocketQUICFlow_send_window (conn_fc));
  ASSERT_EQ (QUIC_FLOW_DEFAULT_STREAM_WINDOW - bytes_to_send,
             SocketQUICFlowStream_send_window (stream_fc));

  Arena_dispose (&arena);
}

TEST (flow_result_string)
{
  const char *str;

  str = SocketQUICFlow_result_string (QUIC_FLOW_OK);
  ASSERT_NOT_NULL (str);
  ASSERT (strcmp (str, "QUIC_FLOW_OK") == 0);

  str = SocketQUICFlow_result_string (QUIC_FLOW_ERROR_BLOCKED);
  ASSERT_NOT_NULL (str);
  ASSERT (strcmp (str, "QUIC_FLOW_ERROR_BLOCKED") == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
