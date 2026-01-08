/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_blocked.c
 * @brief Unit tests for QPACK Blocked Stream Management (RFC 9204 Sections
 * 2.1.2, 2.2.1)
 *
 * Tests the blocked stream manager functionality including:
 * - Stream queueing and limit enforcement
 * - Automatic unblocking when insert count advances
 * - Stream cancellation
 * - Statistics and metrics
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * HELPER STRUCTURES
 * ============================================================================
 */

/**
 * @brief Context for unblock callback testing.
 */
typedef struct
{
  uint64_t *stream_ids;
  size_t *data_lens;
  uint64_t *rics;
  size_t count;
  size_t capacity;
  int should_fail;
} UnblockContext;

/**
 * @brief Test unblock callback that records calls.
 */
static int
test_unblock_callback (uint64_t stream_id,
                       const unsigned char *data,
                       size_t data_len,
                       uint64_t ric,
                       void *user_data)
{
  UnblockContext *ctx = (UnblockContext *)user_data;

  if (ctx->should_fail)
    return -1;

  if (ctx->count < ctx->capacity)
    {
      ctx->stream_ids[ctx->count] = stream_id;
      ctx->data_lens[ctx->count] = data_len;
      ctx->rics[ctx->count] = ric;
      ctx->count++;
    }

  (void)data; /* May be used in future tests */

  return 0;
}

/* ============================================================================
 * MANAGER CREATION TESTS
 * ============================================================================
 */

TEST (qpack_blocked_manager_new_null_arena)
{
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (NULL, NULL);
  ASSERT (manager == NULL);
}

TEST (qpack_blocked_manager_new_default_config)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  ASSERT (manager != NULL);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 0);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager), 0);
  ASSERT_EQ (SocketQPACK_get_peak_blocked_count (manager), 0);
  ASSERT_EQ (SocketQPACK_get_total_unblock_count (manager), 0);

  Arena_dispose (&arena);
}

TEST (qpack_blocked_manager_new_custom_config)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedConfig config
      = { .max_blocked_streams = 50, .max_blocked_bytes = 1024 };

  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, &config);

  ASSERT (manager != NULL);

  Arena_dispose (&arena);
}

/* ============================================================================
 * WOULD_BLOCK TESTS
 * ============================================================================
 */

TEST (qpack_would_block_false_equal)
{
  /* RIC == Insert Count - should NOT block */
  ASSERT (!SocketQPACK_would_block (5, 5));
}

TEST (qpack_would_block_false_less)
{
  /* RIC < Insert Count - should NOT block */
  ASSERT (!SocketQPACK_would_block (3, 5));
}

TEST (qpack_would_block_true)
{
  /* RIC > Insert Count - SHOULD block */
  ASSERT (SocketQPACK_would_block (10, 5));
}

TEST (qpack_would_block_zero)
{
  /* RIC == 0 means no dynamic table references, never blocks */
  ASSERT (!SocketQPACK_would_block (0, 0));
  ASSERT (!SocketQPACK_would_block (0, 5));
}

/* ============================================================================
 * QUEUE BLOCKED TESTS
 * ============================================================================
 */

TEST (qpack_queue_blocked_null_manager)
{
  unsigned char data[] = { 0x01, 0x02, 0x03 };
  SocketQPACK_BlockedResult result
      = SocketQPACK_queue_blocked (NULL, 1, 5, data, sizeof (data));
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_NULL_PARAM);
}

TEST (qpack_queue_blocked_null_data_with_len)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  SocketQPACK_BlockedResult result
      = SocketQPACK_queue_blocked (manager, 1, 5, NULL, 10);
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_empty_data)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  /* Empty data is allowed (unusual but valid) */
  SocketQPACK_BlockedResult result
      = SocketQPACK_queue_blocked (manager, 1, 5, NULL, 0);
  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_single_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
  SocketQPACK_BlockedResult result
      = SocketQPACK_queue_blocked (manager, 1, 10, data, sizeof (data));

  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager), sizeof (data));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 1));
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 2));

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_multiple_streams)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data1[] = { 0x01, 0x02, 0x03 };
  unsigned char data2[] = { 0x04, 0x05, 0x06, 0x07 };
  unsigned char data3[] = { 0x08, 0x09 };

  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data1, sizeof (data1)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 15, data2, sizeof (data2)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 20, data3, sizeof (data3)),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 3);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager),
             sizeof (data1) + sizeof (data2) + sizeof (data3));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 1));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 2));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 3));

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_same_stream_multiple_sections)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data1[] = { 0x01, 0x02 };
  unsigned char data2[] = { 0x03, 0x04 };
  unsigned char data3[] = { 0x05, 0x06 };

  /* Queue multiple sections for the same stream */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data1, sizeof (data1)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 15, data2, sizeof (data2)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 12, data3, sizeof (data3)),
             QPACK_BLOCKED_OK);

  /* Still only one stream, but multiple sections */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager),
             sizeof (data1) + sizeof (data2) + sizeof (data3));

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_limit_streams)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedConfig config
      = { .max_blocked_streams = 2, .max_blocked_bytes = 1024 * 1024 };

  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, &config);

  unsigned char data[] = { 0x01 };

  /* Queue up to limit */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  /* Exceed limit */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 10, data, sizeof (data)),
             QPACK_BLOCKED_LIMIT_STREAMS);

  /* Adding to existing stream should still work */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 15, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_limit_bytes)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedConfig config
      = { .max_blocked_streams = 100, .max_blocked_bytes = 10 };

  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, &config);

  unsigned char data1[5] = { 0 };
  unsigned char data2[5] = { 0 };
  unsigned char data3[5] = { 0 };

  /* Queue up to limit */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data1, sizeof (data1)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 10, data2, sizeof (data2)),
             QPACK_BLOCKED_OK);

  /* Exceed limit */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 10, data3, sizeof (data3)),
             QPACK_BLOCKED_LIMIT_BYTES);

  Arena_dispose (&arena);
}

TEST (qpack_queue_blocked_limit_sections_per_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedConfig config
      = { .max_blocked_streams = 100, .max_blocked_bytes = 1024 * 1024 };

  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, &config);

  unsigned char data[] = { 0x01 };

  /* Queue up to the per-stream section limit (QPACK_MAX_SECTIONS_PER_STREAM=64)
   */
  for (size_t i = 0; i < QPACK_MAX_SECTIONS_PER_STREAM; i++)
    {
      ASSERT_EQ (
          SocketQPACK_queue_blocked (manager, 1, 10 + i, data, sizeof (data)),
          QPACK_BLOCKED_OK);
    }

  /* Verify we have exactly 64 sections queued */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);

  /* 65th section should fail with section limit error */
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 100, data, sizeof (data)),
             QPACK_BLOCKED_ERR_SECTION_LIMIT);

  /* Verify stream still has 64 sections and didn't grow */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager),
             QPACK_MAX_SECTIONS_PER_STREAM * sizeof (data));

  Arena_dispose (&arena);
}

/* ============================================================================
 * MINIMUM RIC TESTS
 * ============================================================================
 */

TEST (qpack_get_min_blocked_ric_empty)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 0);

  Arena_dispose (&arena);
}

TEST (qpack_get_min_blocked_ric_single)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 10);

  Arena_dispose (&arena);
}

TEST (qpack_get_min_blocked_ric_multiple)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 20, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 15, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 10);

  Arena_dispose (&arena);
}

/* ============================================================================
 * PROCESS UNBLOCKED TESTS
 * ============================================================================
 */

TEST (qpack_process_unblocked_null_manager)
{
  size_t count = 999;
  SocketQPACK_BlockedResult result = SocketQPACK_process_unblocked (
      NULL, 10, test_unblock_callback, NULL, &count);
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_NULL_PARAM);
}

TEST (qpack_process_unblocked_null_callback)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  size_t count = 999;
  SocketQPACK_BlockedResult result
      = SocketQPACK_process_unblocked (manager, 10, NULL, NULL, &count);
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_NULL_PARAM);

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_no_blocked_streams)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  size_t count = 999;
  SocketQPACK_BlockedResult result = SocketQPACK_process_unblocked (
      manager, 10, test_unblock_callback, &ctx, &count);

  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (count, 0);
  ASSERT_EQ (ctx.count, 0);

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_single_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01, 0x02, 0x03 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  /* Insert count 5 should unblock RIC 5 */
  size_t count = 0;
  SocketQPACK_BlockedResult result = SocketQPACK_process_unblocked (
      manager, 5, test_unblock_callback, &ctx, &count);

  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (count, 1);
  ASSERT_EQ (ctx.count, 1);
  ASSERT_EQ (ctx.stream_ids[0], 1);
  ASSERT_EQ (ctx.data_lens[0], sizeof (data));
  ASSERT_EQ (ctx.rics[0], 5);

  /* Stream should be removed */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 0);
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 1));

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_multiple_streams)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 8, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  /* Insert count 8 should unblock RIC 5 and 8 */
  size_t count = 0;
  SocketQPACK_BlockedResult result = SocketQPACK_process_unblocked (
      manager, 8, test_unblock_callback, &ctx, &count);

  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (count, 2);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 1));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 2));
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 3));

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_multiple_sections_same_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 8, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  /* Insert count 8 should unblock RIC 5 and 8, but not 10 */
  size_t count = 0;
  ASSERT_EQ (SocketQPACK_process_unblocked (
                 manager, 8, test_unblock_callback, &ctx, &count),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (count, 2);
  ASSERT_EQ (ctx.count, 2);
  /* Stream should still exist (has RIC 10 section) */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT (SocketQPACK_is_stream_blocked (manager, 1));
  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 10);

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_callback_failure)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx
      = { stream_ids, data_lens, rics, 0, 10, 1 }; /* should_fail = 1 */

  size_t count = 0;
  SocketQPACK_BlockedResult result = SocketQPACK_process_unblocked (
      manager, 10, test_unblock_callback, &ctx, &count);

  /* Should return error on callback failure */
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_INTERNAL);
  /* First section processed before failure */
  ASSERT_EQ (count, 1);

  Arena_dispose (&arena);
}

TEST (qpack_process_unblocked_statistics)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 5, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  /* Peak should be 3 */
  ASSERT_EQ (SocketQPACK_get_peak_blocked_count (manager), 3);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  ASSERT_EQ (SocketQPACK_process_unblocked (
                 manager, 10, test_unblock_callback, &ctx, NULL),
             QPACK_BLOCKED_OK);

  /* Peak should still be 3 (historical max) */
  ASSERT_EQ (SocketQPACK_get_peak_blocked_count (manager), 3);
  /* Total unblock count should be 3 */
  ASSERT_EQ (SocketQPACK_get_total_unblock_count (manager), 3);

  Arena_dispose (&arena);
}

/* ============================================================================
 * CANCEL BLOCKED STREAM TESTS
 * ============================================================================
 */

TEST (qpack_cancel_blocked_stream_null_manager)
{
  SocketQPACK_BlockedResult result
      = SocketQPACK_cancel_blocked_stream (NULL, 1);
  ASSERT_EQ (result, QPACK_BLOCKED_ERR_NULL_PARAM);
}

TEST (qpack_cancel_blocked_stream_not_found)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  /* Cancelling non-existent stream should succeed */
  SocketQPACK_BlockedResult result
      = SocketQPACK_cancel_blocked_stream (manager, 999);
  ASSERT_EQ (result, QPACK_BLOCKED_OK);

  Arena_dispose (&arena);
}

TEST (qpack_cancel_blocked_stream_single)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data[] = { 0x01, 0x02, 0x03 };
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data, sizeof (data)),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager), sizeof (data));

  SocketQPACK_BlockedResult result
      = SocketQPACK_cancel_blocked_stream (manager, 1);

  ASSERT_EQ (result, QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 0);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager), 0);
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 1));

  Arena_dispose (&arena);
}

TEST (qpack_cancel_blocked_stream_multiple)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  unsigned char data1[] = { 0x01, 0x02 };
  unsigned char data2[] = { 0x03, 0x04, 0x05 };
  unsigned char data3[] = { 0x06 };

  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 1, 10, data1, sizeof (data1)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 2, 15, data2, sizeof (data2)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (manager, 3, 20, data3, sizeof (data3)),
             QPACK_BLOCKED_OK);

  /* Cancel middle stream */
  ASSERT_EQ (SocketQPACK_cancel_blocked_stream (manager, 2), QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 2);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (manager),
             sizeof (data1) + sizeof (data3));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 1));
  ASSERT (!SocketQPACK_is_stream_blocked (manager, 2));
  ASSERT (SocketQPACK_is_stream_blocked (manager, 3));

  Arena_dispose (&arena);
}

/* ============================================================================
 * RESULT STRING TESTS
 * ============================================================================
 */

TEST (qpack_blocked_result_string_all_values)
{
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_OK) != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_WOULD_BLOCK)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_LIMIT_STREAMS)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_LIMIT_BYTES)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_ERR_NULL_PARAM)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_ERR_NOT_FOUND)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_ERR_INTERNAL)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_ERR_INVALID_RIC)
          != NULL);
  ASSERT (SocketQPACK_blocked_result_string (QPACK_BLOCKED_ERR_SECTION_LIMIT)
          != NULL);
  /* Unknown value */
  ASSERT (SocketQPACK_blocked_result_string ((SocketQPACK_BlockedResult)999)
          != NULL);
}

/* ============================================================================
 * NULL MANAGER TESTS FOR GETTERS
 * ============================================================================
 */

TEST (qpack_blocked_getters_null_manager)
{
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (NULL), 0);
  ASSERT_EQ (SocketQPACK_get_blocked_bytes (NULL), 0);
  ASSERT_EQ (SocketQPACK_get_peak_blocked_count (NULL), 0);
  ASSERT_EQ (SocketQPACK_get_total_unblock_count (NULL), 0);
  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (NULL), 0);
  ASSERT (!SocketQPACK_is_stream_blocked (NULL, 1));
}

/* ============================================================================
 * INTEGRATION TESTS
 * ============================================================================
 */

TEST (qpack_blocked_integration_typical_scenario)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_BlockedManager_T manager
      = SocketQPACK_BlockedManager_new (arena, NULL);

  /* Simulate HTTP/3 scenario:
   * - Stream 4 arrives with RIC=5
   * - Stream 8 arrives with RIC=3
   * - Stream 12 arrives with RIC=7
   */
  unsigned char stream4_data[] = { 0x01, 0x02 };
  unsigned char stream8_data[] = { 0x03, 0x04, 0x05 };
  unsigned char stream12_data[] = { 0x06 };

  ASSERT_EQ (SocketQPACK_queue_blocked (
                 manager, 4, 5, stream4_data, sizeof (stream4_data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (
                 manager, 8, 3, stream8_data, sizeof (stream8_data)),
             QPACK_BLOCKED_OK);
  ASSERT_EQ (SocketQPACK_queue_blocked (
                 manager, 12, 7, stream12_data, sizeof (stream12_data)),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 3);
  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 3);

  uint64_t stream_ids[10];
  size_t data_lens[10];
  uint64_t rics[10];
  UnblockContext ctx = { stream_ids, data_lens, rics, 0, 10, 0 };

  /* Insert count advances to 5 - should unblock streams with RIC <= 5 */
  size_t count = 0;
  ASSERT_EQ (SocketQPACK_process_unblocked (
                 manager, 5, test_unblock_callback, &ctx, &count),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (count, 2); /* Stream 4 (RIC=5) and Stream 8 (RIC=3) */
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 1);
  ASSERT (SocketQPACK_is_stream_blocked (manager, 12));
  ASSERT_EQ (SocketQPACK_get_min_blocked_ric (manager), 7);

  /* Insert count advances to 10 - should unblock remaining */
  ctx.count = 0;
  ASSERT_EQ (SocketQPACK_process_unblocked (
                 manager, 10, test_unblock_callback, &ctx, &count),
             QPACK_BLOCKED_OK);

  ASSERT_EQ (count, 1);
  ASSERT_EQ (SocketQPACK_get_blocked_stream_count (manager), 0);
  ASSERT_EQ (SocketQPACK_get_total_unblock_count (manager), 3);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
