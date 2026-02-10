/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_stream.c
 * @brief Unit tests for HTTP/3 stream mapping (RFC 9114 Section 6).
 */

#include "core/Arena.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3-stream.h"
#include "test/Test.h"

/* ============================================================================
 * Stream ID Reference (RFC 9000 §2.1)
 *
 *   0, 4, 8  — Client-initiated bidi  (id & 0x03 == 0x00)
 *   1, 5, 9  — Server-initiated bidi  (id & 0x03 == 0x01)
 *   2, 6, 10 — Client-initiated unidi (id & 0x03 == 0x02)
 *   3, 7, 11 — Server-initiated unidi (id & 0x03 == 0x03)
 * ============================================================================
 */

/* ============================================================================
 * Registration Tests
 * ============================================================================
 */

TEST (h3_stream_register_control)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);
  ASSERT_NOT_NULL (map);

  /* Register stream 2 (client-initiated unidi) as control */
  uint64_t err
      = SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_CONTROL);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_CONTROL, SocketHTTP3_StreamMap_role (map, 2));
  ASSERT_EQ (2LL, SocketHTTP3_StreamMap_get_control (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_qpack_encoder)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  uint64_t err
      = SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_ENCODER);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_QPACK_ENCODER, SocketHTTP3_StreamMap_role (map, 6));
  ASSERT_EQ (6LL, SocketHTTP3_StreamMap_get_qpack_encoder (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_qpack_decoder)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  uint64_t err
      = SocketHTTP3_StreamMap_register (map, 10, H3_STREAM_TYPE_QPACK_DECODER);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_QPACK_DECODER,
             SocketHTTP3_StreamMap_role (map, 10));
  ASSERT_EQ (10LL, SocketHTTP3_StreamMap_get_qpack_decoder (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_push)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Stream 3 is server-initiated unidi */
  uint64_t err = SocketHTTP3_StreamMap_register (map, 3, H3_STREAM_TYPE_PUSH);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_PUSH, SocketHTTP3_StreamMap_role (map, 3));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_unknown_type)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Unknown type 0xFF on unidi stream 2: silently ignored */
  uint64_t err = SocketHTTP3_StreamMap_register (map, 2, 0xFF);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_UNKNOWN, SocketHTTP3_StreamMap_role (map, 2));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_grease)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* GREASE value 0x21 (0x1f*0 + 0x21) on unidi stream 6 */
  uint64_t err = SocketHTTP3_StreamMap_register (map, 6, 0x21);
  ASSERT_EQ (0ULL, err);
  ASSERT_EQ (H3_STREAM_ROLE_UNKNOWN, SocketHTTP3_StreamMap_role (map, 6));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Duplicate Critical Stream Tests
 * ============================================================================
 */

TEST (h3_stream_duplicate_control)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  ASSERT_EQ (0ULL,
             SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_CONTROL));
  /* Second control stream must fail */
  ASSERT_EQ (H3_STREAM_CREATION_ERROR,
             SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_CONTROL));

  Arena_dispose (&arena);
}

TEST (h3_stream_duplicate_qpack_encoder)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  ASSERT_EQ (
      0ULL,
      SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_QPACK_ENCODER));
  ASSERT_EQ (
      H3_STREAM_CREATION_ERROR,
      SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_ENCODER));

  Arena_dispose (&arena);
}

TEST (h3_stream_duplicate_qpack_decoder)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  ASSERT_EQ (
      0ULL,
      SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_QPACK_DECODER));
  ASSERT_EQ (
      H3_STREAM_CREATION_ERROR,
      SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_DECODER));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Error Condition Tests
 * ============================================================================
 */

TEST (h3_stream_register_bidi_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Stream 0 is client-initiated bidi — cannot register a stream type */
  ASSERT_EQ (H3_STREAM_CREATION_ERROR,
             SocketHTTP3_StreamMap_register (map, 0, H3_STREAM_TYPE_CONTROL));

  Arena_dispose (&arena);
}

TEST (h3_stream_register_null_map)
{
  ASSERT_EQ (H3_STREAM_CREATION_ERROR,
             SocketHTTP3_StreamMap_register (NULL, 2, H3_STREAM_TYPE_CONTROL));
}

TEST (h3_stream_push_from_client_rejected)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Stream 2 is client-initiated unidi — push must be server-initiated */
  ASSERT_EQ (H3_STREAM_CREATION_ERROR,
             SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_PUSH));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Role Classification Tests
 * ============================================================================
 */

TEST (h3_stream_role_bidi_is_request)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Client-initiated bidi: 0, 4, 8 */
  ASSERT_EQ (H3_STREAM_ROLE_REQUEST, SocketHTTP3_StreamMap_role (map, 0));
  ASSERT_EQ (H3_STREAM_ROLE_REQUEST, SocketHTTP3_StreamMap_role (map, 4));
  ASSERT_EQ (H3_STREAM_ROLE_REQUEST, SocketHTTP3_StreamMap_role (map, 8));

  Arena_dispose (&arena);
}

TEST (h3_stream_role_server_bidi_is_request)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Server-initiated bidi: 1, 5 */
  ASSERT_EQ (H3_STREAM_ROLE_REQUEST, SocketHTTP3_StreamMap_role (map, 1));
  ASSERT_EQ (H3_STREAM_ROLE_REQUEST, SocketHTTP3_StreamMap_role (map, 5));

  Arena_dispose (&arena);
}

TEST (h3_stream_role_unregistered_unidi)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Unidi stream 2 not registered */
  ASSERT_EQ (H3_STREAM_ROLE_UNKNOWN, SocketHTTP3_StreamMap_role (map, 2));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Critical Streams Ready Tests
 * ============================================================================
 */

TEST (h3_stream_critical_not_ready_initially)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  ASSERT_EQ (0, SocketHTTP3_StreamMap_critical_streams_ready (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_critical_ready_after_all_three)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_CONTROL);
  SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_ENCODER);
  SocketHTTP3_StreamMap_register (map, 10, H3_STREAM_TYPE_QPACK_DECODER);

  ASSERT_EQ (1, SocketHTTP3_StreamMap_critical_streams_ready (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_critical_partial_not_ready)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_CONTROL);
  SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_ENCODER);
  /* Missing QPACK decoder */

  ASSERT_EQ (0, SocketHTTP3_StreamMap_critical_streams_ready (map));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Getter Tests
 * ============================================================================
 */

TEST (h3_stream_get_before_register)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  ASSERT_EQ (H3_STREAM_ID_NONE, SocketHTTP3_StreamMap_get_control (map));
  ASSERT_EQ (H3_STREAM_ID_NONE, SocketHTTP3_StreamMap_get_qpack_encoder (map));
  ASSERT_EQ (H3_STREAM_ID_NONE, SocketHTTP3_StreamMap_get_qpack_decoder (map));

  Arena_dispose (&arena);
}

TEST (h3_stream_get_after_register)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  SocketHTTP3_StreamMap_register (map, 2, H3_STREAM_TYPE_CONTROL);
  SocketHTTP3_StreamMap_register (map, 6, H3_STREAM_TYPE_QPACK_ENCODER);
  SocketHTTP3_StreamMap_register (map, 10, H3_STREAM_TYPE_QPACK_DECODER);

  ASSERT_EQ (2LL, SocketHTTP3_StreamMap_get_control (map));
  ASSERT_EQ (6LL, SocketHTTP3_StreamMap_get_qpack_encoder (map));
  ASSERT_EQ (10LL, SocketHTTP3_StreamMap_get_qpack_decoder (map));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Local Stream Tests
 * ============================================================================
 */

TEST (h3_stream_set_local_control)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Stream 2 is our local control stream */
  SocketHTTP3_StreamMap_set_local_control (map, 2);
  ASSERT_EQ (H3_STREAM_ROLE_CONTROL, SocketHTTP3_StreamMap_role (map, 2));

  Arena_dispose (&arena);
}

TEST (h3_stream_local_and_peer_distinct)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Peer control on stream 3 (server-initiated unidi) */
  SocketHTTP3_StreamMap_register (map, 3, H3_STREAM_TYPE_CONTROL);
  /* Local control on stream 2 (client-initiated unidi) */
  SocketHTTP3_StreamMap_set_local_control (map, 2);

  ASSERT_EQ (H3_STREAM_ROLE_CONTROL, SocketHTTP3_StreamMap_role (map, 3));
  ASSERT_EQ (H3_STREAM_ROLE_CONTROL, SocketHTTP3_StreamMap_role (map, 2));
  /* get_control returns peer, not local */
  ASSERT_EQ (3LL, SocketHTTP3_StreamMap_get_control (map));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Push Stream Tests
 * ============================================================================
 */

TEST (h3_stream_multiple_push_streams)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_StreamMap_T map = SocketHTTP3_StreamMap_new (arena);

  /* Server-initiated unidi streams: 3, 7, 11 */
  ASSERT_EQ (0ULL,
             SocketHTTP3_StreamMap_register (map, 3, H3_STREAM_TYPE_PUSH));
  ASSERT_EQ (0ULL,
             SocketHTTP3_StreamMap_register (map, 7, H3_STREAM_TYPE_PUSH));
  ASSERT_EQ (0ULL,
             SocketHTTP3_StreamMap_register (map, 11, H3_STREAM_TYPE_PUSH));

  ASSERT_EQ (H3_STREAM_ROLE_PUSH, SocketHTTP3_StreamMap_role (map, 3));
  ASSERT_EQ (H3_STREAM_ROLE_PUSH, SocketHTTP3_StreamMap_role (map, 7));
  ASSERT_EQ (H3_STREAM_ROLE_PUSH, SocketHTTP3_StreamMap_role (map, 11));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Role Name Test
 * ============================================================================
 */

TEST (h3_stream_role_name)
{
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_REQUEST) != NULL);
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_CONTROL) != NULL);
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_PUSH) != NULL);
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_QPACK_ENCODER) != NULL);
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_QPACK_DECODER) != NULL);
  ASSERT (SocketHTTP3_StreamRole_name (H3_STREAM_ROLE_UNKNOWN) != NULL);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
