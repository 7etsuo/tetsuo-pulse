/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_session.c
 * @brief Tests for QUIC Session Resumption and HelloRetryRequest (RFC 9001 §4.5, §4.7).
 *
 * Covers:
 * - Session ticket storage and validation
 * - 0-RTT capability detection
 * - Ticket expiration handling
 * - Transport parameter validation for 0-RTT
 * - HelloRetryRequest state tracking
 * - ALPN validation for resumption
 */

#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICSession.h"
#include "test/Test.h"

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================
 */

TEST (session_new_creates_session)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketQUICSession_T session = SocketQUICSession_new (arena);
  ASSERT_NOT_NULL (session);

  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_NONE);

  SocketQUICSession_free (&session);
  ASSERT_NULL (session);

  Arena_dispose (&arena);
}

TEST (session_new_null_arena_returns_null)
{
  SocketQUICSession_T session = SocketQUICSession_new (NULL);
  ASSERT_NULL (session);
}

TEST (session_free_null_is_safe)
{
  SocketQUICSession_free (NULL);
  /* Should not crash */

  SocketQUICSession_T session = NULL;
  SocketQUICSession_free (&session);
  /* Should not crash */
}

/* ============================================================================
 * Session Ticket Tests (RFC 9001 §4.5)
 * ============================================================================
 */

TEST (session_store_ticket_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);
  ASSERT_NOT_NULL (session);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket_data, sizeof (ticket_data), 86400, /* 24 hours */
      0x12345678,                                        /* age_add */
      QUIC_SESSION_0RTT_SENTINEL                         /* enable 0-RTT */
  );

  ASSERT_EQ (result, QUIC_SESSION_OK);
  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_STORED);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_null_session)
{
  uint8_t ticket_data[64];
  memset (ticket_data, 0, sizeof (ticket_data));
  SocketQUICSession_Result result
      = SocketQUICSession_store_ticket (NULL, ticket_data, 64, 86400, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);
}

TEST (session_store_ticket_null_data)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_Result result
      = SocketQUICSession_store_ticket (session, NULL, 64, 86400, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TICKET);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_zero_length)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  SocketQUICSession_Result result
      = SocketQUICSession_store_ticket (session, ticket_data, 0, 86400, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TICKET);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_too_large)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* Ticket larger than max size should fail */
  uint8_t ticket_data[1];
  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket_data, QUIC_SESSION_MAX_TICKET_SIZE + 1, 86400, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TICKET);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_zero_lifetime)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket_data, sizeof (ticket_data), 0, /* zero lifetime */
      0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TICKET);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_exceeds_max_age)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  /* Lifetime exceeding 7 days should fail per RFC 8446 */
  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket_data, sizeof (ticket_data),
      QUIC_SESSION_MAX_AGE_SECONDS + 1, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TICKET);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_exact_max_size)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* Exactly max size should succeed */
  uint8_t ticket_data[QUIC_SESSION_MAX_TICKET_SIZE];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket_data, QUIC_SESSION_MAX_TICKET_SIZE, 86400, 0, 0);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_store_ticket_replaces_previous)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* Store first ticket */
  uint8_t ticket1[64];
  memset (ticket1, 0xAA, sizeof (ticket1));
  SocketQUICSession_store_ticket (session, ticket1, sizeof (ticket1), 86400,
                                  0x11111111, 0);

  /* Store second ticket - should replace first */
  uint8_t ticket2[32];
  memset (ticket2, 0xBB, sizeof (ticket2));
  SocketQUICSession_Result result = SocketQUICSession_store_ticket (
      session, ticket2, sizeof (ticket2), 3600, 0x22222222,
      QUIC_SESSION_0RTT_SENTINEL);

  ASSERT_EQ (result, QUIC_SESSION_OK);

  /* Verify new ticket properties */
  uint32_t age = SocketQUICSession_get_obfuscated_age (session);
  /* age_add should be from second ticket */
  ASSERT (age >= 0x22222222 && age < 0x22222222 + 1000);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * 0-RTT Capability Tests (RFC 9001 §4.6.1)
 * ============================================================================
 */

TEST (session_can_attempt_0rtt_with_sentinel)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  /* Store ticket with 0-RTT sentinel */
  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, 0x12345678,
                                  QUIC_SESSION_0RTT_SENTINEL);

  /* Need to save transport params for 0-RTT to work */
  SocketQUICTransportParams_T params;
  memset (&params, 0, sizeof (params));
  params.initial_max_data = 65536;
  params.initial_max_streams_bidi = 100;
  SocketQUICSession_save_transport_params (session, &params);

  ASSERT_NE (SocketQUICSession_can_attempt_0rtt (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_cannot_attempt_0rtt_without_sentinel)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  /* Store ticket without 0-RTT sentinel */
  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, 0x12345678,
                                  0 /* NOT the sentinel */
  );

  ASSERT_EQ (SocketQUICSession_can_attempt_0rtt (session), 0);

  /* Can still resume though */
  ASSERT_NE (SocketQUICSession_can_resume (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_cannot_attempt_0rtt_without_params)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  /* Store ticket with 0-RTT sentinel but no transport params */
  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, 0x12345678, QUIC_SESSION_0RTT_SENTINEL);

  /* Should fail because no transport params saved */
  ASSERT_EQ (SocketQUICSession_can_attempt_0rtt (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_can_resume_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, 0x12345678, 0);

  ASSERT_NE (SocketQUICSession_can_resume (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_cannot_resume_null)
{
  ASSERT_EQ (SocketQUICSession_can_resume (NULL), 0);
}

TEST (session_cannot_resume_no_ticket)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* No ticket stored */
  ASSERT_EQ (SocketQUICSession_can_resume (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Obfuscated Age Tests (RFC 8446 §4.2.11.1)
 * ============================================================================
 */

TEST (session_get_obfuscated_age_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  uint32_t age_add = 0x12345678;

  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, age_add, 0);

  /* Age should include age_add obfuscation */
  uint32_t obfuscated = SocketQUICSession_get_obfuscated_age (session);
  /* For a just-issued ticket, age ~= age_add (within a second) */
  ASSERT (obfuscated >= age_add && obfuscated < age_add + 1000);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_get_obfuscated_age_null)
{
  ASSERT_EQ (SocketQUICSession_get_obfuscated_age (NULL), 0);
}

TEST (session_get_obfuscated_age_no_ticket)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  ASSERT_EQ (SocketQUICSession_get_obfuscated_age (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Transport Parameter Tests (RFC 9001 §4.6.3)
 * ============================================================================
 */

TEST (session_save_transport_params_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T params;
  memset (&params, 0, sizeof (params));
  params.initial_max_data = 65536;
  params.initial_max_stream_data_bidi_local = 32768;
  params.initial_max_streams_bidi = 100;

  SocketQUICSession_Result result
      = SocketQUICSession_save_transport_params (session, &params);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_save_transport_params_null)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_Result result
      = SocketQUICSession_save_transport_params (session, NULL);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);

  result = SocketQUICSession_save_transport_params (NULL, NULL);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_transport_params_ok)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T saved_params;
  memset (&saved_params, 0, sizeof (saved_params));
  saved_params.initial_max_data = 65536;
  saved_params.initial_max_streams_bidi = 100;

  SocketQUICSession_save_transport_params (session, &saved_params);

  /* New params that are MORE permissive should pass */
  SocketQUICTransportParams_T new_params;
  memset (&new_params, 0, sizeof (new_params));
  new_params.initial_max_data = 131072; /* greater than saved */
  new_params.initial_max_streams_bidi = 200;

  SocketQUICSession_Result result
      = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_transport_params_equal)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T params;
  memset (&params, 0, sizeof (params));
  params.initial_max_data = 65536;
  params.initial_max_streams_bidi = 100;

  SocketQUICSession_save_transport_params (session, &params);

  /* Equal params should pass */
  SocketQUICSession_Result result
      = SocketQUICSession_validate_transport_params (session, &params);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_transport_params_less_permissive)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T saved_params;
  memset (&saved_params, 0, sizeof (saved_params));
  saved_params.initial_max_data = 65536;
  saved_params.initial_max_streams_bidi = 100;

  SocketQUICSession_save_transport_params (session, &saved_params);

  /* New params that are LESS permissive should fail */
  SocketQUICTransportParams_T new_params;
  memset (&new_params, 0, sizeof (new_params));
  new_params.initial_max_data = 32768; /* less than saved */
  new_params.initial_max_streams_bidi = 100;

  SocketQUICSession_Result result
      = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TRANSPORT);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_transport_params_no_saved)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T new_params;
  memset (&new_params, 0, sizeof (new_params));

  /* No params saved - should fail */
  SocketQUICSession_Result result
      = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TRANSPORT);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_transport_params_connid_limit)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICTransportParams_T saved_params;
  memset (&saved_params, 0, sizeof (saved_params));
  saved_params.active_connection_id_limit = 8;

  SocketQUICSession_save_transport_params (session, &saved_params);

  /* Less permissive active_connection_id_limit should fail */
  SocketQUICTransportParams_T new_params;
  memset (&new_params, 0, sizeof (new_params));
  new_params.active_connection_id_limit = 4; /* less than saved */

  SocketQUICSession_Result result
      = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_TRANSPORT);

  /* Equal or greater should pass */
  new_params.active_connection_id_limit = 8;
  result = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  new_params.active_connection_id_limit = 16;
  result = SocketQUICSession_validate_transport_params (session, &new_params);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Ticket Clear Tests
 * ============================================================================
 */

TEST (session_clear_ticket_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t ticket_data[64];
  memset (ticket_data, 0xAB, sizeof (ticket_data));

  SocketQUICSession_store_ticket (session, ticket_data, sizeof (ticket_data),
                                  86400, 0, QUIC_SESSION_0RTT_SENTINEL);

  ASSERT_NE (SocketQUICSession_can_resume (session), 0);

  SocketQUICSession_clear_ticket (session);

  ASSERT_EQ (SocketQUICSession_can_resume (session), 0);
  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_NONE);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_clear_ticket_null_is_safe)
{
  SocketQUICSession_clear_ticket (NULL);
  /* Should not crash */
}

/* ============================================================================
 * HelloRetryRequest Tests (RFC 9001 §4.7)
 * ============================================================================
 */

TEST (session_on_hrr_received_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  ASSERT_EQ (SocketQUICSession_is_hrr (session), 0);

  SocketQUICSession_Result result
      = SocketQUICSession_on_hrr_received (session, NULL, 0);
  ASSERT_EQ (result, QUIC_SESSION_OK);
  ASSERT_NE (SocketQUICSession_is_hrr (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_on_hrr_received_with_cookie)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t cookie[32];
  memset (cookie, 0xCC, sizeof (cookie));

  SocketQUICSession_Result result
      = SocketQUICSession_on_hrr_received (session, cookie, sizeof (cookie));
  ASSERT_EQ (result, QUIC_SESSION_OK);

  const uint8_t *retrieved_cookie;
  size_t cookie_len;
  result = SocketQUICSession_get_hrr_cookie (session, &retrieved_cookie,
                                             &cookie_len);
  ASSERT_EQ (result, QUIC_SESSION_OK);
  ASSERT_EQ (cookie_len, sizeof (cookie));
  ASSERT_EQ (memcmp (retrieved_cookie, cookie, sizeof (cookie)), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_on_hrr_received_cookie_too_large)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t cookie[1];
  SocketQUICSession_Result result = SocketQUICSession_on_hrr_received (
      session, cookie, QUIC_SESSION_MAX_COOKIE_SIZE + 1);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_COOKIE);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_on_hrr_received_null)
{
  SocketQUICSession_Result result
      = SocketQUICSession_on_hrr_received (NULL, NULL, 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);
}

TEST (session_on_hrr_sent_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  ASSERT_EQ (SocketQUICSession_is_hrr (session), 0);

  SocketQUICSession_Result result = SocketQUICSession_on_hrr_sent (session);
  ASSERT_EQ (result, QUIC_SESSION_OK);
  ASSERT_NE (SocketQUICSession_is_hrr (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_on_hrr_sent_null)
{
  SocketQUICSession_Result result = SocketQUICSession_on_hrr_sent (NULL);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);
}

TEST (session_hrr_rejects_0rtt)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* Before HRR, 0-RTT is not rejected by HRR */
  ASSERT_EQ (SocketQUICSession_hrr_rejects_0rtt (session), 0);

  /* Server sends HRR */
  SocketQUICSession_on_hrr_sent (session);

  /* After HRR, 0-RTT should be rejected per RFC 9001 §4.6.2 */
  ASSERT_NE (SocketQUICSession_hrr_rejects_0rtt (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_get_hrr_cookie_no_hrr)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  const uint8_t *cookie;
  size_t len;
  SocketQUICSession_Result result
      = SocketQUICSession_get_hrr_cookie (session, &cookie, &len);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_HRR);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_get_hrr_cookie_no_cookie)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* HRR received but no cookie */
  SocketQUICSession_on_hrr_received (session, NULL, 0);

  const uint8_t *cookie;
  size_t len;
  SocketQUICSession_Result result
      = SocketQUICSession_get_hrr_cookie (session, &cookie, &len);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_COOKIE);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_set_hrr_transcript_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  uint8_t hash[32];
  memset (hash, 0xDD, sizeof (hash));

  SocketQUICSession_Result result
      = SocketQUICSession_set_hrr_transcript (session, hash);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_set_hrr_transcript_null)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_Result result
      = SocketQUICSession_set_hrr_transcript (session, NULL);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);

  result = SocketQUICSession_set_hrr_transcript (NULL, NULL);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * State Query Tests
 * ============================================================================
 */

TEST (session_state_transitions)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_NONE);

  /* Store a ticket */
  uint8_t ticket[64];
  SocketQUICSession_store_ticket (session, ticket, sizeof (ticket), 86400, 0,
                                  0);
  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_STORED);

  /* Mark as resumed */
  SocketQUICSession_mark_resumed (session);
  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_RESUMED);
  ASSERT_NE (SocketQUICSession_is_resumed (session), 0);

  /* Mark as new */
  SocketQUICSession_mark_new (session);
  ASSERT_EQ (SocketQUICSession_get_state (session), QUIC_SESSION_STATE_NEW);
  ASSERT_EQ (SocketQUICSession_is_resumed (session), 0);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_get_state_null)
{
  ASSERT_EQ (SocketQUICSession_get_state (NULL), QUIC_SESSION_STATE_NONE);
}

TEST (session_is_resumed_null)
{
  ASSERT_EQ (SocketQUICSession_is_resumed (NULL), 0);
}

TEST (session_mark_resumed_null_is_safe)
{
  SocketQUICSession_mark_resumed (NULL);
  /* Should not crash */
}

TEST (session_mark_new_null_is_safe)
{
  SocketQUICSession_mark_new (NULL);
  /* Should not crash */
}

/* ============================================================================
 * ALPN Tests (RFC 9001 §4.6.3)
 * ============================================================================
 */

TEST (session_save_alpn_basic)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  const char *alpn = "h3";
  SocketQUICSession_Result result
      = SocketQUICSession_save_alpn (session, alpn, strlen (alpn));
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_save_alpn_null)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_Result result = SocketQUICSession_save_alpn (NULL, "h3", 2);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_NULL);

  result = SocketQUICSession_save_alpn (session, NULL, 2);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_ALPN);

  result = SocketQUICSession_save_alpn (session, "h3", 0);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_ALPN);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_alpn_match)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  const char *alpn = "h3";
  SocketQUICSession_save_alpn (session, alpn, strlen (alpn));

  SocketQUICSession_Result result
      = SocketQUICSession_validate_alpn (session, alpn, strlen (alpn));
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_alpn_mismatch)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_save_alpn (session, "h3", 2);

  /* Different ALPN should fail */
  SocketQUICSession_Result result
      = SocketQUICSession_validate_alpn (session, "h2", 2);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_ALPN);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_alpn_length_mismatch)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  SocketQUICSession_save_alpn (session, "h3", 2);

  /* Different length should fail */
  SocketQUICSession_Result result
      = SocketQUICSession_validate_alpn (session, "h3-29", 5);
  ASSERT_EQ (result, QUIC_SESSION_ERROR_ALPN);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

TEST (session_validate_alpn_no_saved_ok)
{
  Arena_T arena = Arena_new ();
  SocketQUICSession_T session = SocketQUICSession_new (arena);

  /* No ALPN saved - should pass (no validation needed) */
  SocketQUICSession_Result result
      = SocketQUICSession_validate_alpn (session, "h3", 2);
  ASSERT_EQ (result, QUIC_SESSION_OK);

  SocketQUICSession_free (&session);
  Arena_dispose (&arena);
}

/* ============================================================================
 * String Conversion Tests
 * ============================================================================
 */

TEST (session_state_string)
{
  const char *s;

  s = SocketQUICSession_state_string (QUIC_SESSION_STATE_NONE);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "NONE"), 0);

  s = SocketQUICSession_state_string (QUIC_SESSION_STATE_STORED);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "STORED"), 0);

  s = SocketQUICSession_state_string (QUIC_SESSION_STATE_RESUMED);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "RESUMED"), 0);

  s = SocketQUICSession_state_string ((SocketQUICSessionState)999);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "UNKNOWN"), 0);
}

TEST (session_result_string)
{
  const char *s;

  s = SocketQUICSession_result_string (QUIC_SESSION_OK);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "OK"), 0);

  s = SocketQUICSession_result_string (QUIC_SESSION_ERROR_NULL);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "NULL argument"), 0);

  s = SocketQUICSession_result_string (QUIC_SESSION_ERROR_TRANSPORT);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "Transport parameter mismatch"), 0);

  s = SocketQUICSession_result_string ((SocketQUICSession_Result)999);
  ASSERT_NOT_NULL (s);
  ASSERT_EQ (strcmp (s, "UNKNOWN"), 0);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
