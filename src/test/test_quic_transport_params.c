/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_transport_params.c - QUIC Transport Parameters unit tests
 *
 * Tests encoding/decoding/validation of QUIC transport parameters (RFC 9000
 * Section 18). Covers initialization, round-trip encoding, validation, and
 * error conditions.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICTransportParams.h"
#include "test/Test.h"

TEST (quic_tp_init_defaults)
{
  SocketQUICTransportParams_T params;

  SocketQUICTransportParams_init (&params);

  /* Verify RFC 9000 Section 18.2 default values */
  ASSERT_EQ (params.max_idle_timeout, QUIC_TP_DEFAULT_MAX_IDLE_TIMEOUT);
  ASSERT_EQ (params.max_udp_payload_size, QUIC_TP_DEFAULT_MAX_UDP_PAYLOAD_SIZE);
  ASSERT_EQ (params.initial_max_data, QUIC_TP_DEFAULT_INITIAL_MAX_DATA);
  ASSERT_EQ (params.initial_max_stream_data_bidi_local,
             QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA);
  ASSERT_EQ (params.initial_max_stream_data_bidi_remote,
             QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA);
  ASSERT_EQ (params.initial_max_stream_data_uni,
             QUIC_TP_DEFAULT_INITIAL_MAX_STREAM_DATA);
  ASSERT_EQ (params.initial_max_streams_bidi,
             QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS);
  ASSERT_EQ (params.initial_max_streams_uni,
             QUIC_TP_DEFAULT_INITIAL_MAX_STREAMS);
  ASSERT_EQ (params.ack_delay_exponent, QUIC_TP_DEFAULT_ACK_DELAY_EXPONENT);
  ASSERT_EQ (params.max_ack_delay, QUIC_TP_DEFAULT_MAX_ACK_DELAY);
  ASSERT_EQ (params.active_connection_id_limit,
             QUIC_TP_DEFAULT_ACTIVE_CONNID_LIMIT);
  ASSERT_EQ (params.disable_active_migration, 0);

  /* Verify optional fields are not set */
  ASSERT_EQ (params.has_original_dcid, 0);
  ASSERT_EQ (params.has_initial_scid, 0);
  ASSERT_EQ (params.has_retry_scid, 0);
  ASSERT_EQ (params.has_stateless_reset_token, 0);
  ASSERT_EQ (params.preferred_address.present, 0);
}

TEST (quic_tp_set_defaults_client)
{
  SocketQUICTransportParams_T params;

  SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_CLIENT);

  /* Verify reasonable defaults are set */
  ASSERT (params.max_idle_timeout > 0);
  ASSERT (params.initial_max_data > 0);
  ASSERT (params.initial_max_streams_bidi > 0);
  ASSERT (params.active_connection_id_limit >= QUIC_TP_MIN_ACTIVE_CONNID_LIMIT);
}

TEST (quic_tp_set_defaults_server)
{
  SocketQUICTransportParams_T params;

  SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_SERVER);

  /* Verify reasonable defaults are set */
  ASSERT (params.max_idle_timeout > 0);
  ASSERT (params.initial_max_data > 0);
  ASSERT (params.initial_max_streams_bidi > 0);
}

TEST (quic_tp_roundtrip_minimal_client)
{
  SocketQUICTransportParams_T original, decoded;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];
  size_t encoded_len, consumed;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&original);

  /* Set required client parameter */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&original.initial_scid, scid_data, 4);
  original.has_initial_scid = 1;

  /* Encode as client */
  encoded_len = SocketQUICTransportParams_encode (
      &original, QUIC_ROLE_CLIENT, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode as if from client */
  res = SocketQUICTransportParams_decode (
      buf, encoded_len, QUIC_ROLE_CLIENT, &decoded, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (consumed, encoded_len);

  /* Verify decoded values */
  ASSERT_EQ (decoded.has_initial_scid, 1);
  ASSERT (SocketQUICConnectionID_equal (&decoded.initial_scid,
                                        &original.initial_scid));
}

TEST (quic_tp_roundtrip_minimal_server)
{
  SocketQUICTransportParams_T original, decoded;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];
  size_t encoded_len, consumed;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&original);

  /* Set required server parameters */
  uint8_t odcid_data[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
  SocketQUICConnectionID_set (&original.original_dcid, odcid_data, 5);
  original.has_original_dcid = 1;

  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&original.initial_scid, scid_data, 4);
  original.has_initial_scid = 1;

  /* Encode as server */
  encoded_len = SocketQUICTransportParams_encode (
      &original, QUIC_ROLE_SERVER, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode as if from server */
  res = SocketQUICTransportParams_decode (
      buf, encoded_len, QUIC_ROLE_SERVER, &decoded, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (consumed, encoded_len);

  /* Verify decoded values */
  ASSERT_EQ (decoded.has_original_dcid, 1);
  ASSERT (SocketQUICConnectionID_equal (&decoded.original_dcid,
                                        &original.original_dcid));
  ASSERT_EQ (decoded.has_initial_scid, 1);
  ASSERT (SocketQUICConnectionID_equal (&decoded.initial_scid,
                                        &original.initial_scid));
}

TEST (quic_tp_roundtrip_full_client)
{
  SocketQUICTransportParams_T original, decoded;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];
  size_t encoded_len, consumed;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_set_defaults (&original, QUIC_ROLE_CLIENT);

  /* Set various parameters */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&original.initial_scid, scid_data, 4);
  original.has_initial_scid = 1;

  original.max_idle_timeout = 30000;
  original.max_udp_payload_size = 1500;
  original.initial_max_data = 1048576;
  original.initial_max_stream_data_bidi_local = 262144;
  original.initial_max_stream_data_bidi_remote = 262144;
  original.initial_max_stream_data_uni = 262144;
  original.initial_max_streams_bidi = 100;
  original.initial_max_streams_uni = 100;
  original.ack_delay_exponent = 8;
  original.max_ack_delay = 100;
  original.active_connection_id_limit = 8;
  original.disable_active_migration = 1;
  original.max_datagram_frame_size = 65535;
  original.has_max_datagram_frame_size = 1;

  /* Encode */
  encoded_len = SocketQUICTransportParams_encode (
      &original, QUIC_ROLE_CLIENT, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode */
  res = SocketQUICTransportParams_decode (
      buf, encoded_len, QUIC_ROLE_CLIENT, &decoded, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (consumed, encoded_len);

  /* Verify all parameters */
  ASSERT_EQ (decoded.max_idle_timeout, original.max_idle_timeout);
  ASSERT_EQ (decoded.max_udp_payload_size, original.max_udp_payload_size);
  ASSERT_EQ (decoded.initial_max_data, original.initial_max_data);
  ASSERT_EQ (decoded.initial_max_stream_data_bidi_local,
             original.initial_max_stream_data_bidi_local);
  ASSERT_EQ (decoded.initial_max_stream_data_bidi_remote,
             original.initial_max_stream_data_bidi_remote);
  ASSERT_EQ (decoded.initial_max_stream_data_uni,
             original.initial_max_stream_data_uni);
  ASSERT_EQ (decoded.initial_max_streams_bidi,
             original.initial_max_streams_bidi);
  ASSERT_EQ (decoded.initial_max_streams_uni, original.initial_max_streams_uni);
  ASSERT_EQ (decoded.ack_delay_exponent, original.ack_delay_exponent);
  ASSERT_EQ (decoded.max_ack_delay, original.max_ack_delay);
  ASSERT_EQ (decoded.active_connection_id_limit,
             original.active_connection_id_limit);
  ASSERT_EQ (decoded.disable_active_migration, 1);
  ASSERT_EQ (decoded.has_max_datagram_frame_size, 1);
  ASSERT_EQ (decoded.max_datagram_frame_size, original.max_datagram_frame_size);
}

TEST (quic_tp_roundtrip_server_with_token)
{
  SocketQUICTransportParams_T original, decoded;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];
  size_t encoded_len, consumed;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&original);

  /* Set required parameters */
  uint8_t odcid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&original.original_dcid, odcid_data, 4);
  original.has_original_dcid = 1;

  uint8_t scid_data[] = { 0x05, 0x06, 0x07, 0x08 };
  SocketQUICConnectionID_set (&original.initial_scid, scid_data, 4);
  original.has_initial_scid = 1;

  /* Set stateless reset token */
  for (int i = 0; i < QUIC_STATELESS_RESET_TOKEN_LEN; i++)
    original.stateless_reset_token[i] = (uint8_t)(i + 0x10);
  original.has_stateless_reset_token = 1;

  /* Encode as server */
  encoded_len = SocketQUICTransportParams_encode (
      &original, QUIC_ROLE_SERVER, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode */
  res = SocketQUICTransportParams_decode (
      buf, encoded_len, QUIC_ROLE_SERVER, &decoded, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (consumed, encoded_len);

  /* Verify reset token */
  ASSERT_EQ (decoded.has_stateless_reset_token, 1);
  ASSERT_EQ (memcmp (decoded.stateless_reset_token,
                     original.stateless_reset_token,
                     QUIC_STATELESS_RESET_TOKEN_LEN),
             0);
}

TEST (quic_tp_roundtrip_preferred_address)
{
  SocketQUICTransportParams_T original, decoded;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];
  size_t encoded_len, consumed;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&original);

  /* Set required parameters */
  uint8_t odcid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&original.original_dcid, odcid_data, 4);
  original.has_original_dcid = 1;

  uint8_t scid_data[] = { 0x05, 0x06, 0x07, 0x08 };
  SocketQUICConnectionID_set (&original.initial_scid, scid_data, 4);
  original.has_initial_scid = 1;

  /* Set preferred address */
  original.preferred_address.ipv4_address[0] = 192;
  original.preferred_address.ipv4_address[1] = 168;
  original.preferred_address.ipv4_address[2] = 1;
  original.preferred_address.ipv4_address[3] = 100;
  original.preferred_address.ipv4_port = 4433;

  original.preferred_address.ipv6_address[0] = 0x20;
  original.preferred_address.ipv6_address[1] = 0x01;
  /* rest zeros */
  original.preferred_address.ipv6_port = 4434;

  uint8_t pa_cid[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  SocketQUICConnectionID_set (
      &original.preferred_address.connection_id, pa_cid, 4);

  for (int i = 0; i < 16; i++)
    original.preferred_address.stateless_reset_token[i] = (uint8_t)(i + 0xA0);

  original.preferred_address.present = 1;

  /* Encode as server */
  encoded_len = SocketQUICTransportParams_encode (
      &original, QUIC_ROLE_SERVER, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode */
  res = SocketQUICTransportParams_decode (
      buf, encoded_len, QUIC_ROLE_SERVER, &decoded, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (consumed, encoded_len);

  /* Verify preferred address */
  ASSERT_EQ (decoded.preferred_address.present, 1);
  ASSERT_EQ (decoded.preferred_address.ipv4_address[0], 192);
  ASSERT_EQ (decoded.preferred_address.ipv4_address[1], 168);
  ASSERT_EQ (decoded.preferred_address.ipv4_address[2], 1);
  ASSERT_EQ (decoded.preferred_address.ipv4_address[3], 100);
  ASSERT_EQ (decoded.preferred_address.ipv4_port, 4433);
  ASSERT_EQ (decoded.preferred_address.ipv6_port, 4434);
  ASSERT (
      SocketQUICConnectionID_equal (&decoded.preferred_address.connection_id,
                                    &original.preferred_address.connection_id));
}

TEST (quic_tp_validate_valid_params)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_CLIENT);

  /* Set required parameter */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&params.initial_scid, scid_data, 4);
  params.has_initial_scid = 1;

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_OK);
}

TEST (quic_tp_validate_udp_payload_size_too_small)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);
  params.max_udp_payload_size = 1199; /* Below minimum of 1200 */

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_validate_ack_delay_exponent_too_large)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);
  params.ack_delay_exponent = 21; /* Maximum is 20 */

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_validate_max_ack_delay_too_large)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);
  params.max_ack_delay = 16385; /* Maximum is 16384 (2^14) */

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_validate_active_connid_limit_too_small)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);
  params.active_connection_id_limit = 1; /* Minimum is 2 */

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_validate_client_with_server_params)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);

  /* Set server-only parameter on client params */
  uint8_t odcid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&params.original_dcid, odcid_data, 4);
  params.has_original_dcid = 1;

  res = SocketQUICTransportParams_validate (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_ROLE);
}

TEST (quic_tp_validate_required_client)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);

  /* Missing initial_scid */
  res = SocketQUICTransportParams_validate_required (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_REQUIRED);

  /* Add initial_scid */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&params.initial_scid, scid_data, 4);
  params.has_initial_scid = 1;

  res = SocketQUICTransportParams_validate_required (&params, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_OK);
}

TEST (quic_tp_validate_required_server)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);

  /* Add initial_scid but missing original_dcid */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&params.initial_scid, scid_data, 4);
  params.has_initial_scid = 1;

  res = SocketQUICTransportParams_validate_required (&params, QUIC_ROLE_SERVER);
  ASSERT_EQ (res, QUIC_TP_ERROR_REQUIRED);

  /* Add original_dcid */
  uint8_t odcid_data[] = { 0xAA, 0xBB, 0xCC, 0xDD };
  SocketQUICConnectionID_set (&params.original_dcid, odcid_data, 4);
  params.has_original_dcid = 1;

  res = SocketQUICTransportParams_validate_required (&params, QUIC_ROLE_SERVER);
  ASSERT_EQ (res, QUIC_TP_OK);
}

TEST (quic_tp_decode_truncated)
{
  /* Parameter ID without length */
  uint8_t data[] = { 0x01 }; /* Just the ID, no length */
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_INCOMPLETE);
}

TEST (quic_tp_decode_truncated_value)
{
  /* Parameter with length but insufficient data */
  uint8_t data[]
      = { 0x01, 0x08, 0x00, 0x00 }; /* ID=1, len=8, but only 2 bytes */
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_INCOMPLETE);
}

TEST (quic_tp_decode_server_param_from_client)
{
  /* Client tries to send original_destination_connection_id (server only) */
  uint8_t data[]
      = { 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 }; /* ID=0, len=4, CID */
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_ROLE);
}

TEST (quic_tp_decode_invalid_reset_token_length)
{
  /* stateless_reset_token with wrong length (should be 16) */
  uint8_t data[]
      = { 0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_SERVER, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_decode_duplicate_param)
{
  /* Same parameter twice */
  uint8_t data[] = {
    0x01, 0x01, 0x00, /* max_idle_timeout = 0 */
    0x01, 0x01, 0x00  /* max_idle_timeout = 0 (duplicate) */
  };
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_DUPLICATE);
}

TEST (quic_tp_decode_disable_migration_nonzero_length)
{
  /* disable_active_migration should have length 0 */
  uint8_t data[] = { 0x0c, 0x01, 0x00 }; /* ID=12, len=1, value=0 */
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_INVALID_VALUE);
}

TEST (quic_tp_decode_unknown_param_ignored)
{
  /* Unknown parameter ID (0xFF) should be ignored */
  uint8_t data[] = {
    0x40, 0xFF, 0x04, 0x01,
    0x02, 0x03, 0x04, /* Unknown ID=0xFF (2-byte varint), len=4 */
    0x01, 0x01, 0x0A  /* max_idle_timeout = 10 */
  };
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (params.max_idle_timeout, 10);
}

TEST (quic_tp_encoded_size_matches_encode)
{
  SocketQUICTransportParams_T params;
  uint8_t buf[QUIC_TP_MAX_ENCODED_SIZE];

  SocketQUICTransportParams_set_defaults (&params, QUIC_ROLE_CLIENT);

  /* Set required parameter */
  uint8_t scid_data[] = { 0x01, 0x02, 0x03, 0x04 };
  SocketQUICConnectionID_set (&params.initial_scid, scid_data, 4);
  params.has_initial_scid = 1;

  size_t expected_size
      = SocketQUICTransportParams_encoded_size (&params, QUIC_ROLE_CLIENT);
  size_t actual_size = SocketQUICTransportParams_encode (
      &params, QUIC_ROLE_CLIENT, buf, sizeof (buf));

  ASSERT_EQ (actual_size, expected_size);
}

TEST (quic_tp_copy)
{
  SocketQUICTransportParams_T src, dst;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_set_defaults (&src, QUIC_ROLE_CLIENT);
  src.max_idle_timeout = 12345;
  src.initial_max_data = 999999;

  res = SocketQUICTransportParams_copy (&dst, &src);
  ASSERT_EQ (res, QUIC_TP_OK);
  ASSERT_EQ (dst.max_idle_timeout, src.max_idle_timeout);
  ASSERT_EQ (dst.initial_max_data, src.initial_max_data);
}

TEST (quic_tp_effective_idle_timeout)
{
  SocketQUICTransportParams_T local, remote;
  uint64_t effective;

  SocketQUICTransportParams_init (&local);
  SocketQUICTransportParams_init (&remote);

  /* Both zero = disabled */
  effective
      = SocketQUICTransportParams_effective_idle_timeout (&local, &remote);
  ASSERT_EQ (effective, 0);

  /* One zero = disabled */
  local.max_idle_timeout = 30000;
  remote.max_idle_timeout = 0;
  effective
      = SocketQUICTransportParams_effective_idle_timeout (&local, &remote);
  ASSERT_EQ (effective, 0);

  /* Both non-zero = minimum */
  local.max_idle_timeout = 30000;
  remote.max_idle_timeout = 60000;
  effective
      = SocketQUICTransportParams_effective_idle_timeout (&local, &remote);
  ASSERT_EQ (effective, 30000);

  /* Remote smaller */
  local.max_idle_timeout = 60000;
  remote.max_idle_timeout = 30000;
  effective
      = SocketQUICTransportParams_effective_idle_timeout (&local, &remote);
  ASSERT_EQ (effective, 30000);
}

TEST (quic_tp_result_string)
{
  ASSERT_NOT_NULL (SocketQUICTransportParams_result_string (QUIC_TP_OK));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_NULL));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_BUFFER));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_INCOMPLETE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_INVALID_VALUE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_DUPLICATE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_ROLE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_REQUIRED));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_result_string (QUIC_TP_ERROR_ENCODING));
  ASSERT_NOT_NULL (SocketQUICTransportParams_result_string (
      (SocketQUICTransportParams_Result)99));
}

TEST (quic_tp_id_string)
{
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (QUIC_TP_ORIGINAL_DCID));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_MAX_IDLE_TIMEOUT));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_STATELESS_RESET_TOKEN));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_MAX_UDP_PAYLOAD_SIZE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_INITIAL_MAX_DATA));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (
      QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (
      QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (
      QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_INITIAL_MAX_STREAMS_BIDI));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_INITIAL_MAX_STREAMS_UNI));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_ACK_DELAY_EXPONENT));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (QUIC_TP_MAX_ACK_DELAY));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_DISABLE_ACTIVE_MIGRATION));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_PREFERRED_ADDRESS));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_ACTIVE_CONNID_LIMIT));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (QUIC_TP_INITIAL_SCID));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (QUIC_TP_RETRY_SCID));
  ASSERT_NOT_NULL (SocketQUICTransportParams_id_string (QUIC_TP_VERSION_INFO));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string (QUIC_TP_MAX_DATAGRAM_FRAME_SIZE));
  ASSERT_NOT_NULL (
      SocketQUICTransportParams_id_string ((SocketQUICTransportParamID)999));
}

TEST (quic_tp_null_init)
{
  /* Should not crash */
  SocketQUICTransportParams_init (NULL);
}

TEST (quic_tp_null_set_defaults)
{
  /* Should not crash */
  SocketQUICTransportParams_set_defaults (NULL, QUIC_ROLE_CLIENT);
}

TEST (quic_tp_null_encoded_size)
{
  size_t size = SocketQUICTransportParams_encoded_size (NULL, QUIC_ROLE_CLIENT);
  ASSERT_EQ (size, 0);
}

TEST (quic_tp_null_encode)
{
  SocketQUICTransportParams_T params;
  uint8_t buf[64];

  SocketQUICTransportParams_init (&params);

  size_t len = SocketQUICTransportParams_encode (
      NULL, QUIC_ROLE_CLIENT, buf, sizeof (buf));
  ASSERT_EQ (len, 0);

  len = SocketQUICTransportParams_encode (
      &params, QUIC_ROLE_CLIENT, NULL, sizeof (buf));
  ASSERT_EQ (len, 0);
}

TEST (quic_tp_null_decode)
{
  uint8_t data[] = { 0x01, 0x01, 0x00 };
  SocketQUICTransportParams_T params;
  size_t consumed;

  SocketQUICTransportParams_Result res;

  res = SocketQUICTransportParams_decode (
      NULL, sizeof (data), QUIC_ROLE_CLIENT, &params, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);

  res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, NULL, &consumed);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);

  res = SocketQUICTransportParams_decode (
      data, sizeof (data), QUIC_ROLE_CLIENT, &params, NULL);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);
}

TEST (quic_tp_null_validate)
{
  SocketQUICTransportParams_Result res;

  res = SocketQUICTransportParams_validate (NULL, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);

  res = SocketQUICTransportParams_validate_required (NULL, QUIC_ROLE_CLIENT);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);
}

TEST (quic_tp_null_copy)
{
  SocketQUICTransportParams_T params;
  SocketQUICTransportParams_Result res;

  SocketQUICTransportParams_init (&params);

  res = SocketQUICTransportParams_copy (NULL, &params);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);

  res = SocketQUICTransportParams_copy (&params, NULL);
  ASSERT_EQ (res, QUIC_TP_ERROR_NULL);
}

TEST (quic_tp_null_effective_timeout)
{
  SocketQUICTransportParams_T params;
  uint64_t timeout;

  SocketQUICTransportParams_init (&params);

  timeout = SocketQUICTransportParams_effective_idle_timeout (NULL, &params);
  ASSERT_EQ (timeout, 0);

  timeout = SocketQUICTransportParams_effective_idle_timeout (&params, NULL);
  ASSERT_EQ (timeout, 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
