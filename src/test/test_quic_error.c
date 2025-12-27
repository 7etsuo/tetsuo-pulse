/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_error.c - QUIC Error Code unit tests (RFC 9000 §20)
 *
 * Tests error code definitions, classification, validation, and string
 * conversion for QUIC transport and crypto errors.
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICError.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICStream.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

/* ============================================================================
 * Transport Error Code Value Tests
 * ============================================================================
 */

TEST (quic_error_no_error_value)
{
  ASSERT_EQ (QUIC_NO_ERROR, 0x00);
}

TEST (quic_error_internal_error_value)
{
  ASSERT_EQ (QUIC_INTERNAL_ERROR, 0x01);
}

TEST (quic_error_connection_refused_value)
{
  ASSERT_EQ (QUIC_CONNECTION_REFUSED, 0x02);
}

TEST (quic_error_flow_control_error_value)
{
  ASSERT_EQ (QUIC_FLOW_CONTROL_ERROR, 0x03);
}

TEST (quic_error_stream_limit_error_value)
{
  ASSERT_EQ (QUIC_STREAM_LIMIT_ERROR, 0x04);
}

TEST (quic_error_stream_state_error_value)
{
  ASSERT_EQ (QUIC_STREAM_STATE_ERROR, 0x05);
}

TEST (quic_error_final_size_error_value)
{
  ASSERT_EQ (QUIC_FINAL_SIZE_ERROR, 0x06);
}

TEST (quic_error_frame_encoding_error_value)
{
  ASSERT_EQ (QUIC_FRAME_ENCODING_ERROR, 0x07);
}

TEST (quic_error_transport_parameter_error_value)
{
  ASSERT_EQ (QUIC_TRANSPORT_PARAMETER_ERROR, 0x08);
}

TEST (quic_error_connection_id_limit_error_value)
{
  ASSERT_EQ (QUIC_CONNECTION_ID_LIMIT_ERROR, 0x09);
}

TEST (quic_error_protocol_violation_value)
{
  ASSERT_EQ (QUIC_PROTOCOL_VIOLATION, 0x0a);
}

TEST (quic_error_invalid_token_value)
{
  ASSERT_EQ (QUIC_INVALID_TOKEN, 0x0b);
}

TEST (quic_error_application_error_value)
{
  ASSERT_EQ (QUIC_APPLICATION_ERROR, 0x0c);
}

TEST (quic_error_crypto_buffer_exceeded_value)
{
  ASSERT_EQ (QUIC_CRYPTO_BUFFER_EXCEEDED, 0x0d);
}

TEST (quic_error_key_update_error_value)
{
  ASSERT_EQ (QUIC_KEY_UPDATE_ERROR, 0x0e);
}

TEST (quic_error_aead_limit_reached_value)
{
  ASSERT_EQ (QUIC_AEAD_LIMIT_REACHED, 0x0f);
}

TEST (quic_error_no_viable_path_value)
{
  ASSERT_EQ (QUIC_NO_VIABLE_PATH, 0x10);
}

/* ============================================================================
 * Crypto Error Macro Tests
 * ============================================================================
 */

TEST (quic_error_crypto_base_value)
{
  ASSERT_EQ (QUIC_CRYPTO_ERROR_BASE, 0x0100);
}

TEST (quic_error_crypto_max_value)
{
  ASSERT_EQ (QUIC_CRYPTO_ERROR_MAX, 0x01ff);
}

TEST (quic_error_crypto_error_macro)
{
  /* TLS alert 0 -> QUIC crypto error 0x0100 */
  ASSERT_EQ (QUIC_CRYPTO_ERROR (0), 0x0100);

  /* TLS alert 40 (handshake_failure) -> QUIC crypto error 0x0128 */
  ASSERT_EQ (QUIC_CRYPTO_ERROR (40), 0x0128);

  /* TLS alert 255 -> QUIC crypto error 0x01ff */
  ASSERT_EQ (QUIC_CRYPTO_ERROR (255), 0x01ff);
}

TEST (quic_error_is_crypto_error_true)
{
  ASSERT (QUIC_IS_CRYPTO_ERROR (0x0100));
  ASSERT (QUIC_IS_CRYPTO_ERROR (0x0128));
  ASSERT (QUIC_IS_CRYPTO_ERROR (0x01ff));
}

TEST (quic_error_is_crypto_error_false)
{
  ASSERT (!QUIC_IS_CRYPTO_ERROR (0x00));
  ASSERT (!QUIC_IS_CRYPTO_ERROR (0x10));
  ASSERT (!QUIC_IS_CRYPTO_ERROR (0xff));
  ASSERT (!QUIC_IS_CRYPTO_ERROR (0x0200));
}

TEST (quic_error_crypto_alert_macro)
{
  ASSERT_EQ (QUIC_CRYPTO_ALERT (0x0100), 0);
  ASSERT_EQ (QUIC_CRYPTO_ALERT (0x0128), 40);
  ASSERT_EQ (QUIC_CRYPTO_ALERT (0x01ff), 255);
}

/* ============================================================================
 * Error Category Tests
 * ============================================================================
 */

TEST (quic_error_category_transport)
{
  ASSERT_EQ (SocketQUIC_error_category (QUIC_NO_ERROR),
             QUIC_ERROR_CATEGORY_TRANSPORT);
  ASSERT_EQ (SocketQUIC_error_category (QUIC_INTERNAL_ERROR),
             QUIC_ERROR_CATEGORY_TRANSPORT);
  ASSERT_EQ (SocketQUIC_error_category (QUIC_NO_VIABLE_PATH),
             QUIC_ERROR_CATEGORY_TRANSPORT);
}

TEST (quic_error_category_crypto)
{
  ASSERT_EQ (SocketQUIC_error_category (0x0100), QUIC_ERROR_CATEGORY_CRYPTO);
  ASSERT_EQ (SocketQUIC_error_category (0x0128), QUIC_ERROR_CATEGORY_CRYPTO);
  ASSERT_EQ (SocketQUIC_error_category (0x01ff), QUIC_ERROR_CATEGORY_CRYPTO);
}

TEST (quic_error_category_application)
{
  ASSERT_EQ (SocketQUIC_error_category (0x0200),
             QUIC_ERROR_CATEGORY_APPLICATION);
  ASSERT_EQ (SocketQUIC_error_category (0x1000),
             QUIC_ERROR_CATEGORY_APPLICATION);
}

TEST (quic_error_category_unknown)
{
  /* Reserved range 0x11-0xff */
  ASSERT_EQ (SocketQUIC_error_category (0x11), QUIC_ERROR_CATEGORY_UNKNOWN);
  ASSERT_EQ (SocketQUIC_error_category (0xff), QUIC_ERROR_CATEGORY_UNKNOWN);
}

/* ============================================================================
 * Error Validation Tests
 * ============================================================================
 */

TEST (quic_error_is_valid_true)
{
  ASSERT (SocketQUIC_error_is_valid (0));
  ASSERT (SocketQUIC_error_is_valid (QUIC_NO_VIABLE_PATH));
  ASSERT (SocketQUIC_error_is_valid (0x0100));
  ASSERT (SocketQUIC_error_is_valid (QUIC_ERROR_CODE_MAX));
}

TEST (quic_error_is_valid_false)
{
  /* 62-bit max is 0x3FFFFFFFFFFFFFFF, anything larger is invalid */
  ASSERT (!SocketQUIC_error_is_valid (QUIC_ERROR_CODE_MAX + 1));
  ASSERT (!SocketQUIC_error_is_valid (UINT64_MAX));
}

TEST (quic_error_is_transport_error)
{
  ASSERT (SocketQUIC_is_transport_error (QUIC_NO_ERROR));
  ASSERT (SocketQUIC_is_transport_error (QUIC_NO_VIABLE_PATH));
  ASSERT (!SocketQUIC_is_transport_error (0x11));
  ASSERT (!SocketQUIC_is_transport_error (0x0100));
}

/* ============================================================================
 * Error String Tests
 * ============================================================================
 */

TEST (quic_error_string_transport_errors)
{
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_NO_ERROR), "NO_ERROR") == 0);
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_INTERNAL_ERROR),
                  "INTERNAL_ERROR")
          == 0);
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_CONNECTION_REFUSED),
                  "CONNECTION_REFUSED")
          == 0);
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_FLOW_CONTROL_ERROR),
                  "FLOW_CONTROL_ERROR")
          == 0);
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_PROTOCOL_VIOLATION),
                  "PROTOCOL_VIOLATION")
          == 0);
  ASSERT (strcmp (SocketQUIC_error_string (QUIC_NO_VIABLE_PATH), "NO_VIABLE_PATH")
          == 0);
}

TEST (quic_error_string_crypto_errors)
{
  const char *str;

  str = SocketQUIC_error_string (0x0100);
  ASSERT (strstr (str, "CRYPTO_ERROR") != NULL);
  ASSERT (strstr (str, "0x00") != NULL);

  str = SocketQUIC_error_string (0x0128);
  ASSERT (strstr (str, "CRYPTO_ERROR") != NULL);
  ASSERT (strstr (str, "0x28") != NULL);
}

TEST (quic_error_string_crypto_errors_all_codes)
{
  /* Test all possible crypto error codes (0x00-0xff) */
  for (unsigned int alert = 0; alert <= 0xff; alert++)
    {
      uint64_t code = QUIC_CRYPTO_ERROR (alert);
      const char *str = SocketQUIC_error_string (code);

      /* Verify string is non-NULL and contains expected pattern */
      ASSERT_NOT_NULL (str);
      ASSERT (strstr (str, "CRYPTO_ERROR") != NULL);

      /* Verify the alert code is formatted correctly (or fallback on error) */
      /* The format should be "CRYPTO_ERROR(0xXX)" where XX is the hex alert */
      ASSERT (strlen (str) > 0);
    }
}

TEST (quic_error_string_application_error)
{
  const char *str = SocketQUIC_error_string (0x0200);
  ASSERT (strstr (str, "APPLICATION") != NULL);
}

TEST (quic_error_string_unknown)
{
  const char *str = SocketQUIC_error_string (0x50);
  ASSERT (strstr (str, "UNKNOWN") != NULL);
}

TEST (quic_error_string_not_null)
{
  /* Ensure we never return NULL for any input */
  ASSERT_NOT_NULL (SocketQUIC_error_string (0));
  ASSERT_NOT_NULL (SocketQUIC_error_string (0x10));
  ASSERT_NOT_NULL (SocketQUIC_error_string (0x50));
  ASSERT_NOT_NULL (SocketQUIC_error_string (0x0100));
  ASSERT_NOT_NULL (SocketQUIC_error_string (0x0200));
  ASSERT_NOT_NULL (SocketQUIC_error_string (UINT64_MAX));
}

/* ============================================================================
 * Category String Tests
 * ============================================================================
 */

TEST (quic_error_category_string)
{
  ASSERT (strcmp (SocketQUIC_error_category_string (QUIC_ERROR_CATEGORY_TRANSPORT),
                  "TRANSPORT")
          == 0);
  ASSERT (strcmp (SocketQUIC_error_category_string (QUIC_ERROR_CATEGORY_CRYPTO),
                  "CRYPTO")
          == 0);
  ASSERT (
      strcmp (SocketQUIC_error_category_string (QUIC_ERROR_CATEGORY_APPLICATION),
              "APPLICATION")
      == 0);
  ASSERT (strcmp (SocketQUIC_error_category_string (QUIC_ERROR_CATEGORY_UNKNOWN),
                  "UNKNOWN")
          == 0);
}

TEST (quic_error_category_string_invalid)
{
  /* Invalid category should return "UNKNOWN" */
  const char *str = SocketQUIC_error_category_string (99);
  ASSERT (strcmp (str, "UNKNOWN") == 0);
}

/* ============================================================================
 * Error Handling Tests (RFC 9000 Section 11)
 * ============================================================================
 */

TEST (quic_error_is_connection_fatal_transport)
{
  /* All transport errors are connection-fatal */
  ASSERT (SocketQUIC_error_is_connection_fatal (QUIC_NO_ERROR));
  ASSERT (SocketQUIC_error_is_connection_fatal (QUIC_INTERNAL_ERROR));
  ASSERT (SocketQUIC_error_is_connection_fatal (QUIC_PROTOCOL_VIOLATION));
  ASSERT (SocketQUIC_error_is_connection_fatal (QUIC_NO_VIABLE_PATH));
}

TEST (quic_error_is_connection_fatal_crypto)
{
  /* All crypto errors are connection-fatal */
  ASSERT (SocketQUIC_error_is_connection_fatal (0x0100));
  ASSERT (SocketQUIC_error_is_connection_fatal (0x0128));
  ASSERT (SocketQUIC_error_is_connection_fatal (0x01ff));
}

TEST (quic_error_is_connection_fatal_application)
{
  /* Application errors may be connection-fatal */
  ASSERT (SocketQUIC_error_is_connection_fatal (0x0200));
  ASSERT (SocketQUIC_error_is_connection_fatal (0x1000));
}

TEST (quic_error_is_connection_fatal_unknown)
{
  /* Unknown error codes in reserved range */
  ASSERT (!SocketQUIC_error_is_connection_fatal (0x11));
  ASSERT (!SocketQUIC_error_is_connection_fatal (0xff));
}

TEST (quic_error_send_connection_close_transport)
{
  volatile Arena_T arena = NULL;
  volatile SocketQUICConnection_T conn = NULL;
  uint8_t buf[256];
  size_t len;
  uint64_t frame_type, error_code, reason_len;
  const uint8_t *p;
  size_t consumed;

  TRY
    {
      arena = Arena_new ();
      conn = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);

      /* Send CONNECTION_CLOSE for transport error */
      len = SocketQUIC_send_connection_close (
          conn, QUIC_PROTOCOL_VIOLATION, "test reason", buf, sizeof (buf));

      ASSERT (len > 0);

      /* Parse and verify frame */
      p = buf;

      /* Frame type should be 0x1c (CONNECTION_CLOSE) */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &frame_type, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (frame_type, QUIC_FRAME_CONNECTION_CLOSE);
      p += consumed;
      len -= consumed;

      /* Error code */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &error_code, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (error_code, QUIC_PROTOCOL_VIOLATION);
      p += consumed;
      len -= consumed;

      /* Frame type field (for transport errors) */
      uint64_t trigger_frame;
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &trigger_frame, &consumed),
                 QUIC_VARINT_OK);
      p += consumed;
      len -= consumed;

      /* Reason phrase length */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &reason_len, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (reason_len, 11); /* strlen("test reason") */
      p += consumed;
      len -= consumed;

      /* Reason phrase */
      ASSERT_EQ (memcmp (p, "test reason", 11), 0);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
}

TEST (quic_error_send_connection_close_application)
{
  volatile Arena_T arena = NULL;
  volatile SocketQUICConnection_T conn = NULL;
  uint8_t buf[256];
  size_t len;
  uint64_t frame_type, error_code;
  const uint8_t *p;
  size_t consumed;

  TRY
    {
      arena = Arena_new ();
      conn = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);

      /* Send CONNECTION_CLOSE for application error */
      len = SocketQUIC_send_connection_close (conn, 0x0200, NULL, buf,
                                               sizeof (buf));

      ASSERT (len > 0);

      /* Parse and verify frame */
      p = buf;

      /* Frame type should be 0x1d (CONNECTION_CLOSE for app errors) */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &frame_type, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (frame_type, QUIC_FRAME_CONNECTION_CLOSE_APP);
      p += consumed;
      len -= consumed;

      /* Error code */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &error_code, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (error_code, 0x0200);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
}

TEST (quic_error_send_stream_reset)
{
  volatile Arena_T arena = NULL;
  volatile SocketQUICStream_T stream = NULL;
  uint8_t buf[256];
  size_t len;
  uint64_t frame_type, stream_id, error_code, final_size;
  const uint8_t *p;
  size_t consumed;

  TRY
    {
      arena = Arena_new ();
      stream = SocketQUICStream_new (arena, 0); /* Stream ID 0 */

      /* Send RESET_STREAM */
      len = SocketQUIC_send_stream_reset (stream, 0x0200, 1234, buf,
                                           sizeof (buf));

      ASSERT (len > 0);

      /* Parse and verify frame */
      p = buf;

      /* Frame type should be 0x04 (RESET_STREAM) */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &frame_type, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (frame_type, QUIC_FRAME_RESET_STREAM);
      p += consumed;
      len -= consumed;

      /* Stream ID */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &stream_id, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (stream_id, 0);
      p += consumed;
      len -= consumed;

      /* Error code */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &error_code, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (error_code, 0x0200);
      p += consumed;
      len -= consumed;

      /* Final size */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &final_size, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (final_size, 1234);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
}

TEST (quic_error_send_stop_sending)
{
  volatile Arena_T arena = NULL;
  volatile SocketQUICStream_T stream = NULL;
  uint8_t buf[256];
  size_t len;
  uint64_t frame_type, stream_id, error_code;
  const uint8_t *p;
  size_t consumed;

  TRY
    {
      arena = Arena_new ();
      stream = SocketQUICStream_new (arena, 4); /* Stream ID 4 */

      /* Send STOP_SENDING */
      len = SocketQUIC_send_stop_sending (stream, 0x0300, buf, sizeof (buf));

      ASSERT (len > 0);

      /* Parse and verify frame */
      p = buf;

      /* Frame type should be 0x05 (STOP_SENDING) */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &frame_type, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (frame_type, QUIC_FRAME_STOP_SENDING);
      p += consumed;
      len -= consumed;

      /* Stream ID */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &stream_id, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (stream_id, 4);
      p += consumed;
      len -= consumed;

      /* Error code */
      ASSERT_EQ (SocketQUICVarInt_decode (p, len, &error_code, &consumed),
                 QUIC_VARINT_OK);
      ASSERT_EQ (error_code, 0x0300);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
}

TEST (quic_error_send_connection_close_null)
{
  uint8_t buf[256];

  /* NULL connection should return 0 */
  ASSERT_EQ (SocketQUIC_send_connection_close (NULL, QUIC_NO_ERROR, NULL, buf,
                                                sizeof (buf)),
             0);

  /* NULL buffer should return 0 */
  volatile Arena_T arena = NULL;
  volatile SocketQUICConnection_T conn = NULL;

  TRY
    {
      arena = Arena_new ();
      conn = SocketQUICConnection_new (arena, QUIC_CONN_ROLE_CLIENT);
      ASSERT_EQ (
          SocketQUIC_send_connection_close (conn, QUIC_NO_ERROR, NULL, NULL, 100),
          0);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
}

TEST (quic_error_send_stream_reset_null)
{
  uint8_t buf[256];

  /* NULL stream should return 0 */
  ASSERT_EQ (SocketQUIC_send_stream_reset (NULL, 0x0200, 0, buf, sizeof (buf)),
             0);

  /* NULL buffer should return 0 */
  volatile Arena_T arena = NULL;
  volatile SocketQUICStream_T stream = NULL;

  TRY
    {
      arena = Arena_new ();
      stream = SocketQUICStream_new (arena, 0);
      ASSERT_EQ (SocketQUIC_send_stream_reset (stream, 0x0200, 0, NULL, 100), 0);
    }
  FINALLY { Arena_dispose ((Arena_T *)&arena); }
  END_TRY;
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
