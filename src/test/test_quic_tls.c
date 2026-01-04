/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_tls.c
 * @brief Tests for QUIC-TLS interface (RFC 9001 Section 4.1).
 */

#include "test/Test.h"

#include <string.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICTLS.h"

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (tls_result_string_ok)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_OK);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Success") != NULL);
}

TEST (tls_result_string_null)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_NULL);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "NULL") != NULL);
}

TEST (tls_result_string_init)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_INIT);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "initialization") != NULL);
}

TEST (tls_result_string_cert)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_CERT);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Certificate") != NULL);
}

TEST (tls_result_string_key)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_KEY);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "key") != NULL);
}

TEST (tls_result_string_alpn)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_ALPN);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "ALPN") != NULL);
}

TEST (tls_result_string_transport)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_TRANSPORT);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Transport") != NULL);
}

TEST (tls_result_string_handshake)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_HANDSHAKE);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Handshake") != NULL);
}

TEST (tls_result_string_secrets)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_SECRETS);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Secret") != NULL);
}

TEST (tls_result_string_alert)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_ALERT);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "alert") != NULL);
}

TEST (tls_result_string_no_tls)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_NO_TLS);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "not available") != NULL);
}

TEST (tls_result_string_want_read)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_WANT_READ);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "data") != NULL);
}

TEST (tls_result_string_want_write)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_WANT_WRITE);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "send") != NULL);
}

TEST (tls_result_string_level)
{
  const char *str = SocketQUICTLS_result_string (QUIC_TLS_ERROR_LEVEL);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "level") != NULL);
}

TEST (tls_result_string_unknown)
{
  const char *str = SocketQUICTLS_result_string ((SocketQUICTLS_Result)999);
  ASSERT (str != NULL);
  ASSERT (strstr (str, "Unknown") != NULL);
}

/* ============================================================================
 * Alert to Error Conversion Tests (RFC 9001 §4.8)
 * ============================================================================
 */

TEST (tls_alert_to_error_zero)
{
  /* TLS close_notify (0) -> 0x0100 */
  uint64_t error = SocketQUICTLS_alert_to_error (0);
  ASSERT_EQ (error, 0x0100);
}

TEST (tls_alert_to_error_unexpected_message)
{
  /* TLS unexpected_message (10) -> 0x010A */
  uint64_t error = SocketQUICTLS_alert_to_error (10);
  ASSERT_EQ (error, 0x010A);
}

TEST (tls_alert_to_error_bad_record_mac)
{
  /* TLS bad_record_mac (20) -> 0x0114 */
  uint64_t error = SocketQUICTLS_alert_to_error (20);
  ASSERT_EQ (error, 0x0114);
}

TEST (tls_alert_to_error_handshake_failure)
{
  /* TLS handshake_failure (40) -> 0x0128 */
  uint64_t error = SocketQUICTLS_alert_to_error (40);
  ASSERT_EQ (error, 0x0128);
}

TEST (tls_alert_to_error_certificate_required)
{
  /* TLS certificate_required (116) -> 0x0174 */
  uint64_t error = SocketQUICTLS_alert_to_error (116);
  ASSERT_EQ (error, 0x0174);
}

TEST (tls_alert_to_error_max)
{
  /* TLS alert 255 -> 0x01FF */
  uint64_t error = SocketQUICTLS_alert_to_error (255);
  ASSERT_EQ (error, 0x01FF);
}

/* ============================================================================
 * NULL Argument Tests
 * ============================================================================
 */

TEST (tls_init_context_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_init_context (NULL, NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_create_ssl_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_create_ssl (NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_do_handshake_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_do_handshake (NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_provide_data_null_handshake)
{
  uint8_t data[] = { 0x01, 0x02, 0x03 };
  SocketQUICTLS_Result result
      = SocketQUICTLS_provide_data (NULL, QUIC_CRYPTO_LEVEL_INITIAL, data, 3);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_get_data_null_handshake)
{
  SocketQUICCryptoLevel level;
  const uint8_t *data;
  size_t len;
  SocketQUICTLS_Result result
      = SocketQUICTLS_get_data (NULL, &level, &data, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_consume_data_null)
{
  SocketQUICTLS_Result result
      = SocketQUICTLS_consume_data (NULL, QUIC_CRYPTO_LEVEL_INITIAL, 100);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_is_complete_null)
{
  int complete = SocketQUICTLS_is_complete (NULL);
  ASSERT_EQ (complete, 0);
}

TEST (tls_has_keys_null)
{
  int has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ (has, 0);
}

TEST (tls_derive_keys_null)
{
  SocketQUICTLS_Result result
      = SocketQUICTLS_derive_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_set_transport_params_null_handshake)
{
  uint8_t params[] = { 0x01 };
  SocketQUICTLS_Result result
      = SocketQUICTLS_set_transport_params (NULL, params, 1);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_get_peer_transport_params_null_handshake)
{
  const uint8_t *params;
  size_t len;
  SocketQUICTLS_Result result
      = SocketQUICTLS_get_peer_transport_params (NULL, &params, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_get_error_code_null)
{
  uint64_t code = SocketQUICTLS_get_error_code (NULL);
  ASSERT_EQ (code, 0);
}

TEST (tls_get_error_string_null)
{
  const char *str = SocketQUICTLS_get_error_string (NULL);
  ASSERT (str != NULL);
}

TEST (tls_free_null)
{
  /* Should not crash */
  SocketQUICTLS_free (NULL);
  ASSERT (1); /* If we get here, it didn't crash */
}

/* ============================================================================
 * Invalid Level Tests
 * ============================================================================
 */

TEST (tls_has_keys_invalid_level)
{
  int has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_COUNT);
  ASSERT_EQ (has, 0);
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
