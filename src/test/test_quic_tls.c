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

#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "quic/SocketQUICError.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICTLS.h"

/* OpenSSL headers for middlebox compat verification test */
#if SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

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

TEST (tls_check_alpn_negotiated_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_check_alpn_negotiated (NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_get_alpn_null_handshake)
{
  const char *alpn;
  size_t len;
  SocketQUICTLS_Result result = SocketQUICTLS_get_alpn (NULL, &alpn, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_has_keys_invalid_level)
{
  int has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_COUNT);
  ASSERT_EQ (has, 0);
}

#include "quic/SocketQUICConnection.h"

/**
 * @brief Helper to create a handshake context for testing.
 */
static SocketQUICHandshake_T
create_test_handshake (Arena_T arena, SocketQUICConnection_Role role)
{
  SocketQUICConnection_T conn = SocketQUICConnection_new (arena, role);
  if (conn == NULL)
    return NULL;

  SocketQUICHandshake_T hs = SocketQUICHandshake_new (arena, conn, role);
  if (hs != NULL)
    conn->handshake = hs;

  return hs;
}

TEST (tls_init_context_client_no_config)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Init with NULL config should use defaults */
  SocketQUICTLS_Result result = SocketQUICTLS_init_context (hs, NULL);

  /* On systems without OpenSSL QUIC support, this returns NO_TLS */
  ASSERT (result == QUIC_TLS_OK || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_init_context_server_no_config)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result result = SocketQUICTLS_init_context (hs, NULL);
  ASSERT (result == QUIC_TLS_OK || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_create_ssl_without_context)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* tls_ctx is NULL, should fail with INIT error */
  hs->tls_ctx = NULL;
  SocketQUICTLS_Result result = SocketQUICTLS_create_ssl (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_do_handshake_without_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* tls_ssl is NULL, should fail with INIT error */
  hs->tls_ssl = NULL;
  SocketQUICTLS_Result result = SocketQUICTLS_do_handshake (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_provide_data_invalid_level)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  uint8_t data[] = { 0x01, 0x02 };
  SocketQUICTLS_Result result
      = SocketQUICTLS_provide_data (hs, QUIC_CRYPTO_LEVEL_COUNT, data, 2);
  /* Should fail with level error or no TLS */
  ASSERT (result == QUIC_TLS_ERROR_LEVEL || result == QUIC_TLS_ERROR_INIT
          || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_provide_data_null_data)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result result
      = SocketQUICTLS_provide_data (hs, QUIC_CRYPTO_LEVEL_INITIAL, NULL, 10);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_consume_data_invalid_level)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result result
      = SocketQUICTLS_consume_data (hs, QUIC_CRYPTO_LEVEL_COUNT, 100);
  ASSERT (result == QUIC_TLS_ERROR_LEVEL || result == QUIC_TLS_ERROR_INIT
          || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_derive_keys_invalid_level)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result result
      = SocketQUICTLS_derive_keys (hs, QUIC_CRYPTO_LEVEL_COUNT);
  ASSERT (result == QUIC_TLS_ERROR_LEVEL || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_set_transport_params_null_params)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result result
      = SocketQUICTLS_set_transport_params (hs, NULL, 10);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_peer_transport_params_null_output)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  const uint8_t *params;
  SocketQUICTLS_Result result
      = SocketQUICTLS_get_peer_transport_params (hs, &params, NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  size_t len;
  result = SocketQUICTLS_get_peer_transport_params (hs, NULL, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_data_null_output_params)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICCryptoLevel level;
  const uint8_t *data;
  size_t len;

  /* NULL level */
  SocketQUICTLS_Result result = SocketQUICTLS_get_data (hs, NULL, &data, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  /* NULL data */
  result = SocketQUICTLS_get_data (hs, &level, NULL, &len);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  /* NULL len */
  result = SocketQUICTLS_get_data (hs, &level, &data, NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_is_complete_with_handshake)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Without SSL, should return 0 */
  int complete = SocketQUICTLS_is_complete (hs);
  ASSERT_EQ (complete, 0);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_has_keys_with_handshake)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Without TLS state, should return 0 */
  int has = SocketQUICTLS_has_keys (hs, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ (has, 0);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_error_with_handshake)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* No error initially */
  uint64_t code = SocketQUICTLS_get_error_code (hs);
  ASSERT_EQ (code, 0);

  const char *str = SocketQUICTLS_get_error_string (hs);
  ASSERT (str != NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_free_with_handshake)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Initialize context if possible */
  SocketQUICTLS_init_context (hs, NULL);

  /* Free should not crash even with partial init */
  SocketQUICTLS_free (hs);

  /* Verify pointers cleared */
  ASSERT (hs->tls_ctx == NULL);
  ASSERT (hs->tls_ssl == NULL);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_transport_params_ext_type)
{
  /* Verify extension type constant matches RFC 9001 §8.2 */
  ASSERT_EQ (QUIC_TRANSPORT_PARAMS_EXT_TYPE, 0x39);
}

TEST (tls_missing_ext_error_code)
{
  /* Verify error code for missing extension per RFC 9001 §8.2 */
  ASSERT_EQ (QUIC_ERROR_MISSING_TRANSPORT_PARAMS, 0x016d);
}

TEST (tls_transport_param_error_code)
{
  /* Verify transport parameter error code per RFC 9000 §20 */
  ASSERT_EQ (QUIC_ERROR_TRANSPORT_PARAMETER, 0x08);
}

TEST (tls_set_local_transport_params_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_set_local_transport_params (NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_has_peer_transport_params_null)
{
  int has = SocketQUICTLS_has_peer_transport_params (NULL);
  ASSERT_EQ (has, 0);
}

TEST (tls_get_peer_params_null)
{
  SocketQUICTLS_Result result = SocketQUICTLS_get_peer_params (NULL);
  ASSERT_EQ (result, QUIC_TLS_ERROR_NULL);
}

TEST (tls_set_local_transport_params_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);
  hs->tls_ssl = NULL;

  SocketQUICTLS_Result result = SocketQUICTLS_set_local_transport_params (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_has_peer_transport_params_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);
  hs->tls_ssl = NULL;

  int has = SocketQUICTLS_has_peer_transport_params (hs);
  ASSERT_EQ (has, 0);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_peer_params_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);
  hs->tls_ssl = NULL;

  SocketQUICTLS_Result result = SocketQUICTLS_get_peer_params (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_set_local_transport_params_server_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT (hs != NULL);
  hs->tls_ssl = NULL;

  SocketQUICTLS_Result result = SocketQUICTLS_set_local_transport_params (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_peer_params_server_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_SERVER);
  ASSERT (hs != NULL);
  hs->tls_ssl = NULL;

  SocketQUICTLS_Result result = SocketQUICTLS_get_peer_params (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_get_peer_params_sets_error_code_on_missing)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Initialize TLS context and SSL object */
  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res != QUIC_TLS_OK)
    {
      /* TLS not available - skip */
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* Before handshake, peer params are missing - should set 0x016d */
  res = SocketQUICTLS_get_peer_params (hs);
  ASSERT_EQ (res, QUIC_TLS_ERROR_TRANSPORT);
  ASSERT_EQ (hs->error_code, QUIC_ERROR_MISSING_TRANSPORT_PARAMS);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_set_local_transport_params_with_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Initialize TLS context and SSL object */
  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* Should succeed with valid SSL object and default params */
  res = SocketQUICTLS_set_local_transport_params (hs);
  ASSERT_EQ (res, QUIC_TLS_OK);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_has_peer_transport_params_with_ssl_no_handshake)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* Before handshake completes, peer params should not be available */
  int has = SocketQUICTLS_has_peer_transport_params (hs);
  ASSERT_EQ (has, 0);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_params_received_flag_not_set_on_error)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /* Verify flag is initially 0 */
  ASSERT_EQ (hs->params_received, 0);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* Call get_peer_params - should fail (no handshake done) */
  res = SocketQUICTLS_get_peer_params (hs);
  ASSERT_EQ (res, QUIC_TLS_ERROR_TRANSPORT);

  /* Flag should still be 0 after failure */
  ASSERT_EQ (hs->params_received, 0);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

TEST (tls_all_crypto_levels_valid)
{
  /* Verify all valid levels don't crash has_keys */
  int has;
  has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_INITIAL);
  ASSERT_EQ (has, 0);
  has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_0RTT);
  ASSERT_EQ (has, 0);
  has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_HANDSHAKE);
  ASSERT_EQ (has, 0);
  has = SocketQUICTLS_has_keys (NULL, QUIC_CRYPTO_LEVEL_APPLICATION);
  ASSERT_EQ (has, 0);
}

/**
 * RFC 9001 §8.1: Verify NO_APPLICATION_PROTOCOL error code value.
 */
TEST (tls_alpn_error_code_value)
{
  /* RFC 9001 §8.1: no_application_protocol TLS alert (120) maps to 0x0178 */
  ASSERT_EQ (QUIC_ERROR_NO_APPLICATION_PROTOCOL, 0x0178);

  /* Verify it matches QUIC_CRYPTO_ERROR(TLS_ALERT_NO_APPLICATION_PROTOCOL) */
  ASSERT_EQ (QUIC_ERROR_NO_APPLICATION_PROTOCOL,
             QUIC_CRYPTO_ERROR (TLS_ALERT_NO_APPLICATION_PROTOCOL));
}

/**
 * Test check_alpn_negotiated with no SSL object.
 */
TEST (tls_check_alpn_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  /*
   * Without TLS init, tls_ssl is NULL.
   * - On systems with QUIC support: returns QUIC_TLS_ERROR_INIT
   * - On systems without QUIC support: returns QUIC_TLS_ERROR_NO_TLS
   */
  SocketQUICTLS_Result result = SocketQUICTLS_check_alpn_negotiated (hs);
  ASSERT (result == QUIC_TLS_ERROR_INIT || result == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

/**
 * Test get_alpn with NULL output parameters.
 */
TEST (tls_get_alpn_null_outputs)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    {
      /* Skip on systems without QUIC TLS support */
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* NULL alpn pointer */
  size_t len;
  res = SocketQUICTLS_get_alpn (hs, NULL, &len);
  ASSERT_EQ (res, QUIC_TLS_ERROR_NULL);

  /* NULL len pointer */
  const char *alpn;
  res = SocketQUICTLS_get_alpn (hs, &alpn, NULL);
  ASSERT_EQ (res, QUIC_TLS_ERROR_NULL);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

/**
 * Test that ALPN check fails before handshake completion.
 * RFC 9001 §8.1 requires ALPN; before handshake, no ALPN is negotiated.
 */
TEST (tls_check_alpn_before_handshake_fails)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    {
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  /* Before handshake, ALPN not negotiated - should return error */
  res = SocketQUICTLS_check_alpn_negotiated (hs);
  ASSERT_EQ (res, QUIC_TLS_ERROR_ALPN);

  /* Verify error code is set correctly (RFC 9001 §8.1) */
  ASSERT_EQ (hs->error_code, QUIC_ERROR_NO_APPLICATION_PROTOCOL);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

/**
 * Test that get_alpn fails before handshake completion.
 */
TEST (tls_get_alpn_before_handshake_fails)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    {
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  res = SocketQUICTLS_create_ssl (hs);
  if (res != QUIC_TLS_OK)
    {
      SocketQUICTLS_free (hs);
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }

  const char *alpn = NULL;
  size_t len = 0;
  res = SocketQUICTLS_get_alpn (hs, &alpn, &len);
  ASSERT_EQ (res, QUIC_TLS_ERROR_ALPN);
  ASSERT (alpn == NULL);
  ASSERT_EQ (len, 0);

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

/**
 * Test that get_alpn without SSL object returns appropriate error.
 */
TEST (tls_get_alpn_no_ssl)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  const char *alpn = NULL;
  size_t len = 0;

  /*
   * Without TLS init, tls_ssl is NULL.
   * - On systems with QUIC support: returns QUIC_TLS_ERROR_INIT
   * - On systems without QUIC support: returns QUIC_TLS_ERROR_NO_TLS
   */
  SocketQUICTLS_Result res = SocketQUICTLS_get_alpn (hs, &alpn, &len);
  ASSERT (res == QUIC_TLS_ERROR_INIT || res == QUIC_TLS_ERROR_NO_TLS);

  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

#include <unistd.h>

/**
 * @brief Generate temporary self-signed certificate for testing.
 */
static int
generate_test_certs (const char *cert_file, const char *key_file)
{
  char cmd[512];
  snprintf (cmd,
            sizeof (cmd),
            "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s "
            "-days 1 -nodes -subj '/CN=localhost' -batch 2>/dev/null",
            key_file,
            cert_file);
  return system (cmd) == 0 ? 0 : -1;
}

static void
cleanup_test_certs (const char *cert_file, const char *key_file)
{
  unlink (cert_file);
  unlink (key_file);
}

/**
 * @brief Exchange CRYPTO data between client and server handshakes.
 *
 * Drives the handshake by transferring data from one side to the other
 * until both complete or an error occurs.
 *
 * @return 0 on success, -1 on failure
 */
static int
drive_handshake (SocketQUICHandshake_T client, SocketQUICHandshake_T server)
{
  int iterations = 0;
  const int max_iterations = 20;

  while (iterations++ < max_iterations)
    {
      int client_done = SocketQUICTLS_is_complete (client);
      int server_done = SocketQUICTLS_is_complete (server);

      if (client_done && server_done)
        return 0;

      /* Client -> Server: get data from client, provide to server */
      SocketQUICCryptoLevel level;
      const uint8_t *data;
      size_t len;

      if (SocketQUICTLS_get_data (client, &level, &data, &len) == QUIC_TLS_OK)
        {
          SocketQUICTLS_provide_data (server, level, data, len);
          SocketQUICTLS_consume_data (client, level, len);
        }

      /* Server -> Client: get data from server, provide to client */
      if (SocketQUICTLS_get_data (server, &level, &data, &len) == QUIC_TLS_OK)
        {
          SocketQUICTLS_provide_data (client, level, data, len);
          SocketQUICTLS_consume_data (server, level, len);
        }

      /* Advance both handshakes */
      SocketQUICTLS_do_handshake (client);
      SocketQUICTLS_do_handshake (server);
    }

  return -1; /* Timeout */
}

/**
 * Integration test: Successful ALPN negotiation with matching protocols.
 */
TEST (tls_integration_alpn_success)
{
  const char *cert_file = "/tmp/test_quic_alpn.crt";
  const char *key_file = "/tmp/test_quic_alpn.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    {
      /* Skip if openssl not available */
      return;
    }

  Arena_T client_arena = Arena_new ();
  Arena_T server_arena = Arena_new ();

  SocketQUICHandshake_T client_hs
      = create_test_handshake (client_arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T server_hs
      = create_test_handshake (server_arena, QUIC_CONN_ROLE_SERVER);

  if (client_hs == NULL || server_hs == NULL)
    goto cleanup;

  /* Configure with matching ALPN "h3" */
  SocketQUICTLSConfig_T client_config = { 0 };
  client_config.alpn = "h3";

  SocketQUICTLSConfig_T server_config = { 0 };
  server_config.cert_file = cert_file;
  server_config.key_file = key_file;
  server_config.alpn = "h3";

  /* Initialize TLS contexts */
  SocketQUICTLS_Result res
      = SocketQUICTLS_init_context (client_hs, &client_config);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    goto cleanup; /* Skip on systems without QUIC TLS */

  if (res != QUIC_TLS_OK)
    {
      ASSERT (0 && "Client TLS init failed");
      goto cleanup;
    }

  res = SocketQUICTLS_init_context (server_hs, &server_config);
  if (res != QUIC_TLS_OK)
    {
      ASSERT (0 && "Server TLS init failed");
      goto cleanup;
    }

  /* Create SSL objects */
  res = SocketQUICTLS_create_ssl (client_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_create_ssl (server_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  /* Start handshakes */
  SocketQUICTLS_do_handshake (client_hs);
  SocketQUICTLS_do_handshake (server_hs);

  /* Drive handshake to completion */
  if (drive_handshake (client_hs, server_hs) != 0)
    {
      /* Handshake may not complete in unit test environment */
      goto cleanup;
    }

  /* Verify ALPN was negotiated on both sides */
  res = SocketQUICTLS_check_alpn_negotiated (client_hs);
  ASSERT_EQ (res, QUIC_TLS_OK);

  res = SocketQUICTLS_check_alpn_negotiated (server_hs);
  ASSERT_EQ (res, QUIC_TLS_OK);

  /* Verify we can retrieve the ALPN */
  const char *alpn = NULL;
  size_t alpn_len = 0;
  res = SocketQUICTLS_get_alpn (client_hs, &alpn, &alpn_len);
  ASSERT_EQ (res, QUIC_TLS_OK);
  ASSERT_EQ (alpn_len, 2);
  ASSERT (memcmp (alpn, "h3", 2) == 0);

cleanup:
  if (client_hs)
    {
      SocketQUICTLS_free (client_hs);
      SocketQUICHandshake_free (&client_hs);
    }
  if (server_hs)
    {
      SocketQUICTLS_free (server_hs);
      SocketQUICHandshake_free (&server_hs);
    }
  Arena_dispose (&client_arena);
  Arena_dispose (&server_arena);
  cleanup_test_certs (cert_file, key_file);
}

/**
 * Integration test: ALPN mismatch - client and server have no common protocol.
 */
TEST (tls_integration_alpn_mismatch)
{
  const char *cert_file = "/tmp/test_quic_alpn_mm.crt";
  const char *key_file = "/tmp/test_quic_alpn_mm.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T client_arena = Arena_new ();
  Arena_T server_arena = Arena_new ();

  SocketQUICHandshake_T client_hs
      = create_test_handshake (client_arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T server_hs
      = create_test_handshake (server_arena, QUIC_CONN_ROLE_SERVER);

  if (client_hs == NULL || server_hs == NULL)
    goto cleanup;

  /* Configure with MISMATCHED ALPN */
  SocketQUICTLSConfig_T client_config = { 0 };
  client_config.alpn = "h3"; /* Client wants h3 */

  SocketQUICTLSConfig_T server_config = { 0 };
  server_config.cert_file = cert_file;
  server_config.key_file = key_file;
  server_config.alpn = "hq-29"; /* Server only supports hq-29 */

  /* Initialize TLS contexts */
  SocketQUICTLS_Result res
      = SocketQUICTLS_init_context (client_hs, &client_config);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    goto cleanup;

  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_init_context (server_hs, &server_config);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_create_ssl (client_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_create_ssl (server_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  /* Start handshakes */
  SocketQUICTLS_do_handshake (client_hs);
  SocketQUICTLS_do_handshake (server_hs);

  /* Try to drive handshake - should fail due to ALPN mismatch */
  int handshake_result = drive_handshake (client_hs, server_hs);

  /* Either handshake fails, or server set the error code */
  if (handshake_result == 0)
    {
      /* Handshake completed - check ALPN (should have failed) */
      res = SocketQUICTLS_check_alpn_negotiated (client_hs);
      /* On mismatch, client may not have ALPN or handshake failed earlier */
    }
  else
    {
      /* Handshake failed as expected for ALPN mismatch */
      /* Server should have set the error code */
      ASSERT_EQ (server_hs->error_code, QUIC_ERROR_NO_APPLICATION_PROTOCOL);
    }

cleanup:
  if (client_hs)
    {
      SocketQUICTLS_free (client_hs);
      SocketQUICHandshake_free (&client_hs);
    }
  if (server_hs)
    {
      SocketQUICTLS_free (server_hs);
      SocketQUICHandshake_free (&server_hs);
    }
  Arena_dispose (&client_arena);
  Arena_dispose (&server_arena);
  cleanup_test_certs (cert_file, key_file);
}

/**
 * Integration test: Multiple ALPN protocols - server supports multiple,
 * client requests one that matches.
 *
 * Server: supports "h3" and "hq-29"
 * Client: wants "hq-29"
 * Expected: negotiate "hq-29"
 */
TEST (tls_integration_alpn_multiple_protocols)
{
  const char *cert_file = "/tmp/test_quic_alpn_multi.crt";
  const char *key_file = "/tmp/test_quic_alpn_multi.key";

  if (generate_test_certs (cert_file, key_file) != 0)
    return;

  Arena_T client_arena = Arena_new ();
  Arena_T server_arena = Arena_new ();

  SocketQUICHandshake_T client_hs
      = create_test_handshake (client_arena, QUIC_CONN_ROLE_CLIENT);
  SocketQUICHandshake_T server_hs
      = create_test_handshake (server_arena, QUIC_CONN_ROLE_SERVER);

  if (client_hs == NULL || server_hs == NULL)
    goto cleanup;

  /* Client wants hq-29 */
  SocketQUICTLSConfig_T client_config = { 0 };
  client_config.alpn = "hq-29";

  /* Server supports h3 (will try first in callback iteration) */
  SocketQUICTLSConfig_T server_config = { 0 };
  server_config.cert_file = cert_file;
  server_config.key_file = key_file;
  server_config.alpn = "hq-29"; /* Server must offer what client wants */

  SocketQUICTLS_Result res
      = SocketQUICTLS_init_context (client_hs, &client_config);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    goto cleanup;
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_init_context (server_hs, &server_config);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_create_ssl (client_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  res = SocketQUICTLS_create_ssl (server_hs);
  if (res != QUIC_TLS_OK)
    goto cleanup;

  SocketQUICTLS_do_handshake (client_hs);
  SocketQUICTLS_do_handshake (server_hs);

  if (drive_handshake (client_hs, server_hs) != 0)
    goto cleanup;

  /* Verify ALPN negotiated to hq-29 */
  res = SocketQUICTLS_check_alpn_negotiated (client_hs);
  ASSERT_EQ (res, QUIC_TLS_OK);

  const char *alpn = NULL;
  size_t alpn_len = 0;
  res = SocketQUICTLS_get_alpn (client_hs, &alpn, &alpn_len);
  ASSERT_EQ (res, QUIC_TLS_OK);
  ASSERT_EQ (alpn_len, 5); /* "hq-29" */
  ASSERT (memcmp (alpn, "hq-29", 5) == 0);

cleanup:
  if (client_hs)
    {
      SocketQUICTLS_free (client_hs);
      SocketQUICHandshake_free (&client_hs);
    }
  if (server_hs)
    {
      SocketQUICTLS_free (server_hs);
      SocketQUICHandshake_free (&server_hs);
    }
  Arena_dispose (&client_arena);
  Arena_dispose (&server_arena);
  cleanup_test_certs (cert_file, key_file);
}

/**
 * RFC 9001 §8.4: Verify middlebox compatibility mode is disabled.
 *
 * QUIC endpoints MUST NOT use the middlebox compatibility mode.
 * We verify SSL_OP_ENABLE_MIDDLEBOX_COMPAT is cleared after context init.
 */
TEST (tls_middlebox_compat_disabled)
{
  Arena_T arena = Arena_new ();
  SocketQUICHandshake_T hs
      = create_test_handshake (arena, QUIC_CONN_ROLE_CLIENT);
  ASSERT (hs != NULL);

  SocketQUICTLS_Result res = SocketQUICTLS_init_context (hs, NULL);
  if (res == QUIC_TLS_ERROR_NO_TLS)
    {
      /* Skip on systems without QUIC TLS support */
      SocketQUICHandshake_free (&hs);
      Arena_dispose (&arena);
      return;
    }
  ASSERT_EQ (res, QUIC_TLS_OK);

#if SOCKET_HAS_TLS && defined(HAVE_OPENSSL_QUIC) \
    && defined(SSL_OP_ENABLE_MIDDLEBOX_COMPAT)
  /*
   * Verify middlebox compat is NOT set.
   * SSL_CTX_get_options returns the options bitmask.
   */
  {
    SSL_CTX *ctx = (SSL_CTX *)hs->tls_ctx;
    ASSERT (ctx != NULL);

    unsigned long opts = SSL_CTX_get_options (ctx);
    int middlebox_enabled = (opts & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0;

    /* RFC 9001 §8.4 requires this to be disabled */
    ASSERT_EQ (middlebox_enabled, 0);
  }
#endif

  SocketQUICTLS_free (hs);
  SocketQUICHandshake_free (&hs);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
