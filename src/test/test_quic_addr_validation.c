/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_addr_validation.c
 * @brief Tests for QUIC Address Validation (RFC 9000 Section 8).
 */

#include "quic/SocketQUICAddrValidation.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

static void
setup_ipv4_addr (struct sockaddr_in *addr, const char *ip, uint16_t port)
{
  memset (addr, 0, sizeof (*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons (port);
  inet_pton (AF_INET, ip, &addr->sin_addr);
}

static void
setup_ipv6_addr (struct sockaddr_in6 *addr, const char *ip, uint16_t port)
{
  memset (addr, 0, sizeof (*addr));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons (port);
  inet_pton (AF_INET6, ip, &addr->sin6_addr);
}

/* ============================================================================
 * Amplification Limit Tests
 * ============================================================================
 */

static void
test_amplification_limit_before_validation (void)
{
  SocketQUICAddrValidation_State_T state = { 0 };

  /* Initial state: 0 bytes received/sent */
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 1)
          == 0);

  /* After receiving 100 bytes, can send up to 300 */
  SocketQUICAddrValidation_update_counters (&state, 0, 100);
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 300)
          == 1);
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 301)
          == 0);

  /* After sending 200 bytes, can send 100 more */
  SocketQUICAddrValidation_update_counters (&state, 200, 0);
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 100)
          == 1);
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 101)
          == 0);

  printf ("PASS: test_amplification_limit_before_validation\n");
}

static void
test_amplification_limit_after_validation (void)
{
  SocketQUICAddrValidation_State_T state = { 0 };

  /* Receive 100 bytes */
  SocketQUICAddrValidation_update_counters (&state, 0, 100);

  /* Mark as validated */
  SocketQUICAddrValidation_mark_validated (&state, 12345);

  /* After validation, no limit */
  assert (SocketQUICAddrValidation_check_amplification_limit (&state, 1000000)
          == 1);
  assert (state.address_validated == 1);
  assert (state.validation_time == 12345);

  printf ("PASS: test_amplification_limit_after_validation\n");
}

/* ============================================================================
 * Token Generation and Validation Tests
 * ============================================================================
 */

static void
test_token_generation_and_validation (void)
{
  struct sockaddr_in addr;
  uint8_t secret[32];
  uint8_t token[256];
  size_t token_len = sizeof (token);
  SocketQUICAddrValidation_Result result;

  /* Setup address and secret */
  setup_ipv4_addr (&addr, "192.0.2.1", 1234);
  SocketCrypto_random_bytes (secret, sizeof (secret));

  /* Generate token */
  result = SocketQUICAddrValidation_generate_token (
      (struct sockaddr *)&addr, secret, token, &token_len);
  assert (result == QUIC_ADDR_VALIDATION_OK);
  assert (token_len == QUIC_ADDR_VALIDATION_TOKEN_SIZE);

  /* Validate token with same address */
  result = SocketQUICAddrValidation_validate_token (
      token, token_len, (struct sockaddr *)&addr, secret);
  assert (result == QUIC_ADDR_VALIDATION_OK);
  (void)result; /* Suppress unused warning when NDEBUG defined */

  printf ("PASS: test_token_generation_and_validation\n");
}

static void
test_token_validation_wrong_address (void)
{
  struct sockaddr_in addr1, addr2;
  uint8_t secret[32];
  uint8_t token[256];
  size_t token_len = sizeof (token);
  SocketQUICAddrValidation_Result result;

  /* Setup addresses and secret */
  setup_ipv4_addr (&addr1, "192.0.2.1", 1234);
  setup_ipv4_addr (&addr2, "192.0.2.2", 1234);
  SocketCrypto_random_bytes (secret, sizeof (secret));

  /* Generate token for addr1 */
  result = SocketQUICAddrValidation_generate_token (
      (struct sockaddr *)&addr1, secret, token, &token_len);
  assert (result == QUIC_ADDR_VALIDATION_OK);

  /* Try to validate with addr2 - should fail */
  result = SocketQUICAddrValidation_validate_token (
      token, token_len, (struct sockaddr *)&addr2, secret);
  assert (result == QUIC_ADDR_VALIDATION_ERROR_INVALID);
  (void)result;

  printf ("PASS: test_token_validation_wrong_address\n");
}

static void
test_token_validation_wrong_secret (void)
{
  struct sockaddr_in addr;
  uint8_t secret1[32], secret2[32];
  uint8_t token[256];
  size_t token_len = sizeof (token);
  SocketQUICAddrValidation_Result result;

  /* Setup address and secrets */
  setup_ipv4_addr (&addr, "192.0.2.1", 1234);
  SocketCrypto_random_bytes (secret1, sizeof (secret1));
  SocketCrypto_random_bytes (secret2, sizeof (secret2));

  /* Generate token with secret1 */
  result = SocketQUICAddrValidation_generate_token (
      (struct sockaddr *)&addr, secret1, token, &token_len);
  assert (result == QUIC_ADDR_VALIDATION_OK);

  /* Try to validate with secret2 - should fail */
  result = SocketQUICAddrValidation_validate_token (
      token, token_len, (struct sockaddr *)&addr, secret2);
  assert (result == QUIC_ADDR_VALIDATION_ERROR_INVALID);
  (void)result;

  printf ("PASS: test_token_validation_wrong_secret\n");
}

static void
test_token_ipv6 (void)
{
  struct sockaddr_in6 addr;
  uint8_t secret[32];
  uint8_t token[256];
  size_t token_len = sizeof (token);
  SocketQUICAddrValidation_Result result;

  /* Setup IPv6 address and secret */
  setup_ipv6_addr (&addr, "2001:db8::1", 1234);
  SocketCrypto_random_bytes (secret, sizeof (secret));

  /* Generate token */
  result = SocketQUICAddrValidation_generate_token (
      (struct sockaddr *)&addr, secret, token, &token_len);
  assert (result == QUIC_ADDR_VALIDATION_OK);

  /* Validate token */
  result = SocketQUICAddrValidation_validate_token (
      token, token_len, (struct sockaddr *)&addr, secret);
  assert (result == QUIC_ADDR_VALIDATION_OK);
  (void)result;

  printf ("PASS: test_token_ipv6\n");
}

/* ============================================================================
 * Path Challenge Tests
 * ============================================================================
 */

static void
test_path_challenge_generation (void)
{
  SocketQUICPathChallenge_T challenge;
  struct sockaddr_in addr;
  SocketQUICAddrValidation_Result result;

  setup_ipv4_addr (&addr, "192.0.2.1", 4433);

  /* Initialize and generate challenge */
  SocketQUICPathChallenge_init (&challenge);
  result = SocketQUICPathChallenge_generate (&challenge,
                                              (struct sockaddr *)&addr, 12345);
  assert (result == QUIC_ADDR_VALIDATION_OK);
  assert (challenge.pending == 1);
  assert (challenge.sent_time == 12345);
  assert (challenge.peer_port == 4433);
  assert (challenge.is_ipv6 == 0);

  /* Data should be non-zero (random) */
  int all_zeros = 1;
  for (int i = 0; i < QUIC_PATH_CHALLENGE_SIZE; i++)
    {
      if (challenge.data[i] != 0)
        {
          all_zeros = 0;
          break;
        }
    }
  assert (all_zeros == 0);
  (void)result;
  (void)all_zeros;

  printf ("PASS: test_path_challenge_generation\n");
}

static void
test_path_challenge_verification (void)
{
  SocketQUICPathChallenge_T challenge;
  struct sockaddr_in addr;
  uint8_t response[QUIC_PATH_CHALLENGE_SIZE];

  setup_ipv4_addr (&addr, "192.0.2.1", 4433);

  /* Generate challenge */
  SocketQUICPathChallenge_init (&challenge);
  SocketQUICPathChallenge_generate (&challenge, (struct sockaddr *)&addr,
                                    12345);

  /* Copy challenge data as response */
  memcpy (response, challenge.data, QUIC_PATH_CHALLENGE_SIZE);

  /* Verify correct response */
  assert (
      SocketQUICPathChallenge_verify_response (&challenge, response, sizeof (response))
      == 1);

  /* Corrupt response */
  response[0] ^= 0xFF;
  assert (
      SocketQUICPathChallenge_verify_response (&challenge, response, sizeof (response))
      == 0);

  printf ("PASS: test_path_challenge_verification\n");
}

static void
test_path_challenge_completion (void)
{
  SocketQUICPathChallenge_T challenge;
  struct sockaddr_in addr;

  setup_ipv4_addr (&addr, "192.0.2.1", 4433);

  /* Generate and verify pending */
  SocketQUICPathChallenge_init (&challenge);
  SocketQUICPathChallenge_generate (&challenge, (struct sockaddr *)&addr,
                                    12345);
  assert (SocketQUICPathChallenge_is_pending (&challenge) == 1);

  /* Complete challenge */
  SocketQUICPathChallenge_complete (&challenge);
  assert (SocketQUICPathChallenge_is_pending (&challenge) == 0);

  printf ("PASS: test_path_challenge_completion\n");
}

static void
test_path_challenge_ipv6 (void)
{
  SocketQUICPathChallenge_T challenge;
  struct sockaddr_in6 addr;
  SocketQUICAddrValidation_Result result;

  setup_ipv6_addr (&addr, "2001:db8::1", 4433);

  /* Generate challenge for IPv6 */
  SocketQUICPathChallenge_init (&challenge);
  result = SocketQUICPathChallenge_generate (&challenge,
                                              (struct sockaddr *)&addr, 12345);
  assert (result == QUIC_ADDR_VALIDATION_OK);
  assert (challenge.is_ipv6 == 1);
  assert (challenge.peer_port == 4433);
  (void)result;

  printf ("PASS: test_path_challenge_ipv6\n");
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

static void
test_null_parameter_handling (void)
{
  SocketQUICAddrValidation_State_T state = { 0 };
  SocketQUICPathChallenge_T challenge;
  uint8_t token[256];
  size_t token_len = sizeof (token);
  uint8_t secret[32];
  struct sockaddr_in addr;

  setup_ipv4_addr (&addr, "192.0.2.1", 1234);

  /* Test NULL checks */
  assert (SocketQUICAddrValidation_check_amplification_limit (NULL, 100) == 0);

  assert (SocketQUICAddrValidation_generate_token (NULL, secret, token,
                                                    &token_len)
          == QUIC_ADDR_VALIDATION_ERROR_NULL);

  assert (SocketQUICAddrValidation_validate_token (
              NULL, QUIC_ADDR_VALIDATION_TOKEN_SIZE, (struct sockaddr *)&addr,
              secret)
          == QUIC_ADDR_VALIDATION_ERROR_NULL);

  assert (SocketQUICPathChallenge_generate (NULL, (struct sockaddr *)&addr,
                                             12345)
          == QUIC_ADDR_VALIDATION_ERROR_NULL);

  assert (SocketQUICPathChallenge_verify_response (NULL, token, 8) == 0);

  assert (SocketQUICPathChallenge_is_pending (NULL) == 0);

  printf ("PASS: test_null_parameter_handling\n");
}

static void
test_buffer_size_errors (void)
{
  struct sockaddr_in addr;
  uint8_t secret[32];
  uint8_t token[10]; /* Too small */
  size_t token_len = sizeof (token);

  setup_ipv4_addr (&addr, "192.0.2.1", 1234);
  SocketCrypto_random_bytes (secret, sizeof (secret));

  /* Buffer too small */
  assert (SocketQUICAddrValidation_generate_token (
              (struct sockaddr *)&addr, secret, token, &token_len)
          == QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE);

  printf ("PASS: test_buffer_size_errors\n");
}

static void
test_result_strings (void)
{
  /* Test all result strings are defined */
  const char *str;

  str = SocketQUICAddrValidation_result_string (QUIC_ADDR_VALIDATION_OK);
  assert (str != NULL && strlen (str) > 0);

  str = SocketQUICAddrValidation_result_string (
      QUIC_ADDR_VALIDATION_ERROR_NULL);
  assert (str != NULL && strlen (str) > 0);

  str = SocketQUICAddrValidation_result_string (
      QUIC_ADDR_VALIDATION_ERROR_INVALID);
  assert (str != NULL && strlen (str) > 0);
  (void)str;

  printf ("PASS: test_result_strings\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("Running QUIC Address Validation Tests...\n\n");

  /* Amplification limit tests */
  test_amplification_limit_before_validation ();
  test_amplification_limit_after_validation ();

  /* Token tests */
  test_token_generation_and_validation ();
  test_token_validation_wrong_address ();
  test_token_validation_wrong_secret ();
  test_token_ipv6 ();

  /* Path challenge tests */
  test_path_challenge_generation ();
  test_path_challenge_verification ();
  test_path_challenge_completion ();
  test_path_challenge_ipv6 ();

  /* Error handling tests */
  test_null_parameter_handling ();
  test_buffer_size_errors ();
  test_result_strings ();

  printf ("\nAll QUIC Address Validation tests passed!\n");
  return 0;
}
