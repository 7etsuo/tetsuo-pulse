/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_addr_validation.c - libFuzzer for QUIC Address Validation (RFC 9000
 * §8)
 *
 * Fuzzes address validation token generation/verification and path challenge:
 * - Token generation from sockaddr
 * - Token validation with expiration
 * - Amplification limit checking
 * - PATH_CHALLENGE/PATH_RESPONSE generation and verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make
 * fuzz_quic_addr_validation ./fuzz_quic_addr_validation corpus/quic_addr/
 * -fork=16 -max_len=1024
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICAddrValidation.h"

/* Operation types */
enum
{
  OP_GENERATE_TOKEN,
  OP_VALIDATE_TOKEN,
  OP_AMPLIFICATION_LIMIT,
  OP_PATH_CHALLENGE,
  OP_PATH_RESPONSE,
  OP_RESULT_STRINGS,
  OP_MAX
};

/* Helper to read uint64_t from buffer */
static uint64_t
read_u64 (const uint8_t *data)
{
  uint64_t val = 0;
  for (int i = 0; i < 8; i++)
    val = (val << 8) | data[i];
  return val;
}

/* Helper to create sockaddr from fuzz data */
static void
make_sockaddr (const uint8_t *data, struct sockaddr_storage *addr,
               socklen_t *len)
{
  int is_ipv6 = data[0] & 1;

  if (is_ipv6)
    {
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
      memset (addr6, 0, sizeof (*addr6));
      addr6->sin6_family = AF_INET6;
      memcpy (&addr6->sin6_addr, data + 1, 16);
      addr6->sin6_port = (data[17] << 8) | data[18];
      *len = sizeof (struct sockaddr_in6);
    }
  else
    {
      struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
      memset (addr4, 0, sizeof (*addr4));
      addr4->sin_family = AF_INET;
      memcpy (&addr4->sin_addr, data + 1, 4);
      addr4->sin_port = (data[5] << 8) | data[6];
      *len = sizeof (struct sockaddr_in);
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 60)
    return 0;

  uint8_t op = data[0] % OP_MAX;

  switch (op)
    {
    case OP_GENERATE_TOKEN:
      {
        /* Test token generation */
        struct sockaddr_storage addr;
        socklen_t addr_len;
        make_sockaddr (data + 1, &addr, &addr_len);

        /* Secret key for HMAC (32 bytes) */
        uint8_t secret[32];
        memcpy (secret, data + 20, 32);

        uint8_t token[QUIC_ADDR_VALIDATION_MAX_TOKEN_SIZE];
        size_t token_len = sizeof (token);

        SocketQUICAddrValidation_Result result
            = SocketQUICAddrValidation_generate_token ((struct sockaddr *)&addr,
                                                       secret, token,
                                                       &token_len);
        (void)result;

        /* Test with small buffer */
        token_len = 10;
        result = SocketQUICAddrValidation_generate_token (
            (struct sockaddr *)&addr, secret, token, &token_len);
        (void)result;

        /* Test with NULL inputs */
        token_len = sizeof (token);
        SocketQUICAddrValidation_generate_token (NULL, secret, token,
                                                 &token_len);
        SocketQUICAddrValidation_generate_token ((struct sockaddr *)&addr, NULL,
                                                 token, &token_len);
        SocketQUICAddrValidation_generate_token ((struct sockaddr *)&addr,
                                                 secret, NULL, &token_len);
        SocketQUICAddrValidation_generate_token ((struct sockaddr *)&addr,
                                                 secret, token, NULL);
        break;
      }

    case OP_VALIDATE_TOKEN:
      {
        /* Test token validation */
        struct sockaddr_storage addr;
        socklen_t addr_len;
        make_sockaddr (data + 1, &addr, &addr_len);

        uint8_t secret[32];
        memcpy (secret, data + 20, 32);

        /* First generate a valid token */
        uint8_t token[QUIC_ADDR_VALIDATION_MAX_TOKEN_SIZE];
        size_t token_len = sizeof (token);

        SocketQUICAddrValidation_Result result
            = SocketQUICAddrValidation_generate_token ((struct sockaddr *)&addr,
                                                       secret, token,
                                                       &token_len);

        if (result == QUIC_ADDR_VALIDATION_OK)
          {
            /* Validate the token we just generated */
            result = SocketQUICAddrValidation_validate_token (
                token, token_len, (struct sockaddr *)&addr, secret);
            (void)result;

            /* Validate with different address */
            struct sockaddr_in different_addr;
            memset (&different_addr, 0, sizeof (different_addr));
            different_addr.sin_family = AF_INET;
            different_addr.sin_addr.s_addr = 0x12345678;
            result = SocketQUICAddrValidation_validate_token (
                token, token_len, (struct sockaddr *)&different_addr, secret);
            (void)result;

            /* Validate with different secret */
            uint8_t wrong_secret[32];
            memset (wrong_secret, 0xAB, 32);
            result = SocketQUICAddrValidation_validate_token (
                token, token_len, (struct sockaddr *)&addr, wrong_secret);
            (void)result;
          }

        /* Test with fuzzed token directly */
        size_t fuzz_token_len = size - 52;
        if (fuzz_token_len > 0 && fuzz_token_len <= QUIC_ADDR_VALIDATION_MAX_TOKEN_SIZE)
          {
            result = SocketQUICAddrValidation_validate_token (
                data + 52, fuzz_token_len, (struct sockaddr *)&addr, secret);
            (void)result;
          }

        /* Test NULL inputs */
        SocketQUICAddrValidation_validate_token (NULL, token_len,
                                                 (struct sockaddr *)&addr,
                                                 secret);
        SocketQUICAddrValidation_validate_token (token, token_len, NULL,
                                                 secret);
        SocketQUICAddrValidation_validate_token (token, token_len,
                                                 (struct sockaddr *)&addr,
                                                 NULL);

        /* Test with wrong token length */
        SocketQUICAddrValidation_validate_token (token, 0,
                                                 (struct sockaddr *)&addr,
                                                 secret);
        SocketQUICAddrValidation_validate_token (
            token, QUIC_ADDR_VALIDATION_MAX_TOKEN_SIZE + 1,
            (struct sockaddr *)&addr, secret);
        break;
      }

    case OP_AMPLIFICATION_LIMIT:
      {
        /* Test amplification limit checking */
        SocketQUICAddrValidation_State_T state;
        memset (&state, 0, sizeof (state));

        uint64_t bytes_received = read_u64 (data + 1);
        uint64_t bytes_sent = read_u64 (data + 9);
        size_t bytes_to_send = (size_t)read_u64 (data + 17);

        state.bytes_received = bytes_received;
        state.bytes_sent = bytes_sent;
        state.address_validated = 0;

        /* Check if we can send */
        int can_send = SocketQUICAddrValidation_check_amplification_limit (
            &state, bytes_to_send);
        (void)can_send;

        /* Update counters */
        SocketQUICAddrValidation_update_counters (&state, 100, 50);
        SocketQUICAddrValidation_update_counters (&state, 0, 1000);

        /* Check again after update */
        can_send = SocketQUICAddrValidation_check_amplification_limit (&state,
                                                                       1000);
        (void)can_send;

        /* Mark as validated - should always allow send */
        SocketQUICAddrValidation_mark_validated (&state, 12345678);
        can_send = SocketQUICAddrValidation_check_amplification_limit (&state,
                                                                       1000000);
        (void)can_send;

        /* Test NULL state */
        SocketQUICAddrValidation_check_amplification_limit (NULL, 100);

        /* Test edge cases */
        state.address_validated = 0;
        state.bytes_received = 0;
        can_send
            = SocketQUICAddrValidation_check_amplification_limit (&state, 1);
        (void)can_send;

        state.bytes_received = UINT64_MAX / 3;
        can_send = SocketQUICAddrValidation_check_amplification_limit (
            &state, UINT64_MAX);
        (void)can_send;
        break;
      }

    case OP_PATH_CHALLENGE:
      {
        /* Test PATH_CHALLENGE generation */
        SocketQUICPathChallenge_T challenge;
        SocketQUICPathChallenge_init (&challenge);

        /* Create destination address */
        struct sockaddr_storage addr;
        socklen_t addr_len;
        make_sockaddr (data + 1, &addr, &addr_len);

        uint64_t timestamp = read_u64 (data + 20);

        /* Generate a challenge */
        SocketQUICAddrValidation_Result result
            = SocketQUICPathChallenge_generate (&challenge,
                                                (struct sockaddr *)&addr,
                                                timestamp);
        (void)result;

        /* Check pending state */
        int pending = SocketQUICPathChallenge_is_pending (&challenge);
        (void)pending;

        /* Generate another challenge (should overwrite) */
        result = SocketQUICPathChallenge_generate (&challenge,
                                                   (struct sockaddr *)&addr,
                                                   timestamp + 1000);
        (void)result;

        /* Test NULL inputs */
        SocketQUICPathChallenge_init (NULL);
        SocketQUICPathChallenge_generate (NULL, (struct sockaddr *)&addr,
                                          timestamp);
        SocketQUICPathChallenge_generate (&challenge, NULL, timestamp);
        SocketQUICPathChallenge_is_pending (NULL);
        break;
      }

    case OP_PATH_RESPONSE:
      {
        /* Test PATH_RESPONSE verification */
        SocketQUICPathChallenge_T challenge;
        SocketQUICPathChallenge_init (&challenge);

        struct sockaddr_storage addr;
        socklen_t addr_len;
        make_sockaddr (data + 1, &addr, &addr_len);

        uint64_t timestamp = read_u64 (data + 20);

        /* Generate a challenge first */
        SocketQUICAddrValidation_Result result
            = SocketQUICPathChallenge_generate (&challenge,
                                                (struct sockaddr *)&addr,
                                                timestamp);

        if (result == QUIC_ADDR_VALIDATION_OK)
          {
            /* Verify with correct response (copy of challenge data) */
            int valid = SocketQUICPathChallenge_verify_response (
                &challenge, challenge.data, QUIC_PATH_CHALLENGE_SIZE);
            (void)valid;

            /* Verify with wrong response */
            uint8_t wrong_response[QUIC_PATH_CHALLENGE_SIZE];
            memcpy (wrong_response, data + 28, QUIC_PATH_CHALLENGE_SIZE);
            valid = SocketQUICPathChallenge_verify_response (
                &challenge, wrong_response, QUIC_PATH_CHALLENGE_SIZE);
            (void)valid;

            /* Verify with wrong length */
            valid = SocketQUICPathChallenge_verify_response (
                &challenge, challenge.data, QUIC_PATH_CHALLENGE_SIZE - 1);
            (void)valid;
            valid = SocketQUICPathChallenge_verify_response (
                &challenge, challenge.data, QUIC_PATH_CHALLENGE_SIZE + 1);
            (void)valid;
            valid
                = SocketQUICPathChallenge_verify_response (&challenge, challenge.data, 0);
            (void)valid;

            /* Complete the challenge */
            SocketQUICPathChallenge_complete (&challenge);

            /* Verify after complete (should fail - not pending) */
            valid = SocketQUICPathChallenge_verify_response (
                &challenge, challenge.data, QUIC_PATH_CHALLENGE_SIZE);
            (void)valid;
          }

        /* Test NULL inputs */
        SocketQUICPathChallenge_verify_response (NULL, data + 28,
                                                 QUIC_PATH_CHALLENGE_SIZE);
        SocketQUICPathChallenge_verify_response (&challenge, NULL,
                                                 QUIC_PATH_CHALLENGE_SIZE);
        SocketQUICPathChallenge_complete (NULL);
        break;
      }

    case OP_RESULT_STRINGS:
      {
        /* Test result string function */
        SocketQUICAddrValidation_Result results[]
            = { QUIC_ADDR_VALIDATION_OK,
                QUIC_ADDR_VALIDATION_ERROR_NULL,
                QUIC_ADDR_VALIDATION_ERROR_INVALID,
                QUIC_ADDR_VALIDATION_ERROR_EXPIRED,
                QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE,
                QUIC_ADDR_VALIDATION_ERROR_CRYPTO,
                QUIC_ADDR_VALIDATION_ERROR_AMPLIFICATION };

        for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
          {
            const char *str
                = SocketQUICAddrValidation_result_string (results[i]);
            (void)str;
          }

        /* Test with fuzzed value */
        const char *str = SocketQUICAddrValidation_result_string (
            (SocketQUICAddrValidation_Result)data[1]);
        (void)str;
        break;
      }
    }

  return 0;
}
