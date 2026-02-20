/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICAddrValidation.c
 * @brief QUIC Address Validation implementation (RFC 9000 Section 8).
 */

#include "quic/SocketQUICAddrValidation.h"

#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"

const Except_T SocketQUICAddrValidation_Failed
    = { &SocketQUICAddrValidation_Failed, "QUIC address validation failed" };

/**
 * @brief Hash sockaddr into fixed-size buffer.
 *
 * Creates a deterministic hash of address for token binding.
 *
 * @param[in] addr Socket address.
 * @param[out] hash Output buffer (QUIC_TOKEN_ADDR_HASH_SIZE bytes).
 */
static void
hash_address (const struct sockaddr *addr,
              uint8_t hash[QUIC_TOKEN_ADDR_HASH_SIZE])
{
  unsigned char sha256_output[SOCKET_CRYPTO_SHA256_SIZE];

  if (!addr)
    {
      memset (hash, 0, QUIC_TOKEN_ADDR_HASH_SIZE);
      return;
    }

  if (addr->sa_family == AF_INET)
    {
      const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
      SocketCrypto_sha256 (
          &addr4->sin_addr, sizeof (addr4->sin_addr), sha256_output);
    }
  else if (addr->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
      SocketCrypto_sha256 (
          &addr6->sin6_addr, sizeof (addr6->sin6_addr), sha256_output);
    }
  else
    {
      memset (hash, 0, QUIC_TOKEN_ADDR_HASH_SIZE);
      return;
    }

  /* Use first QUIC_TOKEN_ADDR_HASH_SIZE bytes of SHA-256 */
  memcpy (hash, sha256_output, QUIC_TOKEN_ADDR_HASH_SIZE);
}

int
SocketQUICAddrValidation_check_amplification_limit (
    const SocketQUICAddrValidation_State_T *state, size_t bytes_to_send)
{
  if (!state)
    {
      return 0;
    }

  /* If already validated, no limit */
  if (state->address_validated)
    {
      return 1;
    }

  /* Check 3x amplification limit (RFC 9000 §8.1) */
  /* Overflow check: if bytes_received is huge, allow sending (conservative) */
  if (state->bytes_received
      > UINT64_MAX / QUIC_ADDR_VALIDATION_AMPLIFICATION_LIMIT)
    {
      return 1; /* No practical limit when overflow would occur */
    }

  uint64_t max_allowed
      = state->bytes_received * QUIC_ADDR_VALIDATION_AMPLIFICATION_LIMIT;

  /* Also check for overflow in addition */
  if (state->bytes_sent > UINT64_MAX - bytes_to_send)
    {
      return 0; /* Overflow in bytes_sent + bytes_to_send */
    }

  return (state->bytes_sent + bytes_to_send) <= max_allowed;
}

void
SocketQUICAddrValidation_update_counters (
    SocketQUICAddrValidation_State_T *state,
    size_t bytes_sent,
    size_t bytes_received)
{
  if (!state)
    {
      return;
    }

  /* Check for overflow in bytes_sent */
  if (state->bytes_sent > UINT64_MAX - bytes_sent)
    {
      /* Saturate at max value instead of wrapping */
      state->bytes_sent = UINT64_MAX;
    }
  else
    {
      state->bytes_sent += bytes_sent;
    }

  /* Check for overflow in bytes_received */
  if (state->bytes_received > UINT64_MAX - bytes_received)
    {
      state->bytes_received = UINT64_MAX;
    }
  else
    {
      state->bytes_received += bytes_received;
    }
}

void
SocketQUICAddrValidation_mark_validated (
    SocketQUICAddrValidation_State_T *state, uint64_t timestamp)
{
  if (!state)
    {
      return;
    }

  state->address_validated = 1;
  state->validation_time = timestamp;
}

/**
 * @brief Compute and verify token HMAC.
 *
 * @param[in] token Token buffer.
 * @param[in] token_timestamp Timestamp from token.
 * @param[in] addr Socket address.
 * @param[in] secret HMAC secret key.
 * @return QUIC_ADDR_VALIDATION_OK if valid, error code otherwise.
 */
static SocketQUICAddrValidation_Result
compute_and_verify_token_hmac (const uint8_t *token,
                               uint64_t token_timestamp,
                               const struct sockaddr *addr,
                               const uint8_t *secret)
{
  uint8_t addr_hash[QUIC_TOKEN_ADDR_HASH_SIZE];
  uint8_t hmac_input[QUIC_TOKEN_HMAC_INPUT_SIZE];
  unsigned char hmac_output[SOCKET_CRYPTO_SHA256_SIZE];

  hash_address (addr, addr_hash);

  socket_util_pack_be64 (hmac_input, token_timestamp);
  memcpy (hmac_input + QUIC_TOKEN_TIMESTAMP_SIZE,
          addr_hash,
          QUIC_TOKEN_ADDR_HASH_SIZE);

  TRY
  {
    SocketCrypto_hmac_sha256 (
        secret, 32, hmac_input, QUIC_TOKEN_HMAC_INPUT_SIZE, hmac_output);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    return QUIC_ADDR_VALIDATION_ERROR_CRYPTO;
  }
  END_TRY;

  if (SocketCrypto_secure_compare (
          token + QUIC_TOKEN_HMAC_OFFSET, hmac_output, QUIC_TOKEN_HMAC_SIZE)
      != 0)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  return QUIC_ADDR_VALIDATION_OK;
}

SocketQUICAddrValidation_Result
SocketQUICAddrValidation_generate_token (const struct sockaddr *addr,
                                         const uint8_t *secret,
                                         uint8_t *token,
                                         size_t *token_len)
{
  uint8_t addr_hash[QUIC_TOKEN_ADDR_HASH_SIZE];
  uint8_t hmac_input[QUIC_TOKEN_HMAC_INPUT_SIZE];
  unsigned char hmac_output[SOCKET_CRYPTO_SHA256_SIZE];
  uint64_t timestamp;

  /* Validate inputs */
  if (!addr || !secret || !token || !token_len)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  /* Token format: 8 timestamp + QUIC_TOKEN_ADDR_HASH_SIZE addr_hash + 32 HMAC
   */
  if (*token_len < QUIC_ADDR_VALIDATION_TOKEN_SIZE)
    {
      return QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE;
    }

  /* Get current timestamp */
  timestamp = (uint64_t)Socket_get_monotonic_ms ();

  /* Hash the address */
  hash_address (addr, addr_hash);

  /* Build HMAC input: timestamp || addr_hash */
  socket_util_pack_be64 (hmac_input, timestamp);
  memcpy (hmac_input + QUIC_TOKEN_TIMESTAMP_SIZE,
          addr_hash,
          QUIC_TOKEN_ADDR_HASH_SIZE);

  /* Compute HMAC-SHA256 */
  TRY
  {
    SocketCrypto_hmac_sha256 (
        secret, 32, hmac_input, QUIC_TOKEN_HMAC_INPUT_SIZE, hmac_output);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    return QUIC_ADDR_VALIDATION_ERROR_CRYPTO;
  }
  END_TRY;

  /* Build token: timestamp || addr_hash || HMAC */
  socket_util_pack_be64 (token, timestamp);
  memcpy (
      token + QUIC_TOKEN_TIMESTAMP_SIZE, addr_hash, QUIC_TOKEN_ADDR_HASH_SIZE);
  memcpy (token + QUIC_TOKEN_HMAC_OFFSET, hmac_output, QUIC_TOKEN_HMAC_SIZE);

  *token_len = QUIC_ADDR_VALIDATION_TOKEN_SIZE;
  return QUIC_ADDR_VALIDATION_OK;
}

SocketQUICAddrValidation_Result
SocketQUICAddrValidation_validate_token (const uint8_t *token,
                                         size_t token_len,
                                         const struct sockaddr *addr,
                                         const uint8_t *secret)
{
  volatile SocketQUICAddrValidation_Result result;
  uint64_t token_timestamp;
  uint64_t current_time;
  uint8_t addr_hash[QUIC_TOKEN_ADDR_HASH_SIZE];

  /* Validate inputs */
  if (!addr || !secret)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  /* Validate token format (inlined from validate_token_format) */
  if (!token)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  if (token_len != QUIC_ADDR_VALIDATION_TOKEN_SIZE)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  /* Extract timestamp */
  token_timestamp = socket_util_unpack_be64 (token);

  /* Check token expiration (inlined from check_token_expiration) */
  current_time = (uint64_t)Socket_get_monotonic_ms ();
  if (current_time > token_timestamp
      && (current_time - token_timestamp)
             > (QUIC_ADDR_VALIDATION_TOKEN_LIFETIME * SOCKET_MS_PER_SECOND))
    {
      return QUIC_ADDR_VALIDATION_ERROR_EXPIRED;
    }

  /* Verify address match (inlined from verify_token_address) */
  hash_address (addr, addr_hash);

  if (SocketCrypto_secure_compare (token + QUIC_TOKEN_TIMESTAMP_SIZE,
                                   addr_hash,
                                   QUIC_TOKEN_ADDR_HASH_SIZE)
      != 0)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  /* Verify HMAC */
  result = compute_and_verify_token_hmac (token, token_timestamp, addr, secret);
  if (result != QUIC_ADDR_VALIDATION_OK)
    {
      return result;
    }

  return QUIC_ADDR_VALIDATION_OK;
}

void
SocketQUICPathChallenge_init (SocketQUICPathChallenge_T *challenge)
{
  if (!challenge)
    {
      return;
    }

  memset (challenge, 0, sizeof (SocketQUICPathChallenge_T));
}

SocketQUICAddrValidation_Result
SocketQUICPathChallenge_generate (SocketQUICPathChallenge_T *challenge,
                                  const struct sockaddr *path,
                                  uint64_t timestamp)
{
  if (!challenge || !path)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  /* Generate 8 random bytes for challenge (RFC 9000 §8.2) */
  if (SocketCrypto_random_bytes (challenge->data, QUIC_PATH_CHALLENGE_SIZE)
      != 0)
    {
      return QUIC_ADDR_VALIDATION_ERROR_CRYPTO;
    }

  /* Store path information */
  if (path->sa_family == AF_INET)
    {
      const struct sockaddr_in *addr4 = (const struct sockaddr_in *)path;
      memcpy (challenge->peer_addr, &addr4->sin_addr, 4);
      challenge->peer_port = ntohs (addr4->sin_port);
      challenge->is_ipv6 = 0;
    }
  else if (path->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)path;
      memcpy (challenge->peer_addr, &addr6->sin6_addr, 16);
      challenge->peer_port = ntohs (addr6->sin6_port);
      challenge->is_ipv6 = 1;
    }
  else
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  challenge->sent_time = timestamp;
  challenge->pending = 1;

  return QUIC_ADDR_VALIDATION_OK;
}

int
SocketQUICPathChallenge_verify_response (
    const SocketQUICPathChallenge_T *challenge,
    const uint8_t *response_data,
    size_t response_len)
{
  if (!challenge || !response_data)
    {
      return 0;
    }

  /* Must be exactly 8 bytes */
  if (response_len != QUIC_PATH_CHALLENGE_SIZE)
    {
      return 0;
    }

  /* Must have pending challenge */
  if (!challenge->pending)
    {
      return 0;
    }

  /* Constant-time comparison to prevent timing attacks */
  return SocketCrypto_secure_compare (
             challenge->data, response_data, QUIC_PATH_CHALLENGE_SIZE)
         == 0;
}

void
SocketQUICPathChallenge_complete (SocketQUICPathChallenge_T *challenge)
{
  if (!challenge)
    {
      return;
    }

  challenge->pending = 0;

  /* Clear sensitive data */
  SocketCrypto_secure_clear (challenge->data, QUIC_PATH_CHALLENGE_SIZE);
}

int
SocketQUICPathChallenge_is_pending (const SocketQUICPathChallenge_T *challenge)
{
  if (!challenge)
    {
      return 0;
    }

  return challenge->pending;
}

const char *
SocketQUICAddrValidation_result_string (SocketQUICAddrValidation_Result result)
{
  switch (result)
    {
    case QUIC_ADDR_VALIDATION_OK:
      return "OK";
    case QUIC_ADDR_VALIDATION_ERROR_NULL:
      return "NULL parameter";
    case QUIC_ADDR_VALIDATION_ERROR_INVALID:
      return "Invalid token/data";
    case QUIC_ADDR_VALIDATION_ERROR_EXPIRED:
      return "Token expired";
    case QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE:
      return "Buffer too small";
    case QUIC_ADDR_VALIDATION_ERROR_CRYPTO:
      return "Cryptographic error";
    case QUIC_ADDR_VALIDATION_ERROR_AMPLIFICATION:
      return "Amplification limit exceeded";
    default:
      return "Unknown error";
    }
}
