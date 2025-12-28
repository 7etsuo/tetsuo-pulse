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

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketQUICAddrValidation_Failed
    = { &SocketQUICAddrValidation_Failed, "QUIC address validation failed" };

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */


/**
 * @brief Hash sockaddr into fixed-size buffer.
 *
 * Creates a deterministic hash of address for token binding.
 *
 * @param[in] addr Socket address.
 * @param[out] hash Output buffer (16 bytes).
 */
static void
hash_address (const struct sockaddr *addr, uint8_t hash[16])
{
  unsigned char sha256_output[SOCKET_CRYPTO_SHA256_SIZE];

  if (!addr)
    {
      memset (hash, 0, 16);
      return;
    }

  if (addr->sa_family == AF_INET)
    {
      const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
      SocketCrypto_sha256 (&addr4->sin_addr, sizeof (addr4->sin_addr),
                           sha256_output);
    }
  else if (addr->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
      SocketCrypto_sha256 (&addr6->sin6_addr, sizeof (addr6->sin6_addr),
                           sha256_output);
    }
  else
    {
      memset (hash, 0, 16);
      return;
    }

  /* Use first 16 bytes of SHA-256 */
  memcpy (hash, sha256_output, 16);
}

/**
 * @brief Write uint64 in network byte order.
 */
static void
write_uint64_be (uint8_t *buf, uint64_t value)
{
  buf[0] = (value >> 56) & 0xFF;
  buf[1] = (value >> 48) & 0xFF;
  buf[2] = (value >> 40) & 0xFF;
  buf[3] = (value >> 32) & 0xFF;
  buf[4] = (value >> 24) & 0xFF;
  buf[5] = (value >> 16) & 0xFF;
  buf[6] = (value >> 8) & 0xFF;
  buf[7] = value & 0xFF;
}

/**
 * @brief Read uint64 in network byte order.
 */
static uint64_t
read_uint64_be (const uint8_t *buf)
{
  return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48)
         | ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32)
         | ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16)
         | ((uint64_t)buf[6] << 8) | (uint64_t)buf[7];
}

/* ============================================================================
 * Amplification Limit Functions
 * ============================================================================
 */

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
  if (state->bytes_received > UINT64_MAX / QUIC_ADDR_VALIDATION_AMPLIFICATION_LIMIT)
    {
      return 1;  /* No practical limit when overflow would occur */
    }

  uint64_t max_allowed
      = state->bytes_received * QUIC_ADDR_VALIDATION_AMPLIFICATION_LIMIT;

  /* Also check for overflow in addition */
  if (state->bytes_sent > UINT64_MAX - bytes_to_send)
    {
      return 0;  /* Overflow in bytes_sent + bytes_to_send */
    }

  return (state->bytes_sent + bytes_to_send) <= max_allowed;
}

void
SocketQUICAddrValidation_update_counters (
    SocketQUICAddrValidation_State_T *state, size_t bytes_sent,
    size_t bytes_received)
{
  if (!state)
    {
      return;
    }

  state->bytes_sent += bytes_sent;
  state->bytes_received += bytes_received;
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

/* ============================================================================
 * Token Functions
 * ============================================================================
 */

SocketQUICAddrValidation_Result
SocketQUICAddrValidation_generate_token (const struct sockaddr *addr,
                                          const uint8_t *secret,
                                          uint8_t *token, size_t *token_len)
{
  uint8_t addr_hash[16];
  uint8_t hmac_input[24]; /* 8 bytes timestamp + 16 bytes addr hash */
  unsigned char hmac_output[SOCKET_CRYPTO_SHA256_SIZE];
  uint64_t timestamp;

  /* Validate inputs */
  if (!addr || !secret || !token || !token_len)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  /* Token format: 8 timestamp + 16 addr_hash + 32 HMAC = 56 bytes */
  if (*token_len < 56)
    {
      return QUIC_ADDR_VALIDATION_ERROR_BUFFER_SIZE;
    }

  /* Get current timestamp */
  timestamp = (uint64_t)Socket_get_monotonic_ms ();

  /* Hash the address */
  hash_address (addr, addr_hash);

  /* Build HMAC input: timestamp || addr_hash */
  write_uint64_be (hmac_input, timestamp);
  memcpy (hmac_input + 8, addr_hash, 16);

  /* Compute HMAC-SHA256 */
  TRY
  {
    SocketCrypto_hmac_sha256 (secret, 32, hmac_input, 24, hmac_output);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    return QUIC_ADDR_VALIDATION_ERROR_CRYPTO;
  }
  END_TRY;

  /* Build token: timestamp || addr_hash || HMAC */
  write_uint64_be (token, timestamp);
  memcpy (token + 8, addr_hash, 16);
  memcpy (token + 24, hmac_output, 32);

  *token_len = 56;
  return QUIC_ADDR_VALIDATION_OK;
}

SocketQUICAddrValidation_Result
SocketQUICAddrValidation_validate_token (const uint8_t *token,
                                          size_t token_len,
                                          const struct sockaddr *addr,
                                          const uint8_t *secret)
{
  uint8_t addr_hash[16];
  uint8_t hmac_input[24];
  unsigned char hmac_output[SOCKET_CRYPTO_SHA256_SIZE];
  uint64_t token_timestamp;
  uint64_t current_time;

  /* Validate inputs */
  if (!token || !addr || !secret)
    {
      return QUIC_ADDR_VALIDATION_ERROR_NULL;
    }

  /* Check token size */
  if (token_len != 56)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  /* Extract timestamp */
  token_timestamp = read_uint64_be (token);

  /* Check expiration */
  current_time = (uint64_t)Socket_get_monotonic_ms ();
  if (current_time > token_timestamp
      && (current_time - token_timestamp)
             > (QUIC_ADDR_VALIDATION_TOKEN_LIFETIME * 1000))
    {
      return QUIC_ADDR_VALIDATION_ERROR_EXPIRED;
    }

  /* Hash current address */
  hash_address (addr, addr_hash);

  /* Verify address hash matches */
  if (SocketCrypto_secure_compare (token + 8, addr_hash, 16) != 0)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  /* Rebuild HMAC input */
  write_uint64_be (hmac_input, token_timestamp);
  memcpy (hmac_input + 8, addr_hash, 16);

  /* Compute expected HMAC */
  TRY
  {
    SocketCrypto_hmac_sha256 (secret, 32, hmac_input, 24, hmac_output);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    return QUIC_ADDR_VALIDATION_ERROR_CRYPTO;
  }
  END_TRY;

  /* Verify HMAC matches (constant-time) */
  if (SocketCrypto_secure_compare (token + 24, hmac_output, 32) != 0)
    {
      return QUIC_ADDR_VALIDATION_ERROR_INVALID;
    }

  return QUIC_ADDR_VALIDATION_OK;
}

/* ============================================================================
 * Path Validation Functions
 * ============================================================================
 */

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
    const SocketQUICPathChallenge_T *challenge, const uint8_t *response_data,
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
  return SocketCrypto_secure_compare (challenge->data, response_data,
                                      QUIC_PATH_CHALLENGE_SIZE)
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

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

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
