/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dtls_config.c - Fuzzer for DTLS Configuration Constants and Validation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets (Section 6 from todo_ssl.md):
 * - 6.1 Protocol Version Constants verification
 * - 6.2 Cipher Suites verification
 * - 6.3 MTU Settings verification
 * - 6.4 Cookie Protection Parameters verification
 * - 6.5 Timeout Configuration verification
 * - 6.6 Session and Limits verification
 * - 6.7 Validation Macros verification
 *
 * Security Focus:
 * - Constant value correctness
 * - Validation macro boundary conditions
 * - MTU range enforcement
 * - Timeout range enforcement
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON -DENABLE_TLS=ON && make
 * fuzz_dtls_config Run:   ./fuzz_dtls_config corpus/dtls_config/ -fork=16
 * -max_len=4096
 */

#if SOCKET_HAS_TLS

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Operation codes for DTLS config fuzzing */
enum DTLSConfigOp
{
  DTLS_CFG_OP_VERIFY_PROTOCOL_VERSIONS = 0,
  DTLS_CFG_OP_VERIFY_CIPHERSUITES,
  DTLS_CFG_OP_VERIFY_MTU_SETTINGS,
  DTLS_CFG_OP_VERIFY_COOKIE_PARAMS,
  DTLS_CFG_OP_VERIFY_TIMEOUT_CONFIG,
  DTLS_CFG_OP_VERIFY_SESSION_LIMITS,
  DTLS_CFG_OP_VERIFY_VALIDATION_MACROS,
  DTLS_CFG_OP_FUZZ_MTU_VALIDATION,
  DTLS_CFG_OP_FUZZ_TIMEOUT_VALIDATION,
  DTLS_CFG_OP_VERIFY_ALL_CONSTANTS,
  DTLS_CFG_OP_COUNT
};

/**
 * Section 6.1: Verify Protocol Version Constants
 *
 * - SOCKET_DTLS_MIN_VERSION: Must be DTLS1_2_VERSION
 * - SOCKET_DTLS_MAX_VERSION: DTLS1_3_VERSION if available, else DTLS1_2_VERSION
 */
static void
verify_protocol_version_constants (void)
{
  /* SOCKET_DTLS_MIN_VERSION must be DTLS 1.2 */
  assert (SOCKET_DTLS_MIN_VERSION == DTLS1_2_VERSION);

  /* SOCKET_DTLS_MAX_VERSION must be at least DTLS 1.2 */
  assert (SOCKET_DTLS_MAX_VERSION >= DTLS1_2_VERSION);

#if defined(DTLS1_3_VERSION)
  /* If DTLS 1.3 is available, max should use it */
  assert (SOCKET_DTLS_MAX_VERSION == DTLS1_3_VERSION);
#else
  /* Otherwise, max should be DTLS 1.2 */
  assert (SOCKET_DTLS_MAX_VERSION == DTLS1_2_VERSION);
#endif

  /* Min must not exceed max */
  /* Note: DTLS version numbers are reversed (higher value = older version) */
  /* DTLS1_2_VERSION = 0xFEFD, DTLS1_0_VERSION = 0xFEFF */
  assert (SOCKET_DTLS_MIN_VERSION >= SOCKET_DTLS_MAX_VERSION);
}

/**
 * Section 6.2: Verify Cipher Suites
 *
 * - SOCKET_DTLS_CIPHERSUITES: Must contain modern ECDHE + AEAD suites
 */
static void
verify_ciphersuites (void)
{
  /* SOCKET_DTLS_CIPHERSUITES must be non-null and non-empty */
  assert (SOCKET_DTLS_CIPHERSUITES != NULL);
  assert (strlen (SOCKET_DTLS_CIPHERSUITES) > 0);

  /* Must contain ECDHE-based suites for forward secrecy */
  assert (strstr (SOCKET_DTLS_CIPHERSUITES, "ECDHE") != NULL);

  /* Must contain AEAD ciphers (GCM or ChaCha20) */
  int has_gcm = strstr (SOCKET_DTLS_CIPHERSUITES, "GCM") != NULL;
  int has_chacha = strstr (SOCKET_DTLS_CIPHERSUITES, "CHACHA20") != NULL;
  assert (has_gcm || has_chacha);

  /* Verify priority order: AES-256-GCM before AES-128-GCM */
  const char *aes256_pos
      = strstr (SOCKET_DTLS_CIPHERSUITES, "AES256-GCM-SHA384");
  const char *aes128_pos
      = strstr (SOCKET_DTLS_CIPHERSUITES, "AES128-GCM-SHA256");
  if (aes256_pos && aes128_pos)
    {
      assert (aes256_pos < aes128_pos);
    }
}

/**
 * Section 6.3: Verify MTU Settings
 *
 * - SOCKET_DTLS_DEFAULT_MTU: 1400 bytes (conservative for tunnels)
 * - SOCKET_DTLS_MIN_MTU: 576 bytes (IPv4 minimum reassembly)
 * - SOCKET_DTLS_MAX_MTU: 9000 bytes (jumbo frames)
 * - SOCKET_DTLS_MAX_RECORD_SIZE: 16384 bytes (TLS record max)
 * - SOCKET_DTLS_RECORD_OVERHEAD: 64 bytes (conservative estimate)
 * - SOCKET_DTLS_MAX_PAYLOAD: Calculated correctly
 */
static void
verify_mtu_settings (void)
{
  /* Default MTU: 1400 bytes conservative for tunnels */
  assert (SOCKET_DTLS_DEFAULT_MTU == 1400);

  /* Minimum MTU: 576 bytes (IPv4 minimum reassembly buffer) */
  assert (SOCKET_DTLS_MIN_MTU == 576);

  /* Maximum MTU: 9000 bytes (jumbo frames) */
  assert (SOCKET_DTLS_MAX_MTU == 9000);

  /* Max record size: 16384 bytes (TLS record max per RFC) */
  assert (SOCKET_DTLS_MAX_RECORD_SIZE == 16384);

  /* Record overhead: 64 bytes (conservative) */
  assert (SOCKET_DTLS_RECORD_OVERHEAD == 64);

  /* Max payload calculation: MTU - overhead - IPv4/UDP headers (28 bytes) */
  size_t expected_payload
      = SOCKET_DTLS_DEFAULT_MTU - SOCKET_DTLS_RECORD_OVERHEAD - 28;
  assert (SOCKET_DTLS_MAX_PAYLOAD == expected_payload);

  /* Sanity: min < default < max */
  assert (SOCKET_DTLS_MIN_MTU < SOCKET_DTLS_DEFAULT_MTU);
  assert (SOCKET_DTLS_DEFAULT_MTU < SOCKET_DTLS_MAX_MTU);
}

/**
 * Section 6.4: Verify Cookie Protection Parameters
 *
 * - SOCKET_DTLS_COOKIE_LEN: 32 bytes (timestamp + truncated HMAC tag)
 * - SOCKET_DTLS_COOKIE_SECRET_LEN: 32 bytes for HMAC key
 * - SOCKET_DTLS_COOKIE_LIFETIME_SEC: 60 seconds validity
 * - SOCKET_DTLS_MAX_PENDING_COOKIES: 1000 concurrent exchanges
 */
static void
verify_cookie_params (void)
{
  /* Cookie length: 32 bytes (timestamp + truncated HMAC tag) */
  assert (SOCKET_DTLS_COOKIE_LEN == 32);

  /* Cookie secret length: 32 bytes for HMAC-SHA256 key */
  assert (SOCKET_DTLS_COOKIE_SECRET_LEN == 32);

  /* Cookie lifetime: 60 seconds */
  assert (SOCKET_DTLS_COOKIE_LIFETIME_SEC == 60);

  /* Max pending cookies: 1000 concurrent exchanges */
  assert (SOCKET_DTLS_MAX_PENDING_COOKIES == 1000);
}

/**
 * Section 6.5: Verify Timeout Configuration
 *
 * - SOCKET_DTLS_INITIAL_TIMEOUT_MS: 1000ms initial retransmission timeout
 * - SOCKET_DTLS_MAX_TIMEOUT_MS: 60000ms maximum timeout
 * - SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS: 30000ms total handshake timeout
 * - SOCKET_DTLS_MAX_RETRANSMITS: 12 retransmissions maximum
 */
static void
verify_timeout_config (void)
{
  /* Initial retransmission timeout: 1000ms */
  assert (SOCKET_DTLS_INITIAL_TIMEOUT_MS == 1000);

  /* Maximum timeout after backoff: 60000ms (60 seconds) */
  assert (SOCKET_DTLS_MAX_TIMEOUT_MS == 60000);

  /* Default total handshake timeout: 30000ms (30 seconds) */
  assert (SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS == 30000);

  /* Maximum retransmissions: 12 */
  assert (SOCKET_DTLS_MAX_RETRANSMITS == 12);

  /* Sanity: initial <= max */
  assert (SOCKET_DTLS_INITIAL_TIMEOUT_MS <= SOCKET_DTLS_MAX_TIMEOUT_MS);

  /* Sanity: handshake timeout <= max * retransmits (approximate) */
  assert (SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
          <= (long)SOCKET_DTLS_MAX_TIMEOUT_MS * SOCKET_DTLS_MAX_RETRANSMITS);
}

/**
 * Section 6.6: Verify Session and Limits
 *
 * - SOCKET_DTLS_SESSION_CACHE_SIZE: 1000 sessions default
 * - SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT: 300 seconds (5 minutes)
 * - SOCKET_DTLS_ERROR_BUFSIZE: 512 bytes for error messages
 * - SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH: 10 levels
 * - SOCKET_DTLS_MAX_SNI_LEN: 255 bytes
 * - SOCKET_DTLS_MAX_ALPN_LEN: 255 bytes
 * - SOCKET_DTLS_MAX_PATH_LEN: 4096 bytes
 * - SOCKET_DTLS_MAX_FILE_SIZE: 1MB limit for cert/key files
 */
static void
verify_session_limits (void)
{
  /* Session cache size: 1000 sessions */
  assert (SOCKET_DTLS_SESSION_CACHE_SIZE == 1000);

  /* Session timeout: 300 seconds (5 minutes) */
  assert (SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT == 300L);

  /* Error buffer size: 512 bytes */
  assert (SOCKET_DTLS_ERROR_BUFSIZE == 512);

  /* Max certificate chain depth: 10 */
  assert (SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH == 10);

  /* Max SNI hostname length: 255 bytes */
  assert (SOCKET_DTLS_MAX_SNI_LEN == 255);

  /* Max ALPN protocol length: 255 bytes */
  assert (SOCKET_DTLS_MAX_ALPN_LEN == 255);

  /* Max ALPN protocols: 16 */
  assert (SOCKET_DTLS_MAX_ALPN_PROTOCOLS == 16);

  /* Max file path length: 4096 bytes */
  assert (SOCKET_DTLS_MAX_PATH_LEN == 4096);

  /* Max file size: 1MB */
  assert (SOCKET_DTLS_MAX_FILE_SIZE == (1024 * 1024));
}

/**
 * Section 6.7: Verify Validation Macros
 *
 * - SOCKET_DTLS_VALID_MTU(): Range check macro
 * - SOCKET_DTLS_VALID_TIMEOUT(): Timeout validation macro
 */
static void
verify_validation_macros (void)
{
  /* SOCKET_DTLS_VALID_MTU() tests */

  /* Valid MTU at minimum */
  assert (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MIN_MTU) == 1);

  /* Valid MTU at maximum */
  assert (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MAX_MTU) == 1);

  /* Valid MTU at default */
  assert (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_DEFAULT_MTU) == 1);

  /* Invalid MTU below minimum */
  assert (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MIN_MTU - 1) == 0);

  /* Invalid MTU above maximum */
  assert (SOCKET_DTLS_VALID_MTU (SOCKET_DTLS_MAX_MTU + 1) == 0);

  /* Invalid MTU at zero */
  assert (SOCKET_DTLS_VALID_MTU (0) == 0);

  /* SOCKET_DTLS_VALID_TIMEOUT() tests */

  /* Valid timeout at zero (immediate) */
  assert (SOCKET_DTLS_VALID_TIMEOUT (0) == 1);

  /* Valid timeout at initial */
  assert (SOCKET_DTLS_VALID_TIMEOUT (SOCKET_DTLS_INITIAL_TIMEOUT_MS) == 1);

  /* Valid timeout at maximum */
  assert (SOCKET_DTLS_VALID_TIMEOUT (SOCKET_DTLS_MAX_TIMEOUT_MS) == 1);

  /* Invalid timeout negative */
  assert (SOCKET_DTLS_VALID_TIMEOUT (-1) == 0);

  /* Invalid timeout above maximum */
  assert (SOCKET_DTLS_VALID_TIMEOUT (SOCKET_DTLS_MAX_TIMEOUT_MS + 1) == 0);
}

/**
 * Comprehensive verification of all DTLS constants
 */
static void
verify_all_constants (void)
{
  verify_protocol_version_constants ();
  verify_ciphersuites ();
  verify_mtu_settings ();
  verify_cookie_params ();
  verify_timeout_config ();
  verify_session_limits ();
  verify_validation_macros ();
}

/**
 * Fuzz MTU validation with random values
 */
static void
fuzz_mtu_validation (const uint8_t *data, size_t size)
{
  if (size < 4)
    return;

  /* Extract MTU value from fuzzer data */
  size_t mtu = 0;
  for (int i = 0; i < 4 && i < (int)size; i++)
    {
      mtu = (mtu << 8) | data[i];
    }

  /* Test validation macro */
  int is_valid = SOCKET_DTLS_VALID_MTU (mtu);

  /* Verify correctness */
  int should_be_valid
      = (mtu >= SOCKET_DTLS_MIN_MTU && mtu <= SOCKET_DTLS_MAX_MTU);
  assert (is_valid == should_be_valid);
}

/**
 * Fuzz timeout validation with random values
 */
static void
fuzz_timeout_validation (const uint8_t *data, size_t size)
{
  if (size < 4)
    return;

  /* Extract timeout value from fuzzer data */
  int timeout = 0;
  for (int i = 0; i < 4 && i < (int)size; i++)
    {
      timeout = (timeout << 8) | data[i];
    }

  /* Test validation macro */
  int is_valid = SOCKET_DTLS_VALID_TIMEOUT (timeout);

  /* Verify correctness */
  int should_be_valid = (timeout >= 0 && timeout <= SOCKET_DTLS_MAX_TIMEOUT_MS);
  assert (is_valid == should_be_valid);
}

/* Main fuzzer entry point */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  /* First byte selects operation */
  enum DTLSConfigOp op = data[0] % DTLS_CFG_OP_COUNT;
  const uint8_t *rest = data + 1;
  size_t rest_size = size - 1;

  /* Clear OpenSSL error queue to start fresh */
  ERR_clear_error ();

  switch (op)
    {
    case DTLS_CFG_OP_VERIFY_PROTOCOL_VERSIONS:
      verify_protocol_version_constants ();
      break;

    case DTLS_CFG_OP_VERIFY_CIPHERSUITES:
      verify_ciphersuites ();
      break;

    case DTLS_CFG_OP_VERIFY_MTU_SETTINGS:
      verify_mtu_settings ();
      break;

    case DTLS_CFG_OP_VERIFY_COOKIE_PARAMS:
      verify_cookie_params ();
      break;

    case DTLS_CFG_OP_VERIFY_TIMEOUT_CONFIG:
      verify_timeout_config ();
      break;

    case DTLS_CFG_OP_VERIFY_SESSION_LIMITS:
      verify_session_limits ();
      break;

    case DTLS_CFG_OP_VERIFY_VALIDATION_MACROS:
      verify_validation_macros ();
      break;

    case DTLS_CFG_OP_FUZZ_MTU_VALIDATION:
      fuzz_mtu_validation (rest, rest_size);
      break;

    case DTLS_CFG_OP_FUZZ_TIMEOUT_VALIDATION:
      fuzz_timeout_validation (rest, rest_size);
      break;

    case DTLS_CFG_OP_VERIFY_ALL_CONSTANTS:
      verify_all_constants ();
      break;

    default:
      break;
    }

  /* Clear any errors generated */
  ERR_clear_error ();

  return 0;
}

#else /* !SOCKET_HAS_TLS */

/* Stub when TLS is disabled */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0;
}

#endif /* SOCKET_HAS_TLS */
