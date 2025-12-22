/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLSContext-pinning.c - Certificate Pinning (SPKI SHA256)
 *
 * Part of the Socket Library
 *
 * Implements OWASP-recommended SPKI (Subject Public Key Info) SHA256 pinning.
 * SPKI pinning hashes the SubjectPublicKeyInfo DER encoding, which survives
 * certificate renewal when the same key is reused.
 *
 * Features:
 * - Binary and hex-encoded hash input
 * - Certificate file SPKI extraction
 * - Constant-time lookup (prevents timing attacks on pin verification)
 * - Chain verification (matches any cert in chain)
 * - Enforcement mode control (strict/warn)
 *
 * Security: Pin lookup uses constant-time comparison via
 * SocketCrypto_secure_compare() to prevent timing side-channel attacks that
 * could leak information about configured pins. With typical pin counts (1-5),
 * O(n) scan is effectively O(1) and preferred over binary search for security
 * reasons.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Verification is read-only post-setup (thread-safe).
 *
 * Generate pin from certificate:
 *   openssl x509 -in cert.pem -pubkey -noout | \
 *     openssl pkey -pubin -outform DER | \
 *     openssl dgst -sha256 -binary | base64
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#define T SocketTLSContext_T

const Except_T SocketTLS_PinVerifyFailed
    = { &SocketTLS_PinVerifyFailed, "Certificate pin verification failed" };

/**
 * parse_hex_hash - Parse hex string to binary hash
 * @hex: Hex string (64 chars for SHA256)
 * @out: Output buffer (SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Returns: 0 on success, -1 on invalid input
 *
 * Accepts optional "sha256//" prefix for compatibility with HPKP format.
 * Uses SocketCrypto_hex_decode for actual decoding.
 */
static int
parse_hex_hash (const char *hex, unsigned char *out)
{
  if (!hex || !out)
    return -1;

  /* Skip optional "sha256//" prefix (HPKP compatibility) */
  if (strncmp (hex, "sha256//", 8) == 0)
    hex += 8;

  size_t len = strlen (hex);
  if (len != SOCKET_TLS_PIN_HASH_LEN * 2)
    return -1;

  ssize_t decoded
      = SocketCrypto_hex_decode (hex, len, out, SOCKET_TLS_PIN_HASH_LEN);
  return (decoded == (ssize_t)SOCKET_TLS_PIN_HASH_LEN) ? 0 : -1;
}

/**
 * check_pin_limit - Ensure pin count does not exceed maximum
 * @ctx: TLS context
 *
 * Raises: SocketTLS_Failed if limit exceeded
 * Thread-safe: Yes (uses thread-local exception)
 */
static void
check_pin_limit (T ctx)
{
  if (ctx->pinning.count >= SOCKET_TLS_MAX_PINS)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Maximum pin count exceeded (max %d)",
                           SOCKET_TLS_MAX_PINS);
    }
}

/**
 * calculate_pin_capacity - Determine next array capacity for growth
 * @current_cap: Current capacity (0 for initial)
 * @max_pins: Absolute maximum pins allowed
 *
 * Returns: Suggested new capacity (initial capacity or doubled, capped at max)
 * Thread-safe: Yes (pure function)
 */
static size_t
calculate_pin_capacity (size_t current_cap, size_t max_pins)
{
  if (current_cap == 0)
    return SOCKET_TLS_PIN_INITIAL_CAPACITY;

  size_t new_cap = current_cap * 2;
  return (new_cap > max_pins) ? max_pins : new_cap;
}

/**
 * grow_pin_array - Expand pin storage capacity
 * @ctx: TLS context
 *
 * Allocates larger array via arena, copies existing pins, updates state.
 *
 * Raises: SocketTLS_Failed on allocation failure
 * Thread-safe: Yes (arena allocation is thread-safe)
 */
static void
grow_pin_array (T ctx)
{
  size_t new_cap
      = calculate_pin_capacity (ctx->pinning.capacity, SOCKET_TLS_MAX_PINS);

  TLSCertPin *new_pins = (TLSCertPin *)Arena_alloc (
      ctx->arena, new_cap * sizeof (TLSCertPin), __FILE__, __LINE__);

  if (!new_pins)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Failed to allocate pin array");

  if (ctx->pinning.pins && ctx->pinning.count > 0)
    {
      memcpy (new_pins, ctx->pinning.pins,
              ctx->pinning.count * sizeof (TLSCertPin));
    }

  ctx->pinning.pins = new_pins;
  ctx->pinning.capacity = new_cap;
}

/**
 * ensure_pin_capacity - Prepare for adding a new pin
 * @ctx: TLS context with pinning state
 *
 * Validates limit and grows array if full. Called before appending pins.
 *
 * Raises: SocketTLS_Failed on limit or allocation issues
 * Thread-safe: Yes
 */
static void
ensure_pin_capacity (T ctx)
{
  check_pin_limit (ctx);

  if (ctx->pinning.count < ctx->pinning.capacity)
    return;

  grow_pin_array (ctx);
}

/**
 * insert_pin - Add pin hash to array if not already present
 * @ctx: TLS context
 * @hash: Pin hash (SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Checks for duplicate using constant-time search, then ensures capacity
 * and appends if unique. Order irrelevant due to linear constant-time lookup.
 *
 * Raises: SocketTLS_Failed via ensure_pin_capacity if limit reached
 * Thread-safe: Yes
 */
static void
insert_pin (T ctx, const unsigned char *hash)
{
  /* Check for duplicate using constant-time comparison */
  if (tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash))
    return;

  ensure_pin_capacity (ctx);

  /* Append - order irrelevant for constant-time scan */
  memcpy (ctx->pinning.pins[ctx->pinning.count].hash, hash,
          SOCKET_TLS_PIN_HASH_LEN);
  ctx->pinning.count++;
}

/**
 * raise_invalid_pin_param - Raise error for invalid pinning input parameters
 * @msg: Error message describing invalid input
 *
 * Common helper for input validation errors in pin APIs.
 *
 * Raises: SocketTLS_Failed with specified message
 * Thread-safe: Yes (uses thread-local exception)
 */
static void
raise_invalid_pin_param (const char *msg)
{
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "%s", msg);
}

/**
 * tls_pinning_extract_spki_hash - Compute SPKI SHA256 hash from X509 cert
 * @cert: Certificate to extract public key info from (non-owning)
 * @out_hash: Output buffer for 32-byte SHA256 hash
 *
 * Extracts SubjectPublicKeyInfo DER from cert, computes SHA256 using
 * SocketCrypto, and stores in out_hash.
 *
 * Returns: 0 on success, -1 on failure (invalid cert or OpenSSL error)
 * Thread-safe: Yes
 */
int
tls_pinning_extract_spki_hash (const X509 *cert, unsigned char *out_hash)
{
  if (!cert || !out_hash)
    return -1;

  X509_PUBKEY *pubkey = X509_get_X509_PUBKEY (cert);
  if (!pubkey)
    return -1;

  unsigned char *spki_der = NULL;
  int spki_len = i2d_X509_PUBKEY (pubkey, &spki_der);
  if (spki_len <= 0 || !spki_der)
    return -1;

  SocketCrypto_sha256 (spki_der, (size_t)spki_len, out_hash);

  OPENSSL_free (spki_der);
  return 0;
}

/**
 * tls_pinning_find - Constant-time search for hash in pin array
 * @pins: Array of TLSCertPin structures
 * @count: Number of pins in array
 * @hash: 32-byte SHA256 hash to search for
 *
 * Linear scan with constant-time comparison for each pin to prevent timing
 * attacks. Scans all pins regardless of match position for constant-time.
 *
 * Returns: 1 if match found, 0 otherwise
 * Thread-safe: No - caller must hold pinning lock
 */
int
tls_pinning_find (const TLSCertPin *pins, size_t count,
                  const unsigned char *hash)
{
  if (!pins || count == 0 || !hash)
    return 0;

  /* Use volatile to prevent compiler optimizations that could leak timing.
   * Use bitwise OR accumulation instead of branching to ensure truly
   * constant-time execution regardless of match position. */
  volatile int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      int match = (SocketCrypto_secure_compare (hash, pins[i].hash,
                                                SOCKET_TLS_PIN_HASH_LEN)
                   == 0);
      found |= match;
    }

  return found;
}

/**
 * tls_pinning_check_chain - Verify if any cert in chain matches a pin
 * @ctx: TLS context with configured pins
 * @chain: Certificate chain to check (non-owning reference)
 *
 * Extracts SPKI SHA256 hash from each cert in chain and checks against
 * configured pins using constant-time comparison.
 *
 * Returns: 1 if pin match found in chain, 0 otherwise
 * Thread-safe: Yes (uses atomic pin snapshot)
 */
int
tls_pinning_check_chain (T ctx, const STACK_OF (X509) * chain)
{
  if (!ctx || !chain)
    return 0;

  /* Early check for no pins */
  pthread_mutex_lock (&ctx->pinning.lock);
  if (ctx->pinning.count == 0)
    {
      pthread_mutex_unlock (&ctx->pinning.lock);
      return 0;
    }
  pthread_mutex_unlock (&ctx->pinning.lock);

  int chain_len = sk_X509_num (chain);
  const int max_check = SOCKET_TLS_MAX_CERT_CHAIN_DEPTH;
  if (chain_len > max_check)
    {
      SOCKET_LOG_WARN_MSG ("Pinning check truncated: chain_len=%d > max=%d",
                           chain_len, max_check);
      chain_len = max_check;
    }

  /* Extract hashes without lock (chain is snapshot, extraction is read-only) */
  unsigned char hashes[SOCKET_TLS_MAX_CERT_CHAIN_DEPTH][SOCKET_TLS_PIN_HASH_LEN];
  int num_hashes = 0;
  for (int i = 0; i < chain_len; i++)
    {
      X509 *cert = sk_X509_value (chain, i);
      if (!cert)
        continue;

      if (tls_pinning_extract_spki_hash (cert, hashes[num_hashes]) == 0)
        num_hashes++;
    }

  /* Snapshot pins atomically under lock to avoid race with config changes */
  const TLSCertPin *local_pins = NULL;
  size_t local_count = 0;
  pthread_mutex_lock (&ctx->pinning.lock);
  local_count = ctx->pinning.count;
  if (local_count > 0)
    local_pins = ctx->pinning.pins;
  pthread_mutex_unlock (&ctx->pinning.lock);

  /* Check extracted hashes against snapshot (constant-time) */
  for (int j = 0; j < num_hashes; j++)
    {
      if (tls_pinning_find (local_pins, local_count, hashes[j]))
        return 1;
    }

  return 0;
}

/**
 * SocketTLSContext_add_pin - Add binary SHA256 SPKI pin to context
 * @ctx: TLS context
 * @sha256_hash: 32-byte SHA256 hash of SubjectPublicKeyInfo DER
 *
 * Adds pin if not already present (deduped via constant-time check).
 *
 * Raises: SocketTLS_Failed if NULL input or max pins reached
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    raise_invalid_pin_param ("PIN hash cannot be NULL");

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, sha256_hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_add_pin_hex - Add pin from hex-encoded SHA256 hash string
 * @ctx: TLS context
 * @hex_hash: Hex string (64 chars) or "sha256//hex" (HPKP compat)
 *
 * Parses hex (optionally skipping "sha256//" prefix), decodes to binary,
 * then adds as pin if unique.
 *
 * Raises: SocketTLS_Failed on invalid format or max reached
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash)
{
  assert (ctx);

  if (!hex_hash || !*hex_hash)
    raise_invalid_pin_param ("PIN hex hash cannot be NULL or empty");

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (parse_hex_hash (hex_hash, hash) != 0)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Invalid hex hash format (expected 64 hex chars): "
                           "'%.32s...'",
                           hex_hash);
    }

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_add_pin_from_cert - Add pin by loading certificate from file
 * @ctx: TLS context
 * @cert_file: Path to PEM-encoded X509 certificate file
 *
 * Loads cert from file, validates path, extracts SPKI hash, adds if unique.
 *
 * Raises: SocketTLS_Failed on file open/read/parse/extract fail or max reached
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file)
{
  assert (ctx);

  if (!cert_file || !*cert_file)
    raise_invalid_pin_param ("Certificate file path cannot be NULL or empty");

  if (!tls_validate_file_path (cert_file))
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Invalid certificate file path: '%.200s'",
                           cert_file);
    }

  /* Load certificate with symlink protection (O_NOFOLLOW) */
  int fd = open (cert_file, O_RDONLY | O_NOFOLLOW);
  if (fd == -1)
    {
      if (errno == ELOOP)
        {
          RAISE_CTX_ERROR_MSG (
              SocketTLS_Failed,
              "Symlinks not allowed for certificate files: %s", cert_file);
        }
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Cannot open certificate file '%.200s': %s",
                           cert_file, Socket_safe_strerror (errno));
    }

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    {
      close (fd);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Cannot fdopen certificate file descriptor");
    }

  /* Validate file size to prevent resource exhaustion.
   * Use fseeko/ftello with off_t for proper large file support on 32-bit
   * systems where long may be 32-bit but off_t is 64-bit with LFS. */
  if (fseeko (fp, 0, SEEK_END) != 0)
    {
      fclose (fp);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Cannot seek in certificate file");
    }

  off_t fsize = ftello (fp);
  if (fsize < 0 || fseeko (fp, 0, SEEK_SET) != 0)
    {
      fclose (fp);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Cannot determine certificate file size");
    }

  /* Safe cast to size_t - fsize is already validated as non-negative above.
   * The subsequent SOCKET_TLS_MAX_CERT_FILE_SIZE check ensures reasonable bounds. */
  size_t usize = (size_t)fsize;
  if (usize > SOCKET_TLS_MAX_CERT_FILE_SIZE
      || !SocketSecurity_check_size (usize))
    {
      fclose (fp);
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Certificate file too large: %ld bytes (max %zu)",
                           fsize, (size_t)SOCKET_TLS_MAX_CERT_FILE_SIZE);
    }

  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp); /* Closes underlying fd */

  if (!cert)
    ctx_raise_openssl_error ("Failed to parse certificate file");

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      X509_free (cert);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from certificate");
    }

  X509_free (cert);

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_add_pin_from_x509 - Add pin from existing X509 certificate
 * @ctx: TLS context to add pin to
 * @cert: Certificate whose SPKI hash to pin (non-owning, copied)
 *
 * Extracts SPKI SHA256 hash and adds to pins if not duplicate.
 *
 * Raises: SocketTLS_Failed on invalid cert or extract fail
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert)
{
  assert (ctx);

  if (!cert)
    raise_invalid_pin_param ("X509 certificate cannot be NULL");

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      RAISE_CTX_ERROR_MSG (
          SocketTLS_Failed,
          "Failed to extract SPKI hash from X509 certificate");
    }

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_clear_pins - Remove all configured pins
 * @ctx: TLS context
 *
 * Clears all pins using secure_clear for security. Capacity preserved
 * for future adds (freed on context disposal via arena).
 *
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_clear_pins (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);

  /* Zero out entire pin array for security using SocketCrypto */
  if (ctx->pinning.pins && ctx->pinning.capacity > 0)
    {
      SocketCrypto_secure_clear (ctx->pinning.pins,
                                 ctx->pinning.capacity * sizeof (TLSCertPin));
    }

  ctx->pinning.count = 0;
  /* Keep capacity - arena will free on context disposal */

  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_set_pin_enforcement - Set strict pin enforcement mode
 * @ctx: TLS context
 * @enforce: 1 for strict (fail on mismatch), 0 for warn/fallback
 *
 * Controls whether pin mismatch causes verification failure or just warning.
 *
 * Thread-safe: Yes - mutex protected
 */
void
SocketTLSContext_set_pin_enforcement (T ctx, int enforce)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  ctx->pinning.enforce = enforce ? 1 : 0;
  pthread_mutex_unlock (&ctx->pinning.lock);
}

/**
 * SocketTLSContext_get_pin_enforcement - Get current enforcement mode
 * @ctx: TLS context
 *
 * Returns: 1 if strict enforcement enabled, 0 if warn mode
 * Thread-safe: Yes - mutex protected
 */
int
SocketTLSContext_get_pin_enforcement (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = ctx->pinning.enforce;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

/**
 * SocketTLSContext_get_pin_count - Get number of configured pins
 * @ctx: TLS context
 *
 * Returns: Current number of pins (0 to SOCKET_TLS_MAX_PINS)
 * Thread-safe: Yes - mutex protected
 */
size_t
SocketTLSContext_get_pin_count (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  size_t res = ctx->pinning.count;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

/**
 * SocketTLSContext_has_pins - Check if any pins configured
 * @ctx: TLS context
 *
 * Returns: 1 if pins configured, 0 otherwise
 * Thread-safe: Yes - mutex protected
 */
int
SocketTLSContext_has_pins (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = (ctx->pinning.count > 0) ? 1 : 0;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

/**
 * SocketTLSContext_verify_pin - Check if hash matches any configured pin
 * @ctx: TLS context
 * @sha256_hash: Hash to verify (SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Performs constant-time search across all pins.
 *
 * Returns: 1 if matches, 0 otherwise
 * Thread-safe: Yes - mutex protected
 */
int
SocketTLSContext_verify_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    return 0;

  pthread_mutex_lock (&ctx->pinning.lock);
  int res
      = tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, sha256_hash);
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

/**
 * SocketTLSContext_verify_cert_pin - Check if certificate matches configured pin
 * @ctx: TLS context with pins configured
 * @cert: Certificate to verify against pins (non-owning)
 *
 * Extracts SPKI hash from cert and checks against configured pins.
 *
 * Returns: 1 if matches any pin, 0 otherwise
 * Thread-safe: Yes (after config)
 */
int
SocketTLSContext_verify_cert_pin (T ctx, const X509 *cert)
{
  assert (ctx);

  if (!cert)
    return 0;

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    return 0;

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);

  if (!res)
    SocketMetrics_counter_inc (SOCKET_CTR_TLS_PINNING_FAILURES);

  return res;
}

#undef T

#endif /* SOCKET_HAS_TLS */
