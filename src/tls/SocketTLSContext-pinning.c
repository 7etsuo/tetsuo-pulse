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
 * Security: Pin lookup uses constant-time comparison via SocketCrypto_secure_compare()
 * to prevent timing side-channel attacks that could leak information about configured
 * pins. With typical pin counts (1-5), O(n) scan is effectively O(1) and preferred
 * over binary search for security reasons.
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 * Verification is read-only post-setup (thread-safe).
 *
 * Generate pin from certificate:
 *   openssl x509 -in cert.pem -pubkey -noout | \
 *     openssl pkey -pubin -outform DER | \
 *     openssl dgst -sha256 -binary | base64
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "core/SocketCrypto.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketTLS_PinVerifyFailed
    = { &SocketTLS_PinVerifyFailed, "Certificate pin verification failed" };

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

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

  /* Use SocketCrypto for hex decoding */
  ssize_t decoded = SocketCrypto_hex_decode (hex, len, out);
  return (decoded == (ssize_t)SOCKET_TLS_PIN_HASH_LEN) ? 0 : -1;
}

/**
 * ensure_pin_capacity - Ensure pin array has capacity for more pins
 * @ctx: TLS context
 *
 * Raises: SocketTLS_Failed on allocation failure or limit exceeded
 */
static void
ensure_pin_capacity (T ctx)
{
  if (ctx->pinning.count >= SOCKET_TLS_MAX_PINS)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Maximum pin count exceeded (max %d)",
                           SOCKET_TLS_MAX_PINS);
    }

  if (ctx->pinning.count >= ctx->pinning.capacity)
    {
      size_t new_cap = ctx->pinning.capacity == 0
                           ? SOCKET_TLS_PIN_INITIAL_CAPACITY
                           : ctx->pinning.capacity * 2;

      if (new_cap > SOCKET_TLS_MAX_PINS)
        new_cap = SOCKET_TLS_MAX_PINS;

      TLSCertPin *new_pins = (TLSCertPin *)Arena_alloc (
          ctx->arena, new_cap * sizeof (TLSCertPin), __FILE__, __LINE__);

      if (!new_pins)
        {
          RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                               "Failed to allocate pin array");
        }

      if (ctx->pinning.pins && ctx->pinning.count > 0)
        {
          memcpy (new_pins, ctx->pinning.pins,
                  ctx->pinning.count * sizeof (TLSCertPin));
        }

      ctx->pinning.pins = new_pins;
      ctx->pinning.capacity = new_cap;
    }
}

/**
 * insert_pin - Insert pin into array (with duplicate detection)
 * @ctx: TLS context
 * @hash: SHA256 hash to insert (SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Appends pin to the array. Order is irrelevant since tls_pinning_find()
 * uses constant-time linear scan for security (prevents timing attacks).
 * Duplicates are detected using constant-time comparison and silently ignored.
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

/* ============================================================================
 * SPKI Hash Extraction
 * ============================================================================
 */

int
tls_pinning_extract_spki_hash (X509 *cert, unsigned char *out_hash)
{
  if (!cert || !out_hash)
    return -1;

  /* Get SubjectPublicKeyInfo structure */
  X509_PUBKEY *pubkey = X509_get_X509_PUBKEY (cert);
  if (!pubkey)
    return -1;

  /* Encode SPKI to DER */
  unsigned char *spki_der = NULL;
  int spki_len = i2d_X509_PUBKEY (pubkey, &spki_der);
  if (spki_len <= 0 || !spki_der)
    return -1;

  /* Compute SHA256 hash using SocketCrypto */
  SocketCrypto_sha256 (spki_der, (size_t)spki_len, out_hash);

  OPENSSL_free (spki_der);
  return 0;
}

/* ============================================================================
 * Pin Lookup
 * ============================================================================
 */

int
tls_pinning_find (const TLSCertPin *pins, size_t count,
                  const unsigned char *hash)
{
  if (!pins || count == 0 || !hash)
    return 0;

  /* Linear scan with constant-time comparison for each pin.
   * This prevents timing attacks that could leak information about
   * configured pins. With typical pin counts (1-5), performance is fine.
   * We scan all pins to maintain constant-time behavior regardless of
   * which pin matches (or if any match). */
  int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      /* SocketCrypto_secure_compare returns 0 on match (like memcmp) */
      if (SocketCrypto_secure_compare (hash, pins[i].hash,
                                       SOCKET_TLS_PIN_HASH_LEN) == 0)
        {
          found = 1;
          /* Don't break - continue scanning for constant time */
        }
    }

  return found;
}

/* ============================================================================
 * Chain Verification
 * ============================================================================
 */

int
tls_pinning_check_chain (T ctx, STACK_OF (X509) * chain)
{
  if (!ctx || !chain || ctx->pinning.count == 0)
    return 0;

  int chain_len = sk_X509_num (chain);
  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];

  for (int i = 0; i < chain_len; i++)
    {
      X509 *cert = sk_X509_value (chain, i);
      if (!cert)
        continue;

      if (tls_pinning_extract_spki_hash (cert, hash) == 0)
        {
          if (tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash))
            return 1;
        }
    }

  return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

void
SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "PIN hash cannot be NULL");
    }

  insert_pin (ctx, sha256_hash);
}

void
SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash)
{
  assert (ctx);

  if (!hex_hash || !*hex_hash)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "PIN hex hash cannot be NULL or empty");
    }

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (parse_hex_hash (hex_hash, hash) != 0)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Invalid hex hash format (expected 64 hex chars): "
                           "'%.32s...'",
                           hex_hash);
    }

  insert_pin (ctx, hash);
}

void
SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file)
{
  assert (ctx);

  if (!cert_file || !*cert_file)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Certificate file path cannot be NULL or empty");
    }

  if (!tls_validate_file_path (cert_file))
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Invalid certificate file path: '%.200s'",
                           cert_file);
    }

  /* Load certificate */
  FILE *fp = fopen (cert_file, "r");
  if (!fp)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Cannot open certificate file '%.200s': %s",
                           cert_file, strerror (errno));
    }

  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!cert)
    {
      ctx_raise_openssl_error ("Failed to parse certificate file");
    }

  /* Extract SPKI hash */
  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      X509_free (cert);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from certificate");
    }

  X509_free (cert);

  insert_pin (ctx, hash);
}

void
SocketTLSContext_add_pin_from_x509 (T ctx, X509 *cert)
{
  assert (ctx);

  if (!cert)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "X509 certificate cannot be NULL");
    }

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from X509 certificate");
    }

  insert_pin (ctx, hash);
}

void
SocketTLSContext_clear_pins (T ctx)
{
  assert (ctx);

  /* Zero out existing pins for security using SocketCrypto */
  if (ctx->pinning.pins && ctx->pinning.count > 0)
    {
      SocketCrypto_secure_clear (ctx->pinning.pins,
                                 ctx->pinning.count * sizeof (TLSCertPin));
    }

  ctx->pinning.count = 0;
  /* Keep capacity - arena will free on context disposal */
}

void
SocketTLSContext_set_pin_enforcement (T ctx, int enforce)
{
  assert (ctx);
  ctx->pinning.enforce = enforce ? 1 : 0;
}

int
SocketTLSContext_get_pin_enforcement (T ctx)
{
  assert (ctx);
  return ctx->pinning.enforce;
}

size_t
SocketTLSContext_get_pin_count (T ctx)
{
  assert (ctx);
  return ctx->pinning.count;
}

int
SocketTLSContext_has_pins (T ctx)
{
  assert (ctx);
  return ctx->pinning.count > 0 ? 1 : 0;
}

int
SocketTLSContext_verify_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    return 0;

  return tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, sha256_hash);
}

int
SocketTLSContext_verify_cert_pin (T ctx, X509 *cert)
{
  assert (ctx);

  if (!cert)
    return 0;

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    return 0;

  return tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash);
}

#undef T

#endif /* SOCKET_HAS_TLS */

