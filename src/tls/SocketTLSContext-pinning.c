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

SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLSContext);
#include "core/SocketCrypto.h"
#include <assert.h>

#include <errno.h>
#include <openssl/pem.h>
#include <stdio.h>

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
  ssize_t decoded = SocketCrypto_hex_decode (hex, len, out, SOCKET_TLS_PIN_HASH_LEN);
  return (decoded == (ssize_t)SOCKET_TLS_PIN_HASH_LEN) ? 0 : -1;
}

/**
 * ensure_pin_capacity - Ensure pin array has capacity for more pins
 * @ctx: TLS context
 *
 * Raises: SocketTLS_Failed on allocation failure or limit exceeded
 */
 /**
  * ensure_pin_capacity - Ensure the pinning array has sufficient capacity
  *
  * @ctx: TLS context with pinning configuration
  *
  * Checks current count against max limit and reallocates array if needed.
  * Doubles capacity on reallocation, caps at SOCKET_TLS_MAX_PINS.
  *
  * Raises: SocketTLS_Failed on limit exceed or alloc fail
  * Thread-safe: No
  */
 /**
  * check_pin_limit - Ensure pin count does not exceed maximum
  *
  * @ctx: TLS context
  *
  * Raises exception if current count at or over limit.
  *
  * Raises: SocketTLS_Failed if limit exceeded
  * Thread-safe: No
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
  *
  * @current_cap: Current capacity (0 for initial)
  * @max_pins: Absolute maximum pins allowed
  *
  * Returns initial capacity if 0, else double current capped at max_pins.
  *
  * Returns: Suggested new capacity
  * Thread-safe: Yes
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
  *
  * @ctx: TLS context
  *
  * Allocates larger array via arena, copies existing pins securely, updates state.
  *
  * Raises: SocketTLS_Failed on allocation failure
  * Thread-safe: No
  */
static void
grow_pin_array (T ctx)
{
  size_t new_cap = calculate_pin_capacity (ctx->pinning.capacity, SOCKET_TLS_MAX_PINS);

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

 /**
  * ensure_pin_capacity - Prepare for adding a new pin
  *
  * @ctx: TLS context with pinning state
  *
  * Validates limit and grows array if full. Called before appending pins.
  *
  * Raises: SocketTLS_Failed on limit or alloc issues
  * Thread-safe: No
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
 * insert_pin - Insert pin into array (with duplicate detection)
 * @ctx: TLS context
 * @hash: SHA256 hash to insert (SOCKET_TLS_PIN_HASH_LEN bytes)
 *
 * Appends pin to the array. Order is irrelevant since tls_pinning_find()
 * uses constant-time linear scan for security (prevents timing attacks).
 * Duplicates are detected using constant-time comparison and silently ignored.
 */
 /**
  * insert_pin - Add pin hash to array if not already present
  *
  * @ctx: TLS context
  * @hash: Pin hash (SOCKET_TLS_PIN_HASH_LEN bytes)
  *
  * Checks for duplicate using constant-time search, then ensures capacity
  * and appends if unique. Order irrelevant due to linear constant-time lookup.
  *
  * Thread-safe: No
  * Raises: SocketTLS_Failed via ensure_pin_capacity if limit reached
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
  * invalid_pin_param - Raise error for invalid pinning input parameters
  *
  * @msg: Error message describing invalid input
  *
  * Common helper for input validation errors in pin APIs.
  * Centralizes exception raising to reduce code duplication in error paths.
  *
  * Raises: SocketTLS_Failed with specified message
  * Thread-safe: Yes (uses thread-local exception)
  */
static void
invalid_pin_param (const char *msg)
{
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "%s", msg);
}

/* ============================================================================
 * SPKI Hash Extraction
 * ============================================================================
 */

 /**
  * tls_pinning_extract_spki_hash - Compute SPKI SHA256 hash from X509 certificate
  *
  * @cert: Certificate to extract public key info from (non-owning)
  * @out_hash: Output buffer for 32-byte SHA256 hash
  *
  * Extracts SubjectPublicKeyInfo DER from cert, computes SHA256 using SocketCrypto,
  * and stores in out_hash. Caller must provide SOCKET_TLS_PIN_HASH_LEN bytes buffer.
  *
  * Returns: 0 on success, -1 on failure (invalid cert or OpenSSL error)
  * Thread-safe: Yes
  * Raises: None (error code only)
  */
int
tls_pinning_extract_spki_hash (const X509 *cert, unsigned char *out_hash)
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

 /**
  * tls_pinning_check_chain - Verify if any certificate in chain matches a configured pin
  *
  * @ctx: TLS context with configured pins
  * @chain: Certificate chain to check (non-owning reference)
  *
  * Extracts SPKI SHA256 hash from each cert in chain and checks against
  * configured pins using constant-time comparison. Returns true if any match.
  *
  * Returns: 1 if pin match found in chain, 0 otherwise (no error)
  * Thread-safe: Yes (read-only after config)
  * Raises: None
  */
int
tls_pinning_check_chain (T ctx, const STACK_OF (X509) * chain)
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

 /**
  * SocketTLSContext_add_pin - Add binary SHA256 SPKI pin to context
  *
  * @ctx: TLS context
  * @sha256_hash: 32-byte SHA256 hash of SubjectPublicKeyInfo DER
  *
  * Adds pin if not already present (deduped via constant-time check).
  *
  * Raises: SocketTLS_Failed if NULL input or max pins reached
  * Thread-safe: No - config modification
  */
void
SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    invalid_pin_param ("PIN hash cannot be NULL");

  insert_pin (ctx, sha256_hash);
}

 /**
  * SocketTLSContext_add_pin_hex - Add pin from hex-encoded SHA256 hash string
  *
  * @ctx: TLS context
  * @hex_hash: Hex string (64 chars) or "sha256//hex" (HPKP compat)
  *
  * Parses hex (optionally skipping "sha256//" prefix), decodes to binary,
  * then adds as pin if unique.
  *
  * Raises: SocketTLS_Failed on invalid format or max reached
  * Thread-safe: No
  */
void
SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash)
{
  assert (ctx);

  if (!hex_hash || !*hex_hash)
    invalid_pin_param ("PIN hex hash cannot be NULL or empty");

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

 /**
  * SocketTLSContext_add_pin_from_cert - Add pin by loading certificate from file
  *
  * @ctx: TLS context
  * @cert_file: Path to PEM-encoded X509 certificate file
  *
  * Loads cert from file, validates path, extracts SPKI hash, adds if unique.
  *
  * Raises: SocketTLS_Failed on file open/read/parse/extract fail or max reached
  * Thread-safe: No
  */
void
SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file)
{
  assert (ctx);

  if (!cert_file || !*cert_file)
    invalid_pin_param ("Certificate file path cannot be NULL or empty");

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

 /**
  * SocketTLSContext_add_pin_from_x509 - Add pin from existing X509 certificate
  *
  * @ctx: TLS context to add pin to
  * @cert: Certificate whose SPKI hash to pin (non-owning, copied)
  *
  * Extracts SPKI SHA256 hash and adds to pins if not duplicate.
  *
  * Raises: SocketTLS_Failed on invalid cert or extract fail
  * Thread-safe: No
  */
void
SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert)
{
  assert (ctx);

  if (!cert)
    invalid_pin_param ("X509 certificate cannot be NULL");

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from X509 certificate");
    }

  insert_pin (ctx, hash);
}

 /**
  * SocketTLSContext_clear_pins - Remove all configured pins
  *
  * @ctx: TLS context
  *
  * Clears all pins using secure_clear for security. Capacity preserved
  * for future adds (freed on context disposal via arena).
  *
  * Thread-safe: No
  * Raises: None
  */
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

 /**
  * SocketTLSContext_set_pin_enforcement - Set strict pin enforcement mode
  *
  * @ctx: TLS context
  * @enforce: 1 for strict (fail on mismatch), 0 for warn/fallback
  *
  * Controls whether pin mismatch causes verification failure or just warning.
  *
  * Thread-safe: No
  * Raises: None
  */
void
SocketTLSContext_set_pin_enforcement (T ctx, int enforce)
{
  assert (ctx);
  ctx->pinning.enforce = enforce ? 1 : 0;
}

 /**
  * SocketTLSContext_get_pin_enforcement - Get current enforcement mode
  *
  * @ctx: TLS context
  *
  * Returns: 1 if strict enforcement enabled, 0 if warn mode
  * Thread-safe: Yes
  * Raises: None
  */
int
SocketTLSContext_get_pin_enforcement (T ctx)
{
  assert (ctx);
  return ctx->pinning.enforce;
}

 /**
  * SocketTLSContext_get_pin_count - Get number of configured pins
  *
  * @ctx: TLS context
  *
  * Returns: Current number of pins (0 to SOCKET_TLS_MAX_PINS)
  * Thread-safe: Yes
  * Raises: None
  */
size_t
SocketTLSContext_get_pin_count (T ctx)
{
  assert (ctx);
  return ctx->pinning.count;
}

 /**
  * SocketTLSContext_has_pins - Check if any pins configured
  *
  * @ctx: TLS context
  *
  * Quick check if pinning is active (count > 0).
  *
  * Returns: 1 if pins configured, 0 otherwise
  * Thread-safe: Yes
  * Raises: None
  */
int
SocketTLSContext_has_pins (T ctx)
{
  assert (ctx);
  return ctx->pinning.count > 0 ? 1 : 0;
}

 /**
  * SocketTLSContext_verify_pin - Check if hash matches any configured pin
  *
  * @ctx: TLS context
  * @sha256_hash: Hash to verify (SOCKET_TLS_PIN_HASH_LEN bytes)
  *
  * Performs constant-time search across all pins.
  *
  * Returns: 1 if matches, 0 otherwise
  * Thread-safe: Yes
  * Raises: None
  */
int
SocketTLSContext_verify_pin (T ctx, const unsigned char *sha256_hash)
{
  assert (ctx);

  if (!sha256_hash)
    return 0;

  return tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, sha256_hash);
}

 /**
  * SocketTLSContext_verify_cert_pin - Check if certificate matches configured pin
  *
  * @ctx: TLS context with pins configured
  * @cert: Certificate to verify against pins (non-owning)
  *
  * Extracts SPKI hash from cert and checks against configured pins.
  *
  * Returns: 1 if matches any pin, 0 otherwise
  * Thread-safe: Yes (after config)
  * Raises: None
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

  return tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash);
}

#undef T

#endif /* SOCKET_HAS_TLS */

