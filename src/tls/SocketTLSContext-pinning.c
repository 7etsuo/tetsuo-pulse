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

/* Accepts optional "sha256//" prefix for HPKP compatibility */
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

static size_t
calculate_pin_capacity (size_t current_cap, size_t max_pins)
{
  if (current_cap == 0)
    return SOCKET_TLS_PIN_INITIAL_CAPACITY;

  size_t new_cap = current_cap * SOCKET_BUFFER_GROWTH_FACTOR;
  return (new_cap > max_pins) ? max_pins : new_cap;
}

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
      memcpy (new_pins,
              ctx->pinning.pins,
              ctx->pinning.count * sizeof (TLSCertPin));
    }

  ctx->pinning.pins = new_pins;
  ctx->pinning.capacity = new_cap;
}

static void
ensure_pin_capacity (T ctx)
{
  check_pin_limit (ctx);

  if (ctx->pinning.count < ctx->pinning.capacity)
    return;

  grow_pin_array (ctx);
}

static void
insert_pin (T ctx, const unsigned char *hash)
{
  if (tls_pinning_find (ctx->pinning.pins, ctx->pinning.count, hash))
    return;

  ensure_pin_capacity (ctx);
  memcpy (ctx->pinning.pins[ctx->pinning.count].hash,
          hash,
          SOCKET_TLS_PIN_HASH_LEN);
  ctx->pinning.count++;
}

static void
raise_invalid_pin_param (const char *msg)
{
  RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "%s", msg);
}

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

/* Constant-time search to prevent timing attacks */
int
tls_pinning_find (const TLSCertPin *pins,
                  size_t count,
                  const unsigned char *hash)
{
  if (!pins || count == 0 || !hash)
    return 0;

  /* Volatile + bitwise OR: constant-time regardless of match position */
  volatile int found = 0;
  for (size_t i = 0; i < count; i++)
    {
      int match = (SocketCrypto_secure_compare (
                       hash, pins[i].hash, SOCKET_TLS_PIN_HASH_LEN)
                   == 0);
      found |= match;
    }

  return found;
}

int
tls_pinning_check_chain (T ctx, const STACK_OF (X509) * chain)
{
  if (!ctx || !chain)
    return 0;

  /* Fast path: no pins configured. */
  pthread_mutex_lock (&ctx->pinning.lock);
  size_t initial_count = ctx->pinning.count;
  pthread_mutex_unlock (&ctx->pinning.lock);
  if (initial_count == 0)
    return 0;

  int chain_len = sk_X509_num (chain);
  const int max_check = SOCKET_TLS_MAX_CERT_CHAIN_DEPTH;
  if (chain_len > max_check)
    {
      SOCKET_LOG_WARN_MSG ("Pinning check truncated: chain_len=%d > max=%d",
                           chain_len,
                           max_check);
      chain_len = max_check;
    }

  unsigned char hashes[SOCKET_TLS_MAX_CERT_CHAIN_DEPTH]
                      [SOCKET_TLS_PIN_HASH_LEN];
  int num_hashes = 0;
  for (int i = 0; i < chain_len; i++)
    {
      X509 *cert = sk_X509_value (chain, i);
      if (!cert)
        continue;

      if (tls_pinning_extract_spki_hash (cert, hashes[num_hashes]) == 0)
        num_hashes++;
    }

  int match = 0;
  pthread_mutex_lock (&ctx->pinning.lock);
  const TLSCertPin *pins = ctx->pinning.pins;
  size_t count = ctx->pinning.count;
  if (pins && count > 0)
    {
      for (int j = 0; j < num_hashes; j++)
        {
          if (tls_pinning_find (pins, count, hashes[j]))
            {
              match = 1;
              break;
            }
        }
    }
  pthread_mutex_unlock (&ctx->pinning.lock);

  return match;
}

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

/* Helper 1: Secure file opening with symlink protection */
static FILE *
open_cert_file_secure (const char *cert_file)
{
  errno = 0;
  int fd = open (cert_file, O_RDONLY | O_NOFOLLOW);
  if (fd == -1)
    {
      if (errno == ELOOP)
        {
          RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                               "Symlinks not allowed for certificate files: %s",
                               cert_file);
        }
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Cannot open certificate file '%.200s': %s",
                           cert_file,
                           Socket_safe_strerror (errno));
    }

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    {
      close (fd);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Cannot fdopen certificate file descriptor");
    }
  return fp;
}

/* Helper 2: Validate certificate file size */
static off_t
validate_cert_file_size (FILE *fp)
{
  if (fseeko (fp, 0, SEEK_END) != 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Cannot seek in certificate file");
    }

  off_t fsize = ftello (fp);
  if (fsize < 0 || fseeko (fp, 0, SEEK_SET) != 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Cannot determine certificate file size");
    }

  size_t usize = (size_t)fsize;
  if (usize > SOCKET_TLS_MAX_CERT_FILE_SIZE
      || !SocketSecurity_check_size (usize))
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Certificate file too large: %ld bytes (max %zu)",
                           fsize,
                           (size_t)SOCKET_TLS_MAX_CERT_FILE_SIZE);
    }
  return fsize;
}

/* Helper 3: Parse certificate and extract SPKI hash */
static void
parse_cert_and_extract_pin (FILE *fp, unsigned char *hash)
{
  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  if (!cert)
    {
      ctx_raise_openssl_error ("Failed to parse certificate file");
    }

  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      X509_free (cert);
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from certificate");
    }

  X509_free (cert);
}

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

  FILE *fp = open_cert_file_secure (cert_file);
  validate_cert_file_size (fp);

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  parse_cert_and_extract_pin (fp, hash);
  fclose (fp);

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

void
SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert)
{
  assert (ctx);

  if (!cert)
    raise_invalid_pin_param ("X509 certificate cannot be NULL");

  unsigned char hash[SOCKET_TLS_PIN_HASH_LEN];
  if (tls_pinning_extract_spki_hash (cert, hash) != 0)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to extract SPKI hash from X509 certificate");
    }

  pthread_mutex_lock (&ctx->pinning.lock);
  insert_pin (ctx, hash);
  pthread_mutex_unlock (&ctx->pinning.lock);
}

void
SocketTLSContext_clear_pins (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);

  if (ctx->pinning.pins && ctx->pinning.capacity > 0)
    {
      SocketCrypto_secure_clear (ctx->pinning.pins,
                                 ctx->pinning.capacity * sizeof (TLSCertPin));
    }
  ctx->pinning.count = 0;

  pthread_mutex_unlock (&ctx->pinning.lock);
}

void
SocketTLSContext_set_pin_enforcement (T ctx, int enforce)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  ctx->pinning.enforce = enforce ? 1 : 0;
  pthread_mutex_unlock (&ctx->pinning.lock);
}

int
SocketTLSContext_get_pin_enforcement (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = ctx->pinning.enforce;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

size_t
SocketTLSContext_get_pin_count (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  size_t res = ctx->pinning.count;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

int
SocketTLSContext_has_pins (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->pinning.lock);
  int res = (ctx->pinning.count > 0) ? 1 : 0;
  pthread_mutex_unlock (&ctx->pinning.lock);

  return res;
}

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
