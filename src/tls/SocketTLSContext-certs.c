/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketTLSContext-certs.c - TLS Certificate Management
 *
 * Part of the Socket Library
 *
 * Certificate loading, CA loading, and SNI-based certificate selection.
 * Handles server certificate chains, private keys, and hostname-based
 * virtual hosting via SNI callbacks.
 *
 * Thread safety: Certificate operations are NOT thread-safe.
 * Perform all certificate setup before sharing context.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "core/SocketSecurity.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define T SocketTLSContext_T

static void
ctx_raise_error_fmt (const char *fmt, ...)
{
  char buf[SOCKET_TLS_ERROR_BUFSIZE];
  va_list args;
  va_start (args, fmt);
  vsnprintf (buf, sizeof (buf), fmt, args);
  va_end (args);
  ctx_raise_openssl_error (buf);
}

static void
validate_file_path_or_raise (const char *path, const char *desc)
{
  if (!tls_validate_file_path (path))
    {
      SOCKET_LOG_DEBUG_MSG ("Path validation failed for %s: %s", desc, path);
      ctx_raise_error_fmt ("Invalid %s file path", desc);
    }
}

static void
validate_cert_key_paths (const char *cert_file, const char *key_file)
{
  validate_file_path_or_raise (cert_file, "certificate");
  validate_file_path_or_raise (key_file, "private key");
}

void
SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                   const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  validate_cert_key_paths (cert_file, key_file);

  if (SSL_CTX_use_certificate_file (ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM)
      != 1)
    ctx_raise_openssl_error ("Failed to load certificate file");

  if (SSL_CTX_use_PrivateKey_file (ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM)
      != 1)
    ctx_raise_openssl_error ("Failed to load private key file");

  if (SSL_CTX_check_private_key (ctx->ssl_ctx) != 1)
    ctx_raise_openssl_error ("Private key does not match certificate");
}

void
SocketTLSContext_load_ca (T ctx, const char *ca_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (ca_file);

  validate_file_path_or_raise (ca_file, "CA");

  if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, ca_file, NULL) != 1)
    {
      if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, NULL, ca_file) != 1)
        ctx_raise_openssl_error ("Failed to load CA certificates");
    }
}

static int
apply_sni_cert (SSL *ssl, const STACK_OF (X509) * chain, EVP_PKEY *pkey)
{
  if (!chain || sk_X509_num (chain) == 0 || !pkey)
    return SSL_TLSEXT_ERR_NOACK;

  X509 *leaf = sk_X509_value (chain, 0);

  if (SSL_use_certificate (ssl, leaf) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_use_PrivateKey (ssl, pkey) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_check_private_key (ssl) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  for (int i = 1; i < sk_X509_num (chain); ++i)
    {
      X509 *inter = sk_X509_value (chain, i);
      if (inter && SSL_add1_chain_cert (ssl, inter) != 1)
        return SSL_TLSEXT_ERR_NOACK;
    }

  return SSL_TLSEXT_ERR_OK;
}

static int
find_sni_cert_index (const T ctx, const char *hostname)
{
  for (size_t i = 0; i < ctx->sni_certs.count; i++)
    {
      const char *stored = ctx->sni_certs.hostnames[i];
      if (stored && strcasecmp (stored, hostname) == 0)
        return (int)i;
    }
  return -1;
}

static int
sni_callback (SSL *ssl, int *ad, void *arg)
{
  TLS_UNUSED (ad);
  T ctx = (T)arg;
  const char *hostname = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);

  if (!hostname || !ctx)
    return SSL_TLSEXT_ERR_NOACK;

  /* RFC 6066: max 255 bytes */
  size_t hostname_len = strlen (hostname);
  if (hostname_len == 0 || hostname_len > SOCKET_TLS_MAX_SNI_LEN)
    return SSL_TLSEXT_ERR_NOACK;

  int idx = find_sni_cert_index (ctx, hostname);
  if (idx < 0)
    return SSL_TLSEXT_ERR_NOACK;

  return apply_sni_cert (ssl, ctx->sni_certs.chains[idx],
                         ctx->sni_certs.pkeys[idx]);
}

static int
sni_realloc_array (void **ptr, size_t new_size)
{
  void *new_ptr = realloc (*ptr, new_size);
  if (!new_ptr)
    return 0;
  *ptr = new_ptr;
  return 1;
}

static void
expand_sni_capacity (T ctx)
{
  size_t new_cap = ctx->sni_certs.capacity == 0
                       ? SOCKET_TLS_SNI_INITIAL_CAPACITY
                       : ctx->sni_certs.capacity * 2;

  size_t alloc_size;
  if (!SocketSecurity_check_multiply (new_cap, sizeof (void *), &alloc_size)
      || !SocketSecurity_check_size (alloc_size))
    ctx_raise_openssl_error ("SNI capacity overflow");

  /* Pre-allocate all arrays atomically to prevent partial failure state
   * corruption. If any allocation fails, rollback successful allocations
   * before raising exception. This ensures context remains consistent. */
  void *new_hostnames = realloc (ctx->sni_certs.hostnames, alloc_size);
  void *new_cert_files = realloc (ctx->sni_certs.cert_files, alloc_size);
  void *new_key_files = realloc (ctx->sni_certs.key_files, alloc_size);
  void *new_chains = realloc (ctx->sni_certs.chains, alloc_size);
  void *new_pkeys = realloc (ctx->sni_certs.pkeys, alloc_size);

  /* Verify all allocations succeeded before committing state */
  if (!new_hostnames || !new_cert_files || !new_key_files || !new_chains
      || !new_pkeys)
    {
      /* Rollback successful allocations: only free if pointer changed
       * (realloc may return same pointer if shrinking or in-place resize) */
      if (new_hostnames && new_hostnames != ctx->sni_certs.hostnames)
        free (new_hostnames);
      if (new_cert_files && new_cert_files != ctx->sni_certs.cert_files)
        free (new_cert_files);
      if (new_key_files && new_key_files != ctx->sni_certs.key_files)
        free (new_key_files);
      if (new_chains && new_chains != ctx->sni_certs.chains)
        free (new_chains);
      if (new_pkeys && new_pkeys != ctx->sni_certs.pkeys)
        free (new_pkeys);

      ctx_raise_openssl_error ("Failed to allocate SNI certificate arrays");
    }

  /* All allocations succeeded - atomically commit new state */
  ctx->sni_certs.hostnames = new_hostnames;
  ctx->sni_certs.cert_files = new_cert_files;
  ctx->sni_certs.key_files = new_key_files;
  ctx->sni_certs.chains = new_chains;
  ctx->sni_certs.pkeys = new_pkeys;
  ctx->sni_certs.capacity = new_cap;
}

static char *
validate_and_copy_hostname (T ctx, const char *hostname)
{
  if (!tls_validate_hostname (hostname))
    ctx_raise_error_fmt ("Invalid SNI hostname '%s': invalid format or length",
                         hostname);

  return ctx_arena_strdup (ctx, hostname, "Failed to allocate hostname buffer");
}

static void
store_sni_metadata (T ctx, const char *hostname, const char *cert_file,
                    const char *key_file)
{
  size_t idx = ctx->sni_certs.count;

  ctx->sni_certs.hostnames[idx]
      = hostname ? validate_and_copy_hostname (ctx, hostname) : NULL;

  ctx->sni_certs.cert_files[idx] = ctx_arena_strdup (
      ctx, cert_file, "Failed to allocate certificate path buffer");

  ctx->sni_certs.key_files[idx]
      = ctx_arena_strdup (ctx, key_file, "Failed to allocate key path buffer");
}

static void
check_pem_file_size (FILE *fp, const char *path, const char *obj_type)
{
  if (fseek (fp, 0, SEEK_END) != 0)
    {
      fclose (fp);
      ctx_raise_openssl_error ("Cannot seek in PEM file");
    }

  long fsize = ftell (fp);
  if (fseek (fp, 0, SEEK_SET) != 0 || fsize == -1)
    {
      fclose (fp);
      ctx_raise_openssl_error ("Cannot determine PEM file size");
    }

  if ((size_t)fsize > SOCKET_TLS_MAX_CERT_FILE_SIZE)
    {
      fclose (fp);
      ctx_raise_error_fmt ("%s file '%s' too large: %ld bytes (max %zu)",
                           obj_type, path, fsize,
                           (size_t)SOCKET_TLS_MAX_CERT_FILE_SIZE);
    }
}

static FILE *
open_pem_file (const char *path, const char *obj_type)
{
  FILE *fp = fopen (path, "r");
  if (!fp)
    ctx_raise_error_fmt ("Cannot open %s file '%s': %s", obj_type, path,
                         strerror (errno));

  check_pem_file_size (fp, path, obj_type);
  return fp;
}

static STACK_OF (X509) * load_chain_from_file (const char *cert_file)
{
  FILE *fp = open_pem_file (cert_file, "certificate");

  STACK_OF (X509) *chain = sk_X509_new_null ();
  if (!chain)
    {
      fclose (fp);
      ctx_raise_openssl_error ("Failed to allocate certificate chain stack");
    }

  X509 *cert = NULL;
  int num_certs = 0;

  while ((cert = PEM_read_X509 (fp, NULL, NULL, NULL)) != NULL)
    {
      /* Security: Limit certificate chain depth to prevent DoS */
      if (num_certs >= SOCKET_TLS_MAX_CERT_CHAIN_DEPTH)
        {
          X509_free (cert);
          fclose (fp);
          sk_X509_pop_free (chain, X509_free);
          ctx_raise_error_fmt (
              "Certificate chain exceeds maximum depth of %d",
              SOCKET_TLS_MAX_CERT_CHAIN_DEPTH);
        }

      if (sk_X509_push (chain, cert) > 0)
        num_certs++;
      else
        X509_free (cert);
      cert = NULL;
    }

  fclose (fp);

  if (num_certs == 0)
    {
      sk_X509_free (chain);
      ctx_raise_openssl_error ("No certificates found in certificate file");
    }

  ERR_clear_error ();
  return chain;
}

/* NOTE: Encrypted private keys not supported - passphrase callback is NULL */
static EVP_PKEY *
load_pkey_from_file (const char *key_file)
{
  FILE *fp = open_pem_file (key_file, "private key");
  EVP_PKEY *pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!pkey)
    ctx_raise_openssl_error (
        "Failed to parse private key PEM (encrypted keys not supported)");

  return pkey;
}

static void
verify_keypair_match (STACK_OF (X509) * chain, EVP_PKEY *pkey)
{
  if (sk_X509_num (chain) == 0)
    {
      sk_X509_free (chain);
      tls_secure_free_pkey (pkey);
      ctx_raise_openssl_error ("Empty certificate chain");
    }

  X509 *leaf = sk_X509_value (chain, 0);
  if (X509_check_private_key (leaf, pkey) != 1)
    {
      sk_X509_pop_free (chain, X509_free);
      tls_secure_free_pkey (pkey);
      ctx_raise_openssl_error ("Private key does not match leaf certificate");
    }
}

static void
load_and_verify_keypair (const char *cert_file, const char *key_file,
                         STACK_OF (X509) * *chain_out, EVP_PKEY **pkey_out)
{
  STACK_OF (X509) *chain = load_chain_from_file (cert_file);
  EVP_PKEY *pkey = NULL;

  TRY pkey = load_pkey_from_file (key_file);
  EXCEPT (SocketTLS_Failed)
  sk_X509_pop_free (chain, X509_free);
  RERAISE;
  END_TRY;

  verify_keypair_match (chain, pkey);

  *chain_out = chain;
  *pkey_out = pkey;
}

static void
validate_server_context (const T ctx)
{
  if (!ctx->is_server)
    ctx_raise_openssl_error (
        "SNI certificates only supported for server contexts");
}

static void
validate_sni_count (const T ctx)
{
  if (ctx->sni_certs.count >= SOCKET_TLS_MAX_SNI_CERTS)
    ctx_raise_openssl_error ("Too many SNI certificates");
}

static void
ensure_sni_capacity (T ctx)
{
  if (ctx->sni_certs.count >= ctx->sni_certs.capacity)
    expand_sni_capacity (ctx);
}

static void
register_sni_callback_if_needed (T ctx, const char *hostname)
{
  if (ctx->sni_certs.count > 1 || (ctx->sni_certs.count == 1 && hostname))
    {
      SSL_CTX_set_tlsext_servername_callback (ctx->ssl_ctx, sni_callback);
      SSL_CTX_set_tlsext_servername_arg (ctx->ssl_ctx, ctx);
    }
}

static void
validate_hostname_matches_cert (STACK_OF (X509) * chain, EVP_PKEY *pkey,
                                const char *hostname)
{
  X509 *leaf = sk_X509_value (chain, 0);
  int match = X509_check_host (leaf, hostname, 0, 0, NULL);

  if (match != 1)
    {
      sk_X509_pop_free (chain, X509_free);
      tls_secure_free_pkey (pkey);
      const char *reason = (match == 0) ? "certificate subject mismatch"
                                        : "hostname validation error";
      ctx_raise_error_fmt ("SNI %s for hostname '%s'", reason, hostname);
    }
}

static void
validate_and_prepare_sni_slot (T ctx, const char *hostname,
                               const char *cert_file, const char *key_file)
{
  validate_cert_key_paths (cert_file, key_file);
  validate_server_context (ctx);
  validate_sni_count (ctx);
  ensure_sni_capacity (ctx);
  store_sni_metadata (ctx, hostname, cert_file, key_file);
}

static void
load_and_commit_sni_entry (T ctx, const char *hostname, const char *cert_file,
                           const char *key_file)
{
  STACK_OF (X509) *chain = NULL;
  EVP_PKEY *pkey = NULL;
  load_and_verify_keypair (cert_file, key_file, &chain, &pkey);

  if (hostname)
    validate_hostname_matches_cert (chain, pkey, hostname);

  size_t idx = ctx->sni_certs.count;
  ctx->sni_certs.chains[idx] = chain;
  ctx->sni_certs.pkeys[idx] = pkey;

  if (!hostname)
    SocketTLSContext_load_certificate (ctx, cert_file, key_file);

  ctx->sni_certs.count++;
  register_sni_callback_if_needed (ctx, hostname);
}

void
SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                  const char *cert_file, const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  validate_and_prepare_sni_slot (ctx, hostname, cert_file, key_file);
  load_and_commit_sni_entry (ctx, hostname, cert_file, key_file);
}

#undef T

#endif /* SOCKET_HAS_TLS */
