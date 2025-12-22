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

/**
 * ctx_raise_error_fmt - Raise TLS exception with formatted message
 * @fmt: Format string
 * @...: Format arguments
 *
 * Raises: SocketTLS_Failed with formatted error message
 */
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

/**
 * validate_file_path_or_raise - Validate file path and raise on failure
 * @path: File path to validate
 * @desc: Description for error message (e.g., "certificate", "private key")
 *
 * Security: Error messages use generic text to avoid leaking filesystem
 * structure information. Full path is logged at DEBUG level for diagnostics.
 *
 * Raises: SocketTLS_Failed on invalid path
 */
static void
validate_file_path_or_raise (const char *path, const char *desc)
{
  if (!tls_validate_file_path (path))
    {
      /* Log full path at debug level for diagnostics, but don't expose in
       * exception message to prevent filesystem structure disclosure. */
      SOCKET_LOG_DEBUG_MSG ("Path validation failed for %s: %s", desc, path);
      ctx_raise_error_fmt ("Invalid %s file path", desc);
    }
}

/**
 * validate_cert_key_paths - Validate certificate and key file paths
 * @cert_file: Certificate file path
 * @key_file: Private key file path
 *
 * Raises: SocketTLS_Failed on invalid paths
 */
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

/**
 * apply_sni_cert - Apply certificate and key to SSL connection
 * @ssl: SSL connection object
 * @chain: Certificate chain (leaf at index 0)
 * @pkey: Private key to apply
 *
 * Returns: SSL_TLSEXT_ERR_OK on success, SSL_TLSEXT_ERR_NOACK on failure
 */
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

/**
 * find_sni_cert_index - Find certificate index matching hostname
 * @ctx: TLS context with SNI certificates
 * @hostname: Hostname to match (case-insensitive per RFC 6066)
 *
 * Returns: Index of matching certificate, or -1 if not found
 */
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

/**
 * sni_callback - SNI callback for hostname-based certificate selection
 * @ssl: SSL connection object
 * @ad: Alert descriptor (unused)
 * @arg: Context pointer
 *
 * Security: Validates hostname length before processing to prevent
 * issues with malformed SNI extensions containing excessive lengths.
 *
 * Returns: SSL_TLSEXT_ERR_OK on match, SSL_TLSEXT_ERR_NOACK otherwise
 */
static int
sni_callback (SSL *ssl, int *ad, void *arg)
{
  TLS_UNUSED (ad);
  T ctx = (T)arg;
  const char *hostname = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);

  if (!hostname || !ctx)
    return SSL_TLSEXT_ERR_NOACK;

  /* Security: Validate hostname length per RFC 6066 (max 255 bytes).
   * Prevents issues with malformed SNI extensions. */
  size_t hostname_len = strlen (hostname);
  if (hostname_len == 0 || hostname_len > SOCKET_TLS_MAX_SNI_LEN)
    return SSL_TLSEXT_ERR_NOACK;

  int idx = find_sni_cert_index (ctx, hostname);
  if (idx < 0)
    return SSL_TLSEXT_ERR_NOACK;

  return apply_sni_cert (ssl, ctx->sni_certs.chains[idx],
                         ctx->sni_certs.pkeys[idx]);
}

/**
 * sni_realloc_array - Safely reallocate a single SNI array
 * @ptr: Pointer to array pointer
 * @new_size: New size in bytes
 *
 * Returns: 1 on success, 0 on failure (original pointer unchanged)
 */
static int
sni_realloc_array (void **ptr, size_t new_size)
{
  void *new_ptr = realloc (*ptr, new_size);
  if (!new_ptr)
    return 0;
  *ptr = new_ptr;
  return 1;
}

/**
 * expand_sni_capacity - Expand SNI arrays capacity
 * @ctx: Context with SNI arrays to expand
 *
 * Doubles capacity or initializes to SOCKET_TLS_SNI_INITIAL_CAPACITY if empty.
 * Raises: SocketTLS_Failed on allocation failure
 */
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

  /* Reallocate each array - on failure, originals are preserved */
  if (!sni_realloc_array ((void **)&ctx->sni_certs.hostnames, alloc_size)
      || !sni_realloc_array ((void **)&ctx->sni_certs.cert_files, alloc_size)
      || !sni_realloc_array ((void **)&ctx->sni_certs.key_files, alloc_size)
      || !sni_realloc_array ((void **)&ctx->sni_certs.chains, alloc_size)
      || !sni_realloc_array ((void **)&ctx->sni_certs.pkeys, alloc_size))
    ctx_raise_openssl_error ("Failed to allocate SNI certificate arrays");

  ctx->sni_certs.capacity = new_cap;
}

/**
 * validate_and_copy_hostname - Validate and copy hostname to arena
 * @ctx: Context with arena
 * @hostname: Hostname to validate and copy
 *
 * Returns: Arena-allocated copy of hostname
 * Raises: SocketTLS_Failed on invalid hostname or allocation failure
 */
static char *
validate_and_copy_hostname (T ctx, const char *hostname)
{
  if (!tls_validate_hostname (hostname))
    ctx_raise_error_fmt ("Invalid SNI hostname '%s': invalid format or length",
                         hostname);

  return ctx_arena_strdup (ctx, hostname, "Failed to allocate hostname buffer");
}

/**
 * store_sni_metadata - Store hostname and paths in SNI arrays
 * @ctx: Context
 * @hostname: Hostname to store (NULL for default)
 * @cert_file: Certificate file path
 * @key_file: Key file path
 */
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

/**
 * check_pem_file_size - Validate PEM file size against security limits
 * @fp: Open file pointer (will be reset to beginning)
 * @path: File path for error messages
 * @obj_type: Object type for error messages
 *
 * Enforces SOCKET_TLS_MAX_CERT_FILE_SIZE (1MB) limit to prevent memory
 * exhaustion attacks from maliciously oversized certificate/key files.
 *
 * Raises: SocketTLS_Failed if file too large or seek fails
 */
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

  /* Use defined constant for certificate file size limit (1MB default) */
  if ((size_t)fsize > SOCKET_TLS_MAX_CERT_FILE_SIZE)
    {
      fclose (fp);
      ctx_raise_error_fmt ("%s file '%s' too large: %ld bytes (max %zu)",
                           obj_type, path, fsize,
                           (size_t)SOCKET_TLS_MAX_CERT_FILE_SIZE);
    }
}

/**
 * open_pem_file - Open a PEM file for reading with size validation
 * @path: File path
 * @obj_type: Object type for error messages
 *
 * Returns: FILE pointer
 * Raises: SocketTLS_Failed if file cannot be opened or is too large
 */
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

/**
 * load_chain_from_file - Load X509 certificate chain from PEM file
 * @cert_file: Certificate file path
 *
 * Returns: Loaded certificate chain (caller owns)
 * Raises: SocketTLS_Failed on file or parse error
 */
static STACK_OF (X509) * load_chain_from_file (const char *cert_file)
{
  FILE *fp = open_pem_file (cert_file, "certificate");

  STACK_OF (X509) *chain = sk_X509_new_null ();
  if (!chain)
    {
      fclose (fp);
      ctx_raise_openssl_error ("Failed to allocate certificate chain stack");
    }

  X509 *volatile cert = NULL;
  volatile int num_certs = 0;

  while ((cert = PEM_read_X509 (fp, NULL, NULL, NULL)) != NULL)
    {
      if (sk_X509_push (chain, (X509 *)cert) > 0)
        num_certs++;
      else
        X509_free ((X509 *)cert);
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

/**
 * load_pkey_from_file - Load private key from PEM file
 * @key_file: Key file path
 *
 * Loads an unencrypted private key from a PEM-formatted file.
 *
 * NOTE: Encrypted private keys (those requiring a passphrase) are NOT
 * supported by this function. The passphrase callback is set to NULL,
 * so encrypted keys will fail with "Failed to parse private key PEM".
 * To use encrypted keys, applications must:
 * 1. Decrypt the key externally before loading, OR
 * 2. Implement a custom loading mechanism with SSL_CTX_set_default_passwd_cb()
 *
 * Returns: Loaded EVP_PKEY (caller owns)
 * Raises: SocketTLS_Failed on file or parse error (including encrypted keys)
 */
static EVP_PKEY *
load_pkey_from_file (const char *key_file)
{
  FILE *fp = open_pem_file (key_file, "private key");

  /* NULL password callback - encrypted keys will fail.
   * This is intentional: passphrase prompts are interactive and
   * incompatible with automated server deployment. */
  EVP_PKEY *pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!pkey)
    ctx_raise_openssl_error (
        "Failed to parse private key PEM (encrypted keys not supported)");

  return pkey;
}

/**
 * verify_keypair_match - Verify certificate and key match
 * @chain: Certificate chain (leaf at index 0)
 * @pkey: Private key
 *
 * Raises: SocketTLS_Failed if key doesn't match or chain is empty
 */
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

/**
 * load_and_verify_keypair - Load cert/key and verify they match
 * @cert_file: Certificate file path
 * @key_file: Key file path
 * @chain_out: Output certificate chain pointer
 * @pkey_out: Output private key pointer
 *
 * Raises: SocketTLS_Failed on any load or validation error
 */
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

/**
 * validate_server_context - Ensure context is a server context
 * @ctx: Context to validate
 *
 * Raises: SocketTLS_Failed if not a server context
 */
static void
validate_server_context (const T ctx)
{
  if (!ctx->is_server)
    ctx_raise_openssl_error (
        "SNI certificates only supported for server contexts");
}

/**
 * validate_sni_count - Ensure SNI cert count limit not exceeded
 * @ctx: Context to validate
 *
 * Raises: SocketTLS_Failed if limit exceeded
 */
static void
validate_sni_count (const T ctx)
{
  if (ctx->sni_certs.count >= SOCKET_TLS_MAX_SNI_CERTS)
    ctx_raise_openssl_error ("Too many SNI certificates");
}

/**
 * ensure_sni_capacity - Ensure SNI arrays have room for one more entry
 * @ctx: Context
 */
static void
ensure_sni_capacity (T ctx)
{
  if (ctx->sni_certs.count >= ctx->sni_certs.capacity)
    expand_sni_capacity (ctx);
}

/**
 * register_sni_callback_if_needed - Register SNI callback when appropriate
 * @ctx: Context to configure
 * @hostname: Hostname that was added (NULL if default)
 */
static void
register_sni_callback_if_needed (T ctx, const char *hostname)
{
  if (ctx->sni_certs.count > 1 || (ctx->sni_certs.count == 1 && hostname))
    {
      SSL_CTX_set_tlsext_servername_callback (ctx->ssl_ctx, sni_callback);
      SSL_CTX_set_tlsext_servername_arg (ctx->ssl_ctx, ctx);
    }
}

/**
 * validate_hostname_matches_cert - Verify hostname matches certificate CN/SAN
 * @chain: Certificate chain
 * @pkey: Private key (freed on error)
 * @hostname: Hostname to verify
 *
 * Raises: SocketTLS_Failed if hostname doesn't match certificate
 */
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

/**
 * validate_and_prepare_sni_slot - Validate inputs and prepare SNI metadata
 * @ctx: TLS context
 * @hostname: SNI hostname (NULL for default certificate)
 * @cert_file: Path to certificate PEM file
 * @key_file: Path to private key PEM file
 *
 * Raises: SocketTLS_Failed on any validation or allocation failure
 */
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

/**
 * load_and_commit_sni_entry - Load keypair, store objects, and commit entry
 * @ctx: TLS context
 * @hostname: SNI hostname (NULL for default)
 * @cert_file: Certificate file path
 * @key_file: Private key file path
 *
 * Raises: SocketTLS_Failed on load, verification, or default set failure
 */
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
