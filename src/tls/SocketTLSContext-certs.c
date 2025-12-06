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

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp for RFC 6066 case-insensitive SNI matching */

#define T SocketTLSContext_T

/* ============================================================================
 * Certificate Management
 * ============================================================================
 */

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
  if (!tls_validate_file_path (cert_file)
      || !tls_validate_file_path (key_file))
    {
      ctx_raise_openssl_error ("Invalid certificate or key file path");
    }
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
    {
      ctx_raise_openssl_error ("Failed to load certificate file");
    }

  if (SSL_CTX_use_PrivateKey_file (ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM)
      != 1)
    {
      ctx_raise_openssl_error ("Failed to load private key file");
    }

  if (SSL_CTX_check_private_key (ctx->ssl_ctx) != 1)
    {
      ctx_raise_openssl_error ("Private key does not match certificate");
    }
}

void
SocketTLSContext_load_ca (T ctx, const char *ca_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (ca_file);

  if (!tls_validate_file_path (ca_file))
    {
      ctx_raise_openssl_error ("Invalid CA file path");
    }

  if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, ca_file, NULL) != 1)
    {
      if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, NULL, ca_file) != 1)
        {
          ctx_raise_openssl_error ("Failed to load CA certificates");
        }
    }
}

/* ============================================================================
 * SNI Certificate Management - Internal Helpers
 * ============================================================================
 */

/**
 * apply_sni_cert - Apply certificate and key to SSL connection
 * @ssl: SSL connection object
 * @cert: X509 certificate to apply
 * @pkey: Private key to apply
 *
 * Returns: SSL_TLSEXT_ERR_OK on success, SSL_TLSEXT_ERR_NOACK on failure
 */
static int
apply_sni_cert (SSL *ssl, X509 *cert, EVP_PKEY *pkey)
{
  if (!cert || !pkey)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_use_certificate (ssl, cert) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_use_PrivateKey (ssl, pkey) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  if (SSL_check_private_key (ssl) != 1)
    return SSL_TLSEXT_ERR_NOACK;

  return SSL_TLSEXT_ERR_OK;
}

/**
 * find_sni_cert_index - Find certificate index matching hostname
 * @ctx: TLS context with SNI certificates
 * @hostname: Hostname to match (case-insensitive per RFC 6066)
 *
 * Returns: Index of matching certificate, or -1 if not found
 *
 * Note: Uses O(n) linear scan. Sufficient for typical SNI certificate
 * counts (< 100). For high-volume virtual hosting, consider hash table.
 * Per RFC 6066 Section 3, hostnames are DNS names which are case-insensitive.
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

  int idx = find_sni_cert_index (ctx, hostname);
  if (idx < 0)
    return SSL_TLSEXT_ERR_NOACK;

  return apply_sni_cert (ssl, ctx->sni_certs.certs[idx],
                         ctx->sni_certs.pkeys[idx]);
}

/* ============================================================================
 * SNI Array Expansion
 * ============================================================================
 */

/**
 * sni_alloc_new_arrays - Allocate new SNI arrays with given capacity
 * @cap: New capacity
 * @hostnames: Output hostname array pointer
 * @cert_files: Output cert_files array pointer
 * @key_files: Output key_files array pointer
 * @certs: Output certs array pointer
 * @pkeys: Output pkeys array pointer
 *
 * Returns: 1 on success (all allocated), 0 on failure (none changed)
 */
static int
sni_alloc_new_arrays (size_t cap, char ***hostnames, char ***cert_files,
                      char ***key_files, X509 ***certs, EVP_PKEY ***pkeys)
{
  char **new_hostnames = realloc (*hostnames, cap * sizeof (char *));
  char **new_cert_files = realloc (*cert_files, cap * sizeof (char *));
  char **new_key_files = realloc (*key_files, cap * sizeof (char *));
  X509 **new_certs = realloc (*certs, cap * sizeof (X509 *));
  EVP_PKEY **new_pkeys = realloc (*pkeys, cap * sizeof (EVP_PKEY *));

  if (!new_hostnames || !new_cert_files || !new_key_files || !new_certs
      || !new_pkeys)
    {
      /* Free only NEW allocations that differ from originals */
      if (new_hostnames && new_hostnames != *hostnames)
        free (new_hostnames);
      if (new_cert_files && new_cert_files != *cert_files)
        free (new_cert_files);
      if (new_key_files && new_key_files != *key_files)
        free (new_key_files);
      if (new_certs && new_certs != *certs)
        free (new_certs);
      if (new_pkeys && new_pkeys != *pkeys)
        free (new_pkeys);
      return 0;
    }

  *hostnames = new_hostnames;
  *cert_files = new_cert_files;
  *key_files = new_key_files;
  *certs = new_certs;
  *pkeys = new_pkeys;
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

  int ok = sni_alloc_new_arrays (new_cap, &ctx->sni_certs.hostnames,
                                 &ctx->sni_certs.cert_files,
                                 &ctx->sni_certs.key_files, &ctx->sni_certs.certs,
                                 &ctx->sni_certs.pkeys);
  if (!ok)
    {
      ctx_raise_openssl_error ("Failed to allocate SNI certificate arrays");
    }

  ctx->sni_certs.capacity = new_cap;
}

/* ============================================================================
 * SNI Certificate Loading Helpers
 * ============================================================================
 */

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
    {
      ctx_raise_openssl_error ("Invalid SNI hostname format or length");
    }

  return ctx_arena_strdup (ctx, hostname, "Failed to allocate hostname buffer");
}

/**
 * store_sni_hostname - Store hostname in SNI array
 * @ctx: Context
 * @hostname: Hostname to store (NULL for default)
 */
static void
store_sni_hostname (T ctx, const char *hostname)
{
  size_t idx = ctx->sni_certs.count;
  ctx->sni_certs.hostnames[idx]
      = hostname ? validate_and_copy_hostname (ctx, hostname) : NULL;
}

/**
 * store_sni_paths - Store cert/key paths in SNI arrays
 * @ctx: Context
 * @cert_file: Certificate file path
 * @key_file: Key file path
 */
static void
store_sni_paths (T ctx, const char *cert_file, const char *key_file)
{
  size_t idx = ctx->sni_certs.count;

  ctx->sni_certs.cert_files[idx]
      = ctx_arena_strdup (ctx, cert_file,
                          "Failed to allocate certificate path buffer");

  ctx->sni_certs.key_files[idx]
      = ctx_arena_strdup (ctx, key_file, "Failed to allocate key path buffer");
}

/**
 * open_pem_file - Open a PEM file for reading
 * @path: File path
 * @error_msg: Error message on failure
 *
 * Returns: FILE pointer
 * Raises: SocketTLS_Failed if file cannot be opened
 */
static FILE *
open_pem_file (const char *path, const char *error_msg)
{
  FILE *fp = fopen (path, "r");
  if (!fp)
    {
      ctx_raise_openssl_error (error_msg);
    }
  return fp;
}

/**
 * load_cert_from_file - Load X509 certificate from PEM file
 * @cert_file: Certificate file path
 *
 * Returns: Loaded X509 certificate
 * Raises: SocketTLS_Failed on file or parse error
 */
static X509 *
load_cert_from_file (const char *cert_file)
{
  FILE *fp = open_pem_file (cert_file, "Cannot open certificate file");

  X509 *cert = PEM_read_X509 (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!cert)
    {
      ctx_raise_openssl_error ("Failed to parse certificate PEM");
    }

  return cert;
}

/**
 * load_pkey_from_file - Load private key from PEM file
 * @key_file: Key file path
 *
 * Returns: Loaded EVP_PKEY
 * Raises: SocketTLS_Failed on file or parse error
 */
static EVP_PKEY *
load_pkey_from_file (const char *key_file)
{
  FILE *fp = open_pem_file (key_file, "Cannot open private key file");

  EVP_PKEY *pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!pkey)
    {
      ctx_raise_openssl_error ("Failed to parse private key PEM");
    }

  return pkey;
}

/**
 * free_cert_and_pkey - Free certificate and private key (helper)
 * @cert: Certificate to free (may be NULL)
 * @pkey: Private key to free (may be NULL)
 */
static void
free_cert_and_pkey (X509 *cert, EVP_PKEY *pkey)
{
  if (pkey)
    EVP_PKEY_free (pkey);
  if (cert)
    X509_free (cert);
}

/**
 * load_and_verify_keypair - Load cert/key and verify they match
 * @cert_file: Certificate file path
 * @key_file: Key file path
 * @cert_out: Output certificate pointer
 * @pkey_out: Output private key pointer
 *
 * Raises: SocketTLS_Failed on any load or validation error
 */
static void
load_and_verify_keypair (const char *cert_file, const char *key_file,
                         X509 **cert_out, EVP_PKEY **pkey_out)
{
  X509 *cert = load_cert_from_file (cert_file);
  EVP_PKEY *pkey = NULL;

  TRY
    pkey = load_pkey_from_file (key_file);
  EXCEPT (SocketTLS_Failed)
    X509_free (cert);
    RERAISE;
  END_TRY;

  if (X509_check_private_key (cert, pkey) != 1)
    {
      free_cert_and_pkey (cert, pkey);
      ctx_raise_openssl_error ("Private key does not match certificate");
    }

  *cert_out = cert;
  *pkey_out = pkey;
}

/**
 * store_sni_objects - Store loaded cert/key in SNI arrays
 * @ctx: Context
 * @cert: Loaded certificate
 * @pkey: Loaded private key
 */
static void
store_sni_objects (T ctx, X509 *cert, EVP_PKEY *pkey)
{
  size_t idx = ctx->sni_certs.count;
  ctx->sni_certs.certs[idx] = cert;
  ctx->sni_certs.pkeys[idx] = pkey;
}

/* ============================================================================
 * SNI Certificate Validation
 * ============================================================================
 */

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
    {
      ctx_raise_openssl_error (
          "SNI certificates only supported for server contexts");
    }
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
    {
      ctx_raise_openssl_error ("Too many SNI certificates");
    }
}

/**
 * ensure_sni_capacity - Ensure SNI arrays have room for one more entry
 * @ctx: Context
 */
static void
ensure_sni_capacity (T ctx)
{
  if (ctx->sni_certs.count >= ctx->sni_certs.capacity)
    {
      expand_sni_capacity (ctx);
    }
}

/**
 * register_sni_callback_if_needed - Register SNI callback when appropriate
 * @ctx: Context to configure
 * @hostname: Hostname that was added (NULL if default)
 *
 * Registers the SNI callback if we have multiple certificates or
 * if the certificate has a specific hostname (not the default).
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
 * set_default_certificate - Apply default certificate to context
 * @ctx: Context
 * @cert_file: Certificate file path
 * @key_file: Key file path
 *
 * Called when hostname is NULL to set the default certificate.
 */
static void
set_default_certificate (T ctx, const char *cert_file, const char *key_file)
{
  SocketTLSContext_load_certificate (ctx, cert_file, key_file);
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

void
SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                  const char *cert_file, const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  /* Validate inputs */
  validate_cert_key_paths (cert_file, key_file);
  validate_server_context (ctx);
  validate_sni_count (ctx);
  ensure_sni_capacity (ctx);

  /* Store metadata */
  store_sni_hostname (ctx, hostname);
  store_sni_paths (ctx, cert_file, key_file);

  /* Load and verify keypair */
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  load_and_verify_keypair (cert_file, key_file, &cert, &pkey);
  store_sni_objects (ctx, cert, pkey);

  /* Set as default if no hostname specified */
  if (!hostname)
    {
      set_default_certificate (ctx, cert_file, key_file);
    }

  ctx->sni_certs.count++;
  register_sni_callback_if_needed (ctx, hostname);
}

#undef T

#endif /* SOCKET_HAS_TLS */
