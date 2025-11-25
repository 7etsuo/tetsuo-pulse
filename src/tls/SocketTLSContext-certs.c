/**
 * SocketTLSContext-certs.c - TLS Certificate Management
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles certificate and CA loading, SNI certificate mapping for virtual
 * hosting, and SNI callback registration. Validates paths and certificates.
 *
 * Thread safety: Not thread-safe (modifies shared context).
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLSContext-private.h"
#include <assert.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#define T SocketTLSContext_T

/* ============================================================================
 * SNI Certificate Selection Helpers
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
 * @hostname: Hostname to match
 *
 * Returns: Index of matching certificate, or -1 if not found
 */
static int
find_sni_cert_index (T ctx, const char *hostname)
{
  for (size_t i = 0; i < ctx->sni_certs.count; i++)
    {
      const char *stored = ctx->sni_certs.hostnames[i];
      if (stored && strcmp (stored, hostname) == 0)
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
  (void)ad;
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
 * Public Certificate Loading
 * ============================================================================
 */

void
SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                   const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  if (!tls_validate_file_path (cert_file)
      || !tls_validate_file_path (key_file))
    {
      ctx_raise_openssl_error ("Invalid certificate or key file path");
    }

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
 * SNI Array Management
 * ============================================================================
 */

/**
 * expand_sni_capacity - Expand SNI arrays capacity
 * @ctx: Context with SNI arrays to expand
 *
 * Doubles capacity or initializes to 4 if empty.
 * Raises: SocketTLS_Failed on allocation failure
 */
static void
expand_sni_capacity (T ctx)
{
  size_t new_cap
      = ctx->sni_certs.capacity == 0 ? 4 : ctx->sni_certs.capacity * 2;

  ctx->sni_certs.hostnames
      = realloc (ctx->sni_certs.hostnames, new_cap * sizeof (char *));
  ctx->sni_certs.cert_files
      = realloc (ctx->sni_certs.cert_files, new_cap * sizeof (char *));
  ctx->sni_certs.key_files
      = realloc (ctx->sni_certs.key_files, new_cap * sizeof (char *));
  ctx->sni_certs.certs
      = realloc (ctx->sni_certs.certs, new_cap * sizeof (X509 *));
  ctx->sni_certs.pkeys
      = realloc (ctx->sni_certs.pkeys, new_cap * sizeof (EVP_PKEY *));

  if (!ctx->sni_certs.hostnames || !ctx->sni_certs.cert_files
      || !ctx->sni_certs.key_files || !ctx->sni_certs.certs
      || !ctx->sni_certs.pkeys)
    {
      ctx_raise_openssl_error ("Failed to allocate SNI certificate arrays");
    }

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
  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_TLS_MAX_SNI_LEN)
    {
      ctx_raise_openssl_error ("Invalid SNI hostname length");
    }

  if (!tls_validate_hostname (hostname))
    {
      ctx_raise_openssl_error ("Invalid SNI hostname format");
    }

  char *copy = Arena_alloc (ctx->arena, len + 1, __FILE__, __LINE__);
  if (!copy)
    {
      ctx_raise_openssl_error ("Failed to allocate hostname buffer");
    }

  memcpy (copy, hostname, len + 1);
  return copy;
}

/**
 * store_sni_hostname - Store hostname in SNI array
 * @ctx: Context
 * @hostname: Hostname to store (NULL for default)
 */
static void
store_sni_hostname (T ctx, const char *hostname)
{
  if (hostname)
    {
      ctx->sni_certs.hostnames[ctx->sni_certs.count]
          = validate_and_copy_hostname (ctx, hostname);
    }
  else
    {
      ctx->sni_certs.hostnames[ctx->sni_certs.count] = NULL;
    }
}

/**
 * copy_path_to_arena - Copy file path to context arena
 * @ctx: Context with arena
 * @path: Path to copy
 * @error_msg: Error message for allocation failure
 *
 * Returns: Arena-allocated copy of path
 * Raises: SocketTLS_Failed on allocation failure
 */
static char *
copy_path_to_arena (T ctx, const char *path, const char *error_msg)
{
  size_t len = strlen (path) + 1;
  char *copy = Arena_alloc (ctx->arena, len, __FILE__, __LINE__);
  if (!copy)
    {
      ctx_raise_openssl_error (error_msg);
    }
  memcpy (copy, path, len);
  return copy;
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
  ctx->sni_certs.cert_files[ctx->sni_certs.count]
      = copy_path_to_arena (ctx, cert_file,
                            "Failed to allocate certificate path buffer");

  ctx->sni_certs.key_files[ctx->sni_certs.count]
      = copy_path_to_arena (ctx, key_file,
                            "Failed to allocate key path buffer");
}

/* ============================================================================
 * SNI Certificate Loading
 * ============================================================================
 */

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
  FILE *fp = fopen (cert_file, "r");
  if (!fp)
    {
      ctx_raise_openssl_error ("Cannot open certificate file");
    }

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
 * @cert: Certificate for cleanup on failure (may be NULL)
 *
 * Returns: Loaded EVP_PKEY
 * Raises: SocketTLS_Failed on file or parse error (frees cert on failure)
 */
static EVP_PKEY *
load_pkey_from_file (const char *key_file, X509 *cert)
{
  FILE *fp = fopen (key_file, "r");
  if (!fp)
    {
      if (cert)
        X509_free (cert);
      ctx_raise_openssl_error ("Cannot open private key file");
    }

  EVP_PKEY *pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!pkey)
    {
      if (cert)
        X509_free (cert);
      ctx_raise_openssl_error ("Failed to parse private key PEM");
    }

  return pkey;
}

/**
 * load_sni_objects - Load cert and key OpenSSL objects
 * @ctx: Context (unused, for future extensions)
 * @cert_file: Certificate file path
 * @key_file: Key file path
 * @cert_out: Output certificate pointer
 * @pkey_out: Output private key pointer
 *
 * Raises: SocketTLS_Failed on any load or validation error
 */
static void
load_sni_objects (T ctx __attribute__ ((unused)), const char *cert_file,
                  const char *key_file, X509 **cert_out, EVP_PKEY **pkey_out)
{
  *cert_out = load_cert_from_file (cert_file);
  *pkey_out = load_pkey_from_file (key_file, *cert_out);

  if (X509_check_private_key (*cert_out, *pkey_out) != 1)
    {
      EVP_PKEY_free (*pkey_out);
      X509_free (*cert_out);
      *cert_out = NULL;
      *pkey_out = NULL;
      ctx_raise_openssl_error ("Private key does not match certificate");
    }
}

/* ============================================================================
 * SNI Certificate Registration
 * ============================================================================
 */

/**
 * validate_add_cert_params - Validate parameters for add_certificate
 * @ctx: Context to validate
 * @cert_file: Certificate file path
 * @key_file: Key file path
 *
 * Raises: SocketTLS_Failed on validation failure
 */
static void
validate_add_cert_params (T ctx, const char *cert_file, const char *key_file)
{
  if (!tls_validate_file_path (cert_file)
      || !tls_validate_file_path (key_file))
    {
      ctx_raise_openssl_error ("Invalid certificate or key file path");
    }

  if (!ctx->is_server)
    {
      ctx_raise_openssl_error (
          "SNI certificates only supported for server contexts");
    }

  if (ctx->sni_certs.count >= SOCKET_TLS_MAX_SNI_CERTS)
    {
      ctx_raise_openssl_error ("Too many SNI certificates");
    }
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

void
SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                  const char *cert_file, const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  validate_add_cert_params (ctx, cert_file, key_file);

  if (ctx->sni_certs.count >= ctx->sni_certs.capacity)
    {
      expand_sni_capacity (ctx);
    }

  store_sni_hostname (ctx, hostname);
  store_sni_paths (ctx, cert_file, key_file);

  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  load_sni_objects (ctx, cert_file, key_file, &cert, &pkey);

  ctx->sni_certs.certs[ctx->sni_certs.count] = cert;
  ctx->sni_certs.pkeys[ctx->sni_certs.count] = pkey;

  if (!hostname)
    {
      SocketTLSContext_load_certificate (ctx, cert_file, key_file);
    }

  ctx->sni_certs.count++;
  register_sni_callback_if_needed (ctx, hostname);
}

#undef T

#endif /* SOCKET_HAS_TLS */
