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
  const char *sni_hostname
      = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);

  if (!sni_hostname || !ctx)
    return SSL_TLSEXT_ERR_NOACK;

  for (size_t i = 0; i < ctx->sni_certs.count; i++)
    {
      const char *stored = ctx->sni_certs.hostnames[i];
      if (stored && strcmp (stored, sni_hostname) == 0)
        {
          X509 *cert = ctx->sni_certs.certs[i];
          EVP_PKEY *pkey = ctx->sni_certs.pkeys[i];

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
    }

  return SSL_TLSEXT_ERR_NOACK;
}

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
  size_t new_cap = ctx->sni_certs.capacity == 0 ? 4 : ctx->sni_certs.capacity * 2;

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
 * store_sni_hostname - Store hostname in SNI array
 * @ctx: Context
 * @hostname: Hostname to store (NULL for default)
 */
static void
store_sni_hostname (T ctx, const char *hostname)
{
  if (hostname)
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
      ctx->sni_certs.hostnames[ctx->sni_certs.count] = copy;
    }
  else
    {
      ctx->sni_certs.hostnames[ctx->sni_certs.count] = NULL;
    }
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
  size_t cert_len = strlen (cert_file) + 1;
  char *cert_copy = Arena_alloc (ctx->arena, cert_len, __FILE__, __LINE__);
  if (!cert_copy)
    {
      ctx_raise_openssl_error ("Failed to allocate certificate path buffer");
    }
  memcpy (cert_copy, cert_file, cert_len);
  ctx->sni_certs.cert_files[ctx->sni_certs.count] = cert_copy;

  size_t key_len = strlen (key_file) + 1;
  char *key_copy = Arena_alloc (ctx->arena, key_len, __FILE__, __LINE__);
  if (!key_copy)
    {
      ctx_raise_openssl_error ("Failed to allocate key path buffer");
    }
  memcpy (key_copy, key_file, key_len);
  ctx->sni_certs.key_files[ctx->sni_certs.count] = key_copy;
}

/**
 * load_sni_objects - Load cert and key OpenSSL objects
 * @ctx: Context
 * @cert_file: Certificate file path
 * @key_file: Key file path
 * @cert_out: Output certificate pointer
 * @pkey_out: Output private key pointer
 */
static void
load_sni_objects (T ctx __attribute__ ((unused)), const char *cert_file,
                  const char *key_file, X509 **cert_out, EVP_PKEY **pkey_out)
{
  FILE *cert_fp = fopen (cert_file, "r");
  if (!cert_fp)
    {
      ctx_raise_openssl_error ("Cannot open certificate file");
    }
  *cert_out = PEM_read_X509 (cert_fp, NULL, NULL, NULL);
  fclose (cert_fp);
  if (!*cert_out)
    {
      ctx_raise_openssl_error ("Failed to parse certificate PEM");
    }

  FILE *key_fp = fopen (key_file, "r");
  if (!key_fp)
    {
      X509_free (*cert_out);
      *cert_out = NULL;
      ctx_raise_openssl_error ("Cannot open private key file");
    }
  *pkey_out = PEM_read_PrivateKey (key_fp, NULL, NULL, NULL);
  fclose (key_fp);
  if (!*pkey_out)
    {
      X509_free (*cert_out);
      *cert_out = NULL;
      ctx_raise_openssl_error ("Failed to parse private key PEM");
    }

  if (X509_check_private_key (*cert_out, *pkey_out) != 1)
    {
      EVP_PKEY_free (*pkey_out);
      X509_free (*cert_out);
      *cert_out = NULL;
      *pkey_out = NULL;
      ctx_raise_openssl_error ("Private key does not match certificate");
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

  if (ctx->sni_certs.count > 1 || (ctx->sni_certs.count == 1 && hostname))
    {
      SSL_CTX_set_tlsext_servername_callback (ctx->ssl_ctx, sni_callback);
      SSL_CTX_set_tlsext_servername_arg (ctx->ssl_ctx, ctx);
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */

