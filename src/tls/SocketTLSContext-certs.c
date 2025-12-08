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
#include <assert.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/evp.h>  /* For i2d_PrivateKey in secure free */
#include <openssl/x509v3.h>  /* For X509_check_host in SNI validation */
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
  if (!tls_validate_file_path (cert_file))
    {
      char buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (buf, sizeof (buf), "Invalid certificate file path '%s'", cert_file);
      ctx_raise_openssl_error (buf);
    }
  if (!tls_validate_file_path (key_file))
    {
      char buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (buf, sizeof (buf), "Invalid private key file path '%s'", key_file);
      ctx_raise_openssl_error (buf);
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
      char buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (buf, sizeof (buf), "Invalid CA file path '%s'", ca_file);
      ctx_raise_openssl_error (buf);
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
apply_sni_cert (SSL *ssl, STACK_OF(X509) *chain, EVP_PKEY *pkey)
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

  /* Add intermediate certificates from chain (indices 1+), retaining refs with add1 */
  for (int i = 1; i < sk_X509_num (chain); ++i)
    {
      X509 *inter = sk_X509_value (chain, i);
      if (inter && SSL_add1_chain_cert (ssl, inter) != 1)
        {
          /* Failure to add intermediate; client may still validate if has it cached,
             but log and continue? For strict, could cleanup and return error.
             Here, return NOACK to fallback to default cert. */
          return SSL_TLSEXT_ERR_NOACK;
        }
    }

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

  return apply_sni_cert (ssl, ctx->sni_certs.chains[idx],
                         ctx->sni_certs.pkeys[idx]);
}

/* ============================================================================
 * SNI Array Expansion
 * ============================================================================
 */

#include "core/SocketSecurity.h"
#include "core/SocketCrypto.h"  /* For secure_clear if needed */


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
                      char ***key_files, STACK_OF(X509) ***chains, EVP_PKEY ***pkeys)
{
  struct {
    void **orig;
    void *newp;
  } arrays[5] = {
    { (void **)*hostnames, NULL },
    { (void **)*cert_files, NULL },
    { (void **)*key_files, NULL },
    { (void **)*chains, NULL },
    { (void **)*pkeys, NULL }
  };

  size_t alloc_size;
  if (!SocketSecurity_check_multiply (cap, sizeof (void *), &alloc_size) ||
      !SocketSecurity_check_size (alloc_size))
    {
      return 0;  /* Overflow or too large - fail allocation */
    }
  size_t size = alloc_size;

  int success = 1;
  for (int i = 0; i < 5; ++i)
    {
      arrays[i].newp = realloc (arrays[i].orig, size);
      if (!arrays[i].newp)
        {
          success = 0;
          break;
        }
    }

  if (!success)
    {
      for (int i = 0; i < 5; ++i)
        {
          void *newp = arrays[i].newp;
          if (newp && newp != arrays[i].orig)
            {
              free (newp);
            }
        }
      return 0;
    }

  /* Assign back */
  *hostnames = (char **)arrays[0].newp;
  *cert_files = (char **)arrays[1].newp;
  *key_files = (char **)arrays[2].newp;
  *chains = (STACK_OF(X509) **)arrays[3].newp;
  *pkeys = (EVP_PKEY **)arrays[4].newp;

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
                                 &ctx->sni_certs.key_files, &ctx->sni_certs.chains,
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
      char buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (buf, sizeof (buf), "Invalid SNI hostname '%s': invalid format or length", hostname);
      ctx_raise_openssl_error (buf);
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
open_pem_file (const char *path, const char *obj_type)
{
  FILE *fp = fopen (path, "r");
  if (!fp)
    {
      char temp_buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (temp_buf, sizeof (temp_buf), "Cannot open %s file '%s': %s", obj_type, path, strerror (errno));
      ctx_raise_openssl_error (temp_buf);
    }

  /* Check file size to prevent DoS from oversized PEM files */
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

  size_t max_file_size = SocketSecurity_get_max_allocation () / 16;  /* Conservative limit ~1-16MB depending on config */
  if ((size_t) fsize > max_file_size)
    {
      fclose (fp);
      char temp_buf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (temp_buf, sizeof (temp_buf), "%s file '%s' too large: %ld bytes (max %zu)", obj_type, path, fsize, max_file_size);
      ctx_raise_openssl_error (temp_buf);
    }

  return fp;
}

/**
 * load_pem_object - Generic PEM object loader from file
 * @path: File path to PEM
 * @obj_type: Object type string for error messages ("certificate", "private key")
 * @reader: PEM reader function (e.g., PEM_read_X509 or PEM_read_PrivateKey)
 *
 * Loads a PEM-encoded object using the provided reader function.
 * Handles file open, read, close, and error raising consistently.
 *
 * Returns: Loaded object (caller casts to X509* or EVP_PKEY*)
 * Raises: SocketTLS_Failed on file open or parse failure
 * Thread-safe: No
 */
static void *
load_pem_object (const char *path, const char *obj_type,
                 void *(*reader)(FILE *, void *, void *, void *))
{
  FILE *fp = open_pem_file (path, obj_type);

  void *obj = reader (fp, NULL, NULL, NULL);
  fclose (fp);

  if (!obj)
    {
      char errbuf[SOCKET_TLS_ERROR_BUFSIZE];
      snprintf (errbuf, sizeof (errbuf), "Failed to parse %s PEM", obj_type);
      ctx_raise_openssl_error (errbuf);
    }

  return obj;
}

/**
 * load_cert_from_file - Load X509 certificate from PEM file
 * @cert_file: Certificate file path
 *
 * Returns: Loaded X509 certificate
 * Raises: SocketTLS_Failed on file or parse error
 * Thread-safe: No
 */
static STACK_OF(X509) *
load_chain_from_file (const char *cert_file)
{
  FILE *fp = open_pem_file (cert_file, "certificate");

  STACK_OF(X509) *chain = sk_X509_new_null ();
  if (!chain)
    {
      fclose (fp);
      ctx_raise_openssl_error ("Failed to allocate certificate chain stack");
    }

  /* Use volatile to prevent clobbering by longjmp in exception handlers.
   * GCC warns that cert may be clobbered by calls to ctx_raise_openssl_error
   * which uses longjmp internally. */
  X509 *volatile cert = NULL;
  int num_certs = 0;

  while ((cert = PEM_read_X509 (fp, NULL, NULL, NULL)) != NULL)
    {
      if (sk_X509_push (chain, (X509 *)cert) > 0)
        num_certs++;
      else
        X509_free ((X509 *)cert);  /* Push failed, free it */
      cert = NULL;
    }

  fclose (fp);

  if (num_certs == 0)
    {
      sk_X509_free (chain);
      /* No certificates read - this is a real error */
      ctx_raise_openssl_error ("No certificates found in certificate file");
    }

  /* Clear the OpenSSL error queue after successful reading.
   * PEM_read_X509 returns NULL and sets PEM_R_NO_START_LINE error
   * when reaching EOF, which is expected behavior, not an error.
   * Only treat as error if we failed to read any certificates. */
  ERR_clear_error ();

  return chain;
}

/**
 * load_pkey_from_file - Load private key from PEM file
 * @key_file: Key file path
 *
 * Returns: Loaded EVP_PKEY
 * Raises: SocketTLS_Failed on file or parse error
 * Thread-safe: No
 */
static EVP_PKEY *
load_pkey_from_file (const char *key_file)
{
  return (EVP_PKEY *) load_pem_object (key_file, "private key",
                                       (void *(*)(FILE *, void *, void *, void *)) PEM_read_PrivateKey);
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
                         STACK_OF(X509) **chain_out, EVP_PKEY **pkey_out)
{
  STACK_OF(X509) *chain = load_chain_from_file (cert_file);
  EVP_PKEY *pkey = NULL;

  TRY
    pkey = load_pkey_from_file (key_file);
  EXCEPT (SocketTLS_Failed)
    sk_X509_pop_free (chain, X509_free);
    RERAISE;
  END_TRY;

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

  *chain_out = chain;
  *pkey_out = pkey;
}

/**
 * store_sni_objects - Store loaded cert/key in SNI arrays
 * @ctx: Context
 * @cert: Loaded certificate
 * @pkey: Loaded private key
 */
static void
store_sni_chain_and_pkey (T ctx, size_t idx, STACK_OF(X509) *chain, EVP_PKEY *pkey)
{
  ctx->sni_certs.chains[idx] = chain;
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

/**
 * validate_and_prepare_sni_slot - Validate inputs and prepare SNI metadata slot
 * @ctx: TLS context
 * @hostname: SNI hostname (NULL for default certificate)
 * @cert_file: Path to certificate PEM file
 * @key_file: Path to private key PEM file
 *
 * Validates context, file paths, hostname (if provided), count limits, and capacity.
 * Stores hostname and file paths in the next available slot (ctx->sni_certs.count).
 * Does not load certificates/keys or increment count.
 *
 * Raises: SocketTLS_Failed on any validation or allocation failure
 * Thread-safe: No
 */
static void
validate_and_prepare_sni_slot (T ctx, const char *hostname,
                               const char *cert_file, const char *key_file)
{
  validate_cert_key_paths (cert_file, key_file);
  validate_server_context (ctx);
  validate_sni_count (ctx);
  ensure_sni_capacity (ctx);
  store_sni_hostname (ctx, hostname);
  store_sni_paths (ctx, cert_file, key_file);
}

/**
 * load_and_commit_sni_entry - Load keypair, store objects, and commit entry
 * @ctx: TLS context
 * @hostname: SNI hostname (NULL for default)
 * @cert_file: Certificate file path
 * @key_file: Private key file path
 *
 * Loads and verifies certificate/key pair, stores objects in current slot,
 * sets default certificate on context if no hostname, increments count,
 * and registers SNI callback if needed.
 * Assumes slot prepared (metadata stored) by validate_and_prepare_sni_slot.
 *
 * Raises: SocketTLS_Failed on load, verification, or default set failure
 * Thread-safe: No
 */
static void
load_and_commit_sni_entry (T ctx, const char *hostname,
                           const char *cert_file, const char *key_file)
{
  STACK_OF(X509) *chain = NULL;
  EVP_PKEY *pkey = NULL;
  load_and_verify_keypair (cert_file, key_file, &chain, &pkey);

  if (hostname != NULL) {
    X509 *leaf = sk_X509_value (chain, 0);
    int match = X509_check_host (leaf, hostname, 0, 0, NULL);
    if (match != 1) {
      sk_X509_pop_free (chain, X509_free);
      tls_secure_free_pkey (pkey);
      char buf[SOCKET_TLS_ERROR_BUFSIZE];
      const char *reason = (match == 0) ? "certificate subject mismatch" : "hostname validation error";
      snprintf (buf, sizeof (buf), "SNI %s for hostname '%s'", reason, hostname);
      ctx_raise_openssl_error (buf);
    }
  }

  store_sni_chain_and_pkey (ctx, ctx->sni_certs.count, chain, pkey);

  /* Set as default if no hostname specified */
  if (!hostname)
    {
      set_default_certificate (ctx, cert_file, key_file);
    }

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
