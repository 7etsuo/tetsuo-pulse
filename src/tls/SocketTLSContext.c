/**
 * SocketTLSContext.c - TLS Context Management
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Manages OpenSSL SSL_CTX objects with socket library integration. Provides:
 * - Context lifecycle (new_server, new_client, free)
 * - Certificate and CA loading with SNI support
 * - ALPN protocol negotiation
 * - Session caching and session tickets
 * - Certificate verification and CRL support
 * - OCSP stapling
 *
 * Thread safety: Context creation is thread-safe (independent instances).
 * Context modification is NOT thread-safe after sharing.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Forward Declarations (for functions used before their definition)
 * ============================================================================
 */

void SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                        const char *key_file);
void SocketTLSContext_load_ca (T ctx, const char *ca_file);
void SocketTLSContext_free (T *ctx);
void SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */

#ifdef _WIN32
__declspec (thread) char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
__declspec (thread) Except_T SocketTLSContext_DetailedException;
#else
__thread char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
__thread Except_T SocketTLSContext_DetailedException;
#endif

/* Global ex_data index for context lookup */
int tls_context_exdata_idx = -1;

/* ============================================================================
 * OpenSSL Error Handling
 * ============================================================================
 */

/**
 * ctx_raise_openssl_error - Format and raise OpenSSL error
 * @context: Error context description
 */
void
ctx_raise_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "%s: %s",
                context, err_str);
    }
  else
    {
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "%s: Unknown TLS error", context);
    }

  RAISE_CTX_ERROR (SocketTLS_Failed);
}

/* ============================================================================
 * Context Initialization Helpers
 * ============================================================================
 */

/**
 * init_sni_certs - Initialize SNI certificate structure
 * @sni: SNI certificate structure to initialize
 */
static void
init_sni_certs (TLSContextSNICerts *sni)
{
  sni->hostnames = NULL;
  sni->cert_files = NULL;
  sni->key_files = NULL;
  sni->certs = NULL;
  sni->pkeys = NULL;
  sni->count = 0;
  sni->capacity = 0;
}

/**
 * init_alpn - Initialize ALPN configuration structure
 * @alpn: ALPN configuration to initialize
 */
static void
init_alpn (TLSContextALPN *alpn)
{
  alpn->protocols = NULL;
  alpn->count = 0;
  alpn->selected = NULL;
  alpn->callback = NULL;
  alpn->callback_user_data = NULL;
}

/**
 * init_stats_mutex - Initialize statistics mutex
 * @ctx: Context to initialize mutex for
 *
 * Raises: SocketTLS_Failed on mutex init failure
 */
static void
init_stats_mutex (T ctx)
{
  if (pthread_mutex_init (&ctx->stats_mutex, NULL) != 0)
    {
      ctx_raise_openssl_error ("Failed to initialize stats mutex");
    }
}

/**
 * configure_tls13_only - Apply TLS1.3-only security settings
 * @ssl_ctx: OpenSSL context to configure
 *
 * Sets minimum/maximum protocol to TLS1.3 and configures modern ciphers.
 *
 * Raises: SocketTLS_Failed on configuration failure
 */
static void
configure_tls13_only (SSL_CTX *ssl_ctx)
{
  if (SSL_CTX_set_min_proto_version (ssl_ctx, SOCKET_TLS_MIN_VERSION) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      ctx_raise_openssl_error ("Failed to set TLS1.3 min version");
    }

  if (SSL_CTX_set_max_proto_version (ssl_ctx, SOCKET_TLS_MAX_VERSION) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      ctx_raise_openssl_error ("Failed to enforce TLS1.3 max version");
    }

  if (SSL_CTX_set_ciphersuites (ssl_ctx, SOCKET_TLS13_CIPHERSUITES) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      ctx_raise_openssl_error ("Failed to set secure ciphersuites");
    }
}

/**
 * alloc_context_struct - Allocate and zero-initialize context structure
 * @ssl_ctx: OpenSSL context (ownership transferred on success)
 *
 * Returns: Allocated context structure
 * Raises: SocketTLS_Failed on allocation failure
 */
static T
alloc_context_struct (SSL_CTX *ssl_ctx)
{
  T ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      SSL_CTX_free (ssl_ctx);
      ctx_raise_openssl_error ("ENOMEM: calloc for context struct");
    }

  ctx->arena = Arena_new ();
  if (!ctx->arena)
    {
      free (ctx);
      SSL_CTX_free (ssl_ctx);
      ctx_raise_openssl_error ("Failed to create context arena");
    }

  return ctx;
}

/**
 * register_exdata - Register context in SSL_CTX ex_data
 * @ctx: Context to register
 */
static void
register_exdata (T ctx)
{
  if (tls_context_exdata_idx == -1)
    {
      tls_context_exdata_idx
          = SSL_CTX_get_ex_new_index (0, "SocketTLSContext", NULL, NULL, NULL);
    }
  SSL_CTX_set_ex_data (ctx->ssl_ctx, tls_context_exdata_idx, ctx);
}

/**
 * alloc_and_init_ctx - Create and initialize TLS context
 * @method: OpenSSL method (server or client)
 * @is_server: 1 for server, 0 for client
 *
 * Returns: New initialized context
 * Raises: SocketTLS_Failed on any failure
 */
static T
alloc_and_init_ctx (const SSL_METHOD *method, int is_server)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    {
      ctx_raise_openssl_error ("Failed to create SSL_CTX");
    }

  configure_tls13_only (ssl_ctx);

  T ctx = alloc_context_struct (ssl_ctx);
  ctx->ssl_ctx = ssl_ctx;

  register_exdata (ctx);

  ctx->is_server = !!is_server;
  ctx->session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;
  init_stats_mutex (ctx);
  init_sni_certs (&ctx->sni_certs);
  init_alpn (&ctx->alpn);

  return ctx;
}

/* ============================================================================
 * Context Cleanup Helpers
 * ============================================================================
 */

/**
 * free_sni_arrays - Free SNI certificate arrays
 * @ctx: Context with SNI data to free
 */
static void
free_sni_arrays (T ctx)
{
  free (ctx->sni_certs.hostnames);
  free (ctx->sni_certs.cert_files);
  free (ctx->sni_certs.key_files);
}

/**
 * free_sni_objects - Free pre-loaded OpenSSL objects
 * @ctx: Context with OpenSSL objects to free
 */
static void
free_sni_objects (T ctx)
{
  if (ctx->sni_certs.certs)
    {
      for (size_t i = 0; i < ctx->sni_certs.count; ++i)
        {
          if (ctx->sni_certs.certs[i])
            X509_free (ctx->sni_certs.certs[i]);
        }
      free (ctx->sni_certs.certs);
    }
  if (ctx->sni_certs.pkeys)
    {
      for (size_t i = 0; i < ctx->sni_certs.count; ++i)
        {
          if (ctx->sni_certs.pkeys[i])
            EVP_PKEY_free (ctx->sni_certs.pkeys[i]);
        }
      free (ctx->sni_certs.pkeys);
    }
}

/* ============================================================================
 * Context Lookup Functions
 * ============================================================================
 */

SocketTLSContext_T
tls_context_get_from_ssl_ctx (SSL_CTX *ssl_ctx)
{
  if (!ssl_ctx)
    return NULL;
  return (T)SSL_CTX_get_ex_data (ssl_ctx, tls_context_exdata_idx);
}

SocketTLSContext_T
tls_context_get_from_ssl (const SSL *ssl)
{
  if (!ssl)
    return NULL;
  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX ((SSL *)ssl);
  return tls_context_get_from_ssl_ctx (ssl_ctx);
}

/* ============================================================================
 * Public Context Lifecycle API
 * ============================================================================
 */

T
SocketTLSContext_new_server (const char *cert_file, const char *key_file,
                             const char *ca_file)
{
  T ctx;

  assert (cert_file);
  assert (key_file);

  ctx = alloc_and_init_ctx (TLS_server_method (), 1);

  TRY
  SocketTLSContext_load_certificate (ctx, cert_file, key_file);
  if (ca_file)
    {
      SocketTLSContext_load_ca (ctx, ca_file);
    }
  EXCEPT (SocketTLS_Failed)
  SocketTLSContext_free (&ctx);
  RERAISE;
  END_TRY;

  return ctx;
}

T
SocketTLSContext_new_client (const char *ca_file)
{
  T ctx = alloc_and_init_ctx (TLS_client_method (), 0);

  if (ca_file)
    {
      TRY
      SocketTLSContext_load_ca (ctx, ca_file);
      SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
      EXCEPT (SocketTLS_Failed)
      SocketTLSContext_free (&ctx);
      RERAISE;
      END_TRY;
    }

  return ctx;
}

void
SocketTLSContext_free (T *ctx)
{
  assert (ctx);

  if (*ctx)
    {
      T c = *ctx;

      if (c->ssl_ctx)
        {
          SSL_CTX_free (c->ssl_ctx);
          c->ssl_ctx = NULL;
        }

      if (c->arena)
        {
          Arena_dispose (&c->arena);
        }

      free_sni_arrays (c);
      free_sni_objects (c);

      pthread_mutex_destroy (&c->stats_mutex);
      free (c);
      *ctx = NULL;
    }
}

void *
SocketTLSContext_get_ssl_ctx (T ctx)
{
  assert (ctx);
  return (void *)ctx->ssl_ctx;
}

int
SocketTLSContext_is_server (T ctx)
{
  assert (ctx);
  return ctx->is_server;
}

/* ============================================================================
 * Certificate Management
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
 * SNI Certificate Management
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
  size_t new_cap = ctx->sni_certs.capacity == 0
                       ? SOCKET_TLS_SNI_INITIAL_CAPACITY
                       : ctx->sni_certs.capacity * 2;

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

/* ============================================================================
 * ALPN Protocol Negotiation
 * ============================================================================
 */

/* Forward declaration for free_client_protos (used by parse_client_protos) */
static void free_client_protos (const char **protos, size_t count);

/**
 * count_wire_format_protos - Count protocols in ALPN wire format
 * @in: Wire format input (length-prefixed strings)
 * @inlen: Input length
 *
 * Returns: Number of protocols found in wire format
 */
static size_t
count_wire_format_protos (const unsigned char *in, unsigned int inlen)
{
  size_t count = 0;
  size_t offset = 0;

  while (offset < inlen)
    {
      if (offset + 1 > inlen)
        break;
      unsigned char len = in[offset++];
      if (offset + len > inlen)
        break;
      count++;
      offset += len;
    }
  return count;
}

/**
 * extract_single_proto - Extract and copy a single protocol from wire format
 * @in: Wire format input at current position
 * @inlen: Remaining input length
 * @offset: Current offset (updated on success)
 *
 * Returns: Allocated protocol string, or NULL on failure
 */
static char *
extract_single_proto (const unsigned char *in, unsigned int inlen,
                      size_t *offset)
{
  if (*offset >= inlen)
    return NULL;

  unsigned char len = in[(*offset)++];
  if (*offset + len > inlen)
    return NULL;

  char *proto = malloc (len + 1);
  if (!proto)
    return NULL;

  memcpy (proto, &in[*offset], len);
  proto[len] = '\0';
  *offset += len;
  return proto;
}

/**
 * parse_client_protos - Parse client protocols from wire format
 * @in: Wire format input (length-prefixed strings)
 * @inlen: Input length
 * @count_out: Output: number of protocols parsed
 *
 * Returns: Array of null-terminated protocol strings (caller frees)
 */
static const char **
parse_client_protos (const unsigned char *in, unsigned int inlen,
                     size_t *count_out)
{
  size_t count = count_wire_format_protos (in, inlen);
  if (count == 0)
    {
      *count_out = 0;
      return NULL;
    }

  const char **protos = calloc (count, sizeof (const char *));
  if (!protos)
    {
      *count_out = 0;
      return NULL;
    }

  size_t offset = 0;
  for (size_t idx = 0; idx < count; idx++)
    {
      protos[idx] = extract_single_proto (in, inlen, &offset);
      if (!protos[idx])
        {
          free_client_protos (protos, idx);
          *count_out = 0;
          return NULL;
        }
    }

  *count_out = count;
  return protos;
}

/**
 * free_client_protos - Free parsed client protocols array
 * @protos: Protocol array to free
 * @count: Number of protocols
 */
static void
free_client_protos (const char **protos, size_t count)
{
  if (!protos)
    return;

  for (size_t i = 0; i < count; i++)
    {
      free ((void *)protos[i]);
    }
  free (protos);
}

/**
 * find_matching_proto - Find first matching protocol
 * @server_protos: Server's protocol list (preference order)
 * @server_count: Number of server protocols
 * @client_protos: Client's offered protocols
 * @client_count: Number of client protocols
 *
 * Returns: Selected protocol string or NULL
 */
static const char *
find_matching_proto (const char **server_protos, size_t server_count,
                     const char **client_protos, size_t client_count)
{
  for (size_t i = 0; i < server_count; i++)
    {
      for (size_t j = 0; j < client_count; j++)
        {
          if (strcmp (server_protos[i], client_protos[j]) == 0)
            {
              return server_protos[i];
            }
        }
    }
  return NULL;
}

/**
 * alpn_select_cb - OpenSSL ALPN selection callback
 * @ssl: SSL connection (unused)
 * @out: Output: selected protocol
 * @outlen: Output: selected protocol length
 * @in: Client protocol list (wire format)
 * @inlen: Client protocol list length
 * @arg: Context pointer
 *
 * Returns: SSL_TLSEXT_ERR_OK or SSL_TLSEXT_ERR_NOACK
 */
static int
alpn_select_cb (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                const unsigned char *in, unsigned int inlen, void *arg)
{
  (void)ssl;
  T ctx = (T)arg;

  if (!ctx || !ctx->alpn.protocols || ctx->alpn.count == 0)
    return SSL_TLSEXT_ERR_NOACK;

  size_t client_count;
  const char **client_protos = parse_client_protos (in, inlen, &client_count);
  if (!client_protos)
    return SSL_TLSEXT_ERR_NOACK;

  const char *selected = NULL;

  if (ctx->alpn.callback)
    {
      selected = ctx->alpn.callback (client_protos, client_count,
                                     ctx->alpn.callback_user_data);
    }
  else
    {
      selected = find_matching_proto (ctx->alpn.protocols, ctx->alpn.count,
                                      client_protos, client_count);
    }

  free_client_protos (client_protos, client_count);

  if (selected)
    {
      *out = (const unsigned char *)selected;
      *outlen = (unsigned char)strlen (selected);
      return SSL_TLSEXT_ERR_OK;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

/**
 * copy_protocol_to_arena - Copy protocol string to context arena
 * @ctx: Context with arena
 * @proto: Protocol string to copy
 *
 * Returns: Arena-allocated copy
 * Raises: SocketTLS_Failed on allocation failure
 */
static char *
copy_protocol_to_arena (T ctx, const char *proto)
{
  size_t len = strlen (proto);
  char *copy = Arena_alloc (ctx->arena, len + 1, __FILE__, __LINE__);
  if (!copy)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN protocol buffer");
    }
  memcpy (copy, proto, len + 1);
  return copy;
}

/**
 * build_wire_format - Build ALPN wire format from protocol list
 * @ctx: Context with arena
 * @protos: Protocol strings
 * @count: Number of protocols
 * @len_out: Output: wire format length
 *
 * Returns: Wire format buffer (arena-allocated)
 * Raises: SocketTLS_Failed on allocation failure
 */
static unsigned char *
build_wire_format (T ctx, const char **protos, size_t count, size_t *len_out)
{
  /* Cache protocol lengths to avoid redundant strlen calls */
  size_t *lengths = Arena_alloc (ctx->arena, count * sizeof (size_t),
                                 __FILE__, __LINE__);
  if (!lengths)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN length cache");
    }

  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    {
      lengths[i] = strlen (protos[i]);
      total += 1 + lengths[i];
    }

  unsigned char *buf = Arena_alloc (ctx->arena, total, __FILE__, __LINE__);
  if (!buf)
    {
      ctx_raise_openssl_error ("Failed to allocate ALPN buffer");
    }

  size_t offset = 0;
  for (size_t i = 0; i < count; i++)
    {
      buf[offset++] = (unsigned char)lengths[i];
      memcpy (buf + offset, protos[i], lengths[i]);
      offset += lengths[i];
    }

  *len_out = total;
  return buf;
}

/**
 * validate_alpn_count - Validate ALPN protocol count
 * @count: Number of protocols
 *
 * Raises: SocketTLS_Failed if count exceeds maximum
 */
static void
validate_alpn_count (size_t count)
{
  if (count > SOCKET_TLS_MAX_ALPN_PROTOCOLS)
    ctx_raise_openssl_error ("Too many ALPN protocols");
}

/**
 * alloc_alpn_array - Allocate ALPN protocols array in context arena
 * @ctx: TLS context
 * @count: Number of protocols
 *
 * Returns: Allocated array
 * Raises: SocketTLS_Failed on allocation failure
 */
static const char **
alloc_alpn_array (T ctx, size_t count)
{
  const char **arr = Arena_alloc (ctx->arena, count * sizeof (const char *),
                                  __FILE__, __LINE__);
  if (!arr)
    ctx_raise_openssl_error ("Failed to allocate ALPN protocols array");
  return arr;
}

/**
 * copy_alpn_protocols - Validate and copy protocols to context
 * @ctx: TLS context
 * @protos: Source protocol strings
 * @count: Number of protocols
 */
static void
copy_alpn_protocols (T ctx, const char **protos, size_t count)
{
  for (size_t i = 0; i < count; i++)
    {
      assert (protos[i]);
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
        ctx_raise_openssl_error ("Invalid ALPN protocol length");
      ctx->alpn.protocols[i] = copy_protocol_to_arena (ctx, protos[i]);
    }
}

/**
 * apply_alpn_to_ssl_ctx - Apply ALPN configuration to OpenSSL context
 * @ctx: TLS context
 * @protos: Protocol strings
 * @count: Number of protocols
 */
static void
apply_alpn_to_ssl_ctx (T ctx, const char **protos, size_t count)
{
  size_t wire_len;
  unsigned char *wire = build_wire_format (ctx, protos, count, &wire_len);

  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len)
      != 0)
    ctx_raise_openssl_error ("Failed to set ALPN protocols");

  SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
}

void
SocketTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (protos || count == 0);

  if (count == 0)
    return;

  validate_alpn_count (count);
  ctx->alpn.protocols = alloc_alpn_array (ctx, count);
  copy_alpn_protocols (ctx, protos, count);
  ctx->alpn.count = count;
  apply_alpn_to_ssl_ctx (ctx, protos, count);
}

void
SocketTLSContext_set_alpn_callback (T ctx, SocketTLSAlpnCallback callback,
                                    void *user_data)
{
  assert (ctx);

  ctx->alpn.callback = callback;
  ctx->alpn.callback_user_data = user_data;
}

/* ============================================================================
 * Verification Configuration
 * ============================================================================
 */

/* Forward declaration for OpenSSL callback */
static int internal_verify_callback (int pre_ok, X509_STORE_CTX *x509_ctx);

/**
 * verify_mode_to_openssl - Convert TLSVerifyMode to OpenSSL flags
 * @mode: Our verification mode enum
 *
 * Returns: OpenSSL SSL_VERIFY_* flags
 */
static int
verify_mode_to_openssl (TLSVerifyMode mode)
{
  switch (mode)
    {
    case TLS_VERIFY_NONE:
      return SSL_VERIFY_NONE;
    case TLS_VERIFY_PEER:
      return SSL_VERIFY_PEER;
    case TLS_VERIFY_FAIL_IF_NO_PEER_CERT:
      return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    case TLS_VERIFY_CLIENT_ONCE:
      return SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
    default:
      return SSL_VERIFY_NONE;
    }
}

/**
 * apply_verify_settings - Apply verification mode and callback to context
 * @ctx: TLS context
 *
 * Consolidates the SSL_CTX_set_verify call used by both set_verify_mode
 * and set_verify_callback.
 */
static void
apply_verify_settings (T ctx)
{
  int openssl_mode = verify_mode_to_openssl (ctx->verify_mode);
  SSL_verify_cb cb
      = ctx->verify_callback ? (SSL_verify_cb)internal_verify_callback : NULL;
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, cb);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"

/**
 * internal_verify_callback - OpenSSL verification wrapper
 * @pre_ok: OpenSSL pre-verification result
 * @x509_ctx: Certificate store context
 *
 * Returns: 1 to continue verification, 0 to fail
 */
static int
internal_verify_callback (int pre_ok, X509_STORE_CTX *x509_ctx)
{
  SSL *ssl = X509_STORE_CTX_get_ex_data (
      x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
  if (!ssl)
    return pre_ok;

  Socket_T sock = (Socket_T)SSL_get_app_data (ssl);
  if (!sock)
    return pre_ok;

  T ctx = (T)sock->tls_ctx;
  if (!ctx || !ctx->verify_callback)
    return pre_ok;

  volatile int result;
  TRY
  {
    result
        = ctx->verify_callback (pre_ok, x509_ctx, ctx, sock, ctx->verify_user_data);
  }
  EXCEPT (SocketTLS_Failed)
  {
    result = 0;
    X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
  }
  END_TRY;

  if (!result)
    {
      X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    }

  return result;
}

#pragma GCC diagnostic pop

void
SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_mode = mode;
  ERR_clear_error ();
  apply_verify_settings (ctx);
}

void
SocketTLSContext_set_verify_callback (T ctx, SocketTLSVerifyCallback callback,
                                      void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->verify_callback = callback;
  ctx->verify_user_data = user_data;
  apply_verify_settings (ctx);
}

void
SocketTLSContext_load_crl (T ctx, const char *crl_path)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!crl_path || !*crl_path)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "CRL path cannot be NULL or empty");

  X509_STORE *store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Failed to get certificate store");

  struct stat st;
  if (stat (crl_path, &st) != 0)
    RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Invalid CRL path '%s': %s",
                         crl_path, strerror (errno));

  int ret = S_ISDIR (st.st_mode)
                ? X509_STORE_load_locations (store, NULL, crl_path)
                : X509_STORE_load_locations (store, crl_path, NULL);

  if (ret != 1)
    ctx_raise_openssl_error ("Failed to load CRL");

  X509_STORE_set_flags (store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
}

void
SocketTLSContext_refresh_crl (T ctx, const char *crl_path)
{
  SocketTLSContext_load_crl (ctx, crl_path);
}

void
SocketTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    {
#if defined(SSL_OP_NO_SSLv2) && defined(SSL_OP_NO_SSLv3)
      long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

      if (version > TLS1_VERSION)
        options |= SSL_OP_NO_TLSv1;
      if (version > TLS1_1_VERSION)
        options |= SSL_OP_NO_TLSv1_1;
      if (version > TLS1_2_VERSION)
        options |= SSL_OP_NO_TLSv1_2;

      long current = SSL_CTX_set_options (ctx->ssl_ctx, options);
      if (!(current & options))
        {
          ctx_raise_openssl_error ("Failed to set minimum TLS protocol version");
        }
#else
      ctx_raise_openssl_error (
          "Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
    }
}

void
SocketTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    {
      ctx_raise_openssl_error ("Failed to set maximum TLS protocol version");
    }
}

void
SocketTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  const char *list = ciphers
      ? ciphers
      : "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA";

  if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, list) != 1)
    {
      ctx_raise_openssl_error ("Failed to set cipher list");
    }
}

/* ============================================================================
 * Session Management
 * ============================================================================
 */

/**
 * new_session_cb - Called when new session is created
 * @ssl: SSL connection
 * @sess: New session (unused)
 *
 * Returns: 1 to indicate we took ownership (we didn't, but OpenSSL expects 1)
 */
static int
new_session_cb (SSL *ssl, SSL_SESSION *sess)
{
  (void)sess;
  T ctx = tls_context_get_from_ssl (ssl);
  if (ctx)
    {
      pthread_mutex_lock (&ctx->stats_mutex);
      ctx->cache_stores++;
      pthread_mutex_unlock (&ctx->stats_mutex);
    }
  return 1;
}

/**
 * info_callback - Called on TLS state changes
 * @ssl: SSL connection
 * @where: Event type flags
 * @ret: Return code (unused unless error)
 *
 * Tracks session reuse on handshake completion.
 */
static void
info_callback (const SSL *ssl, int where, int ret)
{
  if (ret == 0)
    return;

  if (where & SSL_CB_HANDSHAKE_DONE)
    {
      T ctx = tls_context_get_from_ssl (ssl);
      if (ctx)
        {
          pthread_mutex_lock (&ctx->stats_mutex);
          if (SSL_session_reused ((SSL *)ssl))
            {
              ctx->cache_hits++;
            }
          else
            {
              ctx->cache_misses++;
            }
          pthread_mutex_unlock (&ctx->stats_mutex);
        }
    }
}

/**
 * set_cache_size - Set session cache size with validation
 * @ctx: TLS context
 * @size: Cache size (must be > 0)
 *
 * Raises: SocketTLS_Failed on invalid size or OpenSSL error
 */
static void
set_cache_size (T ctx, size_t size)
{
  if (size == 0)
    ctx_raise_openssl_error ("Session cache size cannot be zero");

  if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)size) == 0)
    ctx_raise_openssl_error ("Failed to set session cache size");

  ctx->session_cache_size = size;
}

void
SocketTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                       long timeout_seconds)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  long mode = ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT;
  if (SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, mode) == 0)
    ctx_raise_openssl_error ("Failed to enable session cache mode");

  SSL_CTX_sess_set_new_cb (ctx->ssl_ctx, new_session_cb);
  SSL_CTX_set_info_callback (ctx->ssl_ctx, info_callback);

  if (max_sessions > 0)
    set_cache_size (ctx, max_sessions);

  SSL_CTX_set_timeout (ctx->ssl_ctx, timeout_seconds > 0
                                         ? timeout_seconds
                                         : SOCKET_TLS_SESSION_TIMEOUT_DEFAULT);
  ctx->session_cache_enabled = 1;
}

void
SocketTLSContext_set_session_cache_size (T ctx, size_t size)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  set_cache_size (ctx, size);
}

void
SocketTLSContext_get_cache_stats (T ctx, size_t *hits, size_t *misses,
                                  size_t *stores)
{
  if (!ctx || !ctx->session_cache_enabled)
    {
      if (hits)
        *hits = 0;
      if (misses)
        *misses = 0;
      if (stores)
        *stores = 0;
      return;
    }

  pthread_mutex_lock (&ctx->stats_mutex);
  if (hits)
    *hits = ctx->cache_hits;
  if (misses)
    *misses = ctx->cache_misses;
  if (stores)
    *stores = ctx->cache_stores;
  pthread_mutex_unlock (&ctx->stats_mutex);
}

void
SocketTLSContext_enable_session_tickets (T ctx, const unsigned char *key,
                                         size_t key_len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (key_len != SOCKET_TLS_TICKET_KEY_LEN)
    {
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed,
                           "Session ticket key length must be exactly %d bytes",
                           SOCKET_TLS_TICKET_KEY_LEN);
    }

  unsigned char *keys = Arena_alloc (ctx->arena, key_len, __FILE__, __LINE__);
  if (!keys)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                           "Failed to allocate ticket keys buffer");
    }
  memcpy (keys, key, key_len);
  ctx->tickets_enabled = 1;

  if (SSL_CTX_ctrl (ctx->ssl_ctx, SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
                    (int)key_len, keys)
      != 1)
    {
      ctx_raise_openssl_error ("Failed to set session ticket keys");
    }
}

/* ============================================================================
 * OCSP Stapling
 * ============================================================================
 */

/**
 * status_cb_wrapper - OpenSSL OCSP status callback wrapper
 * @ssl: SSL connection
 * @arg: User argument (unused, we get context from SSL)
 *
 * Returns: SSL_TLSEXT_ERR_OK or SSL_TLSEXT_ERR_NOACK
 */
static int
status_cb_wrapper (SSL *ssl, void *arg)
{
  (void)arg;
  T ctx = tls_context_get_from_ssl (ssl);
  if (!ctx || !ctx->ocsp_gen_cb)
    return SSL_TLSEXT_ERR_NOACK;

  OCSP_RESPONSE *resp = ctx->ocsp_gen_cb (ssl, ctx->ocsp_gen_arg);
  if (!resp)
    return SSL_TLSEXT_ERR_NOACK;

  unsigned char *der = NULL;
  int len = i2d_OCSP_RESPONSE (resp, &der);
  if (len > 0 && der)
    {
      SSL_set_tlsext_status_ocsp_resp (ssl, der, len);
    }

  OCSP_RESPONSE_free (resp);
  if (der)
    OPENSSL_free (der);

  return len > 0 ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}

void
SocketTLSContext_set_ocsp_response (T ctx, const unsigned char *response,
                                    size_t len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!response || len == 0)
    RAISE_CTX_ERROR_MSG (SocketTLS_Failed,
                         "Invalid OCSP response (null or zero length)");

  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &response, len);
  if (!resp)
    {
      RAISE_CTX_ERROR_MSG (SocketTLS_Failed, "Invalid OCSP response format");
    }
  OCSP_RESPONSE_free (resp);

  unsigned char *copy = Arena_alloc (ctx->arena, len, __FILE__, __LINE__);
  if (!copy)
    {
      RAISE_CTX_ERROR (SocketTLS_Failed);
    }
  memcpy (copy, response, len);
  ctx->ocsp_response = copy;
  ctx->ocsp_len = len;
}

void
SocketTLSContext_set_ocsp_gen_callback (T ctx, SocketTLSOcspGenCallback cb,
                                        void *arg)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->ocsp_gen_cb = cb;
  ctx->ocsp_gen_arg = arg;

  SSL_CTX_set_tlsext_status_cb (ctx->ssl_ctx, status_cb_wrapper);

  /* Check for OpenSSL errors - ERR_get_error consumes the error */
  unsigned long err = ERR_get_error ();
  if (err != 0)
    {
      char err_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_CTX_ERROR_FMT (SocketTLS_Failed, "Failed to set OCSP status cb: %s",
                           err_buf);
    }
}

/**
 * validate_socket_for_ocsp - Check socket is ready for OCSP status query
 * @socket: Socket to validate
 *
 * Returns: 1 if valid, 0 if not ready for OCSP
 */
static int
validate_socket_for_ocsp (Socket_T socket)
{
  return socket && socket->tls_enabled && socket->tls_ssl
         && socket->tls_handshake_done;
}

/**
 * get_ocsp_response_bytes - Get raw OCSP response from SSL
 * @ssl: SSL connection
 * @resp_bytes: Output pointer to response bytes
 *
 * Returns: Length of response, or 0 if no response
 */
static int
get_ocsp_response_bytes (SSL *ssl, const unsigned char **resp_bytes)
{
  int len = SSL_get_tlsext_status_ocsp_resp (ssl, resp_bytes);
  return (len > 0 && *resp_bytes) ? len : 0;
}

/**
 * validate_ocsp_basic_response - Validate OCSP basic response structure
 * @resp: OCSP response to validate
 *
 * Returns: 1 if valid, error status code otherwise
 */
static int
validate_ocsp_basic_response (OCSP_RESPONSE *resp)
{
  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  if (!basic)
    return OCSP_RESPONSE_STATUS_INTERNALERROR;
  OCSP_BASICRESP_free (basic);
  return 1;
}

int
SocketTLS_get_ocsp_status (Socket_T socket)
{
  if (!validate_socket_for_ocsp (socket))
    return 0;

  SSL *ssl = (SSL *)socket->tls_ssl;
  const unsigned char *resp_bytes;
  int resp_len = get_ocsp_response_bytes (ssl, &resp_bytes);
  if (resp_len == 0)
    return 0;

  const unsigned char *p = resp_bytes;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, resp_len);
  if (!resp)
    return OCSP_RESPONSE_STATUS_MALFORMEDREQUEST;

  int status = OCSP_response_status (resp);
  if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return status;
    }

  int result = validate_ocsp_basic_response (resp);
  OCSP_RESPONSE_free (resp);
  return result;
}

#undef T

#endif /* SOCKET_HAS_TLS */


