/**
 * SocketTLSContext.c - TLS Context Management Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Manages creation, configuration, and lifecycle of OpenSSL SSL_CTX objects.
 * Encapsulates secure defaults (TLS1.3-only, PFS ciphers), cert loading,
 * verification modes, ALPN, and session caching. Uses Arena for internal
 * allocations. Provides opaque T interface with exception-based errors.
 *
 * Key integration:
 * - Automatic protocol/cipher hardening
 * - CA cert loading for verification
 * - ALPN wire-format construction from strings
 * - Session cache config for perf
 * - Detailed OpenSSL error formatting in exceptions
 *
 * Thread safety: Context modification not thread-safe. After setup, sharing
 * for SSL_new() is safe (OpenSSL CTX is ref-counted). Use mutex if modifying
 * shared. Per-connection SSL objects are independent.
 *
 * Error handling: Uses SocketTLS_Failed exception with context-specific
 * details.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <ctype.h>

/* Thread-local error buffer for detailed error messages
 * Prevents race conditions when multiple threads raise TLS context errors
 * simultaneously */
#ifdef _WIN32
static
    __declspec (thread) char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
static __thread char tls_context_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* Thread-local exception for detailed TLS context error messages
 * Prevents race conditions when multiple threads raise same exception type. */
#ifdef _WIN32
static __declspec (thread) Except_T SocketTLSContext_DetailedException;
#else
static __thread Except_T SocketTLSContext_DetailedException;
#endif

/* Macro to raise TLS context exception with detailed error message
 * Creates a thread-local copy of the exception with detailed reason */
#define RAISE_TLS_CONTEXT_ERROR(exception)                                    \
  do                                                                          \
    {                                                                         \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

#define T SocketTLSContext_T

struct T
{
  SSL_CTX *ssl_ctx;          /* OpenSSL context */
  Arena_T arena;             /* Arena for allocations */
  int is_server;             /* 1 for server, 0 for client */
  int session_cache_enabled; /* Session cache flag */
  size_t session_cache_size; /* Session cache size */

  /* SNI certificate mapping for virtual hosting */
  struct
  {
    char **hostnames;  /* Array of hostname strings */
    char **cert_files; /* Array of certificate file paths */
    char **key_files;  /* Array of private key file paths */
    X509 **certs;      /* Pre-loaded certificate objects */
    EVP_PKEY **pkeys;  /* Pre-loaded private key objects */
    size_t count;      /* Number of certificate mappings */
    size_t capacity;   /* Allocated capacity */
  } sni_certs;

  /* ALPN configuration */
  struct
  {
    const char **protocols;         /* Array of protocol strings */
    size_t count;                   /* Number of protocols */
    const char *selected;           /* Negotiated protocol (for clients) */
    SocketTLSAlpnCallback callback; /* Custom selection callback */
    void *callback_user_data;       /* User data for callback */
  } alpn;
};

/* Helper function to format OpenSSL errors and raise TLS context exceptions */
static void
raise_tls_context_error (const char *context)
{
  unsigned long openssl_error = ERR_get_error ();
  char openssl_error_buf[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (openssl_error != 0)
    {
      ERR_error_string_n (openssl_error, openssl_error_buf,
                          sizeof (openssl_error_buf));
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "%s: OpenSSL error: %s", context, openssl_error_buf);
    }
  else
    {
      snprintf (tls_context_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "%s: Unknown TLS error", context);
    }

  /* Use SocketTLS_Failed for general TLS context errors */
  RAISE_TLS_CONTEXT_ERROR (SocketTLS_Failed);
}

/**
 * validate_file_path - Basic validation for certificate/key/CA file paths
 * @path: File path string to validate
 *
 * Performs security checks to prevent path traversal and unreasonable paths.
 * Checks for non-empty, reasonable length, no ".." sequences.
 *
 * Returns: 1 if valid, 0 if invalid
 */
static int
validate_file_path (const char *path)
{
  if (!path || !*path)
    return 0;

  size_t len = strlen (path);
  if (len == 0 || len > 4096) /* Reasonable max path length */
    return 0;

  if (strstr (path, "..") != NULL)
    return 0; /* Prevent potential path traversal */

  /* Additional checks can be added: no null bytes, valid chars, etc. */

  return 1;
}

/**
 * validate_hostname - Validate SNI hostname format
 * @hostname: Hostname string to validate
 *
 * Validates hostname according to DNS rules: labels with alphanum/-, length limits.
 *
 * Returns: 1 if valid, 0 if invalid
 */
static int
validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_TLS_MAX_SNI_LEN)
    return 0;

  const char *p = hostname;
  int label_len = 0;
  int expecting_dot = 0; /* After dot or start */

  while (*p)
    {
      if (*p == '.')
        {
          if (label_len == 0 || label_len > 63)
            return 0;
          label_len = 0;
          expecting_dot = 0;
        }
      else
        {
          if (expecting_dot)
            return 0; /* Non-dot after dot? No, after dot expect label char
 */
          if (! (isalnum ((unsigned char)*p) || *p == '-'))
            return 0;
          if (*p == '-' && label_len == 0)
            return 0; /* Label can't start with - */
          label_len++;
          if (label_len > 63)
            return 0;
          expecting_dot = 1; /* Can have dot next */
        }
      p++;
    }

  if (label_len == 0 || label_len > 63)
    return 0;

  return 1;
}

/* SNI callback function for hostname-based certificate selection */
static int
sni_callback (SSL *ssl, int *ad, void *arg)
{
  (void)ad;  /* unused */
  T ctx = (T)arg;
  const char *sni_hostname = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);

  if (!sni_hostname || !ctx)
    return SSL_TLSEXT_ERR_NOACK;

  /* Look up certificate for this hostname using pre-loaded objects */
  for (size_t i = 0; i < ctx->sni_certs.count; i++)
    {
      const char *stored_hostname = ctx->sni_certs.hostnames[i];
      if (stored_hostname && strcmp (stored_hostname, sni_hostname) == 0)
        {
          X509 *cert = ctx->sni_certs.certs[i];
          EVP_PKEY *pkey = ctx->sni_certs.pkeys[i];

          if (!cert || !pkey)
            return SSL_TLSEXT_ERR_NOACK;

          /* Use pre-loaded certificate and key */
          if (SSL_use_certificate (ssl, cert) != 1)
            return SSL_TLSEXT_ERR_NOACK;

          if (SSL_use_PrivateKey (ssl, pkey) != 1)
            return SSL_TLSEXT_ERR_NOACK;

          if (SSL_check_private_key (ssl) != 1)
            return SSL_TLSEXT_ERR_NOACK;

          return SSL_TLSEXT_ERR_OK;
        }
    }

  /* No matching certificate found; fallback to default in context */
  return SSL_TLSEXT_ERR_NOACK;
}

/* ALPN select callback function for customizable protocol selection */
static int
alpn_select_callback (SSL *ssl, const unsigned char **out,
                      unsigned char *outlen, const unsigned char *in,
                      unsigned int inlen, void *arg)
{
  (void)ssl; /* unused */
  T ctx = (T)arg;
  const unsigned char *client_protocols = in;
  unsigned int client_protocols_len = inlen;

  if (!ctx || !ctx->alpn.protocols || ctx->alpn.count == 0)
    return SSL_TLSEXT_ERR_NOACK;

  /* Parse client protocols from wire format */
  size_t client_count = 0;
  const char **client_protos = NULL;

  /* Count client protocols */
  size_t offset = 0;
  while (offset < client_protocols_len)
    {
      if (offset + 1 > client_protocols_len)
        break; /* Malformed */
      unsigned char len = client_protocols[offset++];
      if (offset + len > client_protocols_len)
        break; /* Malformed */

      client_count++;
      offset += len;
    }

  if (client_count == 0)
    return SSL_TLSEXT_ERR_NOACK;

  /* Allocate array for client protocols */
  client_protos = calloc (client_count, sizeof (const char *));
  if (!client_protos)
    return SSL_TLSEXT_ERR_NOACK;

  /* Parse client protocols into strings */
  offset = 0;
  size_t idx = 0;
  while (offset < client_protocols_len && idx < client_count)
    {
      unsigned char len = client_protocols[offset++];
      if (offset + len > client_protocols_len)
        break;

      /* Create null-terminated string */
      char *proto = malloc (len + 1);
      if (!proto)
        {
          free (client_protos);
          return SSL_TLSEXT_ERR_NOACK;
        }
      memcpy (proto, &client_protocols[offset], len);
      proto[len] = '\0';
      client_protos[idx++] = proto;
      offset += len;
    }

  /* Call user callback or use default selection */
  const char *selected = NULL;
  if (ctx->alpn.callback)
    {
      selected = ctx->alpn.callback (client_protos, client_count,
                                     ctx->alpn.callback_user_data);
    }
  else
    {
      /* Default: select first matching protocol in our preference order */
      for (size_t i = 0; i < ctx->alpn.count && !selected; i++)
        {
          for (size_t j = 0; j < client_count && !selected; j++)
            {
              if (strcmp (ctx->alpn.protocols[i], client_protos[j]) == 0)
                {
                  selected = ctx->alpn.protocols[i];
                }
            }
        }
    }

  /* Clean up client protocols array */
  for (size_t i = 0; i < client_count; i++)
    {
      free ((void *)client_protos[i]);
    }
  free (client_protos);

  /* Set selected protocol */
  if (selected)
    {
      *out = (const unsigned char *)selected;
      *outlen = (unsigned char)strlen (selected);
      return SSL_TLSEXT_ERR_OK;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

/**
 * alloc_and_init_ctx - Allocate and initialize common TLS context structure
 * @method: OpenSSL method (TLS_server_method() or TLS_client_method())
 * @is_server: Non-zero for server mode, zero for client
 *
 * Shared initialization logic for client and server contexts. Creates SSL_CTX,
 * configures secure TLS1.3-only settings and ciphersuites, allocates context
 * struct with calloc, creates arena, initializes fields.
 *
 * Returns: New T instance ready for further configuration
 * Raises: SocketTLS_Failed on any failure (OpenSSL config, memory)
 * Thread-safe: Yes - independent instances
 *
 * Note: Caller must load certificates and set other options. Uses calloc for
 * ctx struct (freed separately); arena for internal buffers.
 */
static T
alloc_and_init_ctx (const SSL_METHOD *method, int is_server)
{
  T ctx;
  SSL_CTX *ssl_ctx;

  /* Create SSL_CTX with specified method */
  ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    {
      raise_tls_context_error ("Failed to create SSL_CTX");
    }

  /* Set protocol and cipher configs */
  if (SSL_CTX_set_min_proto_version (ssl_ctx, SOCKET_TLS_MIN_VERSION) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      raise_tls_context_error ("Failed to set TLS1.3 min version");
    }

  if (SSL_CTX_set_max_proto_version (ssl_ctx, SOCKET_TLS_MAX_VERSION) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      raise_tls_context_error ("Failed to enforce TLS1.3 max version");
    }

  if (SSL_CTX_set_ciphersuites (ssl_ctx, SOCKET_TLS13_CIPHERSUITES) != 1)
    {
      SSL_CTX_free (ssl_ctx);
      raise_tls_context_error ("Failed to set secure ciphersuites");
    }

  /* Allocate and initialize context structure */
  ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      SSL_CTX_free (ssl_ctx);
      raise_tls_context_error ("ENOMEM: calloc for context struct");
    }

  /* Create arena */
  ctx->arena = Arena_new ();
  if (!ctx->arena)
    {
      free (ctx);
      SSL_CTX_free (ssl_ctx);
      raise_tls_context_error ("Failed to create context arena");
    }

  /* Initialize fields - transfer ownership of ssl_ctx */
  ctx->ssl_ctx = ssl_ctx;
  ctx->is_server = !!is_server;
  ctx->session_cache_enabled = 0;
  ctx->session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;

  /* Initialize SNI certificate mapping */
  ctx->sni_certs.hostnames = NULL;
  ctx->sni_certs.cert_files = NULL;
  ctx->sni_certs.key_files = NULL;
  ctx->sni_certs.certs = NULL;
  ctx->sni_certs.pkeys = NULL;
  ctx->sni_certs.count = 0;
  ctx->sni_certs.capacity = 0;

  /* Initialize ALPN configuration */
  ctx->alpn.protocols = NULL;
  ctx->alpn.count = 0;
  ctx->alpn.selected = NULL;
  ctx->alpn.callback = NULL;
  ctx->alpn.callback_user_data = NULL;

  return ctx;
}

/**
 * SocketTLSContext_new_server - Create a new server TLS context
 * @cert_file: Server certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 * @ca_file: CA certificate file path (optional, may be NULL)
 *
 * Creates a new SSL_CTX for server-side TLS operations. Loads the server
 * certificate and private key. Optionally loads CA certificates for client
 * certificate verification.
 *
 * Returns: New TLS context instance
 * Raises: SocketTLS_Failed on error (file not found, invalid cert/key, etc.)
 * Thread-safe: Yes (creates independent context)
 */
T
SocketTLSContext_new_server (const char *cert_file, const char *key_file,
                             const char *ca_file)
{
  T ctx;

  assert (cert_file);
  assert (key_file);

  /* Allocate and initialize common context structure */
  ctx = alloc_and_init_ctx (TLS_server_method (), 1);

  /* Load server certificate and key */
  TRY SocketTLSContext_load_certificate (ctx, cert_file, key_file);
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

/**
 * SocketTLSContext_new_client - Create a new client TLS context
 * @ca_file: CA certificate file path for server verification (optional, may be
 * NULL)
 *
 * Creates a new SSL_CTX for client-side TLS operations. Optionally loads CA
 * certificates for server certificate verification.
 *
 * Returns: New TLS context instance
 * Raises: SocketTLS_Failed on error
 * Thread-safe: Yes (creates independent context)
 */
T
SocketTLSContext_new_client (const char *ca_file)
{
  T ctx;

  /* Allocate and initialize common context structure */
  ctx = alloc_and_init_ctx (TLS_client_method (), 0);

  /* Load CA certificates if provided */
  if (ca_file)
    {
      TRY SocketTLSContext_load_ca (ctx, ca_file);
      /* Enable verification by default when CA is provided */
      SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
      EXCEPT (SocketTLS_Failed)
      SocketTLSContext_free (&ctx);
      RERAISE;
      END_TRY;
    }

  return ctx;
}

/**
 * SocketTLSContext_load_certificate - Load server certificate and private key
 * @ctx: TLS context instance
 * @cert_file: Certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 *
 * Loads a server certificate and its corresponding private key into the TLS
 * context. Both files must be in PEM format.
 *
 * Raises: SocketTLS_Failed on error (file not found, invalid format, key/cert
 * mismatch) Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                   const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  if (!validate_file_path (cert_file) || !validate_file_path (key_file))
    {
      raise_tls_context_error ("Invalid certificate or key file path");
    }

  /* Load certificate */
  if (SSL_CTX_use_certificate_file (ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM)
      != 1)
    {
      raise_tls_context_error ("Failed to load certificate file");
    }

  /* Load private key */
  if (SSL_CTX_use_PrivateKey_file (ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM)
      != 1)
    {
      raise_tls_context_error ("Failed to load private key file");
    }

  /* Verify that the private key matches the certificate */
  if (SSL_CTX_check_private_key (ctx->ssl_ctx) != 1)
    {
      raise_tls_context_error ("Private key does not match certificate");
    }
}

/**
 * SocketTLSContext_load_ca - Load CA certificates for peer verification
 * @ctx: TLS context instance
 * @ca_file: CA certificate file or directory path
 *
 * Loads CA certificates used for verifying peer certificates. The path can be
 * either a single file containing CA certificates or a directory containing
 * multiple CA certificate files.
 *
 * Raises: SocketTLS_Failed on error (file not found, invalid format)
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_load_ca (T ctx, const char *ca_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (ca_file);

  if (!validate_file_path (ca_file))
    {
      raise_tls_context_error ("Invalid CA file path");
    }

  /* Load CA certificates */
  if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, ca_file, NULL) != 1)
    {
      /* Try as directory if file loading failed */
      if (SSL_CTX_load_verify_locations (ctx->ssl_ctx, NULL, ca_file) != 1)
        {
          raise_tls_context_error ("Failed to load CA certificates");
        }
    }
}

/**
 * SocketTLSContext_add_certificate - Add certificate mapping for SNI virtual
 * hosting
 * @ctx: TLS context instance
 * @hostname: Hostname this certificate is for (NULL for default certificate)
 * @cert_file: Certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 *
 * Adds a certificate/key pair for SNI-based virtual hosting. Multiple
 * certificates can be loaded for different hostnames. The first certificate
 * loaded becomes the default if no hostname match is found.
 *
 * Raises: SocketTLS_Failed on error (file not found, invalid cert/key,
 * allocation) Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                  const char *cert_file, const char *key_file)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (cert_file);
  assert (key_file);

  if (!validate_file_path (cert_file) || !validate_file_path (key_file))
    {
      raise_tls_context_error ("Invalid certificate or key file path");
    }

  /* Only meaningful for server contexts */
  if (!ctx->is_server)
    {
      raise_tls_context_error (
          "SNI certificates only supported for server contexts");
    }

  /* Limit number of SNI certificates to prevent memory exhaustion */
  if (ctx->sni_certs.count >= SOCKET_TLS_MAX_SNI_CERTS)
    {
      raise_tls_context_error ("Too many SNI certificates");
    }

  /* Expand capacity if needed */
  if (ctx->sni_certs.count >= ctx->sni_certs.capacity)
    {
      size_t new_capacity
          = ctx->sni_certs.capacity == 0 ? 4 : ctx->sni_certs.capacity * 2;

      ctx->sni_certs.hostnames
          = realloc (ctx->sni_certs.hostnames, new_capacity * sizeof (char *));
      ctx->sni_certs.cert_files = realloc (ctx->sni_certs.cert_files,
                                           new_capacity * sizeof (char *));
      ctx->sni_certs.key_files
          = realloc (ctx->sni_certs.key_files, new_capacity * sizeof (char *));
      ctx->sni_certs.certs
          = realloc (ctx->sni_certs.certs, new_capacity * sizeof (X509 *));
      ctx->sni_certs.pkeys
          = realloc (ctx->sni_certs.pkeys, new_capacity * sizeof (EVP_PKEY *));

      if (!ctx->sni_certs.hostnames || !ctx->sni_certs.cert_files
          || !ctx->sni_certs.key_files || !ctx->sni_certs.certs
          || !ctx->sni_certs.pkeys)
        {
          raise_tls_context_error (
              "Failed to allocate SNI certificate arrays");
        }

      ctx->sni_certs.capacity = new_capacity;
    }

  /* Store hostname (NULL for default) */
  if (hostname)
    {
      size_t host_len = strlen (hostname);
      if (host_len == 0 || host_len > SOCKET_TLS_MAX_SNI_LEN)
        {
          raise_tls_context_error ("Invalid SNI hostname length");
        }
      if (!validate_hostname (hostname))
        {
          raise_tls_context_error ("Invalid SNI hostname format");
        }
      size_t hostname_len = host_len + 1;
      char *hostname_copy
          = Arena_alloc (ctx->arena, hostname_len, __FILE__, __LINE__);
      if (!hostname_copy)
        {
          raise_tls_context_error ("Failed to allocate hostname buffer");
        }
      memcpy (hostname_copy, hostname, hostname_len);
      ctx->sni_certs.hostnames[ctx->sni_certs.count] = hostname_copy;
    }
  else
    {
      ctx->sni_certs.hostnames[ctx->sni_certs.count] = NULL;
    }

  /* Store certificate file path */
  size_t cert_len = strlen (cert_file) + 1;
  char *cert_copy = Arena_alloc (ctx->arena, cert_len, __FILE__, __LINE__);
  if (!cert_copy)
    {
      raise_tls_context_error ("Failed to allocate certificate path buffer");
    }
  memcpy (cert_copy, cert_file, cert_len);
  ctx->sni_certs.cert_files[ctx->sni_certs.count] = cert_copy;

  /* Store key file path */
  size_t key_len = strlen (key_file) + 1;
  char *key_copy = Arena_alloc (ctx->arena, key_len, __FILE__, __LINE__);
  if (!key_copy)
    {
      raise_tls_context_error ("Failed to allocate key path buffer");
    }
  memcpy (key_copy, key_file, key_len);
  ctx->sni_certs.key_files[ctx->sni_certs.count] = key_copy;

  /* Load and store certificate and private key objects */
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;

  /* Load certificate */
  FILE *cert_fp = fopen (cert_file, "r");
  if (!cert_fp)
    {
      raise_tls_context_error ("Cannot open certificate file");
    }
  cert = PEM_read_X509 (cert_fp, NULL, NULL, NULL);
  fclose (cert_fp);
  if (!cert)
    {
      raise_tls_context_error ("Failed to parse certificate PEM");
    }

  /* Load private key */
  FILE *key_fp = fopen (key_file, "r");
  if (!key_fp)
    {
      X509_free (cert);
      raise_tls_context_error ("Cannot open private key file");
    }
  pkey = PEM_read_PrivateKey (key_fp, NULL, NULL, NULL);
  fclose (key_fp);
  if (!pkey)
    {
      X509_free (cert);
      raise_tls_context_error ("Failed to parse private key PEM");
    }

  /* Validate key matches certificate */
  if (X509_check_private_key (cert, pkey) != 1)
    {
      EVP_PKEY_free (pkey);
      X509_free (cert);
      raise_tls_context_error ("Private key does not match certificate");
    }

  /* Store loaded objects (OpenSSL will manage refs during use) */
  ctx->sni_certs.certs[ctx->sni_certs.count] = cert;
  ctx->sni_certs.pkeys[ctx->sni_certs.count] = pkey;

  /* If default certificate (no hostname), also load into context using file for fallback */
  if (!hostname)
    {
      SocketTLSContext_load_certificate (ctx, cert_file, key_file);
    }

  ctx->sni_certs.count++;

  /* Enable SNI callback if we have multiple certificates or hostname-specific
   * ones */
  if (ctx->sni_certs.count > 1 || (ctx->sni_certs.count == 1 && hostname))
    {
      SSL_CTX_set_tlsext_servername_callback (ctx->ssl_ctx, sni_callback);
      SSL_CTX_set_tlsext_servername_arg (ctx->ssl_ctx, ctx);
    }
}

/**
 * SocketTLSContext_set_verify_mode - Configure certificate verification mode
 * @ctx: TLS context instance
 * @mode: Verification mode (TLS_VERIFY_NONE, TLS_VERIFY_PEER, etc.)
 *
 * Sets the certificate verification mode for TLS connections. This controls
 * whether peer certificates are verified and what happens when verification
 * fails.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  int openssl_mode = 0;

  /* Convert our enum to OpenSSL flags */
  switch (mode)
    {
    case TLS_VERIFY_NONE:
      openssl_mode = SSL_VERIFY_NONE;
      break;
    case TLS_VERIFY_PEER:
      openssl_mode = SSL_VERIFY_PEER;
      break;
    case TLS_VERIFY_FAIL_IF_NO_PEER_CERT:
      openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      break;
    case TLS_VERIFY_CLIENT_ONCE:
      openssl_mode = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
      break;
    default:
      raise_tls_context_error ("Invalid TLS verification mode");
      return;
    }

  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, NULL);
}

/**
 * SocketTLSContext_set_min_protocol - Set minimum TLS protocol version
 * @ctx: TLS context instance
 * @version: Minimum TLS version (e.g., TLS1_2_VERSION)
 *
 * Sets the minimum allowed TLS protocol version for connections.
 * Attempts to use SSL_CTX_set_min_proto_version() for OpenSSL 1.1.0+,
 * falls back to SSL_CTX_set_options() for older versions.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Try the modern API first (OpenSSL 1.1.0+) */
  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    {
#if defined(SSL_OP_NO_SSLv2) && defined(SSL_OP_NO_SSLv3)
      /* Fall back to disabling older protocols via options */
      long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

      if (version > TLS1_VERSION)
        options |= SSL_OP_NO_TLSv1;
      if (version > TLS1_1_VERSION)
        options |= SSL_OP_NO_TLSv1_1;
      if (version > TLS1_2_VERSION)
        options |= SSL_OP_NO_TLSv1_2;

      long current_options = SSL_CTX_set_options (ctx->ssl_ctx, options);
      if (!(current_options & options))
        {
          raise_tls_context_error (
              "Failed to set minimum TLS protocol version");
        }
#else
      /* On modern OpenSSL without deprecated macros, assume
       * set_min_proto_version works or we are stuck. If it failed above, we
       * can't fallback easily. */
      raise_tls_context_error (
          "Failed to set minimum TLS protocol version (fallback unavailable)");
#endif
    }
}

/**
 * SocketTLSContext_set_max_protocol - Set maximum TLS protocol version
 * @ctx: TLS context instance
 * @version: Maximum TLS version (e.g., TLS1_3_VERSION)
 *
 * Sets the maximum allowed TLS protocol version for connections.
 * Uses SSL_CTX_set_max_proto_version() (OpenSSL 1.1.0+).
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    {
      raise_tls_context_error ("Failed to set maximum TLS protocol version");
    }
}

/**
 * SocketTLSContext_set_cipher_list - Configure allowed cipher suites
 * @ctx: TLS context instance
 * @ciphers: OpenSSL cipher list string (e.g.,
 * "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA")
 *
 * Sets the list of allowed cipher suites for TLS connections. Uses OpenSSL's
 * cipher list format. Pass NULL to use OpenSSL defaults.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (ciphers)
    {
      if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, ciphers) != 1)
        {
          raise_tls_context_error ("Failed to set cipher list");
        }
    }
  else
    {
      /* Use default cipher list */
      if (SSL_CTX_set_cipher_list (
              ctx->ssl_ctx,
              "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA")
          != 1)
        {
          raise_tls_context_error ("Failed to set default cipher list");
        }
    }
}

/**
 * SocketTLSContext_set_alpn_protos - Configure ALPN protocol negotiation
 * @ctx: TLS context instance
 * @protos: Array of protocol name strings (e.g., ["h2", "http/1.1"])
 * @count: Number of protocols in the array
 *
 * Sets the list of protocols to advertise during ALPN negotiation.
 * Each protocol string must be <= SOCKET_TLS_MAX_ALPN_LEN bytes.
 * For servers, this sets the list of supported protocols.
 * For clients, this sets the list of desired protocols in preference order.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);
  assert (ctx->ssl_ctx);
  assert (protos || count == 0);

  if (count == 0)
    return;

  if (count > SOCKET_TLS_MAX_ALPN_PROTOCOLS)
    {
      raise_tls_context_error ("Too many ALPN protocols");
    }

  /* Store protocols in context for later reference */
  ctx->alpn.protocols = Arena_alloc (ctx->arena, count * sizeof (const char *),
                                     __FILE__, __LINE__);
  if (!ctx->alpn.protocols)
    {
      raise_tls_context_error ("Failed to allocate ALPN protocols array");
    }

  for (size_t i = 0; i < count; i++)
    {
      assert (protos[i]);
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_TLS_MAX_ALPN_LEN)
        {
          raise_tls_context_error ("Invalid ALPN protocol length");
        }

      /* Copy protocol string to arena */
      char *proto_copy = Arena_alloc (ctx->arena, len + 1, __FILE__, __LINE__);
      if (!proto_copy)
        {
          raise_tls_context_error ("Failed to allocate ALPN protocol buffer");
        }
      memcpy (proto_copy, protos[i], len + 1);
      ctx->alpn.protocols[i] = proto_copy;
    }
  ctx->alpn.count = count;

  /* Calculate total buffer size needed for wire format */
  size_t total_len = 0;
  for (size_t i = 0; i < count; i++)
    {
      size_t len = strlen (protos[i]);
      total_len += 1 + len; /* 1 byte length + protocol string */
    }

  /* Allocate buffer from context arena */
  unsigned char *wire_buf
      = Arena_alloc (ctx->arena, total_len, __FILE__, __LINE__);
  if (!wire_buf)
    {
      raise_tls_context_error ("Failed to allocate ALPN buffer");
    }

  /* Convert to wire format (length-prefixed strings) */
  size_t offset = 0;
  for (size_t i = 0; i < count; i++)
    {
      size_t len = strlen (protos[i]);
      wire_buf[offset++] = (unsigned char)len;
      memcpy (wire_buf + offset, protos[i], len);
      offset += len;
    }

  /* Set ALPN protocols */
  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire_buf, (unsigned int)total_len)
      != 0)
    {
      raise_tls_context_error ("Failed to set ALPN protocols");
    }

  /* Set ALPN select callback */
  SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_callback, ctx);
}

/**
 * SocketTLSContext_set_alpn_callback - Set custom ALPN protocol selection
 * callback
 * @ctx: TLS context instance
 * @callback: Function to call for ALPN protocol selection
 * @user_data: User data passed to callback function
 *
 * Sets a custom callback for ALPN protocol selection instead of using default
 * priority order. The callback receives client-offered protocols and should
 * return the selected protocol string.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_alpn_callback (T ctx, SocketTLSAlpnCallback callback,
                                    void *user_data)
{
  assert (ctx);

  ctx->alpn.callback = callback;
  ctx->alpn.callback_user_data = user_data;
}

/**
 * SocketTLSContext_enable_session_cache - Enable TLS session caching
 * @ctx: TLS context instance
 *
 * Enables TLS session caching to improve performance by reusing established
 * sessions. Session caching is enabled by default for both client and server
 * contexts, but this function allows explicit control.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_enable_session_cache (T ctx)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  long mode;

  if (ctx->is_server)
    {
      mode = SSL_SESS_CACHE_SERVER;
    }
  else
    {
      mode = SSL_SESS_CACHE_CLIENT;
    }

  if (SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, mode) == 0)
    {
      raise_tls_context_error ("Failed to enable session cache");
    }

  ctx->session_cache_enabled = 1;
}

/**
 * SocketTLSContext_set_session_cache_size - Set session cache size limit
 * @ctx: TLS context instance
 * @size: Maximum number of cached sessions
 *
 * Sets the maximum number of sessions that can be cached. This helps control
 * memory usage for session caching. The default is
 * SOCKET_TLS_SESSION_CACHE_SIZE.
 *
 * Thread-safe: No (modifies shared context)
 */
void
SocketTLSContext_set_session_cache_size (T ctx, size_t size)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (size == 0)
    {
      raise_tls_context_error ("Session cache size cannot be zero");
    }

  if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)size) == 0)
    {
      raise_tls_context_error ("Failed to set session cache size");
    }

  ctx->session_cache_size = size;
}

/**
 * SocketTLSContext_free - Destroy TLS context and free resources
 * @ctx: Pointer to TLS context instance
 *
 * Frees all resources associated with the TLS context, including the
 * OpenSSL SSL_CTX and arena allocations. Sets the pointer to NULL.
 *
 * Thread-safe: No (not safe to free while in use by other threads)
 */
void
SocketTLSContext_free (T *ctx)
{
  assert (ctx);

  if (*ctx)
    {
      T c = *ctx;

      /* Free OpenSSL context */
      if (c->ssl_ctx)
        {
          SSL_CTX_free (c->ssl_ctx);
          c->ssl_ctx = NULL;
        }

      /* Free arena (this cleans up all arena allocations) */
      if (c->arena)
        {
          Arena_dispose (&c->arena);
        }

      /* Free SNI path arrays */
      if (c->sni_certs.hostnames)
        {
          free (c->sni_certs.hostnames);
          c->sni_certs.hostnames = NULL;
        }
      if (c->sni_certs.cert_files)
        {
          free (c->sni_certs.cert_files);
          c->sni_certs.cert_files = NULL;
        }
      if (c->sni_certs.key_files)
        {
          free (c->sni_certs.key_files);
          c->sni_certs.key_files = NULL;
        }

      /* Free pre-loaded OpenSSL objects */
      if (c->sni_certs.certs)
        {
          for (size_t i = 0; i < c->sni_certs.count; ++i)
            {
              if (c->sni_certs.certs[i])
                X509_free (c->sni_certs.certs[i]);
            }
          free (c->sni_certs.certs);
          c->sni_certs.certs = NULL;
        }
      if (c->sni_certs.pkeys)
        {
          for (size_t i = 0; i < c->sni_certs.count; ++i)
            {
              if (c->sni_certs.pkeys[i])
                EVP_PKEY_free (c->sni_certs.pkeys[i]);
            }
          free (c->sni_certs.pkeys);
          c->sni_certs.pkeys = NULL;
        }

      /* Free context structure */
      free (c);
      *ctx = NULL;
    }
}

/**
 * SocketTLSContext_get_ssl_ctx - Get internal SSL_CTX pointer
 * @ctx: TLS context instance
 *
 * Returns the internal OpenSSL SSL_CTX pointer for use by other modules.
 * This breaks the abstraction but is necessary for integration with
 * existing socket TLS functionality.
 *
 * Returns: SSL_CTX pointer (cast to void* for opacity)
 * Thread-safe: Yes (reading pointer is safe)
 */
void *
SocketTLSContext_get_ssl_ctx (T ctx)
{
  assert (ctx);
  return (void *)ctx->ssl_ctx;
}

/**
 * SocketTLSContext_is_server - Check if context is for server
 * @ctx: TLS context instance
 *
 * Returns: 1 if server context, 0 if client context
 * Thread-safe: Yes
 */
int
SocketTLSContext_is_server (T ctx)
{
  assert (ctx);
  return ctx->is_server;
}

#undef T

#endif /* SOCKET_HAS_TLS */
