/**
 * SocketTLSContext.c - TLS Context Management
 *


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

#include "socket/Socket-private.h" /* For Socket_T access in internal verify wrapper */
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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
/* RAISE_TLS_CONTEXT_ERROR variants for flexibility */
#define RAISE_TLS_CONTEXT_ERROR(exception)                                    \
  do                                                                          \
    {                                                                         \
      tls_context_error_buf[0] = '\0'; /* Clear buf for default */            \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

#define RAISE_TLS_CONTEXT_ERROR_MSG(exception, msg)                           \
  do                                                                          \
    {                                                                         \
      strncpy (tls_context_error_buf, msg,                                    \
               sizeof (tls_context_error_buf) - 1);                           \
      tls_context_error_buf[sizeof (tls_context_error_buf) - 1] = '\0';       \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

#define RAISE_TLS_CONTEXT_ERROR_FMT(exception, fmt, ...)                      \
  do                                                                          \
    {                                                                         \
      snprintf (tls_context_error_buf, sizeof (tls_context_error_buf), fmt,   \
                __VA_ARGS__);                                                 \
      SocketTLSContext_DetailedException = (exception);                       \
      SocketTLSContext_DetailedException.reason = tls_context_error_buf;      \
      RAISE (SocketTLSContext_DetailedException);                             \
    }                                                                         \
  while (0)

static int tls_context_exdata_idx = -1;

#define T SocketTLSContext_T

struct T
{
  SSL_CTX *ssl_ctx;          /* OpenSSL context */
  Arena_T arena;             /* Arena for allocations */
  int is_server;             /* 1 for server, 0 for client */
  int session_cache_enabled; /* Session cache flag */
  size_t session_cache_size; /* Session cache size */
  size_t cache_hits;   /* Number of session resumptions (hits/tickets/ID) */
  size_t cache_misses; /* Number of full handshakes */
  size_t cache_stores; /* Number of new sessions stored */
  pthread_mutex_t stats_mutex;          /* Thread-safe stats update */
  unsigned char ticket_key[48];         /* Session ticket encryption key */
  int tickets_enabled;                  /* 1 if session tickets enabled */
  SocketTLSOcspGenCallback ocsp_gen_cb; /* Dynamic OCSP generation callback */
  void *ocsp_gen_arg;                   /* Arg for OCSP gen cb */

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

  /* Custom verification callback */
  SocketTLSVerifyCallback verify_callback;
  void *verify_user_data;
  TLSVerifyMode verify_mode; /* Stored verification mode for reconfig */

  /* OCSP stapling support */
  const unsigned char
      *ocsp_response; /* Static response bytes (ref, user managed) */
  size_t ocsp_len;
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
 * Validates hostname according to DNS rules: labels with alphanum/-, length
 * limits.
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
          if (!(isalnum ((unsigned char)*p) || *p == '-'))
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
  (void)ad; /* unused */
  T ctx = (T)arg;
  const char *sni_hostname
      = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);

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
          for (size_t j = 0; j < idx; j++)
            free ((void *)client_protos[j]);
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"

static int
socket_tls_internal_verify (int pre_ok, X509_STORE_CTX *x509_ctx)
{
  /* Get SSL object from X509_STORE_CTX ex_data */
  SSL *ssl = X509_STORE_CTX_get_ex_data (
      x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
  if (!ssl)
    return pre_ok; /* Fallback if no SSL context available */

  /* Get Socket_T from SSL app_data (to be set in SocketTLS_base.c during TLS
   * enable) */
  Socket_T sock = (Socket_T)SSL_get_app_data (ssl);
  if (!sock)
    return pre_ok;

  /* Get TLS context from socket's private tls_ctx field (void* cast to T) */
  SocketTLSContext_T ctx = (SocketTLSContext_T)sock->tls_ctx;
  if (!ctx || !ctx->verify_callback)
    return pre_ok; /* No custom callback, fallback to default/pre_ok */

  /* Invoke user callback with exception safety for thread-safe execution */
  volatile int result;
  TRY
  {
    result = ctx->verify_callback (pre_ok, x509_ctx, ctx, sock,
                                   ctx->verify_user_data);
  }
  EXCEPT (SocketTLS_Failed)
  {
    /* Catch module errors raised by user callback, treat as verification
     * failure */
    const char *orig_reason = Except_frame.exception->reason;
    strncpy (tls_context_error_buf,
             orig_reason ? orig_reason
                         : "Verification callback raised SocketTLS_Failed",
             sizeof (tls_context_error_buf) - 1);
    tls_context_error_buf[sizeof (tls_context_error_buf) - 1] = '\0';
    SocketTLSContext_DetailedException = *Except_frame.exception;
    SocketTLSContext_DetailedException.reason = tls_context_error_buf;
    result = 0;
    X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
  }
  END_TRY;

  if (!result)
    {
      /* Capture OpenSSL errors for potential logging or post-check raise */
      unsigned long err_code = ERR_get_error ();
      if (err_code != 0)
        {
          char err_buf[256];
          ERR_error_string_n (err_code, err_buf, sizeof (err_buf));
          /* Callback can raise; here propagate fail to OpenSSL */
          /* In SocketTLS_handshake or get_verify_result, can raise detailed */
        }
      /* Optionally set custom error code for further processing */
      X509_STORE_CTX_set_error (x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    }

  return result;
}

#pragma GCC diagnostic pop

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

  if (tls_context_exdata_idx == -1)
    {
      tls_context_exdata_idx
          = SSL_CTX_get_ex_new_index (0, "SocketTLSContext", NULL, NULL, NULL);
    }
  SSL_CTX_set_ex_data (ssl_ctx, tls_context_exdata_idx, ctx);

  ctx->is_server = !!is_server;
  ctx->session_cache_enabled = 0;
  ctx->session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;
  ctx->cache_hits = 0;
  ctx->cache_misses = 0;
  ctx->cache_stores = 0;
  if (pthread_mutex_init (&ctx->stats_mutex, NULL) != 0)
    {
      raise_tls_context_error ("Failed to initialize stats mutex");
    }

  memset (ctx->ticket_key, 0, sizeof (ctx->ticket_key));
  ctx->tickets_enabled = 0;
  ctx->ocsp_gen_cb = NULL;
  ctx->ocsp_gen_arg = NULL;

  /* Initialize custom verification */
  ctx->verify_callback = NULL;
  ctx->verify_user_data = NULL;
  ctx->verify_mode
      = TLS_VERIFY_NONE; /* Default; overridden in new_server/client */

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

  /* If default certificate (no hostname), also load into context using file
   * for fallback */
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

  ctx->verify_mode = mode; /* Store for reconfig in set_callback */

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

  SSL_verify_cb verify_cb = ctx->verify_callback
                                ? (SSL_verify_cb)socket_tls_internal_verify
                                : NULL;
  ERR_clear_error ();
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, verify_cb);
}

/**
 * SocketTLSContext_set_verify_callback - Register custom verification callback
 * @ctx: The TLS context instance
 * @callback: User callback function (NULL to disable custom and use default)
 * @user_data: Opaque data passed to callback (lifetime managed by caller)
 *
 * Sets a custom verification callback for certificate validation, invoked
 * during TLS handshake verification. The internal wrapper handles OpenSSL
 * integration and provides socket/context access. Compatible with current
 * verify_mode.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if OpenSSL reconfiguration fails (rare)
 * Thread-safe: No - modifies shared context; call during setup before use
 * Note: Callback should avoid blocking operations; errors propagate via return
 * 0 (fails handshake) or user-raised exceptions.
 */
void
SocketTLSContext_set_verify_callback (T ctx, SocketTLSVerifyCallback callback,
                                      void *user_data)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  /* Store callback and data */
  ctx->verify_callback = callback;
  ctx->verify_user_data = user_data;

  /* Reconfigure OpenSSL verify with current mode and new cb or NULL */
  int openssl_mode = 0;
  switch (
      ctx->verify_mode) /* Assume ctx->verify_mode stored in set_verify_mode */
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
      RAISE_TLS_CONTEXT_ERROR_FMT (SocketTLS_Failed, "Invalid verify mode: %d",
                                   (int)ctx->verify_mode);
    }

  SSL_verify_cb verify_cb
      = callback ? (SSL_verify_cb)socket_tls_internal_verify : NULL;
  SSL_CTX_set_verify (ctx->ssl_ctx, openssl_mode, verify_cb);
  if (ERR_get_error () != 0)
    {
      unsigned long err = ERR_get_error ();
      char err_buf[256];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_TLS_CONTEXT_ERROR_FMT (
          SocketTLS_Failed, "Failed to set verify callback: %s", err_buf);
    }
}

/**
 * SocketTLSContext_load_crl - Load CRL file or directory for revocation
 * checking
 * @ctx: TLS context instance
 * @crl_path: Path to CRL file (PEM/DER) or directory (auto-detected via stat)
 *
 * Loads CRL data into the context's X509_STORE. Auto-detects file vs
 * directory. Enables X509_V_FLAG_CRL_CHECK | CRL_CHECK_ALL for chain
 * validation. Multiple calls append CRLs; re-call to refresh.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on stat/load/flags error
 * Thread-safe: No (modifies shared store)
 * Note: CRL checking active only with peer verification enabled.
 */
void
SocketTLSContext_load_crl (T ctx, const char *crl_path)
{
  if (!ctx)
    RAISE_TLS_CONTEXT_ERROR (SocketTLS_Failed);
  if (!ctx->ssl_ctx)
    RAISE_TLS_CONTEXT_ERROR (SocketTLS_Failed);
  if (!crl_path || !*crl_path)
    RAISE_TLS_CONTEXT_ERROR_MSG (SocketTLS_Failed,
                                 "CRL path cannot be NULL or empty");

  X509_STORE *store = SSL_CTX_get_cert_store (ctx->ssl_ctx);
  if (!store)
    RAISE_TLS_CONTEXT_ERROR (SocketTLS_Failed);

  struct stat st;
  if (stat (crl_path, &st) != 0)
    RAISE_TLS_CONTEXT_ERROR_FMT (SocketTLS_Failed, "Invalid CRL path '%s': %s",
                                 crl_path, strerror (errno));

  int ret;
  if (S_ISDIR (st.st_mode))
    {
      ret = X509_STORE_load_locations (store, NULL, crl_path);
    }
  else
    {
      ret = X509_STORE_load_locations (store, crl_path, NULL);
    }

  if (ret != 1)
    {
      unsigned long err = ERR_get_error ();
      char err_buf[256];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_TLS_CONTEXT_ERROR_FMT (
          SocketTLS_Failed, "Failed to load CRL '%s': %s", crl_path, err_buf);
    }

  /* Enable CRL flags (idempotent OR with current) */
  long current_flags = X509_STORE_set_flags (
      store, 0); /* Temp set 0 to get current (returns previous) */
  X509_STORE_set_flags (
      store,
      current_flags | (X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL));
}

void
SocketTLSContext_refresh_crl (T ctx, const char *crl_path)
{
  SocketTLSContext_load_crl (ctx, crl_path);
}

/**
 * SocketTLSContext_set_ocsp_response - Set static OCSP stapled response
 * (server-side)
 * @ctx: TLS context instance
 * @response: DER-encoded OCSP response bytes
 * @len: Length of response
 *
 * Sets static OCSP response to staple in server handshakes. Basic len check.
 * Overrides previous. User must ensure response validity and freshness.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if len==0
 * Thread-safe: No
 * Note: Full parse/validation stubbed pending OpenSSL compatibility.
 */
void
SocketTLSContext_set_ocsp_response (T ctx, const unsigned char *response,
                                    size_t len)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  if (!response || len == 0)
    RAISE_TLS_CONTEXT_ERROR_MSG (
        SocketTLS_Failed, "Invalid OCSP response (null or zero length)");

  /* Validate and copy response to arena */
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &response, len);
  if (!resp)
    {
      RAISE_TLS_CONTEXT_ERROR_MSG (SocketTLS_Failed,
                                   "Invalid OCSP response format");
    }
  OCSP_RESPONSE_free (resp); /* Just validate, don't store parsed */

  unsigned char *resp_copy = Arena_alloc (ctx->arena, len, __FILE__, __LINE__);
  if (!resp_copy)
    {
      RAISE_TLS_CONTEXT_ERROR (SocketTLS_Failed);
    }
  memcpy (resp_copy, response, len);
  ctx->ocsp_response = resp_copy;
  ctx->ocsp_len = len;

  /* Copy stored in ctx; set per SSL in SocketTLS_enable */
  /* Validation passed, response ready for stapling */
}

static int status_cb_wrapper (SSL *ssl, void *arg);

void
SocketTLSContext_set_ocsp_gen_callback (T ctx, SocketTLSOcspGenCallback cb,
                                        void *arg)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  ctx->ocsp_gen_cb = cb;
  ctx->ocsp_gen_arg = arg;

  SSL_CTX_set_tlsext_status_cb (ctx->ssl_ctx, status_cb_wrapper);

  if (ERR_get_error ())
    {
      unsigned long err = ERR_get_error ();
      char err_buf[256];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      RAISE_TLS_CONTEXT_ERROR_FMT (
          SocketTLS_Failed, "Failed to set OCSP status cb: %s", err_buf);
    }
}

/**
 * SocketTLS_get_ocsp_status - Retrieve OCSP status from stapled response
 * (client)
 * @socket: TLS socket after successful handshake
 *
 * Checks if stapled OCSP response was received. Basic presence check.
 * Full parse/validation stubbed pending OpenSSL compatibility.
 *
 * Returns: 1 if response present (assume good), 0 none/error
 * Raises: None
 * Thread-safe: Yes
 * Note: Requires client requested stapling.
 */
int
SocketTLS_get_ocsp_status (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    return 0; /* NONE */

  SSL *ssl = (SSL *)socket->tls_ssl;

  const unsigned char *response_bytes;
  int response_len = SSL_get_tlsext_status_ocsp_resp (ssl, &response_bytes);
  if (response_len <= 0 || !response_bytes)
    return 0; /* NONE */

  const unsigned char *p = response_bytes;
  OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE (NULL, &p, response_len);
  if (!resp)
    return OCSP_RESPONSE_STATUS_MALFORMEDREQUEST; /* Error code */

  int rstatus = OCSP_response_status (resp);
  if (rstatus != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
      OCSP_RESPONSE_free (resp);
      return rstatus; /* Map error */
    }

  /* Basic response status (full cert status/basic verify optional for compat)
   */
  OCSP_BASICRESP *basic = OCSP_response_get1_basic (resp);
  OCSP_RESPONSE_free (resp);
  if (!basic)
    return OCSP_RESPONSE_STATUS_INTERNALERROR;

  /* Assume good if basic present and response successful; extend with
   * OCSP_basic_verify(chain, store) for sig check */
  OCSP_BASICRESP_free (basic);
  return 1; /* GOOD - basic validation */
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

static T
get_tls_context_from_ssl_ctx (SSL_CTX *ssl_ctx)
{
  if (!ssl_ctx)
    return NULL;
  return (T)SSL_CTX_get_ex_data (ssl_ctx, tls_context_exdata_idx);
}

static T
get_tls_context_from_ssl (const SSL *ssl)
{
  if (!ssl)
    return NULL;
  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX ((SSL *)ssl);
  return get_tls_context_from_ssl_ctx (ssl_ctx);
}

static int
new_session_cb (SSL *ssl, SSL_SESSION *sess)
{
  (void)sess;
  T ctx = get_tls_context_from_ssl (ssl);
  if (ctx)
    {
      pthread_mutex_lock (&ctx->stats_mutex);
      ctx->cache_stores++;
      pthread_mutex_unlock (&ctx->stats_mutex);
    }
  return 1;
}

static void
info_callback (const SSL *ssl, int where, int ret)
{
  if (ret == 0)
    return;
  if (where & SSL_CB_HANDSHAKE_DONE)
    {
      T ctx = get_tls_context_from_ssl (ssl);
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
 * SocketTLSContext_enable_session_cache - Enable and configure session cache
 * @ctx: TLS context instance
 * @max_sessions: Max sessions to cache (0 for default
 * SOCKET_TLS_SESSION_CACHE_SIZE)
 * @timeout_seconds: Session lifetime in seconds (0 for default 300)
 *
 * Enables OpenSSL built-in session caching with size limit and timeout.
 * Sets server/client mode accordingly, configures callbacks for stats.
 * Thread-safe: No
 */
void
SocketTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                       long timeout_seconds)
{
  assert (ctx);
  assert (ctx->ssl_ctx);

  long mode = ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT;

  if (SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, mode) == 0)
    {
      raise_tls_context_error ("Failed to enable session cache mode");
    }

  /* Set callbacks for stats tracking */
  SSL_CTX_sess_set_new_cb (ctx->ssl_ctx, new_session_cb);
  SSL_CTX_set_info_callback (ctx->ssl_ctx, info_callback);

  /* Configure size if specified */
  if (max_sessions > 0)
    {
      if (SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)max_sessions) == 0)
        {
          raise_tls_context_error ("Failed to set session cache size");
        }
      ctx->session_cache_size = max_sessions;
    }

  /* Configure timeout */
  long to = timeout_seconds > 0 ? timeout_seconds : 300L;
  SSL_CTX_set_timeout (ctx->ssl_ctx, to);

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

  if (key_len != 80)
    {
      RAISE_TLS_CONTEXT_ERROR_MSG (SocketTLS_Failed,
                                   "Session ticket key length must be exactly "
                                   "80 bytes for this OpenSSL version");
    }

  unsigned char *keys = Arena_alloc (ctx->arena, key_len, __FILE__, __LINE__);
  if (!keys)
    {
      RAISE_TLS_CONTEXT_ERROR_MSG (SocketTLS_Failed,
                                   "Failed to allocate ticket keys buffer");
    }
  memcpy (keys, key, key_len);
  ctx->tickets_enabled = 1;

  if (SSL_CTX_ctrl (ctx->ssl_ctx, SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
                    (int)key_len, keys)
      != 1)
    {
      raise_tls_context_error ("Failed to set session ticket keys");
    }

  /* Ticket lifetime follows session timeout by default */
}

static int
status_cb_wrapper (SSL *ssl, void *arg)
{
  (void)arg;
  T ctx = get_tls_context_from_ssl (ssl);
  if (!ctx || !ctx->ocsp_gen_cb)
    return SSL_TLSEXT_ERR_NOACK;

  OCSP_RESPONSE *resp = ctx->ocsp_gen_cb (ssl, ctx->ocsp_gen_arg);
  if (!resp)
    return SSL_TLSEXT_ERR_NOACK;

  unsigned char *der = NULL;
  int len = i2d_OCSP_RESPONSE (resp, &der);
  if (len > 0)
    {
      SSL_set_tlsext_status_ocsp_resp (ssl, der, len);
    }

  OCSP_RESPONSE_free (resp);
  if (der)
    OPENSSL_free (der);

  return len > 0 ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
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
      pthread_mutex_destroy (&c->stats_mutex);
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
#include <openssl/ocsp.h>
