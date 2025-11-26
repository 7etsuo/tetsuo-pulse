/**
 * SocketTLSContext-core.c - TLS Context Core Operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Core TLS context lifecycle: creation, destruction, and basic accessors.
 * Handles SSL_CTX allocation, TLS1.3 configuration, ex_data registration,
 * and context lookup from SSL objects.
 *
 * Thread safety: Context creation is thread-safe (independent instances).
 * Context modification is NOT thread-safe after sharing.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T SocketTLSContext_T

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
T
ctx_alloc_and_init (const SSL_METHOD *method, int is_server)
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

  ctx = ctx_alloc_and_init (TLS_server_method (), 1);

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
  T ctx = ctx_alloc_and_init (TLS_client_method (), 0);

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

#undef T

#endif /* SOCKET_HAS_TLS */

