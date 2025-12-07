/**
 * SocketTLSContext-core.c - TLS Context Core Operations
 *
 * Part of the Socket Library
 *
 * Core TLS context lifecycle: creation, destruction, and basic accessors.
 * Handles SSL_CTX allocation, TLS1.3 configuration, ex_data registration,
 * and context lookup from SSL objects.
 *
 * Thread safety: Context creation is thread-safe (independent instances).
 * Context modification is NOT thread-safe after sharing.
 */

#if SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "core/SocketUtil.h"
#include "core/SocketCrypto.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketTLSContext);

/* Global ex_data index for context lookup (thread-safe initialization) */
int tls_context_exdata_idx = -1;
static pthread_once_t exdata_init_once = PTHREAD_ONCE_INIT;

/**
 * init_exdata_idx - One-time initialization of ex_data index
 *
 * Called via pthread_once to ensure thread-safe single initialization.
 */
static void
init_exdata_idx (void)
{
  tls_context_exdata_idx
      = SSL_CTX_get_ex_new_index (0, "SocketTLSContext", NULL, NULL, NULL);
}

/* ============================================================================
 * Error Handling Helpers
 * ============================================================================
 */

/**
 * raise_system_error - Format and raise system error (errno-based)
 * @context: Error context description
 *
 * Formats errno into thread-local error buffer and raises SocketTLS_Failed.
 * Uses Socket_safe_strerror for thread-safety.
 */
static void
raise_system_error (const char *context)
{
  SOCKET_ERROR_MSG("%s: %s (errno=%d)", context, Socket_safe_strerror(errno), errno);
  RAISE_CTX_ERROR (SocketTLS_Failed);
}

/**
 * ctx_raise_openssl_error - Format and raise OpenSSL error
 * @context: Error context description
 *
 * Reads the first error from OpenSSL's error queue, formats it into
 * the thread-local error buffer, and raises SocketTLS_Failed.
 * Clears the entire error queue to prevent stale errors from affecting
 * subsequent operations or leaking information.
 */
void
ctx_raise_openssl_error (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      SOCKET_ERROR_MSG("%s: %s", context, err_str);
    }
  else
    {
      SOCKET_ERROR_MSG("%s: Unknown TLS error (no OpenSSL error code)", context);
    }

  /* Clear remaining errors to prevent stale error information from
   * affecting subsequent operations or leaking to callers */
  ERR_clear_error ();

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
  sni->chains = NULL;
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
      raise_system_error ("Failed to initialize stats mutex");
    }
}

/**
 * init_crl_mutex - Initialize CRL mutex
 * @ctx: Context to initialize mutex for
 *
 * Raises: SocketTLS_Failed on mutex init failure
 */
static void
init_crl_mutex (T ctx)
{
  pthread_mutexattr_t attr;
  if (pthread_mutexattr_init (&attr) != 0)
    {
      ctx_raise_openssl_error ("Failed to initialize CRL mutex attr");
    }
  if (pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
    {
      pthread_mutexattr_destroy (&attr);
      ctx_raise_openssl_error ("Failed to set recursive mutex type");
    }
  if (pthread_mutex_init (&ctx->crl_mutex, &attr) != 0)
    {
      pthread_mutexattr_destroy (&attr);
      ctx_raise_openssl_error ("Failed to initialize CRL mutex");
    }
  pthread_mutexattr_destroy (&attr);
}

/**
 * configure_tls13_only - Apply TLS1.3-only security settings
 * @ssl_ctx: OpenSSL context to configure
 *
 * Sets minimum/maximum protocol to TLS1.3, configures modern ciphers,
 * and disables renegotiation for security.
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

  /* Disable TLS renegotiation to prevent:
   * - CVE-2009-3555 (prefix injection attack)
   * - Triple Handshake Attack
   * - DoS via repeated renegotiation
   *
   * Note: TLS 1.3 doesn't support renegotiation at all, but this also
   * protects if TLS 1.2 is ever re-enabled via set_min_protocol. */

  /* Additional security options:
   * - Prefer server cipher order (for servers; ignored on clients)
   * - Disable compression (defensive against CRIME-like attacks, redundant for TLS1.3) */
  SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_RENEGOTIATION |
                               SSL_OP_CIPHER_SERVER_PREFERENCE |
                               SSL_OP_NO_COMPRESSION);
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
      raise_system_error ("Failed to allocate context struct (calloc)");
    }

  ctx->arena = Arena_new ();
  if (!ctx->arena)
    {
      free (ctx);
      SSL_CTX_free (ssl_ctx);
      raise_system_error ("Failed to create context arena");
    }

  return ctx;
}

/**
 * register_exdata - Register context in SSL_CTX ex_data
 * @ctx: Context to register
 *
 * Uses pthread_once for thread-safe one-time initialization of the
 * global ex_data index, preventing race conditions during first use.
 */
static void
register_exdata (T ctx)
{
  pthread_once (&exdata_init_once, init_exdata_idx);
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
  init_crl_mutex (ctx);
  init_sni_certs (&ctx->sni_certs);
  init_alpn (&ctx->alpn);
  tls_pinning_init (&ctx->pinning);

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
  if (ctx->sni_certs.chains)
    {
      for (size_t i = 0; i < ctx->sni_certs.count; ++i)
        {
          if (ctx->sni_certs.chains[i])
            sk_X509_pop_free (ctx->sni_certs.chains[i], X509_free);
        }
      free (ctx->sni_certs.chains);
    }
  if (ctx->sni_certs.pkeys)
    {
      for (size_t i = 0; i < ctx->sni_certs.count; ++i)
        {
          if (ctx->sni_certs.pkeys[i])
            tls_secure_free_pkey (ctx->sni_certs.pkeys[i]);
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

  /* Default to peer verification for security; attempt user CA then fallback to system defaults if possible */
  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);

  bool has_trusted_ca = false;
  if (ca_file)
    {
      TRY
        {
          SocketTLSContext_load_ca (ctx, ca_file);
          has_trusted_ca = true;
          SOCKET_LOG_INFO_MSG("Loaded user-provided CA '%s' for client context %p", ca_file, (void*)ctx);
        }
      EXCEPT (SocketTLS_Failed)
        {
          SOCKET_LOG_WARN_MSG("Failed to load user-provided CA '%s' for client context %p - attempting system CA fallback", ca_file, (void*)ctx);
        }
      END_TRY;
    }

  /* Fallback to system default CAs if no user CA successfully loaded */
  if (!has_trusted_ca)
    {
      if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) == 1)
        {
          has_trusted_ca = true;
          SOCKET_LOG_INFO_MSG("Loaded system default CAs as fallback for client context %p", (void*)ctx);
        }
      else
        {
          if (ca_file)
            {
              /* User provided CA but both failed - treat as config error */
              SocketTLSContext_free (&ctx);
              ctx_raise_openssl_error("Both user CA and system fallback failed - cannot establish trusted verification");
            }
          else
            {
              /* No user CA and no system - warn but proceed (app responsibility) */
              SOCKET_LOG_WARN_MSG("Client context %p created with no trusted CAs (user CA absent and system unavailable) - peer verification enabled but handshakes will likely fail (high MITM risk!)", (void*)ctx);
            }
        }
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

      /* Securely clear session ticket key material before freeing.
       * Always clear regardless of tickets_enabled flag for defense in depth. */
      OPENSSL_cleanse (c->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);
      c->tickets_enabled = 0;

      /* Securely clear pinning data before freeing */
      if (c->pinning.pins && c->pinning.count > 0)
        {
          SocketCrypto_secure_clear (c->pinning.pins,
                           c->pinning.count * sizeof (TLSCertPin));
        }
      pthread_mutex_destroy (&c->pinning.lock);

      if (c->arena)
        {
          Arena_dispose (&c->arena);
        }

      free_sni_arrays (c);
      free_sni_objects (c);

      pthread_mutex_destroy (&c->stats_mutex);
      pthread_mutex_destroy (&c->crl_mutex);
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

