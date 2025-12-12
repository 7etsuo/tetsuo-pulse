/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define T SocketTLSContext_T

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketTLSContext);

/* Global ex_data index for context lookup (thread-safe initialization) */
int tls_context_exdata_idx = -1;
static pthread_once_t exdata_init_once = PTHREAD_ONCE_INIT;

/* ============================================================================
 * Internal Helper Macros
 * ============================================================================
 */

/**
 * SSL_CTX_CONFIGURE - Configure SSL_CTX with automatic cleanup on failure
 * @ssl_ctx: OpenSSL SSL_CTX to configure
 * @call: OpenSSL configuration call that returns 1 on success
 * @error_msg: Error message for exception
 *
 * Executes the OpenSSL configuration call, checks for success (return == 1),
 * and on failure: frees the SSL_CTX, formats OpenSSL error, and raises
 * SocketTLS_Failed. Reduces repetitive error handling in TLS configuration.
 */
#define SSL_CTX_CONFIGURE(ssl_ctx, call, error_msg)                           \
  do                                                                          \
    {                                                                         \
      if ((call) != 1)                                                        \
        {                                                                     \
          SSL_CTX_free (ssl_ctx);                                             \
          ctx_raise_openssl_error (error_msg);                                \
        }                                                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * One-Time Initialization
 * ============================================================================
 */

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
  SOCKET_ERROR_MSG ("%s: %s (errno=%d)", context, Socket_safe_strerror (errno),
                    errno);
  RAISE_CTX_ERROR (SocketTLS_Failed);
}

/**
 * ctx_raise_openssl_error - Format and raise OpenSSL error
 * @context: Error context description
 *
 * Reads the first (deepest) error from OpenSSL's thread-local error queue,
 * formats it into the thread-local error buffer, and raises SocketTLS_Failed.
 *
 * ## OpenSSL Error Queue Handling
 *
 * - ERR_get_error() retrieves errors FIFO (first-in, first-out)
 * - First error is typically the root cause and most specific
 * - ERR_error_string_n() safely formats with buffer size limit
 * - ERR_clear_error() clears the entire queue to prevent stale errors
 *
 * ## Buffer Size Rationale
 *
 * Uses SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE (256 bytes), which provides:
 * - 2x safety margin for typical ~120 char OpenSSL errors
 * - Safe truncation via ERR_error_string_n() if overflow
 *
 * @note This function always raises an exception and never returns.
 * @note ERR_clear_error() is called before raising to prevent error leakage.
 *
 * @see ssl_format_openssl_error_to_buf() for non-raising version.
 */
void
ctx_raise_openssl_error (const char *context)
{
  unsigned long err;
  char err_str[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];

  /* ERR_get_error() returns 0 if queue is empty.
   * Removes the error from queue as side effect. */
  err = ERR_get_error ();

  if (err != 0)
    {
      /* ERR_error_string_n() safely formats with size limit.
       * Format: "error:[hex]:[lib]:[func]:[reason]" */
      ERR_error_string_n (err, err_str, sizeof (err_str));
      SOCKET_ERROR_MSG ("%s: %s", context, err_str);
    }
  else
    {
      SOCKET_ERROR_MSG ("%s: Unknown TLS error (no OpenSSL error code)",
                        context);
    }

  /* Clear remaining errors before raising to prevent:
   * 1. Stale errors affecting subsequent operations
   * 2. Memory buildup from unread errors */
  ERR_clear_error ();
  RAISE_CTX_ERROR (SocketTLS_Failed);
}

/* ============================================================================
 * Structure Initialization Helpers
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
    raise_system_error ("Failed to initialize stats mutex");
}

/**
 * init_crl_mutex - Initialize recursive CRL mutex
 * @ctx: Context to initialize mutex for
 *
 * Raises: SocketTLS_Failed on mutex init failure
 */
static void
init_crl_mutex (T ctx)
{
  pthread_mutexattr_t attr;

  if (pthread_mutexattr_init (&attr) != 0)
    ctx_raise_openssl_error ("Failed to initialize CRL mutex attr");

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

/* ============================================================================
 * SSL_CTX Configuration
 * ============================================================================
 */

/**
 * configure_tls13_only - Apply TLS1.3-only security settings
 * @ssl_ctx: OpenSSL context to configure
 *
 * Sets minimum/maximum protocol to TLS1.3, configures modern ciphers,
 * disables renegotiation for security, and sets certificate chain
 * depth limit.
 *
 * Raises: SocketTLS_Failed on configuration failure
 */
static void
configure_tls13_only (SSL_CTX *ssl_ctx)
{
  SSL_CTX_CONFIGURE (ssl_ctx,
                     SSL_CTX_set_min_proto_version (ssl_ctx,
                                                    SOCKET_TLS_MIN_VERSION),
                     "Failed to set TLS1.3 min version");

  SSL_CTX_CONFIGURE (ssl_ctx,
                     SSL_CTX_set_max_proto_version (ssl_ctx,
                                                    SOCKET_TLS_MAX_VERSION),
                     "Failed to enforce TLS1.3 max version");

  SSL_CTX_CONFIGURE (ssl_ctx,
                     SSL_CTX_set_ciphersuites (ssl_ctx,
                                               SOCKET_TLS13_CIPHERSUITES),
                     "Failed to set secure ciphersuites");

  /* Security options:
   * - NO_RENEGOTIATION: Prevents CVE-2009-3555, Triple Handshake, DoS
   * - CIPHER_SERVER_PREFERENCE: Server chooses cipher (for servers)
   * - NO_COMPRESSION: Defensive against CRIME-like attacks */
  SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_RENEGOTIATION
                                    | SSL_OP_CIPHER_SERVER_PREFERENCE
                                    | SSL_OP_NO_COMPRESSION);

  /* Set maximum certificate chain depth to prevent DoS from excessively
   * long chains. SOCKET_TLS_MAX_CERT_CHAIN_DEPTH (default 10) allows
   * typical commercial CA hierarchies while blocking malicious chains. */
  SSL_CTX_set_verify_depth (ssl_ctx, SOCKET_TLS_MAX_CERT_CHAIN_DEPTH);
}

/* ============================================================================
 * Context Allocation
 * ============================================================================
 */

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
 * global ex_data index.
 */
static void
register_exdata (T ctx)
{
  pthread_once (&exdata_init_once, init_exdata_idx);
  SSL_CTX_set_ex_data (ctx->ssl_ctx, tls_context_exdata_idx, ctx);
}

/**
 * init_context_fields - Initialize context fields after allocation
 * @ctx: Context to initialize
 * @is_server: 1 for server, 0 for client
 */
static void
init_context_fields (T ctx, int is_server)
{
  ctx->is_server = !!is_server;
  ctx->session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;
  init_stats_mutex (ctx);
  init_crl_mutex (ctx);
  init_sni_certs (&ctx->sni_certs);
  init_alpn (&ctx->alpn);
  tls_pinning_init (&ctx->pinning);
}

/**
 * ctx_alloc_and_init - Create and initialize TLS context
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
    ctx_raise_openssl_error ("Failed to create SSL_CTX");

  configure_tls13_only (ssl_ctx);

  T ctx = alloc_context_struct (ssl_ctx);
  ctx->ssl_ctx = ssl_ctx;

  register_exdata (ctx);
  init_context_fields (ctx, is_server);

  return ctx;
}

/* ============================================================================
 * Context Cleanup Helpers
 * ============================================================================
 */

/**
 * free_sni_arrays - Free SNI certificate path arrays
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
 * free_sni_chain - Free a single SNI certificate chain
 * @chain: X509 chain stack to free (may be NULL)
 */
static void
free_sni_chain (STACK_OF (X509) * chain)
{
  if (chain)
    sk_X509_pop_free (chain, X509_free);
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
        free_sni_chain (ctx->sni_certs.chains[i]);
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

/**
 * secure_clear_sensitive_data - Clear sensitive context data
 * @ctx: Context with sensitive data to clear
 *
 * Securely wipes session ticket keys and pinning data.
 */
static void
secure_clear_sensitive_data (T ctx)
{
  OPENSSL_cleanse (ctx->ticket_key, SOCKET_TLS_TICKET_KEY_LEN);
  ctx->tickets_enabled = 0;

  if (ctx->pinning.pins && ctx->pinning.count > 0)
    {
      SocketCrypto_secure_clear (ctx->pinning.pins,
                                 ctx->pinning.count * sizeof (TLSCertPin));
    }
  pthread_mutex_destroy (&ctx->pinning.lock);
}

/**
 * destroy_context_mutexes - Destroy context mutex resources
 * @ctx: Context with mutexes to destroy
 */
static void
destroy_context_mutexes (T ctx)
{
  pthread_mutex_destroy (&ctx->stats_mutex);
  pthread_mutex_destroy (&ctx->crl_mutex);
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
 * Client Context CA Loading Helpers
 * ============================================================================
 */

/**
 * try_load_user_ca - Attempt to load user-provided CA file
 * @ctx: Client context
 * @ca_file: Path to CA file
 *
 * Returns: 1 if CA loaded successfully, 0 on failure
 */
static int
try_load_user_ca (T ctx, const char *ca_file)
{
  volatile int loaded = 0;

  TRY
  {
    SocketTLSContext_load_ca (ctx, ca_file);
    SOCKET_LOG_INFO_MSG ("Loaded user-provided CA '%s' for client context %p",
                         ca_file, (void *)ctx);
    loaded = 1;
  }
  EXCEPT (SocketTLS_Failed)
  {
    SOCKET_LOG_WARN_MSG ("Failed to load user-provided CA '%s' for client "
                         "context %p - attempting system CA fallback",
                         ca_file, (void *)ctx);
    loaded = 0;
  }
  END_TRY;

  return loaded;
}

/**
 * try_load_system_ca - Attempt to load system default CAs
 * @ctx: Client context
 *
 * Returns: 1 if system CAs loaded, 0 on failure
 */
static int
try_load_system_ca (T ctx)
{
  if (SSL_CTX_set_default_verify_paths (ctx->ssl_ctx) == 1)
    {
      SOCKET_LOG_INFO_MSG (
          "Loaded system default CAs as fallback for client context %p",
          (void *)ctx);
      return 1;
    }
  return 0;
}

/**
 * handle_no_trusted_ca - Handle case when no CA could be loaded
 * @ctx: Client context (freed on error)
 * @user_ca_provided: 1 if user provided a CA file
 */
static void
handle_no_trusted_ca (T *ctx_ptr, int user_ca_provided)
{
  if (user_ca_provided)
    {
      SocketTLSContext_free (ctx_ptr);
      ctx_raise_openssl_error (
          "Both user CA and system fallback failed - cannot establish "
          "trusted verification");
    }
  else
    {
      SOCKET_LOG_WARN_MSG (
          "Client context %p created with no trusted CAs (user CA "
          "absent and system unavailable) - peer verification enabled "
          "but handshakes will likely fail (high MITM risk!)",
          (void *)*ctx_ptr);
    }
}

/* ============================================================================
 * Custom Protocol Configuration
 * ============================================================================
 */

/**
 * apply_custom_protocol_config - Apply custom protocol version limits
 * @ctx: Context to configure
 * @config: Custom configuration
 *
 * Applies min/max protocol versions from config if different from defaults.
 */
static void
apply_custom_protocol_config (T ctx, const SocketTLSConfig_T *config)
{
  if (config->min_version != SOCKET_TLS_MIN_VERSION)
    SocketTLSContext_set_min_protocol (ctx, config->min_version);

  if (config->max_version != SOCKET_TLS_MAX_VERSION)
    SocketTLSContext_set_max_protocol (ctx, config->max_version);
}

/* ============================================================================
 * Public Context Lifecycle API
 * ============================================================================
 */

T
SocketTLSContext_new (const SocketTLSConfig_T *config)
{
  SocketTLSConfig_T default_config;
  SocketTLSConfig_T local_config;
  T ctx;

  /* Copy config to local to avoid clobber warning with TRY/setjmp */
  if (config)
    local_config = *config;
  else
    {
      SocketTLS_config_defaults (&default_config);
      local_config = default_config;
    }

  ctx = ctx_alloc_and_init (TLS_client_method (), 0);

  TRY { apply_custom_protocol_config (ctx, &local_config); }
  EXCEPT (SocketTLS_Failed)
  {
    SocketTLSContext_free (&ctx);
    RERAISE;
  }
  END_TRY;

  return ctx;
}

T
SocketTLSContext_new_server (const char *cert_file, const char *key_file,
                             const char *ca_file)
{
  assert (cert_file);
  assert (key_file);

  T ctx = ctx_alloc_and_init (TLS_server_method (), 1);

  TRY
  {
    SocketTLSContext_load_certificate (ctx, cert_file, key_file);
    if (ca_file)
      SocketTLSContext_load_ca (ctx, ca_file);
  }
  EXCEPT (SocketTLS_Failed)
  {
    SocketTLSContext_free (&ctx);
    RERAISE;
  }
  END_TRY;

  return ctx;
}

T
SocketTLSContext_new_client (const char *ca_file)
{
  T ctx = ctx_alloc_and_init (TLS_client_method (), 0);
  int has_trusted_ca = 0;

  SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);

  if (ca_file)
    has_trusted_ca = try_load_user_ca (ctx, ca_file);

  if (!has_trusted_ca)
    has_trusted_ca = try_load_system_ca (ctx);

  if (!has_trusted_ca)
    handle_no_trusted_ca (&ctx, ca_file != NULL);

  return ctx;
}

void
SocketTLSContext_free (T *ctx)
{
  assert (ctx);

  if (!*ctx)
    return;

  T c = *ctx;

  if (c->ssl_ctx)
    {
      SSL_CTX_free (c->ssl_ctx);
      c->ssl_ctx = NULL;
    }

  secure_clear_sensitive_data (c);

  if (c->arena)
    Arena_dispose (&c->arena);

  free_sni_arrays (c);
  free_sni_objects (c);
  destroy_context_mutexes (c);

  free (c);
  *ctx = NULL;
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
