/**
 * SocketDTLSContext.c - DTLS Context Management Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements DTLS context lifecycle, certificate loading, cookie exchange
 * configuration, and session management using OpenSSL.
 *
 * Thread safety: Context creation is thread-safe. Modification after creation
 * is not thread-safe - configure before sharing across threads.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketDTLS-private.h"
#include <assert.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/stat.h>

#define T SocketDTLSContext_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketDTLS_Failed = { &SocketDTLS_Failed, "DTLS operation failed" };
const Except_T SocketDTLS_HandshakeFailed
    = { &SocketDTLS_HandshakeFailed, "DTLS handshake failed" };
const Except_T SocketDTLS_VerifyFailed
    = { &SocketDTLS_VerifyFailed, "DTLS certificate verification failed" };
const Except_T SocketDTLS_CookieFailed
    = { &SocketDTLS_CookieFailed, "DTLS cookie exchange failed" };
const Except_T SocketDTLS_TimeoutExpired
    = { &SocketDTLS_TimeoutExpired, "DTLS handshake timeout expired" };
const Except_T SocketDTLS_ShutdownFailed
    = { &SocketDTLS_ShutdownFailed, "DTLS shutdown failed" };

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */

#ifdef _WIN32
__declspec (thread) char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
__declspec (thread) Except_T SocketDTLSContext_DetailedException;
#else
__thread char dtls_context_error_buf[SOCKET_DTLS_ERROR_BUFSIZE];
__thread Except_T SocketDTLSContext_DetailedException;
#endif

/* Global ex_data index for storing context pointer in SSL_CTX */
static int dtls_context_exdata_idx = -1;
static pthread_once_t dtls_exdata_once = PTHREAD_ONCE_INIT;

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * init_exdata_index - Initialize ex_data index (called once)
 */
static void
init_exdata_index (void)
{
  dtls_context_exdata_idx
      = SSL_CTX_get_ex_new_index (0, NULL, NULL, NULL, NULL);
}

/**
 * ctx_raise_openssl_error_dtls - Raise DTLS exception with OpenSSL error
 * @context: Context description for error message
 */
static void
ctx_raise_openssl_error_dtls (const char *context)
{
  unsigned long err = ERR_get_error ();
  char err_str[256];

  if (err != 0)
    {
      ERR_error_string_n (err, err_str, sizeof (err_str));
      snprintf (dtls_context_error_buf, SOCKET_DTLS_ERROR_BUFSIZE, "%s: %s",
                context, err_str);
    }
  else
    {
      snprintf (dtls_context_error_buf, SOCKET_DTLS_ERROR_BUFSIZE,
                "%s: Unknown error", context);
    }
  RAISE_DTLS_CTX_ERROR (SocketDTLS_Failed);
}

/**
 * apply_dtls_defaults - Apply secure defaults to SSL_CTX
 * @ssl_ctx: OpenSSL context
 * @is_server: 1 for server, 0 for client
 */
static void
apply_dtls_defaults (SSL_CTX *ssl_ctx, int is_server)
{
  /* Set DTLS 1.2 minimum/maximum versions */
  if (SSL_CTX_set_min_proto_version (ssl_ctx, SOCKET_DTLS_MIN_VERSION) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set minimum DTLS version");

  if (SSL_CTX_set_max_proto_version (ssl_ctx, SOCKET_DTLS_MAX_VERSION) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set maximum DTLS version");

  /* Set modern cipher suites */
  if (SSL_CTX_set_cipher_list (ssl_ctx, SOCKET_DTLS_CIPHERSUITES) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set DTLS cipher list");

  /* Disable session tickets by default (enable explicitly if needed) */
  SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_TICKET);

  /* Enable all workarounds for maximum compatibility */
  SSL_CTX_set_options (ssl_ctx, SSL_OP_ALL);

  /* Set verification depth */
  SSL_CTX_set_verify_depth (ssl_ctx, SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH);

  /* For servers, set session cache mode */
  if (is_server)
    {
      SSL_CTX_set_session_cache_mode (ssl_ctx, SSL_SESS_CACHE_SERVER);
    }
  else
    {
      SSL_CTX_set_session_cache_mode (ssl_ctx, SSL_SESS_CACHE_CLIENT);
    }
}

/**
 * alloc_context - Allocate and initialize context structure
 * @ssl_ctx: OpenSSL context to wrap
 * @is_server: 1 for server, 0 for client
 *
 * Returns: New context, raises on failure
 */
static T
alloc_context (SSL_CTX *ssl_ctx, int is_server)
{
  T ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      SSL_CTX_free (ssl_ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to allocate DTLS context");
    }

  ctx->arena = Arena_new ();
  if (!ctx->arena)
    {
      SSL_CTX_free (ssl_ctx);
      free (ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to allocate DTLS context arena");
    }

  ctx->ssl_ctx = ssl_ctx;
  ctx->is_server = is_server;
  ctx->mtu = SOCKET_DTLS_DEFAULT_MTU;
  ctx->initial_timeout_ms = SOCKET_DTLS_INITIAL_TIMEOUT_MS;
  ctx->max_timeout_ms = SOCKET_DTLS_MAX_TIMEOUT_MS;

  /* Initialize cookie state */
  ctx->cookie.cookie_enabled = 0;
  if (pthread_mutex_init (&ctx->cookie.secret_mutex, NULL) != 0)
    {
      Arena_dispose (&ctx->arena);
      SSL_CTX_free (ssl_ctx);
      free (ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to initialize cookie mutex");
    }

  /* Initialize stats mutex */
  if (pthread_mutex_init (&ctx->stats_mutex, NULL) != 0)
    {
      pthread_mutex_destroy (&ctx->cookie.secret_mutex);
      Arena_dispose (&ctx->arena);
      SSL_CTX_free (ssl_ctx);
      free (ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to initialize stats mutex");
    }

  /* Store context pointer in SSL_CTX ex_data for callback access */
  pthread_once (&dtls_exdata_once, init_exdata_index);
  if (dtls_context_exdata_idx >= 0)
    {
      SSL_CTX_set_ex_data (ssl_ctx, dtls_context_exdata_idx, ctx);
    }

  return ctx;
}

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

T
SocketDTLSContext_new_server (const char *cert_file, const char *key_file,
                              const char *ca_file)
{
  assert (cert_file);
  assert (key_file);

  if (!dtls_validate_file_path (cert_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid certificate path");

  if (!dtls_validate_file_path (key_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid key path");

  /* Create DTLS server method context */
  const SSL_METHOD *method = DTLS_server_method ();
  if (!method)
    ctx_raise_openssl_error_dtls ("Failed to get DTLS server method");

  SSL_CTX *ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    ctx_raise_openssl_error_dtls ("Failed to create DTLS server context");

  apply_dtls_defaults (ssl_ctx, 1);

  T ctx = alloc_context (ssl_ctx, 1);

  /* Load certificate and key */
  TRY
  {
    SocketDTLSContext_load_certificate (ctx, cert_file, key_file);

    if (ca_file && ca_file[0])
      {
        SocketDTLSContext_load_ca (ctx, ca_file);
      }
  }
  EXCEPT (SocketDTLS_Failed)
  {
    SocketDTLSContext_free (&ctx);
    RERAISE;
  }
  END_TRY;

  return ctx;
}

T
SocketDTLSContext_new_client (const char *ca_file)
{
  /* Create DTLS client method context */
  const SSL_METHOD *method = DTLS_client_method ();
  if (!method)
    ctx_raise_openssl_error_dtls ("Failed to get DTLS client method");

  SSL_CTX *ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    ctx_raise_openssl_error_dtls ("Failed to create DTLS client context");

  apply_dtls_defaults (ssl_ctx, 0);

  T ctx = alloc_context (ssl_ctx, 0);

  /* Load CA if provided */
  if (ca_file && ca_file[0])
    {
      TRY { SocketDTLSContext_load_ca (ctx, ca_file); }
      EXCEPT (SocketDTLS_Failed)
      {
        SocketDTLSContext_free (&ctx);
        RERAISE;
      }
      END_TRY;

      /* Enable peer verification when CA provided */
      SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

  return ctx;
}

void
SocketDTLSContext_free (T *ctx_p)
{
  if (!ctx_p || !*ctx_p)
    return;

  T ctx = *ctx_p;

  /* Securely clear cookie secrets */
  OPENSSL_cleanse (ctx->cookie.secret, sizeof (ctx->cookie.secret));
  OPENSSL_cleanse (ctx->cookie.prev_secret, sizeof (ctx->cookie.prev_secret));

  /* Destroy mutexes */
  pthread_mutex_destroy (&ctx->cookie.secret_mutex);
  pthread_mutex_destroy (&ctx->stats_mutex);

  /* Free SSL_CTX */
  if (ctx->ssl_ctx)
    {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
      /* Flush session cache to prevent memory leaks (OpenSSL < 3.0) */
      SSL_CTX_flush_sessions (ctx->ssl_ctx, 0);
#endif
      SSL_CTX_free (ctx->ssl_ctx);
      ctx->ssl_ctx = NULL;
    }

  /* Free arena (releases all arena-allocated memory) */
  if (ctx->arena)
    {
      Arena_dispose (&ctx->arena);
    }

  free (ctx);
  *ctx_p = NULL;
}

/* ============================================================================
 * Certificate Management
 * ============================================================================
 */

void
SocketDTLSContext_load_certificate (T ctx, const char *cert_file,
                                    const char *key_file)
{
  assert (ctx);
  assert (cert_file);
  assert (key_file);

  if (!dtls_validate_file_path (cert_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid certificate path");

  if (!dtls_validate_file_path (key_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid key path");

  /* Load certificate */
  if (SSL_CTX_use_certificate_chain_file (ctx->ssl_ctx, cert_file) != 1)
    ctx_raise_openssl_error_dtls ("Failed to load certificate");

  /* Load private key */
  if (SSL_CTX_use_PrivateKey_file (ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM)
      != 1)
    ctx_raise_openssl_error_dtls ("Failed to load private key");

  /* Verify key matches certificate */
  if (SSL_CTX_check_private_key (ctx->ssl_ctx) != 1)
    ctx_raise_openssl_error_dtls ("Certificate and private key mismatch");
}

void
SocketDTLSContext_load_ca (T ctx, const char *ca_file)
{
  assert (ctx);
  assert (ca_file);

  if (!dtls_validate_file_path (ca_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid CA path");

  /* Check if path is directory or file */
  struct stat st;
  if (stat (ca_file, &st) != 0)
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed, "Cannot access CA path: %s",
                                ca_file);
    }

  int result;
  if (S_ISDIR (st.st_mode))
    {
      result = SSL_CTX_load_verify_locations (ctx->ssl_ctx, NULL, ca_file);
    }
  else
    {
      result = SSL_CTX_load_verify_locations (ctx->ssl_ctx, ca_file, NULL);
    }

  if (result != 1)
    ctx_raise_openssl_error_dtls ("Failed to load CA certificates");
}

void
SocketDTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode)
{
  assert (ctx);

  int ssl_mode = SSL_VERIFY_NONE;

  if (mode & TLS_VERIFY_PEER)
    ssl_mode |= SSL_VERIFY_PEER;
  if (mode & TLS_VERIFY_FAIL_IF_NO_PEER_CERT)
    ssl_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  if (mode & TLS_VERIFY_CLIENT_ONCE)
    ssl_mode |= SSL_VERIFY_CLIENT_ONCE;

  SSL_CTX_set_verify (ctx->ssl_ctx, ssl_mode, NULL);
}

/* ============================================================================
 * Cookie Exchange (DoS Protection)
 * ============================================================================
 */

void
SocketDTLSContext_enable_cookie_exchange (T ctx)
{
  assert (ctx);

  if (!ctx->is_server)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Cookie exchange only for server contexts");
    }

  /* Generate random secret */
  if (RAND_bytes (ctx->cookie.secret, SOCKET_DTLS_COOKIE_SECRET_LEN) != 1)
    ctx_raise_openssl_error_dtls ("Failed to generate cookie secret");

  /* Clear previous secret */
  OPENSSL_cleanse (ctx->cookie.prev_secret, sizeof (ctx->cookie.prev_secret));

  /* Set OpenSSL cookie callbacks */
  SSL_CTX_set_cookie_generate_cb (ctx->ssl_ctx, dtls_cookie_generate_cb);
  SSL_CTX_set_cookie_verify_cb (ctx->ssl_ctx, dtls_cookie_verify_cb);

  ctx->cookie.cookie_enabled = 1;
}

void
SocketDTLSContext_set_cookie_secret (T ctx, const unsigned char *secret,
                                     size_t len)
{
  assert (ctx);
  assert (secret);

  if (len != SOCKET_DTLS_COOKIE_SECRET_LEN)
    {
      RAISE_DTLS_CTX_ERROR_FMT (
          SocketDTLS_Failed,
          "Cookie secret must be %d bytes (got %zu)",
          SOCKET_DTLS_COOKIE_SECRET_LEN, len);
    }

  pthread_mutex_lock (&ctx->cookie.secret_mutex);
  memcpy (ctx->cookie.secret, secret, len);
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);
}

void
SocketDTLSContext_rotate_cookie_secret (T ctx)
{
  assert (ctx);

  pthread_mutex_lock (&ctx->cookie.secret_mutex);

  /* Move current to previous */
  memcpy (ctx->cookie.prev_secret, ctx->cookie.secret,
          SOCKET_DTLS_COOKIE_SECRET_LEN);

  /* Generate new secret */
  if (RAND_bytes (ctx->cookie.secret, SOCKET_DTLS_COOKIE_SECRET_LEN) != 1)
    {
      pthread_mutex_unlock (&ctx->cookie.secret_mutex);
      ctx_raise_openssl_error_dtls ("Failed to generate new cookie secret");
    }

  pthread_mutex_unlock (&ctx->cookie.secret_mutex);
}

int
SocketDTLSContext_has_cookie_exchange (T ctx)
{
  return ctx ? ctx->cookie.cookie_enabled : 0;
}

/* ============================================================================
 * MTU Configuration
 * ============================================================================
 */

void
SocketDTLSContext_set_mtu (T ctx, size_t mtu)
{
  assert (ctx);

  if (!SOCKET_DTLS_VALID_MTU (mtu))
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Invalid MTU: %zu (must be %d-%d)", mtu,
                                SOCKET_DTLS_MIN_MTU, SOCKET_DTLS_MAX_MTU);
    }

  ctx->mtu = mtu;
}

size_t
SocketDTLSContext_get_mtu (T ctx)
{
  return ctx ? ctx->mtu : SOCKET_DTLS_DEFAULT_MTU;
}

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

void
SocketDTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set minimum DTLS version");
}

void
SocketDTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set maximum DTLS version");
}

void
SocketDTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  assert (ctx);

  const char *cipher_list = ciphers ? ciphers : SOCKET_DTLS_CIPHERSUITES;

  if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, cipher_list) != 1)
    ctx_raise_openssl_error_dtls ("Failed to set DTLS cipher list");
}

/* ============================================================================
 * ALPN Support
 * ============================================================================
 */

/**
 * alpn_select_cb - ALPN selection callback for server
 */
static int
alpn_select_cb (SSL *ssl, const unsigned char **out, unsigned char *outlen,
                const unsigned char *in, unsigned int inlen, void *arg)
{
  (void)ssl; /* Unused but required by OpenSSL callback signature */
  T ctx = (T)arg;
  if (!ctx || !ctx->alpn.protocols || ctx->alpn.count == 0)
    return SSL_TLSEXT_ERR_NOACK;

  /* Find first matching protocol */
  const unsigned char *client_proto = in;
  const unsigned char *client_end = in + inlen;

  while (client_proto < client_end)
    {
      unsigned int client_len = *client_proto++;
      if (client_proto + client_len > client_end)
        break;

      /* Check against our protocols */
      for (size_t i = 0; i < ctx->alpn.count; i++)
        {
          const char *our_proto = ctx->alpn.protocols[i];
          size_t our_len = strlen (our_proto);

          if (our_len == client_len
              && memcmp (our_proto, client_proto, client_len) == 0)
            {
              *out = client_proto;
              *outlen = (unsigned char)client_len;
              return SSL_TLSEXT_ERR_OK;
            }
        }
      client_proto += client_len;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

void
SocketDTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);

  if (!protos || count == 0)
    {
      ctx->alpn.protocols = NULL;
      ctx->alpn.count = 0;
      return;
    }

  if (count > SOCKET_DTLS_MAX_ALPN_PROTOCOLS)
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Too many ALPN protocols: %zu (max %d)", count,
                                SOCKET_DTLS_MAX_ALPN_PROTOCOLS);
    }

  /* Allocate array in arena */
  ctx->alpn.protocols
      = Arena_alloc (ctx->arena, count * sizeof (char *), __FILE__, __LINE__);
  if (!ctx->alpn.protocols)
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to allocate ALPN protocol array");

  /* Copy protocol strings */
  for (size_t i = 0; i < count; i++)
    {
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_DTLS_MAX_ALPN_LEN)
        {
          RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                    "Invalid ALPN protocol length: %zu", len);
        }

      char *copy = Arena_alloc (ctx->arena, len + 1, __FILE__, __LINE__);
      if (!copy)
        RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                  "Failed to allocate ALPN protocol string");
      memcpy (copy, protos[i], len + 1);
      ctx->alpn.protocols[i] = copy;
    }

  ctx->alpn.count = count;

  /* Set server callback */
  if (ctx->is_server)
    {
      SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
    }
  else
    {
      /* Client: build wire format */
      size_t wire_len = 0;
      for (size_t i = 0; i < count; i++)
        {
          wire_len += 1 + strlen (protos[i]);
        }

      unsigned char *wire
          = Arena_alloc (ctx->arena, wire_len, __FILE__, __LINE__);
      if (!wire)
        RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                  "Failed to allocate ALPN wire format");

      unsigned char *p = wire;
      for (size_t i = 0; i < count; i++)
        {
          size_t len = strlen (protos[i]);
          *p++ = (unsigned char)len;
          memcpy (p, protos[i], len);
          p += len;
        }

      if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len)
          != 0)
        ctx_raise_openssl_error_dtls ("Failed to set ALPN protocols");
    }
}

/* ============================================================================
 * Session Management
 * ============================================================================
 */

void
SocketDTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                        long timeout_seconds)
{
  assert (ctx);

  size_t cache_size
      = max_sessions > 0 ? max_sessions : SOCKET_DTLS_SESSION_CACHE_SIZE;
  long timeout = timeout_seconds > 0 ? timeout_seconds
                                     : SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT;

  if (ctx->is_server)
    {
      SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, SSL_SESS_CACHE_SERVER);
    }
  else
    {
      SSL_CTX_set_session_cache_mode (ctx->ssl_ctx, SSL_SESS_CACHE_CLIENT);
    }

  SSL_CTX_sess_set_cache_size (ctx->ssl_ctx, (long)cache_size);
  SSL_CTX_set_timeout (ctx->ssl_ctx, timeout);

  ctx->session_cache_enabled = 1;
  ctx->session_cache_size = cache_size;
}

void
SocketDTLSContext_get_cache_stats (T ctx, size_t *hits, size_t *misses,
                                   size_t *stores)
{
  if (!ctx)
    return;

  pthread_mutex_lock (&ctx->stats_mutex);

  if (hits)
    *hits = ctx->cache_hits;
  if (misses)
    *misses = ctx->cache_misses;
  if (stores)
    *stores = ctx->cache_stores;

  pthread_mutex_unlock (&ctx->stats_mutex);
}

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

void
SocketDTLSContext_set_timeout (T ctx, int initial_ms, int max_ms)
{
  assert (ctx);

  if (!SOCKET_DTLS_VALID_TIMEOUT (initial_ms))
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Invalid initial timeout: %d", initial_ms);
    }

  if (!SOCKET_DTLS_VALID_TIMEOUT (max_ms))
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed, "Invalid max timeout: %d",
                                max_ms);
    }

  ctx->initial_timeout_ms = initial_ms;
  ctx->max_timeout_ms = max_ms;
}

/* ============================================================================
 * Internal Access
 * ============================================================================
 */

void *
SocketDTLSContext_get_ssl_ctx (T ctx)
{
  return ctx ? ctx->ssl_ctx : NULL;
}

int
SocketDTLSContext_is_server (T ctx)
{
  return ctx ? ctx->is_server : 0;
}

/**
 * dtls_context_get_from_ssl - Get SocketDTLSContext from SSL object
 * @ssl: SSL object
 *
 * Returns: Context pointer or NULL
 */
SocketDTLSContext_T
dtls_context_get_from_ssl (const SSL *ssl)
{
  if (!ssl)
    return NULL;

  SSL_CTX *ssl_ctx = SSL_get_SSL_CTX (ssl);
  if (!ssl_ctx)
    return NULL;

  pthread_once (&dtls_exdata_once, init_exdata_index);
  if (dtls_context_exdata_idx < 0)
    return NULL;

  return SSL_CTX_get_ex_data (ssl_ctx, dtls_context_exdata_idx);
}

#undef T

#endif /* SOCKET_HAS_TLS */

