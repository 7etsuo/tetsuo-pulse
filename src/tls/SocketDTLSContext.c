/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

#if SOCKET_HAS_TLS

#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "tls/SocketDTLS-private.h"
#include "tls/SocketSSL-internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define T SocketDTLSContext_T

/* Module exceptions declared via macro below; general DTLS exceptions defined
 * in SocketDTLS.c */

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDTLSContext);

/* Thread-local error handling via centralized SocketUtil infrastructure
 * (socket_error_buf) */

/* Global ex_data index for storing context pointer in SSL_CTX */
static int dtls_context_exdata_idx = -1;
static pthread_once_t dtls_exdata_once = PTHREAD_ONCE_INIT;

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
 * raise_openssl_error - Format OpenSSL error and raise DTLS exception
 * @context: Context description for error message
 *
 * Uses dtls_format_openssl_error() from private header to format error,
 * then raises SocketDTLS_Failed exception with the formatted message.
 */
static void
raise_openssl_error (const char *context)
{
  dtls_format_openssl_error (context);
  RAISE_DTLS_CTX_ERROR (SocketDTLS_Failed);
}

/**
 * set_protocol_versions - Configure DTLS protocol versions
 * @ssl_ctx: OpenSSL context
 */
static void
set_protocol_versions (SSL_CTX *ssl_ctx)
{
  if (SSL_CTX_set_min_proto_version (ssl_ctx, SOCKET_DTLS_MIN_VERSION) != 1)
    raise_openssl_error ("Failed to set minimum DTLS version");

  if (SSL_CTX_set_max_proto_version (ssl_ctx, SOCKET_DTLS_MAX_VERSION) != 1)
    raise_openssl_error ("Failed to set maximum DTLS version");
}

/**
 * set_security_options - Configure SSL security options
 * @ssl_ctx: OpenSSL context
 */
static void
set_security_options (SSL_CTX *ssl_ctx)
{
  /* Disable session tickets by default */
  SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_TICKET);

  /* Set explicitly secure options */
  SSL_CTX_set_options (ssl_ctx,
                       SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_COMPRESSION
                           | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE
                           | SSL_OP_NO_RENEGOTIATION
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
                           | SSL_OP_PRIORITIZE_CHACHA
#endif
  );

  SSL_CTX_set_verify_depth (ssl_ctx, SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH);
}

/**
 * apply_dtls_defaults - Apply secure defaults to SSL_CTX
 * @ssl_ctx: OpenSSL context
 */
static void
apply_dtls_defaults (SSL_CTX *ssl_ctx)
{
  set_protocol_versions (ssl_ctx);

  if (SSL_CTX_set_cipher_list (ssl_ctx, SOCKET_DTLS_CIPHERSUITES) != 1)
    raise_openssl_error ("Failed to set DTLS cipher list");

  set_security_options (ssl_ctx);
}

/**
 * init_context_mutexes - Initialize context mutexes
 * @ctx: Context structure
 * @ssl_ctx: OpenSSL context (for cleanup on error)
 *
 * Raises exception on failure with cleanup.
 */
static void
init_context_mutexes (T ctx, SSL_CTX *ssl_ctx)
{
  if (pthread_mutex_init (&ctx->cookie.secret_mutex, NULL) != 0)
    {
      Arena_dispose (&ctx->arena);
      SSL_CTX_free (ssl_ctx);
      free (ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to initialize cookie mutex");
    }

  if (pthread_mutex_init (&ctx->stats_mutex, NULL) != 0)
    {
      pthread_mutex_destroy (&ctx->cookie.secret_mutex);
      Arena_dispose (&ctx->arena);
      SSL_CTX_free (ssl_ctx);
      free (ctx);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to initialize stats mutex");
    }
}

/**
 * store_context_in_ssl - Store context pointer in SSL_CTX ex_data
 * @ssl_ctx: OpenSSL context
 * @ctx: DTLS context to store
 */
static void
store_context_in_ssl (SSL_CTX *ssl_ctx, T ctx)
{
  pthread_once (&dtls_exdata_once, init_exdata_index);
  if (dtls_context_exdata_idx >= 0)
    {
      if (SSL_CTX_set_ex_data (ssl_ctx, dtls_context_exdata_idx, ctx) != 1)
        {
          SOCKET_LOG_WARN_MSG (
              "Failed to set SSL_CTX ex_data for DTLS context");
        }
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
  atomic_init (&ctx->refcount, 1);
  ctx->ssl_ctx = ssl_ctx;
  ctx->is_server = is_server;
  ctx->mtu = SOCKET_DTLS_DEFAULT_MTU;
  ctx->initial_timeout_ms = SOCKET_DTLS_INITIAL_TIMEOUT_MS;
  ctx->max_timeout_ms = SOCKET_DTLS_MAX_TIMEOUT_MS;
  ctx->cookie.cookie_enabled = 0;

  init_context_mutexes (ctx, ssl_ctx);
  store_context_in_ssl (ssl_ctx, ctx);

  return ctx;
}

T
SocketDTLSContext_new_server (const char *cert_file,
                              const char *key_file,
                              const char *ca_file)
{
  assert (cert_file);
  assert (key_file);

  /* Full path validation performed in SocketDTLSContext_load_certificate */

  /* Create DTLS server method context */
  const SSL_METHOD *method = DTLS_server_method ();
  if (!method)
    raise_openssl_error ("Failed to get DTLS server method");

  SSL_CTX *ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    raise_openssl_error ("Failed to create DTLS server context");

  apply_dtls_defaults (ssl_ctx);

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
    raise_openssl_error ("Failed to get DTLS client method");

  SSL_CTX *ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    raise_openssl_error ("Failed to create DTLS client context");

  apply_dtls_defaults (ssl_ctx);

  T ctx = alloc_context (ssl_ctx, 0);

  /* Load CA if provided */
  if (ca_file && ca_file[0])
    {
      TRY
      {
        SocketDTLSContext_load_ca (ctx, ca_file);
      }
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
SocketDTLSContext_ref (T ctx)
{
  if (!ctx)
    return;

  atomic_fetch_add (&ctx->refcount, 1);
}

/**
 * cleanup_cookie_secrets - Securely clear cookie secrets
 * @ctx: Context to clean
 */
static void
cleanup_cookie_secrets (T ctx)
{
  SocketCrypto_secure_clear (ctx->cookie.secret, sizeof (ctx->cookie.secret));
  SocketCrypto_secure_clear (ctx->cookie.prev_secret,
                             sizeof (ctx->cookie.prev_secret));
}

/**
 * cleanup_mutexes - Destroy context mutexes
 * @ctx: Context to clean
 */
static void
cleanup_mutexes (T ctx)
{
  pthread_mutex_destroy (&ctx->cookie.secret_mutex);
  pthread_mutex_destroy (&ctx->stats_mutex);
}

/**
 * cleanup_ssl_ctx - Free SSL_CTX with version-specific handling
 * @ctx: Context to clean
 */
static void
cleanup_ssl_ctx (T ctx)
{
  if (!ctx->ssl_ctx)
    return;

#if OPENSSL_VERSION_NUMBER < SOCKET_OPENSSL_VERSION_3_0
  SSL_CTX_flush_sessions (ctx->ssl_ctx, 0);
#endif
  SSL_CTX_free (ctx->ssl_ctx);
  ctx->ssl_ctx = NULL;
}

void
SocketDTLSContext_free (T *ctx_p)
{
  if (!ctx_p || !*ctx_p)
    return;

  T ctx = *ctx_p;
  *ctx_p = NULL;

  if (atomic_fetch_sub (&ctx->refcount, 1) != 1)
    return;

  cleanup_cookie_secrets (ctx);
  cleanup_mutexes (ctx);
  cleanup_ssl_ctx (ctx);

  if (ctx->arena)
    Arena_dispose (&ctx->arena);

  free (ctx);
}

/**
 * open_and_stat_file - Securely open file and retrieve stat info
 * @path: File path to open
 * @desc: Description for error messages
 * @st: Output stat structure
 *
 * Opens file with O_NOFOLLOW to reject symlinks, performs fstat.
 * Returns fd on success, raises exception on failure.
 */
static int
open_and_stat_file (const char *path, const char *desc, struct stat *st)
{
  int fd = open (path, O_RDONLY | O_NOFOLLOW);
  if (fd == -1)
    {
      int saved_errno = errno;
      DTLS_ERROR_FMT (
          "Cannot safely open %s '%s': %s", desc, path, strerror (saved_errno));
      RAISE_DTLS_CTX_ERROR (SocketDTLS_Failed);
    }

  if (fstat (fd, st) != 0)
    {
      int saved_errno = errno;
      close (fd);
      DTLS_ERROR_FMT (
          "fstat failed for %s '%s': %s", desc, path, strerror (saved_errno));
      RAISE_DTLS_CTX_ERROR (SocketDTLS_Failed);
    }

  return fd;
}

/**
 * dtls_read_file_contents - Securely read file contents into memory
 * @path: File path
 * @max_size: Maximum allowed file size
 * @desc: Description for error messages
 * @out_data: Output pointer to allocated buffer (caller must free)
 * @out_size: Output file size
 *
 * Opens file with O_NOFOLLOW, validates via fstat, reads contents into
 * memory buffer. Keeps file descriptor open throughout to prevent TOCTOU.
 * Returns allocated buffer that caller must free with OPENSSL_free.
 */
static void
dtls_read_file_contents (const char *path,
                         size_t max_size,
                         const char *desc,
                         unsigned char **out_data,
                         size_t *out_size)
{
  struct stat st;
  int fd = open_and_stat_file (path, desc, &st);
  volatile unsigned char *data = NULL;

  TRY
  {
    if (!S_ISREG (st.st_mode))
      {
        RAISE_DTLS_CTX_ERROR_FMT (
            SocketDTLS_Failed, "%s '%s' must be a regular file", desc, path);
      }

    size_t file_size = (size_t)st.st_size;
    if (file_size <= 0 || file_size > max_size)
      {
        RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                  "%s '%s' size invalid (max %zu bytes)",
                                  desc,
                                  path,
                                  max_size);
      }

    /* Allocate buffer for file contents using OpenSSL allocator */
    data = OPENSSL_malloc (file_size);
    if (!data)
      {
        RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                  "Failed to allocate memory for file");
      }

    /* Read entire file - no TOCTOU since fd is still open */
    size_t bytes_read = 0;
    while (bytes_read < file_size)
      {
        ssize_t ret = read (
            fd, (unsigned char *)data + bytes_read, file_size - bytes_read);
        if (ret <= 0)
          {
            if (ret == 0)
              {
                RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                          "Unexpected EOF reading %s '%s'",
                                          desc,
                                          path);
              }
            else if (errno != EINTR)
              {
                int saved_errno = errno;
                DTLS_ERROR_FMT ("Failed to read %s '%s': %s",
                                desc,
                                path,
                                strerror (saved_errno));
                RAISE_DTLS_CTX_ERROR (SocketDTLS_Failed);
              }
            /* EINTR: retry */
          }
        else
          {
            bytes_read += (size_t)ret;
          }
      }

    *out_data = (unsigned char *)data;
    *out_size = file_size;
    data = NULL; /* Transfer ownership to caller */
  }
  FINALLY
  {
    close (fd);
    if (data)
      OPENSSL_free ((void *)data);
  }
  END_TRY;
}

/**
 * load_cert_chain_from_bio - Load certificate chain from BIO into SSL_CTX
 * @ssl_ctx: OpenSSL context
 * @cert_bio: BIO containing PEM-encoded certificate(s)
 *
 * Loads primary certificate and any additional chain certificates from BIO.
 * Raises exception on failure.
 */
static void
load_cert_chain_from_bio (SSL_CTX *ssl_ctx, BIO *cert_bio)
{
  /* Load primary certificate */
  X509 *cert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
  if (!cert)
    raise_openssl_error ("Failed to parse certificate");

  if (SSL_CTX_use_certificate (ssl_ctx, cert) != 1)
    {
      X509_free (cert);
      raise_openssl_error ("Failed to load certificate");
    }
  X509_free (cert);

  /* Load additional chain certificates if present */
  X509 *ca_cert = NULL;
  while ((ca_cert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL)) != NULL)
    {
      if (SSL_CTX_add1_chain_cert (ssl_ctx, ca_cert) != 1)
        {
          X509_free (ca_cert);
          raise_openssl_error ("Failed to add chain certificate");
        }
      X509_free (ca_cert);
    }
  ERR_clear_error (); /* Clear expected end-of-file error */
}

/**
 * load_private_key_from_bio - Load private key from BIO into SSL_CTX
 * @ssl_ctx: OpenSSL context
 * @key_bio: BIO containing PEM-encoded private key
 *
 * Loads private key and verifies it matches the loaded certificate.
 * Raises exception on failure.
 */
static void
load_private_key_from_bio (SSL_CTX *ssl_ctx, BIO *key_bio)
{
  /* Load private key */
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey (key_bio, NULL, NULL, NULL);
  if (!pkey)
    raise_openssl_error ("Failed to parse private key");

  if (SSL_CTX_use_PrivateKey (ssl_ctx, pkey) != 1)
    {
      EVP_PKEY_free (pkey);
      raise_openssl_error ("Failed to load private key");
    }
  EVP_PKEY_free (pkey);

  /* Verify key matches certificate */
  if (SSL_CTX_check_private_key (ssl_ctx) != 1)
    raise_openssl_error ("Certificate and private key mismatch");
}

void
SocketDTLSContext_load_certificate (T ctx,
                                    const char *cert_file,
                                    const char *key_file)
{
  assert (ctx);
  assert (cert_file);
  assert (key_file);

  if (!dtls_validate_file_path (cert_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid certificate path");

  if (!dtls_validate_file_path (key_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid key path");

  /* Read cert and key files into memory to prevent TOCTOU */
  /* volatile required: modified in TRY, accessed in FINALLY (longjmp safety) */
  unsigned char *volatile cert_data = NULL;
  unsigned char *volatile key_data = NULL;
  volatile size_t cert_size = 0;
  volatile size_t key_size = 0;
  BIO *volatile cert_bio = NULL;
  BIO *volatile key_bio = NULL;

  TRY
  {
    /* Read certificate file contents */
    dtls_read_file_contents (cert_file,
                             SOCKET_DTLS_MAX_FILE_SIZE,
                             "certificate file",
                             (unsigned char **)&cert_data,
                             (size_t *)&cert_size);

    /* Read private key file contents */
    dtls_read_file_contents (key_file,
                             SOCKET_DTLS_MAX_FILE_SIZE,
                             "private key file",
                             (unsigned char **)&key_data,
                             (size_t *)&key_size);

    /* Create BIO from certificate data */
    cert_bio = BIO_new_mem_buf ((void *)cert_data, (int)cert_size);
    if (!cert_bio)
      raise_openssl_error ("Failed to create BIO for certificate");

    /* Load certificate chain */
    load_cert_chain_from_bio (ctx->ssl_ctx, (BIO *)cert_bio);

    /* Create BIO from key data */
    key_bio = BIO_new_mem_buf ((void *)key_data, (int)key_size);
    if (!key_bio)
      raise_openssl_error ("Failed to create BIO for private key");

    /* Load private key and verify */
    load_private_key_from_bio (ctx->ssl_ctx, (BIO *)key_bio);
  }
  FINALLY
  {
    /* Securely clear and free certificate data */
    if (cert_data)
      {
        SocketCrypto_secure_clear ((void *)cert_data, cert_size);
        OPENSSL_free ((void *)cert_data);
      }

    /* Securely clear and free key data */
    if (key_data)
      {
        SocketCrypto_secure_clear ((void *)key_data, key_size);
        OPENSSL_free ((void *)key_data);
      }

    /* Free BIOs */
    if (cert_bio)
      BIO_free ((BIO *)cert_bio);
    if (key_bio)
      BIO_free ((BIO *)key_bio);
  }
  END_TRY;
}

/**
 * validate_ca_type - Validate CA file/directory type and size
 * @ca_file: Path to validate
 * @st: Stat structure
 * @fd: File descriptor to close on error
 */
static void
validate_ca_type (const char *ca_file, const struct stat *st, int fd)
{
  if (!S_ISREG (st->st_mode) && !S_ISDIR (st->st_mode))
    {
      close (fd);
      RAISE_DTLS_CTX_ERROR_FMT (
          SocketDTLS_Failed,
          "CA path '%s' must be a regular file or directory",
          ca_file);
    }
}

/**
 * validate_ca_file_size - Validate CA file size
 * @ca_file: Path for error messages
 * @st: Stat structure
 * @fd: File descriptor to close on error
 */
static void
validate_ca_file_size (const char *ca_file, const struct stat *st, int fd)
{
  if (!S_ISREG (st->st_mode))
    return;

  size_t file_size = (size_t)st->st_size;
  if (file_size <= 0 || file_size > SOCKET_DTLS_MAX_FILE_SIZE)
    {
      close (fd);
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "CA file '%s' too large (max %zu bytes)",
                                ca_file,
                                SOCKET_DTLS_MAX_FILE_SIZE);
    }
}

/**
 * load_ca_certificates - Load CA certificates into SSL_CTX
 * @ssl_ctx: OpenSSL context
 * @ca_file: Path to CA file or directory
 * @st: Stat structure determining file/dir
 */
static void
load_ca_certificates (SSL_CTX *ssl_ctx,
                      const char *ca_file,
                      const struct stat *st)
{
  int result = S_ISDIR (st->st_mode)
                   ? SSL_CTX_load_verify_locations (ssl_ctx, NULL, ca_file)
                   : SSL_CTX_load_verify_locations (ssl_ctx, ca_file, NULL);

  if (result != 1)
    raise_openssl_error ("Failed to load CA certificates");
}

void
SocketDTLSContext_load_ca (T ctx, const char *ca_file)
{
  assert (ctx);
  assert (ca_file);

  if (!dtls_validate_file_path (ca_file))
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed, "Invalid CA path");

  struct stat st;
  int fd = open_and_stat_file (ca_file, "CA path", &st);

  validate_ca_type (ca_file, &st, fd);
  validate_ca_file_size (ca_file, &st, fd);

  close (fd);

  load_ca_certificates (ctx->ssl_ctx, ca_file, &st);
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

void
SocketDTLSContext_enable_cookie_exchange (T ctx)
{
  assert (ctx);

  if (!ctx->is_server)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Cookie exchange only for server contexts");
    }

  /* Generate random secret using SocketCrypto */
  if (SocketCrypto_random_bytes (ctx->cookie.secret,
                                 SOCKET_DTLS_COOKIE_SECRET_LEN)
      != 0)
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to generate cookie secret");

  /* Clear previous secret using SocketCrypto */
  SocketCrypto_secure_clear (ctx->cookie.prev_secret,
                             sizeof (ctx->cookie.prev_secret));

  /* Set OpenSSL cookie callbacks */
  SSL_CTX_set_cookie_generate_cb (ctx->ssl_ctx, dtls_cookie_generate_cb);
  SSL_CTX_set_cookie_verify_cb (ctx->ssl_ctx, dtls_cookie_verify_cb);

  ctx->cookie.cookie_enabled = 1;
}

void
SocketDTLSContext_set_cookie_secret (T ctx,
                                     const unsigned char *secret,
                                     size_t len)
{
  assert (ctx);

  if (!secret)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Cookie secret cannot be NULL");
    }

  if (len != SOCKET_DTLS_COOKIE_SECRET_LEN)
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Cookie secret must be %d bytes (got %zu)",
                                SOCKET_DTLS_COOKIE_SECRET_LEN,
                                len);
    }

  if (!ctx->is_server)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Cookie secret only for server contexts");
    }

  /* Reject all-zeros secret to prevent weak DoS protection */
  static const unsigned char zeros[SOCKET_DTLS_COOKIE_SECRET_LEN] = { 0 };
  if (SocketCrypto_secure_compare (secret, zeros, SOCKET_DTLS_COOKIE_SECRET_LEN)
      == 0)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Cookie secret cannot be all zeros");
    }

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to acquire mutex for cookie secret");
    }

  memcpy (ctx->cookie.secret, secret, len);
  pthread_mutex_unlock (&ctx->cookie.secret_mutex);

  /* Set OpenSSL cookie callbacks and enable cookie exchange */
  SSL_CTX_set_cookie_generate_cb (ctx->ssl_ctx, dtls_cookie_generate_cb);
  SSL_CTX_set_cookie_verify_cb (ctx->ssl_ctx, dtls_cookie_verify_cb);
  ctx->cookie.cookie_enabled = 1;
}

/**
 * rotate_secret_values - Rotate cookie secrets
 * @ctx: Context to rotate
 *
 * Moves current secret to previous, generates new secret.
 * Must be called with secret_mutex held.
 */
static void
rotate_secret_values (T ctx)
{
  memcpy (ctx->cookie.prev_secret,
          ctx->cookie.secret,
          SOCKET_DTLS_COOKIE_SECRET_LEN);

  if (SocketCrypto_random_bytes (ctx->cookie.secret,
                                 SOCKET_DTLS_COOKIE_SECRET_LEN)
      != 0)
    {
      SocketCrypto_secure_clear (ctx->cookie.prev_secret,
                                 sizeof (ctx->cookie.prev_secret));
      pthread_mutex_unlock (&ctx->cookie.secret_mutex);
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to generate new cookie secret");
    }
}

void
SocketDTLSContext_rotate_cookie_secret (T ctx)
{
  assert (ctx);

  if (pthread_mutex_lock (&ctx->cookie.secret_mutex) != 0)
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Failed to acquire mutex for secret rotation");
    }

  rotate_secret_values (ctx);

  pthread_mutex_unlock (&ctx->cookie.secret_mutex);
}

int
SocketDTLSContext_has_cookie_exchange (T ctx)
{
  return ctx ? ctx->cookie.cookie_enabled : 0;
}

void
SocketDTLSContext_set_mtu (T ctx, size_t mtu)
{
  assert (ctx);

  if (!SOCKET_DTLS_VALID_MTU (mtu))
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Invalid MTU: %zu (must be %d-%d)",
                                mtu,
                                SOCKET_DTLS_MIN_MTU,
                                SOCKET_DTLS_MAX_MTU);
    }

  ctx->mtu = mtu;
}

size_t
SocketDTLSContext_get_mtu (T ctx)
{
  return ctx ? ctx->mtu : SOCKET_DTLS_DEFAULT_MTU;
}

void
SocketDTLSContext_set_min_protocol (T ctx, int version)
{
  assert (ctx);

  if (SSL_CTX_set_min_proto_version (ctx->ssl_ctx, version) != 1)
    raise_openssl_error ("Failed to set minimum DTLS version");
}

void
SocketDTLSContext_set_max_protocol (T ctx, int version)
{
  assert (ctx);

  if (SSL_CTX_set_max_proto_version (ctx->ssl_ctx, version) != 1)
    raise_openssl_error ("Failed to set maximum DTLS version");
}

void
SocketDTLSContext_set_cipher_list (T ctx, const char *ciphers)
{
  assert (ctx);

  const char *cipher_list = ciphers ? ciphers : SOCKET_DTLS_CIPHERSUITES;

  if (SSL_CTX_set_cipher_list (ctx->ssl_ctx, cipher_list) != 1)
    raise_openssl_error ("Failed to set DTLS cipher list");
}

/**
 * alpn_match_protocol - Check if client protocol matches any configured
 * protocol
 * @ctx: DTLS context with ALPN configuration
 * @client_proto: Client protocol string
 * @client_len: Length of client protocol string
 * @out: Output pointer for matched protocol
 * @outlen: Output length of matched protocol
 *
 * Searches configured ALPN protocols for a match with the client-provided
 * protocol. Uses precomputed lengths for O(1) comparison.
 *
 * @return 1 if match found (with out/outlen populated), 0 otherwise
 */
static int
alpn_match_protocol (T ctx,
                     const unsigned char *client_proto,
                     unsigned int client_len,
                     const unsigned char **out,
                     unsigned char *outlen)
{
  for (size_t i = 0; i < ctx->alpn.count; i++)
    {
      const char *our_proto = ctx->alpn.protocols[i];
      size_t our_len = ctx->alpn.lens[i];

      if (our_len == client_len
          && memcmp (our_proto, client_proto, our_len) == 0)
        {
          *out = client_proto;
          *outlen = (unsigned char)client_len;
          return 1; /* Match found */
        }
    }
  return 0; /* No match */
}

/**
 * alpn_select_cb - ALPN selection callback for server
 */
static int
alpn_select_cb (SSL *ssl,
                const unsigned char **out,
                unsigned char *outlen,
                const unsigned char *in,
                unsigned int inlen,
                void *arg)
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

      /* Skip malformed protocol entries with excessive length */
      if (client_len > SOCKET_DTLS_MAX_ALPN_LEN || client_len > 255)
        {
          client_proto += client_len;
          continue;
        }

      if (alpn_match_protocol (ctx, client_proto, client_len, out, outlen))
        return SSL_TLSEXT_ERR_OK;

      client_proto += client_len;
    }

  return SSL_TLSEXT_ERR_NOACK;
}

/**
 * alpn_validate_and_measure_protos - Validate protocols and compute wire length
 * @protos: Array of protocol strings
 * @count: Number of protocols
 * @lens: Output array for protocol lengths (must be pre-allocated)
 * @wire_len_out: Output for total wire format length
 *
 * Validates each protocol length (non-zero, <= max) and computes the total
 * wire format length needed for client ALPN. Raises exception on invalid input.
 */
static void
alpn_validate_and_measure_protos (const char **protos,
                                  size_t count,
                                  size_t *lens,
                                  size_t *wire_len_out)
{
  size_t wire_len = 0;

  for (size_t i = 0; i < count; ++i)
    {
      size_t len = strlen (protos[i]);
      if (len == 0 || len > SOCKET_DTLS_MAX_ALPN_LEN)
        {
          RAISE_DTLS_CTX_ERROR_FMT (
              SocketDTLS_Failed, "Invalid ALPN protocol length: %zu", len);
        }
      lens[i] = len;

      /* Security check for string allocation size */
      size_t ts;
      if (!SocketSecurity_check_add (len, 1, &ts)
          || !SocketSecurity_check_size (ts))
        {
          RAISE_DTLS_CTX_ERROR_MSG (
              SocketDTLS_Failed,
              "ALPN protocol string too long for allocation");
        }

      /* Compute wire_len for client case */
      size_t new_wl;
      if (!SocketSecurity_check_add (wire_len, 1 + len, &new_wl)
          || !SocketSecurity_check_size (new_wl))
        {
          RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                    "ALPN wire format too large");
        }
      wire_len = new_wl;
    }

  *wire_len_out = wire_len;
}

/**
 * alpn_copy_protocol_strings - Copy protocol strings to arena
 * @arena: Memory arena for allocations
 * @protos: Source protocol strings
 * @count: Number of protocols
 * @lens: Pre-computed lengths for each protocol
 * @out_protocols: Output array for copied strings (must be pre-allocated)
 *
 * Allocates and copies each protocol string to the arena.
 * Raises exception on allocation failure.
 */
static void
alpn_copy_protocol_strings (Arena_T arena,
                            const char **protos,
                            size_t count,
                            const size_t *lens,
                            const char **out_protocols)
{
  for (size_t i = 0; i < count; ++i)
    {
      size_t len = lens[i];
      size_t total_size = len + 1;
      char *copy = Arena_alloc (arena, total_size, __FILE__, __LINE__);
      if (!copy)
        RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                  "Failed to allocate ALPN protocol string");
      memcpy (copy, protos[i], total_size);
      out_protocols[i] = copy;
    }
}

/**
 * alpn_build_wire_format - Build ALPN wire format for client
 * @arena: Memory arena for allocation
 * @protos: Protocol strings
 * @count: Number of protocols
 * @lens: Pre-computed lengths for each protocol
 * @wire_len: Total wire format length
 *
 * Builds the wire format buffer (length-prefixed strings) for
 * SSL_CTX_set_alpn_protos.
 *
 * @return Allocated wire format buffer, raises on failure
 */
static unsigned char *
alpn_build_wire_format (Arena_T arena,
                        const char **protos,
                        size_t count,
                        const size_t *lens,
                        size_t wire_len)
{
  unsigned char *wire = Arena_alloc (arena, wire_len, __FILE__, __LINE__);
  if (!wire)
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to allocate ALPN wire format");

  unsigned char *p = wire;
  for (size_t i = 0; i < count; ++i)
    {
      size_t len = lens[i];
      *p++ = (unsigned char)len;
      memcpy (p, protos[i], len);
      p += len;
    }

  return wire;
}

void
SocketDTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count)
{
  assert (ctx);

  /* Reset ALPN state */
  ctx->alpn.protocols = NULL;
  ctx->alpn.lens = NULL;
  ctx->alpn.count = 0;

  if (!protos || count == 0)
    return;

  /* Validate count */
  if (count > SOCKET_DTLS_MAX_ALPN_PROTOCOLS)
    {
      RAISE_DTLS_CTX_ERROR_FMT (SocketDTLS_Failed,
                                "Too many ALPN protocols: %zu (max %d)",
                                count,
                                SOCKET_DTLS_MAX_ALPN_PROTOCOLS);
    }

  /* Allocate lens array */
  ctx->alpn.lens
      = Arena_alloc (ctx->arena, count * sizeof (size_t), __FILE__, __LINE__);
  if (!ctx->alpn.lens)
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to allocate ALPN lens array");

  /* Validate protocols and compute wire length */
  size_t wire_len = 0;
  alpn_validate_and_measure_protos (protos, count, ctx->alpn.lens, &wire_len);

  /* Allocate protocols array */
  ctx->alpn.protocols
      = Arena_alloc (ctx->arena, count * sizeof (char *), __FILE__, __LINE__);
  if (!ctx->alpn.protocols)
    RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                              "Failed to allocate ALPN protocol array");

  /* Copy protocol strings */
  alpn_copy_protocol_strings (
      ctx->arena, protos, count, ctx->alpn.lens, ctx->alpn.protocols);

  ctx->alpn.count = count;

  /* Server: set selection callback */
  if (ctx->is_server)
    {
      SSL_CTX_set_alpn_select_cb (ctx->ssl_ctx, alpn_select_cb, ctx);
      return;
    }

  /* Client: build and set wire format */
  if (wire_len == 0)
    return;

  unsigned char *wire = alpn_build_wire_format (
      ctx->arena, protos, count, ctx->alpn.lens, wire_len);

  if (SSL_CTX_set_alpn_protos (ctx->ssl_ctx, wire, (unsigned int)wire_len) != 0)
    raise_openssl_error ("Failed to set ALPN protocols");
}

void
SocketDTLSContext_enable_session_cache (T ctx,
                                        size_t max_sessions,
                                        long timeout_seconds)
{
  assert (ctx);

  size_t cache_size
      = max_sessions > 0 ? max_sessions : SOCKET_DTLS_SESSION_CACHE_SIZE;
  if (!SocketSecurity_check_size (cache_size))
    {
      RAISE_DTLS_CTX_ERROR_MSG (SocketDTLS_Failed,
                                "Session cache size exceeds security limit");
    }
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
SocketDTLSContext_get_cache_stats (T ctx,
                                   size_t *hits,
                                   size_t *misses,
                                   size_t *stores)
{
  if (!ctx)
    return;

  if (pthread_mutex_lock (&ctx->stats_mutex) != 0)
    return;


  if (hits)
    *hits = ctx->cache_hits;
  if (misses)
    *misses = ctx->cache_misses;
  if (stores)
    *stores = ctx->cache_stores;

  pthread_mutex_unlock (&ctx->stats_mutex);
}

void
SocketDTLSContext_set_timeout (T ctx, int initial_ms, int max_ms)
{
  assert (ctx);

  if (!SOCKET_DTLS_VALID_TIMEOUT (initial_ms))
    {
      RAISE_DTLS_CTX_ERROR_FMT (
          SocketDTLS_Failed, "Invalid initial timeout: %d", initial_ms);
    }

  if (!SOCKET_DTLS_VALID_TIMEOUT (max_ms))
    {
      RAISE_DTLS_CTX_ERROR_FMT (
          SocketDTLS_Failed, "Invalid max timeout: %d", max_ms);
    }

  ctx->initial_timeout_ms = initial_ms;
  ctx->max_timeout_ms = max_ms;
}

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
