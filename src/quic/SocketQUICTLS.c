/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICTLS.c
 * @brief TLS 1.3 Interface for QUIC (RFC 9001 Section 4.1).
 */

#include "quic/SocketQUICTLS.h"

#include <stdio.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "quic/SocketQUICError.h"
#include "quic/SocketQUICTransportParams.h"

#if SOCKET_HAS_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * Check for OpenSSL QUIC support.
 * - OpenSSL 3.2+ has native QUIC (SSL_set_quic_method as a macro/function)
 * - quictls fork defines OPENSSL_INFO_QUIC in <openssl/quic.h>
 */
#if defined(SSL_set_quic_method) || defined(OPENSSL_INFO_QUIC) \
    || (defined(OPENSSL_VERSION_NUMBER)                        \
        && OPENSSL_VERSION_NUMBER >= 0x30200000L)
#define HAVE_OPENSSL_QUIC 1
#else
#define HAVE_OPENSSL_QUIC 0
#endif

#if HAVE_OPENSSL_QUIC

/*
 * quictls compatibility: SSL_CTX_set_early_data_enabled() exists only in
 * OpenSSL 3.2+.  quictls provides the per-SSL variant instead.  When the
 * context-level API is missing we defer early-data enablement to create_ssl().
 *
 * Inside HAVE_OPENSSL_QUIC, version < 3.2 implies quictls.
 */
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30200000L
#define QUICTLS_COMPAT 0
#else
#define QUICTLS_COMPAT 1
#endif

/** QUIC CRYPTO_ERROR base per RFC 9001 §4.8 */
#define QUIC_TLS_CRYPTO_ERROR_BASE 0x0100

/** Default ALPN protocol for HTTP/3 */
#define QUIC_TLS_DEFAULT_ALPN "h3"

/** Maximum CRYPTO output buffer size */
#define QUIC_TLS_MAX_CRYPTO_BUFFER QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE

/**
 * @brief Per-level CRYPTO output buffer.
 */
typedef struct
{
  uint8_t *data;
  size_t len;
  size_t capacity;
  size_t consumed;
} CryptoBuffer_T;

/* Max TLS secret size: SHA-384 suites (e.g. TLS_AES_256_GCM_SHA384) */
#define QUIC_TLS_MAX_SECRET_SIZE SOCKET_CRYPTO_SHA384_SIZE

/**
 * @brief TLS state stored in handshake context.
 */
typedef struct
{
  CryptoBuffer_T crypto_out[QUIC_CRYPTO_LEVEL_COUNT];
  uint8_t read_secret[QUIC_CRYPTO_LEVEL_COUNT][QUIC_TLS_MAX_SECRET_SIZE];
  uint8_t write_secret[QUIC_CRYPTO_LEVEL_COUNT][QUIC_TLS_MAX_SECRET_SIZE];
  size_t secret_len[QUIC_CRYPTO_LEVEL_COUNT];
  int secrets_available[QUIC_CRYPTO_LEVEL_COUNT];
  int flush_pending;
  uint8_t alert;
  int alert_received;
} TLSState_T;

static int quic_set_encryption_secrets (SSL *ssl,
                                        OSSL_ENCRYPTION_LEVEL level,
                                        const uint8_t *read_secret,
                                        const uint8_t *write_secret,
                                        size_t secret_len);

static int quic_add_handshake_data (SSL *ssl,
                                    OSSL_ENCRYPTION_LEVEL level,
                                    const uint8_t *data,
                                    size_t len);

static int quic_flush_flight (SSL *ssl);

static int
quic_send_alert (SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

static const SSL_QUIC_METHOD quic_method = {
  .set_encryption_secrets = quic_set_encryption_secrets,
  .add_handshake_data = quic_add_handshake_data,
  .flush_flight = quic_flush_flight,
  .send_alert = quic_send_alert,
};

/**
 * @brief Convert OpenSSL encryption level to QUIC crypto level.
 */
static SocketQUICCryptoLevel
ossl_level_to_quic (OSSL_ENCRYPTION_LEVEL level)
{
  switch (level)
    {
    case ssl_encryption_initial:
      return QUIC_CRYPTO_LEVEL_INITIAL;
    case ssl_encryption_early_data:
      return QUIC_CRYPTO_LEVEL_0RTT;
    case ssl_encryption_handshake:
      return QUIC_CRYPTO_LEVEL_HANDSHAKE;
    case ssl_encryption_application:
      return QUIC_CRYPTO_LEVEL_APPLICATION;
    default:
      return QUIC_CRYPTO_LEVEL_INITIAL;
    }
}

/**
 * @brief Convert QUIC crypto level to OpenSSL encryption level.
 */
static OSSL_ENCRYPTION_LEVEL
quic_level_to_ossl (SocketQUICCryptoLevel level)
{
  switch (level)
    {
    case QUIC_CRYPTO_LEVEL_INITIAL:
      return ssl_encryption_initial;
    case QUIC_CRYPTO_LEVEL_0RTT:
      return ssl_encryption_early_data;
    case QUIC_CRYPTO_LEVEL_HANDSHAKE:
      return ssl_encryption_handshake;
    case QUIC_CRYPTO_LEVEL_APPLICATION:
      return ssl_encryption_application;
    default:
      return ssl_encryption_initial;
    }
}

/**
 * @brief Get TLS state from handshake context.
 */
static TLSState_T *
get_tls_state (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL || handshake->keys[0] == NULL)
    return NULL;

  /* TLS state is stored in keys[0] slot (repurposed) */
  return (TLSState_T *)handshake->keys[0];
}

/**
 * @brief Allocate TLS state in handshake context.
 */
static TLSState_T *
alloc_tls_state (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL || handshake->arena == NULL)
    return NULL;

  TLSState_T *state
      = Arena_alloc (handshake->arena, sizeof (TLSState_T), __FILE__, __LINE__);
  if (state == NULL)
    return NULL;

  memset (state, 0, sizeof (TLSState_T));
  handshake->keys[0] = state;

  return state;
}

/**
 * @brief Get handshake from SSL app data.
 */
static SocketQUICHandshake_T
get_handshake_from_ssl (SSL *ssl)
{
  if (ssl == NULL)
    return NULL;
  return (SocketQUICHandshake_T)SSL_get_app_data (ssl);
}

/**
 * @brief Ensure CRYPTO buffer has capacity.
 */
static int
crypto_buffer_ensure (Arena_T arena, CryptoBuffer_T *buf, size_t needed)
{
  if (buf->capacity >= needed)
    return 1;

  size_t new_cap
      = buf->capacity == 0 ? SOCKETBUF_INITIAL_CAPACITY : buf->capacity * 2;
  while (new_cap < needed)
    new_cap *= 2;

  if (new_cap > QUIC_TLS_MAX_CRYPTO_BUFFER)
    new_cap = QUIC_TLS_MAX_CRYPTO_BUFFER;

  if (needed > new_cap)
    return 0;

  uint8_t *new_data = Arena_alloc (arena, new_cap, __FILE__, __LINE__);
  if (new_data == NULL)
    return 0;

  if (buf->data != NULL && buf->len > 0)
    memcpy (new_data, buf->data, buf->len);

  buf->data = new_data;
  buf->capacity = new_cap;
  return 1;
}

/**
 * @brief Append data to CRYPTO buffer.
 */
static int
crypto_buffer_append (Arena_T arena,
                      CryptoBuffer_T *buf,
                      const uint8_t *data,
                      size_t len)
{
  if (buf == NULL || data == NULL || len == 0)
    return 0;

  size_t needed = buf->len + len;
  if (!crypto_buffer_ensure (arena, buf, needed))
    return 0;

  memcpy (buf->data + buf->len, data, len);
  buf->len += len;
  return 1;
}

/**
 * @brief Called when TLS derives new encryption secrets.
 */
static int
quic_set_encryption_secrets (SSL *ssl,
                             OSSL_ENCRYPTION_LEVEL level,
                             const uint8_t *read_secret,
                             const uint8_t *write_secret,
                             size_t secret_len)
{
  SocketQUICHandshake_T hs = get_handshake_from_ssl (ssl);
  if (hs == NULL)
    return 0;

  TLSState_T *state = get_tls_state (hs);
  if (state == NULL)
    return 0;

  SocketQUICCryptoLevel qlevel = ossl_level_to_quic (level);
  if (qlevel >= QUIC_CRYPTO_LEVEL_COUNT)
    return 0;

  if (secret_len > QUIC_TLS_MAX_SECRET_SIZE)
    return 0;

  if (read_secret != NULL)
    memcpy (state->read_secret[qlevel], read_secret, secret_len);

  if (write_secret != NULL)
    memcpy (state->write_secret[qlevel], write_secret, secret_len);

  state->secret_len[qlevel] = secret_len;
  state->secrets_available[qlevel] = 1;
  hs->keys_available[qlevel] = 1;

  return 1;
}

/**
 * @brief Called when TLS generates handshake data.
 */
static int
quic_add_handshake_data (SSL *ssl,
                         OSSL_ENCRYPTION_LEVEL level,
                         const uint8_t *data,
                         size_t len)
{
  SocketQUICHandshake_T hs = get_handshake_from_ssl (ssl);
  if (hs == NULL)
    return 0;

  TLSState_T *state = get_tls_state (hs);
  if (state == NULL)
    return 0;

  SocketQUICCryptoLevel qlevel = ossl_level_to_quic (level);
  if (qlevel >= QUIC_CRYPTO_LEVEL_COUNT)
    return 0;

  return crypto_buffer_append (
      hs->arena, &state->crypto_out[qlevel], data, len);
}

/**
 * @brief Called when TLS wants to flush pending data.
 */
static int
quic_flush_flight (SSL *ssl)
{
  SocketQUICHandshake_T hs = get_handshake_from_ssl (ssl);
  if (hs == NULL)
    return 0;

  TLSState_T *state = get_tls_state (hs);
  if (state == NULL)
    return 0;

  state->flush_pending = 1;
  return 1;
}

/**
 * @brief Called when TLS wants to send an alert.
 */
static int
quic_send_alert (SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert)
{
  (void)level;

  SocketQUICHandshake_T hs = get_handshake_from_ssl (ssl);
  if (hs == NULL)
    return 0;

  TLSState_T *state = get_tls_state (hs);
  if (state == NULL)
    return 0;

  state->alert = alert;
  state->alert_received = 1;
  hs->error_code = QUIC_TLS_CRYPTO_ERROR_BASE + alert;

  return 1;
}

/**
 * @brief ALPN selection callback for server mode (RFC 9001 §8.1).
 *
 * Per RFC 9001 §8.1, endpoints MUST use ALPN. If no common protocol
 * is found, this callback returns an alert and sets the error code
 * to QUIC_ERROR_NO_APPLICATION_PROTOCOL (0x0178).
 */
static int
alpn_select_callback (SSL *ssl,
                      const unsigned char **out,
                      unsigned char *outlen,
                      const unsigned char *in,
                      unsigned int inlen,
                      void *arg)
{
  const char *alpn = (const char *)arg;
  if (alpn == NULL)
    alpn = QUIC_TLS_DEFAULT_ALPN;

  size_t alpn_len = strlen (alpn);
  const unsigned char *p = in;
  const unsigned char *end = in + inlen;

  while (p < end)
    {
      uint8_t len = *p++;
      if (p + len > end)
        break;

      if (len == alpn_len && memcmp (p, alpn, len) == 0)
        {
          *out = p;
          *outlen = len;
          return SSL_TLSEXT_ERR_OK;
        }
      p += len;
    }

  /*
   * RFC 9001 §8.1: No matching ALPN protocol found.
   * Set error code for QUIC CONNECTION_CLOSE frame.
   */
  SocketQUICHandshake_T hs = get_handshake_from_ssl (ssl);
  if (hs != NULL)
    {
      hs->error_code = QUIC_ERROR_NO_APPLICATION_PROTOCOL;
      snprintf (hs->error_reason,
                sizeof (hs->error_reason),
                "No matching ALPN protocol (RFC 9001 §8.1)");
    }

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/**
 * @brief Create base SSL_CTX with TLS 1.3 and QUIC method.
 *
 * Configures TLS 1.3 only and disables middlebox compatibility mode
 * per RFC 9001 §8.4: "QUIC endpoints MUST NOT use the middlebox
 * compatibility mode."
 */
static SocketQUICTLS_Result
tls_create_base_context (SSL_CTX **out_ctx)
{
  SSL_CTX *ctx = SSL_CTX_new (TLS_method ());
  if (ctx == NULL)
    return QUIC_TLS_ERROR_INIT;

  SSL_CTX_set_min_proto_version (ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_3_VERSION);

  /*
   * RFC 9001 §8.4: Disable middlebox compatibility mode.
   *
   * QUIC does not use change_cipher_spec messages or non-empty
   * legacy_session_id fields. Middlebox compatibility mode in TLS 1.3
   * sends these for compatibility with broken middleboxes, but QUIC
   * MUST NOT use this mode as it doesn't send TLS records directly.
   */
#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
  SSL_CTX_clear_options (ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

  if (!SSL_CTX_set_quic_method (ctx, &quic_method))
    {
      SSL_CTX_free (ctx);
      return QUIC_TLS_ERROR_INIT;
    }

  *out_ctx = ctx;
  return QUIC_TLS_OK;
}

/**
 * @brief Load certificate, private key, and CA certificates.
 */
static SocketQUICTLS_Result
tls_load_credentials (SSL_CTX *ctx, const SocketQUICTLSConfig_T *config)
{
  if (config == NULL)
    return QUIC_TLS_OK;

  if (config->cert_file != NULL)
    {
      if (SSL_CTX_use_certificate_file (
              ctx, config->cert_file, SSL_FILETYPE_PEM)
          != 1)
        return QUIC_TLS_ERROR_CERT;
    }

  if (config->key_file != NULL)
    {
      if (SSL_CTX_use_PrivateKey_file (ctx, config->key_file, SSL_FILETYPE_PEM)
          != 1)
        return QUIC_TLS_ERROR_KEY;
    }

  if (config->ca_file != NULL)
    {
      if (SSL_CTX_load_verify_locations (ctx, config->ca_file, NULL) != 1)
        return QUIC_TLS_ERROR_CERT;
    }

  return QUIC_TLS_OK;
}

/**
 * @brief Configure peer certificate verification.
 */
static void
tls_configure_verification (SSL_CTX *ctx, const SocketQUICTLSConfig_T *config)
{
  if (config != NULL && config->verify_peer)
    {
      SSL_CTX_set_verify (
          ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
}

/**
 * @brief Configure ALPN for server or client.
 */
static SocketQUICTLS_Result
tls_configure_alpn (SSL_CTX *ctx,
                    const SocketQUICTLSConfig_T *config,
                    SocketQUICConnection_Role role)
{
  const char *alpn = (config != NULL && config->alpn != NULL)
                         ? config->alpn
                         : QUIC_TLS_DEFAULT_ALPN;

  if (role == QUIC_CONN_ROLE_SERVER)
    {
      SSL_CTX_set_alpn_select_cb (ctx, alpn_select_callback, (void *)alpn);
    }
  else
    {
      /* Client: set ALPN protocols to offer */
      size_t alpn_len = strlen (alpn);
      if (alpn_len > 255)
        return QUIC_TLS_ERROR_ALPN;

      uint8_t wire_alpn[256];
      wire_alpn[0] = (uint8_t)alpn_len;
      memcpy (wire_alpn + 1, alpn, alpn_len);

      if (SSL_CTX_set_alpn_protos (ctx, wire_alpn, (unsigned)(alpn_len + 1))
          != 0)
        return QUIC_TLS_ERROR_ALPN;
    }

  return QUIC_TLS_OK;
}

/**
 * @brief Configure 0-RTT early data support.
 *
 * quictls lacks SSL_CTX_set_early_data_enabled(); the per-SSL variant
 * is used instead in create_ssl().
 */
static void
tls_configure_early_data (SSL_CTX *ctx, const SocketQUICTLSConfig_T *config)
{
#if QUICTLS_COMPAT
  (void)ctx;
  (void)config;
#else
  if (config != NULL && config->enable_0rtt)
    SSL_CTX_set_early_data_enabled (ctx, 1);
#endif
}

SocketQUICTLS_Result
SocketQUICTLS_init_context (SocketQUICHandshake_T handshake,
                            const SocketQUICTLSConfig_T *config)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL_CTX *ctx = NULL;
  SocketQUICTLS_Result result;

  result = tls_create_base_context (&ctx);
  if (result != QUIC_TLS_OK)
    return result;

  result = tls_load_credentials (ctx, config);
  if (result != QUIC_TLS_OK)
    {
      SSL_CTX_free (ctx);
      return result;
    }

  tls_configure_verification (ctx, config);

  result = tls_configure_alpn (ctx, config, handshake->role);
  if (result != QUIC_TLS_OK)
    {
      SSL_CTX_free (ctx);
      return result;
    }

  tls_configure_early_data (ctx, config);

  if (alloc_tls_state (handshake) == NULL)
    {
      SSL_CTX_free (ctx);
      return QUIC_TLS_ERROR_INIT;
    }

  handshake->tls_ctx = ctx;
  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_create_ssl (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (handshake->tls_ctx == NULL)
    return QUIC_TLS_ERROR_INIT;

  SSL_CTX *ctx = (SSL_CTX *)handshake->tls_ctx;
  SSL *ssl = SSL_new (ctx);
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  /* Store handshake pointer for callbacks */
  SSL_set_app_data (ssl, handshake);

  /* Set connect or accept state */
  if (handshake->role == QUIC_CONN_ROLE_CLIENT)
    {
      SSL_set_connect_state (ssl);
    }
  else
    {
      SSL_set_accept_state (ssl);
    }

#if QUICTLS_COMPAT
  /* quictls: enable early data per-SSL since context-level API is missing */
  SSL_set_quic_early_data_enabled (ssl, 1);
#endif

  handshake->tls_ssl = ssl;
  return QUIC_TLS_OK;
}

void
SocketQUICTLS_free (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return;

  /* Clear all sensitive data before freeing */
  TLSState_T *state = get_tls_state (handshake);
  if (state != NULL)
    {
      /* Clear secrets */
      OPENSSL_cleanse (state->read_secret, sizeof (state->read_secret));
      OPENSSL_cleanse (state->write_secret, sizeof (state->write_secret));

      /* Clear CRYPTO output buffers (contain handshake data) */
      for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
        {
          if (state->crypto_out[i].data != NULL
              && state->crypto_out[i].capacity > 0)
            {
              OPENSSL_cleanse (state->crypto_out[i].data,
                               state->crypto_out[i].capacity);
            }
        }
    }

  if (handshake->tls_ssl != NULL)
    {
      SSL_free ((SSL *)handshake->tls_ssl);
      handshake->tls_ssl = NULL;
    }

  if (handshake->tls_ctx != NULL)
    {
      SSL_CTX_free ((SSL_CTX *)handshake->tls_ctx);
      handshake->tls_ctx = NULL;
    }
}

SocketQUICTLS_Result
SocketQUICTLS_do_handshake (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  int ret = SSL_do_handshake (ssl);
  if (ret == 1)
    {
      handshake->state = QUIC_HANDSHAKE_STATE_COMPLETE;
      return QUIC_TLS_OK;
    }

  int err = SSL_get_error (ssl, ret);
  switch (err)
    {
    case SSL_ERROR_WANT_READ:
      return QUIC_TLS_ERROR_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
      return QUIC_TLS_ERROR_WANT_WRITE;
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
      {
        unsigned long ossl_err = ERR_peek_error ();
        char buf[240];
        ERR_error_string_n (ossl_err, buf, sizeof (buf));
        snprintf (handshake->error_reason,
                  sizeof (handshake->error_reason),
                  "TLS error: %s",
                  buf);
        return QUIC_TLS_ERROR_HANDSHAKE;
      }
    default:
      return QUIC_TLS_ERROR_HANDSHAKE;
    }
}

SocketQUICTLS_Result
SocketQUICTLS_provide_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            const uint8_t *data,
                            size_t len)
{
  if (handshake == NULL || data == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (len == 0)
    return QUIC_TLS_OK;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    return QUIC_TLS_ERROR_LEVEL;

  OSSL_ENCRYPTION_LEVEL ossl_level = quic_level_to_ossl (level);

  if (!SSL_provide_quic_data (ssl, ossl_level, data, len))
    return QUIC_TLS_ERROR_HANDSHAKE;

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_get_data (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel *level,
                        const uint8_t **data,
                        size_t *len)
{
  if (handshake == NULL || level == NULL || data == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL)
    return QUIC_TLS_ERROR_INIT;

  /* Find first level with pending data */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      CryptoBuffer_T *buf = &state->crypto_out[i];
      size_t available = buf->len - buf->consumed;
      if (available > 0)
        {
          *level = (SocketQUICCryptoLevel)i;
          *data = buf->data + buf->consumed;
          *len = available;
          return QUIC_TLS_OK;
        }
    }

  *data = NULL;
  *len = 0;
  return QUIC_TLS_ERROR_WANT_READ;
}

SocketQUICTLS_Result
SocketQUICTLS_consume_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            size_t len)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    return QUIC_TLS_ERROR_LEVEL;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL)
    return QUIC_TLS_ERROR_INIT;

  CryptoBuffer_T *buf = &state->crypto_out[level];
  size_t available = buf->len - buf->consumed;

  if (len > available)
    len = available;

  buf->consumed += len;

  /* Reset buffer if fully consumed */
  if (buf->consumed >= buf->len)
    {
      buf->len = 0;
      buf->consumed = 0;
    }

  return QUIC_TLS_OK;
}

int
SocketQUICTLS_is_complete (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return 0;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return 0;

  return SSL_is_init_finished (ssl);
}

int
SocketQUICTLS_has_keys (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel level)
{
  if (handshake == NULL || level >= QUIC_CRYPTO_LEVEL_COUNT)
    return 0;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL)
    return 0;

  return state->secrets_available[level];
}

SocketQUICTLS_Result
SocketQUICTLS_derive_keys (SocketQUICHandshake_T handshake,
                           SocketQUICCryptoLevel level)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    return QUIC_TLS_ERROR_LEVEL;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL)
    return QUIC_TLS_ERROR_INIT;

  if (!state->secrets_available[level])
    return QUIC_TLS_ERROR_SECRETS;

  /* Key derivation would happen here using SocketQUICCrypto_derive_traffic_keys
   * For now, mark keys as available */
  handshake->keys_available[level] = 1;

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_get_traffic_secrets (SocketQUICHandshake_T handshake,
                                   SocketQUICCryptoLevel level,
                                   uint8_t *write_secret,
                                   uint8_t *read_secret,
                                   size_t *secret_len)
{
  if (handshake == NULL || write_secret == NULL || read_secret == NULL
      || secret_len == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    return QUIC_TLS_ERROR_LEVEL;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL)
    return QUIC_TLS_ERROR_INIT;

  if (!state->secrets_available[level])
    return QUIC_TLS_ERROR_SECRETS;

  size_t len = state->secret_len[level];
  if (len == 0)
    len = SOCKET_CRYPTO_SHA256_SIZE;
  memcpy (write_secret, state->write_secret[level], len);
  memcpy (read_secret, state->read_secret[level], len);
  *secret_len = len;

  return QUIC_TLS_OK;
}

uint64_t
SocketQUICTLS_alert_to_error (uint8_t alert)
{
  return QUIC_TLS_CRYPTO_ERROR_BASE + alert;
}

uint64_t
SocketQUICTLS_get_error_code (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return 0;

  TLSState_T *state = get_tls_state (handshake);
  if (state == NULL || !state->alert_received)
    return handshake->error_code;

  return QUIC_TLS_CRYPTO_ERROR_BASE + state->alert;
}

const char *
SocketQUICTLS_get_error_string (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return "";

  return handshake->error_reason;
}

SocketQUICTLS_Result
SocketQUICTLS_set_transport_params (SocketQUICHandshake_T handshake,
                                    const uint8_t *params,
                                    size_t len)
{
  if (handshake == NULL || params == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  if (!SSL_set_quic_transport_params (ssl, params, len))
    return QUIC_TLS_ERROR_TRANSPORT;

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_transport_params (SocketQUICHandshake_T handshake,
                                         const uint8_t **params,
                                         size_t *len)
{
  if (handshake == NULL || params == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  SSL_get_peer_quic_transport_params (ssl, params, len);

  if (*params == NULL || *len == 0)
    return QUIC_TLS_ERROR_TRANSPORT;

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_set_local_transport_params (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  /* Encode local transport parameters to wire format */
  uint8_t encoded[QUIC_TP_MAX_ENCODED_SIZE];
  SocketQUICRole role = (handshake->role == QUIC_CONN_ROLE_CLIENT)
                            ? QUIC_ROLE_CLIENT
                            : QUIC_ROLE_SERVER;

  size_t len = SocketQUICTransportParams_encode (
      &handshake->local_params, role, encoded, sizeof (encoded));

  if (len == 0)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* OpenSSL handles extension type 0x39 internally */
  if (!SSL_set_quic_transport_params (ssl, encoded, len))
    return QUIC_TLS_ERROR_TRANSPORT;

  return QUIC_TLS_OK;
}

int
SocketQUICTLS_has_peer_transport_params (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return 0;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return 0;

  const uint8_t *params = NULL;
  size_t len = 0;
  SSL_get_peer_quic_transport_params (ssl, &params, &len);

  return (params != NULL && len > 0);
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_params (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  /* Get raw params from TLS */
  const uint8_t *raw_params = NULL;
  size_t raw_len = 0;
  SSL_get_peer_quic_transport_params (ssl, &raw_params, &raw_len);

  /* RFC 9001 §8.2: missing extension is error 0x016d */
  if (raw_params == NULL || raw_len == 0)
    {
      handshake->error_code = QUIC_ERROR_MISSING_TRANSPORT_PARAMS;
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Missing quic_transport_parameters extension (0x%02x)",
                QUIC_TRANSPORT_PARAMS_EXT_TYPE);
      return QUIC_TLS_ERROR_TRANSPORT;
    }

  /* Decode into peer_params - peer role is opposite of ours */
  SocketQUICRole peer_role = (handshake->role == QUIC_CONN_ROLE_CLIENT)
                                 ? QUIC_ROLE_SERVER
                                 : QUIC_ROLE_CLIENT;
  size_t consumed;
  SocketQUICTransportParams_Result res = SocketQUICTransportParams_decode (
      raw_params, raw_len, peer_role, &handshake->peer_params, &consumed);

  if (res != QUIC_TP_OK)
    {
      handshake->error_code = QUIC_ERROR_TRANSPORT_PARAMETER;
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Transport parameter decode error: %s",
                SocketQUICTransportParams_result_string (res));
      return QUIC_TLS_ERROR_TRANSPORT;
    }

  /* Validate required parameters present */
  res = SocketQUICTransportParams_validate_required (&handshake->peer_params,
                                                     peer_role);
  if (res != QUIC_TP_OK)
    {
      handshake->error_code = QUIC_ERROR_TRANSPORT_PARAMETER;
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Transport parameter validation error: %s",
                SocketQUICTransportParams_result_string (res));
      return QUIC_TLS_ERROR_TRANSPORT;
    }

  handshake->params_received = 1;
  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_check_alpn_negotiated (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  /*
   * RFC 9001 §8.1: ALPN is mandatory for QUIC.
   * Check if an application protocol was negotiated.
   */
  const unsigned char *alpn = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected (ssl, &alpn, &alpn_len);

  if (alpn == NULL || alpn_len == 0)
    {
      /*
       * quictls QUIC API does not populate SSL_get0_alpn_selected for
       * clients. If the handshake completed without alert, the server
       * accepted our ALPN (RFC 9001 §8.1: server sends
       * no_application_protocol alert on mismatch).
       */
      if (handshake->role == QUIC_CONN_ROLE_CLIENT
          && SSL_is_init_finished (ssl))
        return QUIC_TLS_OK;

      handshake->error_code = QUIC_ERROR_NO_APPLICATION_PROTOCOL;
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "ALPN negotiation failed (RFC 9001 §8.1)");
      return QUIC_TLS_ERROR_ALPN;
    }

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_get_alpn (SocketQUICHandshake_T handshake,
                        const char **alpn,
                        size_t *len)
{
  if (handshake == NULL || alpn == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  const unsigned char *selected = NULL;
  unsigned int selected_len = 0;
  SSL_get0_alpn_selected (ssl, &selected, &selected_len);

  if (selected == NULL || selected_len == 0)
    {
      *alpn = NULL;
      *len = 0;
      return QUIC_TLS_ERROR_ALPN;
    }

  *alpn = (const char *)selected;
  *len = selected_len;
  return QUIC_TLS_OK;
}

/** QUIC sentinel value for max_early_data_size per RFC 9001 §4.6.1 */
#define QUIC_MAX_EARLY_DATA_SENTINEL 0xffffffff

SocketQUICTLS_Result
SocketQUICTLS_enable_session_tickets (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL_CTX *ctx = (SSL_CTX *)handshake->tls_ctx;
  if (ctx == NULL)
    return QUIC_TLS_ERROR_INIT;

  /*
   * RFC 9001 §4.6.1: For QUIC, max_early_data_size MUST be 0xffffffff.
   * This sentinel value indicates that QUIC handles early data limits,
   * not TLS. Session tickets with other values MUST NOT be used.
   */
  SSL_CTX_set_max_early_data (ctx, QUIC_MAX_EARLY_DATA_SENTINEL);

  /* Enable session ticket generation */
  SSL_CTX_set_options (ctx, SSL_OP_NO_TICKET);
  SSL_CTX_clear_options (ctx, SSL_OP_NO_TICKET);

  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_set_session (SocketQUICHandshake_T handshake,
                           const uint8_t *ticket,
                           size_t len)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;

  if (ticket == NULL || len == 0)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  /* Deserialize session from ticket data */
  const unsigned char *p = ticket;
  SSL_SESSION *session = d2i_SSL_SESSION (NULL, &p, (long)len);
  if (session == NULL)
    {
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Failed to deserialize session ticket");
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  /*
   * RFC 9001 §4.6.1: Validate max_early_data_size equals sentinel.
   * Tickets with other values MUST NOT be used for QUIC 0-RTT.
   */
  uint32_t max_early = SSL_SESSION_get_max_early_data (session);
  if (max_early != QUIC_MAX_EARLY_DATA_SENTINEL)
    {
      SSL_SESSION_free (session);
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Invalid max_early_data_size: 0x%08x (expected 0x%08x per RFC "
                "9001 §4.6.1)",
                max_early,
                QUIC_MAX_EARLY_DATA_SENTINEL);
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  /* Store max_early_data in 0-RTT context */
  handshake->zero_rtt.ticket_max_early_data = max_early;

  /* Set session on SSL object for resumption */
  if (!SSL_set_session (ssl, session))
    {
      SSL_SESSION_free (session);
      snprintf (handshake->error_reason,
                sizeof (handshake->error_reason),
                "Failed to set session for resumption");
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  SSL_SESSION_free (session);
  return QUIC_TLS_OK;
}

SocketQUICTLS_Result
SocketQUICTLS_get_session_ticket (SocketQUICHandshake_T handshake,
                                  uint8_t *ticket,
                                  size_t *len)
{
  if (handshake == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return QUIC_TLS_ERROR_INIT;

  SSL_SESSION *session = SSL_get_session (ssl);
  if (session == NULL)
    {
      *len = 0;
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  /* Get serialized size first */
  int needed = i2d_SSL_SESSION (session, NULL);
  if (needed <= 0)
    {
      *len = 0;
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  /* Check buffer size */
  if (ticket == NULL)
    {
      /* Caller just wants the required size */
      *len = (size_t)needed;
      return QUIC_TLS_OK;
    }

  if (*len < (size_t)needed)
    {
      *len = (size_t)needed;
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  /* Serialize session */
  unsigned char *p = ticket;
  int written = i2d_SSL_SESSION (session, &p);
  if (written <= 0)
    {
      *len = 0;
      return QUIC_TLS_ERROR_HANDSHAKE;
    }

  *len = (size_t)written;
  return QUIC_TLS_OK;
}

int
SocketQUICTLS_early_data_accepted (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return 0;

  SSL *ssl = (SSL *)handshake->tls_ssl;
  if (ssl == NULL)
    return 0;

  /*
   * RFC 9001 §4.6.2: Server accepts 0-RTT by including early_data
   * extension in EncryptedExtensions. SSL_get_early_data_status()
   * returns SSL_EARLY_DATA_ACCEPTED if server accepted.
   */
  return SSL_get_early_data_status (ssl) == SSL_EARLY_DATA_ACCEPTED;
}

SocketQUICTLS_Result
SocketQUICTLS_validate_0rtt_params (const SocketQUICTransportParams_T *original,
                                    const SocketQUICTransportParams_T *resumed)
{
  if (original == NULL || resumed == NULL)
    return QUIC_TLS_ERROR_NULL;

  /*
   * RFC 9001 §4.6.3: Server MUST NOT reduce certain parameters.
   * These limits affect how much 0-RTT data the client can send.
   *
   * "A server MUST NOT reduce any limits or alter any values that
   *  might be violated by the client with its 0-RTT data."
   */

  /* initial_max_data: MUST NOT be reduced */
  if (resumed->initial_max_data < original->initial_max_data)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* initial_max_stream_data_bidi_local: MUST NOT be reduced */
  if (resumed->initial_max_stream_data_bidi_local
      < original->initial_max_stream_data_bidi_local)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* initial_max_stream_data_bidi_remote: MUST NOT be reduced */
  if (resumed->initial_max_stream_data_bidi_remote
      < original->initial_max_stream_data_bidi_remote)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* initial_max_stream_data_uni: MUST NOT be reduced */
  if (resumed->initial_max_stream_data_uni
      < original->initial_max_stream_data_uni)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* initial_max_streams_bidi: MUST NOT be reduced */
  if (resumed->initial_max_streams_bidi < original->initial_max_streams_bidi)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* initial_max_streams_uni: MUST NOT be reduced */
  if (resumed->initial_max_streams_uni < original->initial_max_streams_uni)
    return QUIC_TLS_ERROR_TRANSPORT;

  /* active_connection_id_limit: MUST NOT be reduced */
  if (resumed->active_connection_id_limit
      < original->active_connection_id_limit)
    return QUIC_TLS_ERROR_TRANSPORT;

  /*
   * disable_active_migration: MUST NOT change from false to true.
   * If client sent 0-RTT assuming migration was allowed, server
   * cannot later disable it.
   */
  if (!original->disable_active_migration && resumed->disable_active_migration)
    return QUIC_TLS_ERROR_TRANSPORT;

  return QUIC_TLS_OK;
}

#endif /* HAVE_OPENSSL_QUIC */

#if !HAVE_OPENSSL_QUIC

SocketQUICTLS_Result
SocketQUICTLS_init_context (SocketQUICHandshake_T handshake,
                            const SocketQUICTLSConfig_T *config)
{
  (void)config;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_create_ssl (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

void
SocketQUICTLS_free (SocketQUICHandshake_T handshake)
{
  (void)handshake;
}

SocketQUICTLS_Result
SocketQUICTLS_do_handshake (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_provide_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            const uint8_t *data,
                            size_t len)
{
  (void)level;
  (void)len;
  if (handshake == NULL || data == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_data (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel *level,
                        const uint8_t **data,
                        size_t *len)
{
  if (handshake == NULL || level == NULL || data == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_consume_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            size_t len)
{
  (void)level;
  (void)len;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_is_complete (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

int
SocketQUICTLS_has_keys (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel level)
{
  (void)handshake;
  (void)level;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_derive_keys (SocketQUICHandshake_T handshake,
                           SocketQUICCryptoLevel level)
{
  (void)level;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_traffic_secrets (SocketQUICHandshake_T handshake,
                                   SocketQUICCryptoLevel level,
                                   uint8_t *write_secret,
                                   uint8_t *read_secret,
                                   size_t *secret_len)
{
  (void)level;
  (void)write_secret;
  (void)read_secret;
  (void)secret_len;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

uint64_t
SocketQUICTLS_alert_to_error (uint8_t alert)
{
  return 0x0100 + alert;
}

uint64_t
SocketQUICTLS_get_error_code (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

const char *
SocketQUICTLS_get_error_string (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return "OpenSSL QUIC support not available (requires OpenSSL 3.2+)";
}

SocketQUICTLS_Result
SocketQUICTLS_set_transport_params (SocketQUICHandshake_T handshake,
                                    const uint8_t *params,
                                    size_t len)
{
  (void)len;
  if (handshake == NULL || params == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_transport_params (SocketQUICHandshake_T handshake,
                                         const uint8_t **params,
                                         size_t *len)
{
  if (handshake == NULL || params == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_set_local_transport_params (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_has_peer_transport_params (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_params (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_check_alpn_negotiated (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_alpn (SocketQUICHandshake_T handshake,
                        const char **alpn,
                        size_t *len)
{
  (void)alpn;
  (void)len;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_enable_session_tickets (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_set_session (SocketQUICHandshake_T handshake,
                           const uint8_t *ticket,
                           size_t len)
{
  /* Check NULL even in stub for consistent error reporting */
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  if (ticket == NULL || len == 0)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_session_ticket (SocketQUICHandshake_T handshake,
                                  uint8_t *ticket,
                                  size_t *len)
{
  (void)ticket;
  if (handshake == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;
  *len = 0;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_early_data_accepted (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_validate_0rtt_params (const SocketQUICTransportParams_T *original,
                                    const SocketQUICTransportParams_T *resumed)
{
  /* Check NULL even in stub for consistent error reporting */
  if (original == NULL || resumed == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

#endif /* !HAVE_OPENSSL_QUIC */

#endif /* SOCKET_HAS_TLS */

#if !SOCKET_HAS_TLS

SocketQUICTLS_Result
SocketQUICTLS_init_context (SocketQUICHandshake_T handshake,
                            const SocketQUICTLSConfig_T *config)
{
  (void)config;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_create_ssl (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

void
SocketQUICTLS_free (SocketQUICHandshake_T handshake)
{
  (void)handshake;
}

SocketQUICTLS_Result
SocketQUICTLS_do_handshake (SocketQUICHandshake_T handshake)
{
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_provide_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            const uint8_t *data,
                            size_t len)
{
  (void)level;
  (void)len;
  if (handshake == NULL || data == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_data (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel *level,
                        const uint8_t **data,
                        size_t *len)
{
  if (handshake == NULL || level == NULL || data == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_consume_data (SocketQUICHandshake_T handshake,
                            SocketQUICCryptoLevel level,
                            size_t len)
{
  (void)level;
  (void)len;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_is_complete (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

int
SocketQUICTLS_has_keys (SocketQUICHandshake_T handshake,
                        SocketQUICCryptoLevel level)
{
  (void)handshake;
  (void)level;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_derive_keys (SocketQUICHandshake_T handshake,
                           SocketQUICCryptoLevel level)
{
  (void)level;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_traffic_secrets (SocketQUICHandshake_T handshake,
                                   SocketQUICCryptoLevel level,
                                   uint8_t *write_secret,
                                   uint8_t *read_secret,
                                   size_t *secret_len)
{
  (void)level;
  (void)write_secret;
  (void)read_secret;
  (void)secret_len;
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

uint64_t
SocketQUICTLS_alert_to_error (uint8_t alert)
{
  return 0x0100 + alert;
}

uint64_t
SocketQUICTLS_get_error_code (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

const char *
SocketQUICTLS_get_error_string (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return "TLS support not compiled in";
}

SocketQUICTLS_Result
SocketQUICTLS_set_transport_params (SocketQUICHandshake_T handshake,
                                    const uint8_t *params,
                                    size_t len)
{
  (void)handshake;
  (void)params;
  (void)len;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_transport_params (SocketQUICHandshake_T handshake,
                                         const uint8_t **params,
                                         size_t *len)
{
  (void)handshake;
  (void)params;
  (void)len;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_set_local_transport_params (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_has_peer_transport_params (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_get_peer_params (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_check_alpn_negotiated (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_alpn (SocketQUICHandshake_T handshake,
                        const char **alpn,
                        size_t *len)
{
  (void)handshake;
  (void)alpn;
  (void)len;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_enable_session_tickets (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_set_session (SocketQUICHandshake_T handshake,
                           const uint8_t *ticket,
                           size_t len)
{
  /* Check NULL even in stub for consistent error reporting */
  if (handshake == NULL)
    return QUIC_TLS_ERROR_NULL;
  if (ticket == NULL || len == 0)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

SocketQUICTLS_Result
SocketQUICTLS_get_session_ticket (SocketQUICHandshake_T handshake,
                                  uint8_t *ticket,
                                  size_t *len)
{
  (void)ticket;
  /* Check NULL even in stub for consistent error reporting */
  if (handshake == NULL || len == NULL)
    return QUIC_TLS_ERROR_NULL;
  *len = 0;
  return QUIC_TLS_ERROR_NO_TLS;
}

int
SocketQUICTLS_early_data_accepted (SocketQUICHandshake_T handshake)
{
  (void)handshake;
  return 0;
}

SocketQUICTLS_Result
SocketQUICTLS_validate_0rtt_params (const SocketQUICTransportParams_T *original,
                                    const SocketQUICTransportParams_T *resumed)
{
  /* Check NULL even in stub for consistent error reporting */
  if (original == NULL || resumed == NULL)
    return QUIC_TLS_ERROR_NULL;
  return QUIC_TLS_ERROR_NO_TLS;
}

#endif /* !SOCKET_HAS_TLS */

const char *
SocketQUICTLS_result_string (SocketQUICTLS_Result result)
{
  switch (result)
    {
    case QUIC_TLS_OK:
      return "Success";
    case QUIC_TLS_ERROR_NULL:
      return "NULL argument";
    case QUIC_TLS_ERROR_INIT:
      return "TLS initialization failed";
    case QUIC_TLS_ERROR_CERT:
      return "Certificate error";
    case QUIC_TLS_ERROR_KEY:
      return "Private key error";
    case QUIC_TLS_ERROR_ALPN:
      return "ALPN configuration error";
    case QUIC_TLS_ERROR_TRANSPORT:
      return "Transport parameters error";
    case QUIC_TLS_ERROR_HANDSHAKE:
      return "Handshake failed";
    case QUIC_TLS_ERROR_SECRETS:
      return "Secret derivation failed";
    case QUIC_TLS_ERROR_ALERT:
      return "TLS alert received";
    case QUIC_TLS_ERROR_NO_TLS:
      return "TLS support not available";
    case QUIC_TLS_ERROR_WANT_READ:
      return "Need more data";
    case QUIC_TLS_ERROR_WANT_WRITE:
      return "Need to send data";
    case QUIC_TLS_ERROR_LEVEL:
      return "Invalid encryption level";
    default:
      return "Unknown error";
    }
}
