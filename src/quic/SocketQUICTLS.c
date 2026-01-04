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

#include <string.h>

#include "core/SocketConfig.h"

#if SOCKET_HAS_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * Check for OpenSSL QUIC support.
 * SSL_QUIC_METHOD was added in OpenSSL 3.2.0.
 * We check for the presence of the SSL_set_quic_method macro.
 */
#if defined(SSL_set_quic_method) \
    || (defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30200000L)
#define HAVE_OPENSSL_QUIC 1
#else
#define HAVE_OPENSSL_QUIC 0
#endif

#if HAVE_OPENSSL_QUIC

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** QUIC CRYPTO_ERROR base per RFC 9001 §4.8 */
#define QUIC_TLS_CRYPTO_ERROR_BASE 0x0100

/** Default ALPN protocol for HTTP/3 */
#define QUIC_TLS_DEFAULT_ALPN "h3"

/** Maximum CRYPTO output buffer size */
#define QUIC_TLS_MAX_CRYPTO_BUFFER QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

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

/**
 * @brief TLS state stored in handshake context.
 */
typedef struct
{
  CryptoBuffer_T crypto_out[QUIC_CRYPTO_LEVEL_COUNT];
  uint8_t read_secret[QUIC_CRYPTO_LEVEL_COUNT][SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t write_secret[QUIC_CRYPTO_LEVEL_COUNT][SOCKET_CRYPTO_SHA256_SIZE];
  int secrets_available[QUIC_CRYPTO_LEVEL_COUNT];
  int flush_pending;
  uint8_t alert;
  int alert_received;
} TLSState_T;

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

static int
quic_set_encryption_secrets (SSL *ssl,
                             OSSL_ENCRYPTION_LEVEL level,
                             const uint8_t *read_secret,
                             const uint8_t *write_secret,
                             size_t secret_len);

static int
quic_add_handshake_data (SSL *ssl,
                         OSSL_ENCRYPTION_LEVEL level,
                         const uint8_t *data,
                         size_t len);

static int
quic_flush_flight (SSL *ssl);

static int
quic_send_alert (SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

/* ============================================================================
 * SSL_QUIC_METHOD Definition
 * ============================================================================
 */

static const SSL_QUIC_METHOD quic_method = {
  .set_encryption_secrets = quic_set_encryption_secrets,
  .add_handshake_data = quic_add_handshake_data,
  .flush_flight = quic_flush_flight,
  .send_alert = quic_send_alert,
};

/* ============================================================================
 * Level Conversion
 * ============================================================================
 */

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

/* ============================================================================
 * TLS State Management
 * ============================================================================
 */

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

/* ============================================================================
 * CRYPTO Buffer Operations
 * ============================================================================
 */

/**
 * @brief Ensure CRYPTO buffer has capacity.
 */
static int
crypto_buffer_ensure (Arena_T arena, CryptoBuffer_T *buf, size_t needed)
{
  if (buf->capacity >= needed)
    return 1;

  size_t new_cap = buf->capacity == 0 ? 4096 : buf->capacity * 2;
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

/* ============================================================================
 * SSL_QUIC_METHOD Callbacks
 * ============================================================================
 */

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

  if (secret_len > SOCKET_CRYPTO_SHA256_SIZE)
    return 0;

  if (read_secret != NULL)
    memcpy (state->read_secret[qlevel], read_secret, secret_len);

  if (write_secret != NULL)
    memcpy (state->write_secret[qlevel], write_secret, secret_len);

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

  return crypto_buffer_append (hs->arena, &state->crypto_out[qlevel], data,
                               len);
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

/* ============================================================================
 * ALPN Callback
 * ============================================================================
 */

/**
 * @brief ALPN selection callback for server mode.
 */
static int
alpn_select_callback (SSL *ssl,
                      const unsigned char **out,
                      unsigned char *outlen,
                      const unsigned char *in,
                      unsigned int inlen,
                      void *arg)
{
  (void)ssl;
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

  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* ============================================================================
 * Context Initialization Helpers
 * ============================================================================
 */

/**
 * @brief Create base SSL_CTX with TLS 1.3 and QUIC method.
 */
static SocketQUICTLS_Result
tls_create_base_context (SSL_CTX **out_ctx)
{
  SSL_CTX *ctx = SSL_CTX_new (TLS_method ());
  if (ctx == NULL)
    return QUIC_TLS_ERROR_INIT;

  SSL_CTX_set_min_proto_version (ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version (ctx, TLS1_3_VERSION);

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
      if (SSL_CTX_use_certificate_file (ctx, config->cert_file,
                                        SSL_FILETYPE_PEM)
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
      SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                          NULL);
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
  const char *alpn
      = (config != NULL && config->alpn != NULL) ? config->alpn : QUIC_TLS_DEFAULT_ALPN;

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
 */
static void
tls_configure_early_data (SSL_CTX *ctx, const SocketQUICTLSConfig_T *config)
{
  if (config != NULL && config->enable_0rtt)
    SSL_CTX_set_early_data_enabled (ctx, 1);
}

/* ============================================================================
 * Context Initialization
 * ============================================================================
 */

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

/* ============================================================================
 * SSL Object Creation
 * ============================================================================
 */

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

  handshake->tls_ssl = ssl;
  return QUIC_TLS_OK;
}

/* ============================================================================
 * Cleanup
 * ============================================================================
 */

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

/* ============================================================================
 * Handshake Operations
 * ============================================================================
 */

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
        char buf[256];
        ERR_error_string_n (ossl_err, buf, sizeof (buf));
        snprintf (handshake->error_reason, sizeof (handshake->error_reason),
                  "TLS error: %s", buf);
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

/* ============================================================================
 * Key Management
 * ============================================================================
 */

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

/* ============================================================================
 * Alert Handling
 * ============================================================================
 */

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

/* ============================================================================
 * Transport Parameters
 * ============================================================================
 */

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

#endif /* HAVE_OPENSSL_QUIC */

/* ============================================================================
 * Stub Implementations (TLS without QUIC support - OpenSSL < 3.0)
 * ============================================================================
 */

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

#endif /* !HAVE_OPENSSL_QUIC */

#endif /* SOCKET_HAS_TLS */

/* ============================================================================
 * Stub Implementations (No TLS at all)
 * ============================================================================
 */

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

#endif /* !SOCKET_HAS_TLS */

/* ============================================================================
 * Utility Functions (Always Available)
 * ============================================================================
 */

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
