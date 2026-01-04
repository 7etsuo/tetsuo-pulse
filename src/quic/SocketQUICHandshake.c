/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICHandshake.c
 * @brief QUIC Cryptographic and Transport Handshake implementation.
 */

#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICTLS.h"
#include "quic/SocketQUICVarInt.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

/* OpenSSL/LibreSSL integration for TLS handshake */
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

/* ============================================================================
 * Exceptions
 * ============================================================================
 */

const Except_T SocketQUICHandshake_Failed = { NULL, "QUIC handshake failed" };

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

static void
crypto_stream_init (SocketQUICCryptoStream_T *stream)
{
  assert (stream);
  memset (stream, 0, sizeof (*stream));
  stream->recv_buffer_size = QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE;
}

static void
crypto_stream_free (SocketQUICCryptoStream_T *stream)
{
  if (!stream)
    return;

  /* Free segment list */
  SocketQUICCryptoSegment_T *seg = stream->segments;
  while (seg)
    {
      SocketQUICCryptoSegment_T *next = seg->next;
      /* Note: data freed by arena */
      seg = next;
    }

  stream->segments = NULL;
  stream->segment_count = 0;
}

static SocketQUICHandshake_Result
crypto_stream_insert_data (Arena_T arena,
                           SocketQUICCryptoStream_T *stream,
                           uint64_t offset,
                           const uint8_t *data,
                           uint64_t length)
{
  assert (stream);
  assert (data || length == 0);

  /* Check for duplicate or old data */
  if (offset < stream->recv_offset)
    {
      /* Data already received */
      uint64_t overlap = stream->recv_offset - offset;
      if (overlap >= length)
        {
          return QUIC_HANDSHAKE_OK; /* Fully duplicate */
        }
      /* Partial duplicate - adjust */
      data += overlap;
      length -= overlap;
      offset = stream->recv_offset;
    }

  /* If contiguous with recv_offset, copy directly */
  if (offset == stream->recv_offset)
    {
      /* Check for overflow before updating recv_offset */
      uint64_t total_offset;
      if (!socket_util_safe_add_u64 (
              stream->recv_offset, length, &total_offset))
        {
          return QUIC_HANDSHAKE_ERROR_BUFFER; /* Overflow would occur */
        }

      if (stream->recv_buffer)
        {
          if (total_offset > stream->recv_buffer_size)
            {
              return QUIC_HANDSHAKE_ERROR_BUFFER;
            }
          /* Validate length fits in size_t for memcpy (CWE-197: 32-bit systems)
           */
          if (length > SIZE_MAX)
            {
              return QUIC_HANDSHAKE_ERROR_BUFFER;
            }
          memcpy (
              stream->recv_buffer + stream->recv_offset, data, (size_t)length);
        }
      stream->recv_offset += length;
      return QUIC_HANDSHAKE_OK;
    }

  /* Out-of-order - buffer as segment */
  if (stream->segment_count >= QUIC_HANDSHAKE_MAX_CRYPTO_SEGMENTS)
    {
      return QUIC_HANDSHAKE_ERROR_BUFFER;
    }

  /* Validate length fits in size_t for Arena_alloc and memcpy (CWE-197: 32-bit
   * systems) */
  if (length > SIZE_MAX)
    {
      return QUIC_HANDSHAKE_ERROR_BUFFER;
    }

  SocketQUICCryptoSegment_T *seg
      = Arena_alloc (arena, sizeof (*seg), __FILE__, __LINE__);
  if (!seg)
    {
      return QUIC_HANDSHAKE_ERROR_MEMORY;
    }

  seg->offset = offset;
  seg->length = length;
  seg->data = Arena_alloc (arena, (size_t)length, __FILE__, __LINE__);
  if (!seg->data)
    {
      return QUIC_HANDSHAKE_ERROR_MEMORY;
    }

  memcpy (seg->data, data, (size_t)length);
  seg->next = stream->segments;
  stream->segments = seg;
  stream->segment_count++;

  return QUIC_HANDSHAKE_OK;
}

static SocketQUICHandshake_Result
crypto_stream_process_buffered (Arena_T arena, SocketQUICCryptoStream_T *stream)
{
  int progress;
  do
    {
      progress = 0;
      SocketQUICCryptoSegment_T **prev = &stream->segments;
      SocketQUICCryptoSegment_T *seg = stream->segments;

      while (seg)
        {
          if (seg->offset == stream->recv_offset)
            {
              /* Contiguous - apply it */
              SocketQUICHandshake_Result res = crypto_stream_insert_data (
                  arena, stream, seg->offset, seg->data, seg->length);
              if (res != QUIC_HANDSHAKE_OK)
                {
                  return res;
                }

              /* Remove from list */
              *prev = seg->next;
              stream->segment_count--;
              progress = 1;
              seg = *prev;
            }
          else
            {
              prev = &seg->next;
              seg = seg->next;
            }
        }
    }
  while (progress);

  return QUIC_HANDSHAKE_OK;
}

/**
 * @brief Validate connection and handshake context for sending Initial packet.
 *
 * Checks that connection is valid, handshake context exists, and caller is
 * a client (only clients send Initial packets).
 *
 * @param conn Connection to validate
 * @param hs_out Output pointer to receive handshake context
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise
 */
static SocketQUICHandshake_Result
send_initial_validate (SocketQUICConnection_T conn,
                       SocketQUICHandshake_T *hs_out)
{
  if (!conn)
    return QUIC_HANDSHAKE_ERROR_NULL;

  SocketQUICHandshake_T hs = conn->handshake;
  if (!hs)
    return QUIC_HANDSHAKE_ERROR_STATE;

  /* Only clients send Initial packets */
  if (hs->role != QUIC_CONN_ROLE_CLIENT)
    return QUIC_HANDSHAKE_ERROR_STATE;

  *hs_out = hs;
  return QUIC_HANDSHAKE_OK;
}

/**
 * @brief Derive Initial secrets and mark keys available.
 *
 * Per RFC 9001 Section 5.2, Initial secrets are derived from the client's
 * Destination Connection ID using HKDF with version-specific salt. This
 * produces client and server keys for Initial packet protection.
 *
 * @note Actual key derivation is implemented in SocketQUICPacket-initial.c
 * via SocketQUICInitial_derive_keys(). Keys are stored in
 * handshake->keys[INITIAL]. For now, we mark keys as available without
 * actual derivation since TLS integration is pending.
 *
 * @param hs Handshake context
 */
static void
send_initial_derive_keys (SocketQUICHandshake_T hs)
{
  hs->state = QUIC_HANDSHAKE_STATE_INITIAL;
  hs->keys_available[QUIC_CRYPTO_LEVEL_INITIAL] = 1;
}

/**
 * @brief Generate ClientHello via TLS stack.
 *
 * Per RFC 9001 Section 4, the ClientHello is generated by the TLS 1.3 stack
 * and includes:
 * - TLS 1.3 handshake messages
 * - QUIC transport parameters extension
 * - Supported cipher suites (AES-128-GCM, ChaCha20-Poly1305)
 *
 * @note Once TLS integration is complete, this will use SSL_do_handshake()
 * or equivalent to generate the ClientHello message.
 *
 * @param hs Handshake context (unused until TLS integration)
 */
static void
send_initial_generate_client_hello (SocketQUICHandshake_T hs
                                    __attribute__ ((unused)))
{
#ifdef HAVE_OPENSSL
  /* TLS integration pending - would call:
   * SSL_do_handshake(hs->tls_ssl);
   * SSL_quic_read_level() to get CRYPTO data;
   */
#endif
}

/**
 * @brief Prepare CRYPTO stream for Initial level.
 *
 * Per RFC 9000 Section 19.6, CRYPTO frames carry TLS handshake messages at
 * each encryption level. For Initial packets, the CRYPTO frame contains the
 * ClientHello.
 *
 * Frame format:
 * - Type (i): 0x06
 * - Offset (i): Stream offset (0 for first ClientHello)
 * - Length (i): Data length
 * - Crypto Data (..): ClientHello bytes
 *
 * @param hs Handshake context
 */
static void
send_initial_prepare_crypto_stream (SocketQUICHandshake_T hs)
{
  SocketQUICCryptoStream_T *stream
      = &hs->crypto_streams[QUIC_CRYPTO_LEVEL_INITIAL];

  /* Mark that we've initiated sending CRYPTO data at Initial level */
  stream->send_offset = 0; /* Will be updated when actual data is sent */
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICHandshake_T
SocketQUICHandshake_new (Arena_T arena,
                         SocketQUICConnection_T conn,
                         SocketQUICConnection_Role role)
{
  if (!arena || !conn)
    {
      return NULL;
    }

  SocketQUICHandshake_T hs
      = Arena_alloc (arena, sizeof (*hs), __FILE__, __LINE__);
  if (!hs)
    {
      return NULL;
    }

  memset (hs, 0, sizeof (*hs));
  hs->arena = arena;
  hs->conn = conn;
  hs->role = role;
  hs->state = QUIC_HANDSHAKE_STATE_IDLE;

  /* Initialize CRYPTO streams for all levels */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      crypto_stream_init (&hs->crypto_streams[i]);
      /* Allocate receive buffers */
      hs->crypto_streams[i].recv_buffer = Arena_alloc (
          arena, QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE, __FILE__, __LINE__);
    }

  /* Initialize transport parameters with defaults */
  SocketQUICTransportParams_init (&hs->local_params);
  SocketQUICTransportParams_init (&hs->peer_params);

  /* Set sensible defaults for local params */
  SocketQUICTransportParams_set_defaults (
      &hs->local_params,
      role == QUIC_CONN_ROLE_CLIENT ? QUIC_ROLE_CLIENT : QUIC_ROLE_SERVER);

  return hs;
}

void
SocketQUICHandshake_free (SocketQUICHandshake_T *handshake)
{
  if (!handshake || !*handshake)
    {
      return;
    }

  SocketQUICHandshake_T hs = *handshake;

  /* Free CRYPTO streams */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      crypto_stream_free (&hs->crypto_streams[i]);
    }

    /* Free TLS context and SSL objects */
    /* Note: Once OpenSSL/LibreSSL integration is added, these pointers
     * will be properly initialized and need cleanup. The NULL checks
     * ensure this is safe to call even before TLS integration. */
#ifdef HAVE_OPENSSL
  if (hs->tls_ssl)
    {
      SSL_free ((SSL *)hs->tls_ssl);
      hs->tls_ssl = NULL;
    }
  if (hs->tls_ctx)
    {
      SSL_CTX_free ((SSL_CTX *)hs->tls_ctx);
      hs->tls_ctx = NULL;
    }
#else
  /* Without OpenSSL, these should always be NULL, but clear for safety */
  hs->tls_ssl = NULL;
  hs->tls_ctx = NULL;
#endif

  /* Securely zero and free keys */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++)
    {
      if (hs->keys[i])
        {
          /* Securely zero key material before freeing (CWE-226, CWE-244) */
          SocketCrypto_secure_clear (hs->keys[i], QUIC_MAX_KEY_MATERIAL_SIZE);
          hs->keys[i] = NULL;
        }
    }

  *handshake = NULL;
}

/* ============================================================================
 * Initialization Functions
 * ============================================================================
 */

SocketQUICHandshake_Result
SocketQUICHandshake_init (SocketQUICConnection_T conn,
                          SocketQUICConnection_Role role
                          __attribute__ ((unused)))
{
  if (!conn)
    {
      return QUIC_HANDSHAKE_ERROR_NULL;
    }

  /* TODO: Initialize TLS context */
  /* This requires:
   * 1. Create SSL_CTX with TLS 1.3 methods
   * 2. Configure QUIC transport parameter extension
   * 3. Set up key derivation callbacks
   * 4. Configure ALPN (if needed)
   */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_set_transport_params (
    SocketQUICHandshake_T handshake, const SocketQUICTransportParams_T *params)
{
  if (!handshake || !params)
    {
      return QUIC_HANDSHAKE_ERROR_NULL;
    }

  /* Copy parameters */
  SocketQUICTransportParams_Result res
      = SocketQUICTransportParams_copy (&handshake->local_params, params);

  if (res != QUIC_TP_OK)
    {
      return QUIC_HANDSHAKE_ERROR_TRANSPORT;
    }

  /* Configure TLS to send transport parameters in QUIC extension */
  if (handshake->tls_ssl)
    {
      /* Encode transport parameters to wire format */
      uint8_t encoded_params[QUIC_TP_MAX_ENCODED_SIZE];
      SocketQUICRole tls_role = (handshake->role == QUIC_CONN_ROLE_CLIENT)
                                    ? QUIC_ROLE_CLIENT
                                    : QUIC_ROLE_SERVER;

      size_t encoded_len
          = SocketQUICTransportParams_encode (&handshake->local_params,
                                              tls_role,
                                              encoded_params,
                                              sizeof (encoded_params));

      if (encoded_len == 0)
        {
          return QUIC_HANDSHAKE_ERROR_TRANSPORT;
        }

#if defined(HAVE_OPENSSL) && defined(SSL_set_quic_transport_params)
      /* Set transport parameters on SSL object (OpenSSL 3.0+ with QUIC support)
       */
      SSL *ssl = (SSL *)handshake->tls_ssl;
      if (SSL_set_quic_transport_params (ssl, encoded_params, encoded_len) != 1)
        {
          return QUIC_HANDSHAKE_ERROR_TLS;
        }
#else
      /* TLS not available or OpenSSL doesn't support QUIC extensions yet.
       * Store encoded params for manual extension handling when TLS is
       * integrated. */
      (void)encoded_len; /* Suppress unused warning */
#endif
    }

  return QUIC_HANDSHAKE_OK;
}

/* ============================================================================
 * Handshake Operations
 * ============================================================================
 */

/**
 * @brief Send Initial packet to start QUIC handshake.
 *
 * This function orchestrates the Initial packet sending process:
 * 1. Validate connection and handshake context
 * 2. Derive Initial secrets from DCID (RFC 9001 Section 5.2)
 * 3. Generate ClientHello via TLS (RFC 9001 Section 4)
 * 4. Prepare CRYPTO frame (RFC 9000 Section 19.6)
 * 5. Protect and send packet (RFC 9001 Section 5.4, RFC 9000 Section 17.2.2)
 *
 * @note Steps 4-5 (protection and transmission) are handled by the packet
 * layer once full integration is complete.
 *
 * @param conn QUIC connection context
 * @return QUIC_HANDSHAKE_OK on success, error code otherwise
 */
SocketQUICHandshake_Result
SocketQUICHandshake_send_initial (SocketQUICConnection_T conn)
{
  SocketQUICHandshake_T hs;
  SocketQUICHandshake_Result res;

  /* Step 1: Validate connection and get handshake context */
  res = send_initial_validate (conn, &hs);
  if (res != QUIC_HANDSHAKE_OK)
    return res;

  /* Step 2: Derive Initial secrets and mark keys available */
  send_initial_derive_keys (hs);

  /* Step 3: Generate ClientHello via TLS stack */
  send_initial_generate_client_hello (hs);

  /* Step 4: Prepare CRYPTO stream for Initial level */
  send_initial_prepare_crypto_stream (hs);

  /* Steps 5-6: Packet protection and transmission are handled by:
   * - SocketQUICInitial_protect() for encryption (RFC 9001 Section 5.4)
   * - Packet layer for transmission (RFC 9000 Section 17.2.2)
   */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_process_crypto (SocketQUICConnection_T conn,
                                    const SocketQUICFrameCrypto_T *frame,
                                    SocketQUICCryptoLevel level)
{
  if (!conn || !frame)
    {
      return QUIC_HANDSHAKE_ERROR_NULL;
    }

  /* Validate encryption level */
  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    {
      return QUIC_HANDSHAKE_ERROR_CRYPTO;
    }

  /* Get handshake context from connection */
  SocketQUICHandshake_T hs = conn->handshake;
  if (!hs)
    {
      return QUIC_HANDSHAKE_ERROR_STATE;
    }

  /* Insert data into CRYPTO stream for the specified encryption level */
  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[level];
  SocketQUICHandshake_Result res = crypto_stream_insert_data (
      hs->arena, stream, frame->offset, frame->data, frame->length);
  if (res != QUIC_HANDSHAKE_OK)
    {
      return res;
    }

  /* Process any newly contiguous data */
  res = crypto_stream_process_buffered (hs->arena, stream);
  if (res != QUIC_HANDSHAKE_OK)
    {
      return res;
    }

  /* TODO: Feed contiguous data to TLS */
  /* This requires SSL_provide_quic_data() or equivalent */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_derive_keys (SocketQUICConnection_T conn,
                                 SocketQUICCryptoLevel level)
{
  if (!conn)
    {
      return QUIC_HANDSHAKE_ERROR_NULL;
    }

  if (level >= QUIC_CRYPTO_LEVEL_COUNT)
    {
      return QUIC_HANDSHAKE_ERROR_CRYPTO;
    }

  /* TODO: Implement key derivation
   * 1. Get TLS traffic secrets for encryption level
   * 2. Derive QUIC packet protection keys via HKDF
   * 3. Store in handshake->keys[level]
   * 4. Set handshake->keys_available[level] = 1
   *
   * Key derivation follows RFC 9001 Section 5:
   * - quic_key = HKDF-Expand-Label(secret, "quic key", "", key_len)
   * - quic_iv = HKDF-Expand-Label(secret, "quic iv", "", iv_len)
   * - quic_hp = HKDF-Expand-Label(secret, "quic hp", "", hp_len)
   */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_process (SocketQUICHandshake_T handshake)
{
  if (!handshake)
    {
      return QUIC_HANDSHAKE_ERROR_NULL;
    }

  /* Set local transport params before first TLS handshake call (RFC 9001 §8.2)
   */
  if (handshake->state == QUIC_HANDSHAKE_STATE_INITIAL
      && handshake->tls_ssl != NULL)
    {
      SocketQUICTLS_Result tls_res
          = SocketQUICTLS_set_local_transport_params (handshake);

      /* NO_TLS is acceptable - means OpenSSL < 3.2 */
      if (tls_res != QUIC_TLS_OK && tls_res != QUIC_TLS_ERROR_NO_TLS)
        {
          return QUIC_HANDSHAKE_ERROR_TRANSPORT;
        }
    }

  /* Advance TLS state machine */
  if (handshake->tls_ssl != NULL)
    {
      SocketQUICTLS_Result tls_res = SocketQUICTLS_do_handshake (handshake);

      /* Handle TLS results */
      if (tls_res == QUIC_TLS_ERROR_HANDSHAKE
          || tls_res == QUIC_TLS_ERROR_ALERT)
        {
          handshake->state = QUIC_HANDSHAKE_STATE_FAILED;
          return QUIC_HANDSHAKE_ERROR_TLS;
        }
    }

  /* After handshake complete, retrieve and decode peer params (RFC 9001 §8.2)
   */
  if (SocketQUICTLS_is_complete (handshake) && !handshake->params_received)
    {
      SocketQUICTLS_Result tls_res = SocketQUICTLS_get_peer_params (handshake);

      if (tls_res != QUIC_TLS_OK)
        {
          handshake->state = QUIC_HANDSHAKE_STATE_FAILED;
          return QUIC_HANDSHAKE_ERROR_TRANSPORT;
        }
    }

  return QUIC_HANDSHAKE_OK;
}

/* ============================================================================
 * Key Management Functions
 * ============================================================================
 */

int
SocketQUICHandshake_has_keys (SocketQUICHandshake_T handshake,
                              SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT)
    {
      return 0;
    }
  return handshake->keys_available[level];
}

void *
SocketQUICHandshake_get_keys (SocketQUICHandshake_T handshake,
                              SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT)
    {
      return NULL;
    }
  return handshake->keys[level];
}

void
SocketQUICHandshake_discard_keys (SocketQUICHandshake_T handshake,
                                  SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT)
    {
      return;
    }

  if (handshake->keys[level])
    {
      /* Securely zero key material before discarding (CWE-226, CWE-244) */
      SocketCrypto_secure_clear (handshake->keys[level],
                                 QUIC_MAX_KEY_MATERIAL_SIZE);
      handshake->keys[level] = NULL;
      handshake->keys_available[level] = 0;
    }
}

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

SocketQUICHandshakeState
SocketQUICHandshake_get_state (SocketQUICHandshake_T handshake)
{
  if (!handshake)
    {
      return QUIC_HANDSHAKE_STATE_FAILED;
    }
  return handshake->state;
}

int
SocketQUICHandshake_is_complete (SocketQUICHandshake_T handshake)
{
  if (!handshake)
    {
      return 0;
    }
  return handshake->state >= QUIC_HANDSHAKE_STATE_COMPLETE;
}

int
SocketQUICHandshake_is_confirmed (SocketQUICHandshake_T handshake)
{
  if (!handshake)
    {
      return 0;
    }
  return handshake->state == QUIC_HANDSHAKE_STATE_CONFIRMED;
}

const SocketQUICTransportParams_T *
SocketQUICHandshake_get_peer_params (SocketQUICHandshake_T handshake)
{
  if (!handshake || !handshake->params_received)
    {
      return NULL;
    }
  return &handshake->peer_params;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQUICHandshake_crypto_level_string (SocketQUICCryptoLevel level)
{
  switch (level)
    {
    case QUIC_CRYPTO_LEVEL_INITIAL:
      return "Initial";
    case QUIC_CRYPTO_LEVEL_0RTT:
      return "0-RTT";
    case QUIC_CRYPTO_LEVEL_HANDSHAKE:
      return "Handshake";
    case QUIC_CRYPTO_LEVEL_APPLICATION:
      return "Application";
    default:
      return "Unknown";
    }
}

const char *
SocketQUICHandshake_state_string (SocketQUICHandshakeState state)
{
  switch (state)
    {
    case QUIC_HANDSHAKE_STATE_IDLE:
      return "Idle";
    case QUIC_HANDSHAKE_STATE_INITIAL:
      return "Initial";
    case QUIC_HANDSHAKE_STATE_HANDSHAKE:
      return "Handshake";
    case QUIC_HANDSHAKE_STATE_COMPLETE:
      return "Complete";
    case QUIC_HANDSHAKE_STATE_CONFIRMED:
      return "Confirmed";
    case QUIC_HANDSHAKE_STATE_FAILED:
      return "Failed";
    default:
      return "Unknown";
    }
}

const char *
SocketQUICHandshake_result_string (SocketQUICHandshake_Result result)
{
  switch (result)
    {
    case QUIC_HANDSHAKE_OK:
      return "OK";
    case QUIC_HANDSHAKE_ERROR_NULL:
      return "NULL argument";
    case QUIC_HANDSHAKE_ERROR_STATE:
      return "Invalid state";
    case QUIC_HANDSHAKE_ERROR_CRYPTO:
      return "Cryptographic error";
    case QUIC_HANDSHAKE_ERROR_TLS:
      return "TLS error";
    case QUIC_HANDSHAKE_ERROR_BUFFER:
      return "Buffer overflow";
    case QUIC_HANDSHAKE_ERROR_OFFSET:
      return "Invalid offset";
    case QUIC_HANDSHAKE_ERROR_DUPLICATE:
      return "Duplicate data";
    case QUIC_HANDSHAKE_ERROR_TRANSPORT:
      return "Transport parameter error";
    case QUIC_HANDSHAKE_ERROR_MEMORY:
      return "Memory allocation failure";
    default:
      return "Unknown error";
    }
}
