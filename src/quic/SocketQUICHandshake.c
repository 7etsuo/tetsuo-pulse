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
#include "quic/SocketQUICVarInt.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum QUIC packet protection key material size.
 *
 * Based on RFC 9001 with AES-256-GCM or ChaCha20-Poly1305:
 * - Packet protection key: 32 bytes
 * - IV: 12 bytes
 * - Header protection key: 32 bytes
 * Total: 76 bytes (rounded to 128 for safety margin)
 */
#define QUIC_MAX_KEY_MATERIAL_SIZE 128

/* ============================================================================
 * Exceptions
 * ============================================================================
 */

const Except_T SocketQUICHandshake_Failed = { NULL, "QUIC handshake failed" };

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Map QUIC packet type to encryption level.
 *
 * @param packet_type Packet type from packet header.
 *
 * @return Corresponding encryption level.
 *
 * @note This mapping is defined by RFC 9000 Section 4.1.4:
 *       - Initial packets use Initial keys
 *       - 0-RTT packets use 0-RTT keys (client only)
 *       - Handshake packets use Handshake keys
 *       - 1-RTT packets use Application keys
 */
static SocketQUICCryptoLevel
packet_type_to_crypto_level(SocketQUICPacket_Type packet_type)
{
  switch (packet_type) {
    case QUIC_PACKET_TYPE_INITIAL:
      return QUIC_CRYPTO_LEVEL_INITIAL;
    case QUIC_PACKET_TYPE_0RTT:
      return QUIC_CRYPTO_LEVEL_0RTT;
    case QUIC_PACKET_TYPE_HANDSHAKE:
      return QUIC_CRYPTO_LEVEL_HANDSHAKE;
    case QUIC_PACKET_TYPE_1RTT:
      return QUIC_CRYPTO_LEVEL_APPLICATION;
    case QUIC_PACKET_TYPE_RETRY:
      /* Retry packets don't carry CRYPTO frames, but map to Initial */
      return QUIC_CRYPTO_LEVEL_INITIAL;
    default:
      /* Default to Initial for unknown types */
      return QUIC_CRYPTO_LEVEL_INITIAL;
  }
}

static void
crypto_stream_init(SocketQUICCryptoStream_T *stream)
{
  assert(stream);
  memset(stream, 0, sizeof(*stream));
  stream->recv_buffer_size = QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE;
}

static void
crypto_stream_free(SocketQUICCryptoStream_T *stream)
{
  if (!stream) return;

  /* Free segment list */
  SocketQUICCryptoSegment_T *seg = stream->segments;
  while (seg) {
    SocketQUICCryptoSegment_T *next = seg->next;
    /* Note: data freed by arena */
    seg = next;
  }

  stream->segments = NULL;
  stream->segment_count = 0;
}

static SocketQUICHandshake_Result
crypto_stream_insert_data(Arena_T arena, SocketQUICCryptoStream_T *stream,
                          uint64_t offset, const uint8_t *data,
                          uint64_t length)
{
  assert(stream);
  assert(data || length == 0);

  /* Check for duplicate or old data */
  if (offset < stream->recv_offset) {
    /* Data already received */
    uint64_t overlap = stream->recv_offset - offset;
    if (overlap >= length) {
      return QUIC_HANDSHAKE_OK; /* Fully duplicate */
    }
    /* Partial duplicate - adjust */
    data += overlap;
    length -= overlap;
    offset = stream->recv_offset;
  }

  /* If contiguous with recv_offset, copy directly */
  if (offset == stream->recv_offset) {
    if (stream->recv_buffer) {
      uint64_t total_offset;
      if (!socket_util_safe_add_u64(stream->recv_offset, length, &total_offset)) {
        return QUIC_HANDSHAKE_ERROR_BUFFER;  /* Overflow would occur */
      }
      if (total_offset > stream->recv_buffer_size) {
        return QUIC_HANDSHAKE_ERROR_BUFFER;
      }
      memcpy(stream->recv_buffer + stream->recv_offset, data, length);
    }
    stream->recv_offset += length;
    return QUIC_HANDSHAKE_OK;
  }

  /* Out-of-order - buffer as segment */
  if (stream->segment_count >= QUIC_HANDSHAKE_MAX_CRYPTO_SEGMENTS) {
    return QUIC_HANDSHAKE_ERROR_BUFFER;
  }

  SocketQUICCryptoSegment_T *seg = Arena_alloc(arena, sizeof(*seg), __FILE__, __LINE__);
  if (!seg) {
    return QUIC_HANDSHAKE_ERROR_MEMORY;
  }

  seg->offset = offset;
  seg->length = length;
  seg->data = Arena_alloc(arena, length, __FILE__, __LINE__);
  if (!seg->data) {
    return QUIC_HANDSHAKE_ERROR_MEMORY;
  }

  memcpy(seg->data, data, length);
  seg->next = stream->segments;
  stream->segments = seg;
  stream->segment_count++;

  return QUIC_HANDSHAKE_OK;
}

static int
crypto_stream_has_contiguous_data(SocketQUICCryptoStream_T *stream)
{
  SocketQUICCryptoSegment_T *seg = stream->segments;
  while (seg) {
    if (seg->offset == stream->recv_offset) {
      return 1;
    }
    seg = seg->next;
  }
  return 0;
}

static SocketQUICHandshake_Result
crypto_stream_process_buffered(Arena_T arena, SocketQUICCryptoStream_T *stream)
{
  int progress;
  do {
    progress = 0;
    SocketQUICCryptoSegment_T **prev = &stream->segments;
    SocketQUICCryptoSegment_T *seg = stream->segments;

    while (seg) {
      if (seg->offset == stream->recv_offset) {
        /* Contiguous - apply it */
        SocketQUICHandshake_Result res =
            crypto_stream_insert_data(arena, stream, seg->offset,
                                      seg->data, seg->length);
        if (res != QUIC_HANDSHAKE_OK) {
          return res;
        }

        /* Remove from list */
        *prev = seg->next;
        stream->segment_count--;
        progress = 1;
        seg = *prev;
      } else {
        prev = &seg->next;
        seg = seg->next;
      }
    }
  } while (progress);

  return QUIC_HANDSHAKE_OK;
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQUICHandshake_T
SocketQUICHandshake_new(Arena_T arena, SocketQUICConnection_T conn,
                        SocketQUICConnection_Role role)
{
  if (!arena || !conn) {
    return NULL;
  }

  SocketQUICHandshake_T hs = Arena_alloc(arena, sizeof(*hs), __FILE__, __LINE__);
  if (!hs) {
    return NULL;
  }

  memset(hs, 0, sizeof(*hs));
  hs->arena = arena;
  hs->conn = conn;
  hs->role = role;
  hs->state = QUIC_HANDSHAKE_STATE_IDLE;

  /* Initialize CRYPTO streams for all levels */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++) {
    crypto_stream_init(&hs->crypto_streams[i]);
    /* Allocate receive buffers */
    hs->crypto_streams[i].recv_buffer =
        Arena_alloc(arena, QUIC_HANDSHAKE_CRYPTO_BUFFER_SIZE, __FILE__, __LINE__);
  }

  /* Initialize transport parameters with defaults */
  SocketQUICTransportParams_init(&hs->local_params);
  SocketQUICTransportParams_init(&hs->peer_params);

  /* Set sensible defaults for local params */
  SocketQUICTransportParams_set_defaults(&hs->local_params,
                                          role == QUIC_CONN_ROLE_CLIENT ?
                                          QUIC_ROLE_CLIENT : QUIC_ROLE_SERVER);

  return hs;
}

void
SocketQUICHandshake_free(SocketQUICHandshake_T *handshake)
{
  if (!handshake || !*handshake) {
    return;
  }

  SocketQUICHandshake_T hs = *handshake;

  /* Free CRYPTO streams */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++) {
    crypto_stream_free(&hs->crypto_streams[i]);
  }

  /* TODO: Free TLS context and SSL objects */
  /* This requires OpenSSL/LibreSSL integration */

  /* Securely zero and free keys */
  for (int i = 0; i < QUIC_CRYPTO_LEVEL_COUNT; i++) {
    if (hs->keys[i]) {
      /* Securely zero key material before freeing (CWE-226, CWE-244) */
      SocketCrypto_secure_clear(hs->keys[i], QUIC_MAX_KEY_MATERIAL_SIZE);
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
SocketQUICHandshake_init(SocketQUICConnection_T conn,
                         SocketQUICConnection_Role role)
{
  if (!conn) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  (void)role; /* Unused for now - will be used for TLS context setup */

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
SocketQUICHandshake_set_transport_params(SocketQUICHandshake_T handshake,
                                         const SocketQUICTransportParams_T *params)
{
  if (!handshake || !params) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  /* Copy parameters */
  SocketQUICTransportParams_Result res =
      SocketQUICTransportParams_copy(&handshake->local_params, params);

  if (res != QUIC_TP_OK) {
    return QUIC_HANDSHAKE_ERROR_TRANSPORT;
  }

  /* TODO: Configure TLS to send these params in extension */

  return QUIC_HANDSHAKE_OK;
}

/* ============================================================================
 * Handshake Operations
 * ============================================================================
 */

SocketQUICHandshake_Result
SocketQUICHandshake_send_initial(SocketQUICConnection_T conn)
{
  if (!conn) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  /* TODO: Implement Initial packet generation
   * 1. Derive Initial secrets from DCID
   * 2. Generate ClientHello via TLS
   * 3. Wrap in CRYPTO frame
   * 4. Protect with Initial keys
   * 5. Send in Initial packet
   */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_process_crypto(SocketQUICConnection_T conn,
                                   const SocketQUICFrameCrypto_T *frame,
                                   SocketQUICCryptoLevel level)
{
  if (!conn || !frame) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  /* Validate encryption level */
  if (level >= QUIC_CRYPTO_LEVEL_COUNT) {
    return QUIC_HANDSHAKE_ERROR_CRYPTO;
  }

  /* Get handshake context from connection */
  /* NOTE: This assumes connection has a handshake field - needs integration */
  SocketQUICHandshake_T hs = NULL; /* TODO: Get from conn->handshake */
  if (!hs) {
    return QUIC_HANDSHAKE_ERROR_STATE;
  }

  /* Insert data into CRYPTO stream for the specified encryption level */
  SocketQUICCryptoStream_T *stream = &hs->crypto_streams[level];
  SocketQUICHandshake_Result res =
      crypto_stream_insert_data(hs->arena, stream, frame->offset,
                                frame->data, frame->length);
  if (res != QUIC_HANDSHAKE_OK) {
    return res;
  }

  /* Process any newly contiguous data */
  res = crypto_stream_process_buffered(hs->arena, stream);
  if (res != QUIC_HANDSHAKE_OK) {
    return res;
  }

  /* TODO: Feed contiguous data to TLS */
  /* This requires SSL_provide_quic_data() or equivalent */

  return QUIC_HANDSHAKE_OK;
}

SocketQUICHandshake_Result
SocketQUICHandshake_derive_keys(SocketQUICConnection_T conn,
                                SocketQUICCryptoLevel level)
{
  if (!conn) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  if (level >= QUIC_CRYPTO_LEVEL_COUNT) {
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
SocketQUICHandshake_process(SocketQUICHandshake_T handshake)
{
  if (!handshake) {
    return QUIC_HANDSHAKE_ERROR_NULL;
  }

  /* TODO: Advance TLS state machine
   * 1. Call SSL_do_handshake() or equivalent
   * 2. Extract CRYPTO data to send via SSL_quic_read_level()
   * 3. Check for handshake completion
   * 4. Extract peer transport parameters
   * 5. Update handshake state
   */

  return QUIC_HANDSHAKE_OK;
}

/* ============================================================================
 * Key Management Functions
 * ============================================================================
 */

int
SocketQUICHandshake_has_keys(SocketQUICHandshake_T handshake,
                             SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT) {
    return 0;
  }
  return handshake->keys_available[level];
}

void *
SocketQUICHandshake_get_keys(SocketQUICHandshake_T handshake,
                             SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT) {
    return NULL;
  }
  return handshake->keys[level];
}

void
SocketQUICHandshake_discard_keys(SocketQUICHandshake_T handshake,
                                 SocketQUICCryptoLevel level)
{
  if (!handshake || level >= QUIC_CRYPTO_LEVEL_COUNT) {
    return;
  }

  if (handshake->keys[level]) {
    /* Securely zero key material before discarding (CWE-226, CWE-244) */
    SocketCrypto_secure_clear(handshake->keys[level], QUIC_MAX_KEY_MATERIAL_SIZE);
    handshake->keys[level] = NULL;
    handshake->keys_available[level] = 0;
  }
}

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

SocketQUICHandshakeState
SocketQUICHandshake_get_state(SocketQUICHandshake_T handshake)
{
  if (!handshake) {
    return QUIC_HANDSHAKE_STATE_FAILED;
  }
  return handshake->state;
}

int
SocketQUICHandshake_is_complete(SocketQUICHandshake_T handshake)
{
  if (!handshake) {
    return 0;
  }
  return handshake->state >= QUIC_HANDSHAKE_STATE_COMPLETE;
}

int
SocketQUICHandshake_is_confirmed(SocketQUICHandshake_T handshake)
{
  if (!handshake) {
    return 0;
  }
  return handshake->state == QUIC_HANDSHAKE_STATE_CONFIRMED;
}

const SocketQUICTransportParams_T *
SocketQUICHandshake_get_peer_params(SocketQUICHandshake_T handshake)
{
  if (!handshake || !handshake->params_received) {
    return NULL;
  }
  return &handshake->peer_params;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQUICHandshake_crypto_level_string(SocketQUICCryptoLevel level)
{
  switch (level) {
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
SocketQUICHandshake_state_string(SocketQUICHandshakeState state)
{
  switch (state) {
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
SocketQUICHandshake_result_string(SocketQUICHandshake_Result result)
{
  switch (result) {
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
