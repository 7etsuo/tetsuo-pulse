/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICTransport.c
 * @brief QUIC transport layer over UDP (RFC 9000).
 */

#ifdef SOCKET_HAS_TLS

#include "quic/SocketQUICTransport.h"

#include <poll.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "quic/SocketQUICAck.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICFlow.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICLoss.h"
#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICTLS.h"
#include "quic/SocketQUICTransportParams.h"
#include "quic/SocketQUICVarInt.h"
#include "quic/SocketQUICVersion.h"
#include "socket/SocketDgram.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

#define TRANSPORT_SEND_BUF_SIZE 1500
#define TRANSPORT_RECV_BUF_SIZE 65536
#define TRANSPORT_MAX_STREAMS 256
#define TRANSPORT_SCID_LEN 8
#define TRANSPORT_DCID_LEN 8
#define TRANSPORT_PN_LEN 4

/* ============================================================================
 * Per-stream send offset tracking
 * ============================================================================
 */

typedef struct
{
  uint64_t stream_id;
  uint64_t send_offset;
  int active;
} QUICStreamState;

/* ============================================================================
 * Internal transport structure
 * ============================================================================
 */

struct SocketQUICTransport
{
  Arena_T arena;
  SocketQUICTransportConfig config;

  /* UDP socket */
  SocketDgram_T socket;

  /* QUIC connection + handshake state */
  SocketQUICConnection_T conn;
  SocketQUICHandshake_T handshake;
  SocketQUICReceive_T recv_ctx;
  SocketQUICFlow_T flow;

  /* ACK generation (one per PN space) */
  SocketQUICAckState_T ack[QUIC_PN_SPACE_COUNT];

  /* Loss detection (one per PN space) */
  SocketQUICLossState_T loss[QUIC_PN_SPACE_COUNT];
  SocketQUICLossRTT_T rtt;

  /* Packet protection keys (send-side) */
  SocketQUICInitialKeys_T initial_keys;
  SocketQUICPacketKeys_T handshake_send_keys;
  SocketQUICPacketKeys_T app_send_keys;
  int handshake_keys_valid;
  int app_keys_valid;

  /* Key update state for 1-RTT */
  SocketQUICKeyUpdate_T key_update;

  /* Packet number state */
  uint64_t next_pn[QUIC_PN_SPACE_COUNT];

  /* Packet build/recv buffers (arena-allocated) */
  uint8_t *send_buf;
  uint8_t *recv_buf;

  /* Per-stream send offset tracking */
  QUICStreamState streams[TRANSPORT_MAX_STREAMS];
  size_t stream_count;

  /* Stream receive callback */
  SocketQUICTransport_StreamCB stream_cb;
  void *stream_cb_userdata;

  /* Next bidi stream ID for client: 0, 4, 8, ... */
  uint64_t next_bidi_id;

  /* Connection IDs */
  SocketQUICConnectionID_T scid;
  SocketQUICConnectionID_T dcid;

  /* State */
  int connected;
  int closed;
};

/* ============================================================================
 * Time helpers
 * ============================================================================
 */

static uint64_t
now_us (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

/* ============================================================================
 * UDP I/O wrappers (exception -> return code)
 * ============================================================================
 */

static int
transport_send_packet (SocketQUICTransport_T t, const uint8_t *data, size_t len)
{
  volatile int result = -1;
  TRY
  {
    SocketDgram_send (t->socket, data, len);
    result = 0;
  }
  EXCEPT (SocketDgram_Failed)
  {
    result = -1;
  }
  END_TRY;
  return result;
}

static ssize_t
transport_recv_packet (SocketQUICTransport_T t, uint8_t *buf, size_t len)
{
  volatile ssize_t nbytes = -1;
  TRY
  {
    nbytes = SocketDgram_recv (t->socket, buf, len);
  }
  EXCEPT (SocketDgram_Failed)
  {
    nbytes = -1;
  }
  END_TRY;
  return nbytes;
}

/* ============================================================================
 * Stream state helpers
 * ============================================================================
 */

static QUICStreamState *
find_or_create_stream (SocketQUICTransport_T t, uint64_t stream_id)
{
  for (size_t i = 0; i < t->stream_count; i++)
    {
      if (t->streams[i].active && t->streams[i].stream_id == stream_id)
        return &t->streams[i];
    }

  if (t->stream_count >= TRANSPORT_MAX_STREAMS)
    return NULL;

  QUICStreamState *s = &t->streams[t->stream_count++];
  s->stream_id = stream_id;
  s->send_offset = 0;
  s->active = 1;
  return s;
}

/* ============================================================================
 * Packet building helpers
 * ============================================================================
 */

static int
build_and_send_1rtt_packet (SocketQUICTransport_T t,
                            const uint8_t *payload,
                            size_t payload_len)
{
  if (!t->app_keys_valid)
    return -1;

  uint64_t pn = t->next_pn[QUIC_PN_SPACE_APPLICATION];
  uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, TRANSPORT_PN_LEN);

  /* Build short header */
  SocketQUICPacketHeader_T hdr;
  SocketQUICPacketHeader_init (&hdr);
  if (SocketQUICPacketHeader_build_short (&hdr,
                                          &t->dcid,
                                          0,
                                          t->key_update.key_phase,
                                          TRANSPORT_PN_LEN,
                                          truncated_pn)
      != QUIC_PACKET_OK)
    return -1;

  size_t hdr_len = SocketQUICPacketHeader_serialize (
      &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
  if (hdr_len == 0)
    return -1;

  size_t pn_offset = hdr_len - TRANSPORT_PN_LEN;

  /* Copy payload after header */
  if (hdr_len + payload_len + 16 > TRANSPORT_SEND_BUF_SIZE)
    return -1;
  memcpy (t->send_buf + hdr_len, payload, payload_len);

  /* Encrypt payload */
  size_t ciphertext_len = TRANSPORT_SEND_BUF_SIZE - hdr_len;
  if (SocketQUICCrypto_encrypt_payload (&t->app_send_keys,
                                        pn,
                                        t->send_buf,
                                        hdr_len,
                                        t->send_buf + hdr_len,
                                        payload_len,
                                        t->send_buf + hdr_len,
                                        &ciphertext_len)
      != QUIC_CRYPTO_OK)
    return -1;

  size_t pkt_len = hdr_len + ciphertext_len;

  /* Apply header protection */
  if (SocketQUICCrypto_protect_header_ex (
          &t->app_send_keys, t->send_buf, pkt_len, pn_offset)
      != QUIC_CRYPTO_OK)
    return -1;

  /* Send */
  if (transport_send_packet (t, t->send_buf, pkt_len) < 0)
    return -1;

  t->next_pn[QUIC_PN_SPACE_APPLICATION]++;
  return 0;
}

/* ============================================================================
 * ACK frame sending
 * ============================================================================
 */

static int
send_ack_if_needed (SocketQUICTransport_T t,
                    SocketQUIC_PNSpace space,
                    uint64_t now)
{
  if (!t->ack[space])
    return 0;
  if (!SocketQUICAck_should_send (t->ack[space], now))
    return 0;

  uint8_t ack_buf[256];
  size_t ack_len = 0;
  if (SocketQUICAck_encode (
          t->ack[space], now, ack_buf, sizeof (ack_buf), &ack_len)
      != QUIC_ACK_OK)
    return -1;

  if (ack_len == 0)
    return 0;

  int rc = -1;
  if (space == QUIC_PN_SPACE_APPLICATION && t->app_keys_valid)
    rc = build_and_send_1rtt_packet (t, ack_buf, ack_len);

  if (rc == 0)
    SocketQUICAck_mark_sent (t->ack[space], now);

  return rc;
}

/* ============================================================================
 * Frame processing during poll()
 * ============================================================================
 */

static int
process_frames (SocketQUICTransport_T t,
                const uint8_t *payload,
                size_t payload_len,
                SocketQUIC_PNSpace space,
                uint64_t now)
{
  size_t offset = 0;
  int events = 0;

  while (offset < payload_len)
    {
      SocketQUICFrame_T frame;
      SocketQUICFrame_init (&frame);
      size_t consumed = 0;
      SocketQUICFrame_Result fr = SocketQUICFrame_parse_arena (
          t->arena, payload + offset, payload_len - offset, &frame, &consumed);
      if (fr != QUIC_FRAME_OK)
        break;

      offset += consumed;

      switch (frame.type)
        {
        case QUIC_FRAME_PADDING:
        case QUIC_FRAME_PING:
          break;

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
          if (t->loss[space])
            {
              size_t lost_count = 0;
              SocketQUICLoss_on_ack_received (t->loss[space],
                                              &t->rtt,
                                              frame.data.ack.largest_ack,
                                              frame.data.ack.ack_delay,
                                              now,
                                              NULL,
                                              NULL,
                                              &lost_count);
            }
          break;

        case QUIC_FRAME_CRYPTO:
          {
            SocketQUICCryptoLevel level;
            if (space == QUIC_PN_SPACE_INITIAL)
              level = QUIC_CRYPTO_LEVEL_INITIAL;
            else if (space == QUIC_PN_SPACE_HANDSHAKE)
              level = QUIC_CRYPTO_LEVEL_HANDSHAKE;
            else
              level = QUIC_CRYPTO_LEVEL_APPLICATION;

            SocketQUICTLS_provide_data (t->handshake,
                                        level,
                                        frame.data.crypto.data,
                                        (size_t)frame.data.crypto.length);
          }
          break;

        case QUIC_FRAME_HANDSHAKE_DONE:
          SocketQUICHandshake_on_confirmed (t->handshake);
          break;

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
          t->closed = 1;
          return -1;

        case QUIC_FRAME_MAX_DATA:
          if (t->flow)
            SocketQUICFlow_update_send_max (t->flow,
                                            frame.data.max_data.max_data);
          break;

        default:
          if (SocketQUICFrame_is_stream (frame.type))
            {
              if (t->stream_cb)
                {
                  t->stream_cb (frame.data.stream.stream_id,
                                frame.data.stream.data,
                                (size_t)frame.data.stream.length,
                                frame.data.stream.has_fin,
                                t->stream_cb_userdata);
                  events++;
                }
            }
          break;
        }
    }

  return events;
}

/* ============================================================================
 * Handshake: send TLS data at a given crypto level
 * ============================================================================
 */

static int
send_crypto_data (SocketQUICTransport_T t,
                  SocketQUICCryptoLevel level,
                  const uint8_t *data,
                  size_t len,
                  uint64_t crypto_offset)
{
  /* Build CRYPTO frame */
  uint8_t frame_buf[TRANSPORT_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_crypto (
      crypto_offset, data, len, frame_buf, sizeof (frame_buf));
  if (frame_len == 0)
    return -1;

  if (level == QUIC_CRYPTO_LEVEL_INITIAL)
    {
      /* Build Initial packet */
      uint64_t pn = t->next_pn[QUIC_PN_SPACE_INITIAL];
      uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, TRANSPORT_PN_LEN);

      SocketQUICPacketHeader_T hdr;
      SocketQUICPacketHeader_init (&hdr);
      SocketQUICPacketHeader_build_initial (&hdr,
                                            QUIC_VERSION_1,
                                            &t->dcid,
                                            &t->scid,
                                            NULL,
                                            0,
                                            TRANSPORT_PN_LEN,
                                            truncated_pn);

      size_t hdr_len = SocketQUICPacketHeader_serialize (
          &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
      if (hdr_len == 0)
        return -1;

      /* Copy CRYPTO frame into payload area */
      memcpy (t->send_buf + hdr_len, frame_buf, frame_len);
      size_t pkt_len = hdr_len + frame_len;

      /* Pad to 1200 bytes minimum for client Initial */
      size_t pad_needed = SocketQUICInitial_padding_needed (pkt_len + 16);
      if (pad_needed > 0)
        {
          memset (t->send_buf + pkt_len, 0, pad_needed);
          pkt_len += pad_needed;
        }

      /* Protect (encrypt + header protection) */
      if (SocketQUICInitial_protect (
              t->send_buf, &pkt_len, hdr_len, &t->initial_keys, 1)
          != QUIC_INITIAL_OK)
        return -1;

      if (transport_send_packet (t, t->send_buf, pkt_len) < 0)
        return -1;

      t->next_pn[QUIC_PN_SPACE_INITIAL]++;
    }
  else if (level == QUIC_CRYPTO_LEVEL_HANDSHAKE)
    {
      if (!t->handshake_keys_valid)
        return -1;

      uint64_t pn = t->next_pn[QUIC_PN_SPACE_HANDSHAKE];
      uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, TRANSPORT_PN_LEN);

      SocketQUICPacketHeader_T hdr;
      SocketQUICPacketHeader_init (&hdr);
      SocketQUICPacketHeader_build_handshake (&hdr,
                                              QUIC_VERSION_1,
                                              &t->dcid,
                                              &t->scid,
                                              TRANSPORT_PN_LEN,
                                              truncated_pn);

      size_t hdr_len = SocketQUICPacketHeader_serialize (
          &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
      if (hdr_len == 0)
        return -1;

      size_t pn_offset = hdr_len - TRANSPORT_PN_LEN;

      memcpy (t->send_buf + hdr_len, frame_buf, frame_len);

      /* Encrypt */
      size_t ciphertext_len = TRANSPORT_SEND_BUF_SIZE - hdr_len;
      if (SocketQUICCrypto_encrypt_payload (&t->handshake_send_keys,
                                            pn,
                                            t->send_buf,
                                            hdr_len,
                                            t->send_buf + hdr_len,
                                            frame_len,
                                            t->send_buf + hdr_len,
                                            &ciphertext_len)
          != QUIC_CRYPTO_OK)
        return -1;

      size_t pkt_len = hdr_len + ciphertext_len;

      /* Header protection */
      if (SocketQUICCrypto_protect_header_ex (
              &t->handshake_send_keys, t->send_buf, pkt_len, pn_offset)
          != QUIC_CRYPTO_OK)
        return -1;

      if (transport_send_packet (t, t->send_buf, pkt_len) < 0)
        return -1;

      /* First Handshake packet sent triggers Initial key discard */
      SocketQUICHandshake_on_handshake_packet_sent (t->handshake);

      t->next_pn[QUIC_PN_SPACE_HANDSHAKE]++;
    }
  else if (level == QUIC_CRYPTO_LEVEL_APPLICATION)
    {
      return build_and_send_1rtt_packet (t, frame_buf, frame_len);
    }

  return 0;
}

/* ============================================================================
 * Flush all pending TLS output data
 * ============================================================================
 */

static int
flush_tls_output (SocketQUICTransport_T t)
{
  SocketQUICCryptoLevel level;
  const uint8_t *data;
  size_t len;

  while (SocketQUICTLS_get_data (t->handshake, &level, &data, &len)
         == QUIC_TLS_OK)
    {
      /* Get the crypto stream offset for this level */
      uint64_t offset = t->handshake->crypto_streams[level].send_offset;

      if (send_crypto_data (t, level, data, len, offset) < 0)
        {
          SocketQUICTLS_consume_data (t->handshake, level, len);
          return -1;
        }

      t->handshake->crypto_streams[level].send_offset += len;
      SocketQUICTLS_consume_data (t->handshake, level, len);
    }

  return 0;
}

/* ============================================================================
 * Try to derive keys from TLS at each level
 * ============================================================================
 */

static void
check_and_derive_keys (SocketQUICTransport_T t)
{
  uint8_t write_secret[SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t read_secret[SOCKET_CRYPTO_SHA256_SIZE];
  size_t secret_len = 0;

  /* Handshake keys */
  if (!t->handshake_keys_valid
      && SocketQUICHandshake_has_keys (t->handshake,
                                       QUIC_CRYPTO_LEVEL_HANDSHAKE))
    {
      if (SocketQUICTLS_get_traffic_secrets (t->handshake,
                                             QUIC_CRYPTO_LEVEL_HANDSHAKE,
                                             write_secret,
                                             read_secret,
                                             &secret_len)
          == QUIC_TLS_OK)
        {
          SocketQUICPacketKeys_T hs_read_keys;
          SocketQUICCrypto_derive_packet_keys (write_secret,
                                               secret_len,
                                               QUIC_AEAD_AES_128_GCM,
                                               &t->handshake_send_keys);
          SocketQUICCrypto_derive_packet_keys (
              read_secret, secret_len, QUIC_AEAD_AES_128_GCM, &hs_read_keys);
          SocketQUICReceive_set_handshake_keys (&t->recv_ctx, &hs_read_keys);
          t->handshake_keys_valid = 1;
        }
    }

  /* Application (1-RTT) keys */
  if (!t->app_keys_valid
      && SocketQUICHandshake_has_keys (t->handshake,
                                       QUIC_CRYPTO_LEVEL_APPLICATION))
    {
      if (SocketQUICTLS_get_traffic_secrets (t->handshake,
                                             QUIC_CRYPTO_LEVEL_APPLICATION,
                                             write_secret,
                                             read_secret,
                                             &secret_len)
          == QUIC_TLS_OK)
        {
          SocketQUICCrypto_derive_packet_keys (write_secret,
                                               secret_len,
                                               QUIC_AEAD_AES_128_GCM,
                                               &t->app_send_keys);
          SocketQUICKeyUpdate_set_initial_keys (&t->key_update,
                                                write_secret,
                                                read_secret,
                                                secret_len,
                                                QUIC_AEAD_AES_128_GCM);
          SocketQUICReceive_set_1rtt_keys (&t->recv_ctx, &t->key_update);
          t->app_keys_valid = 1;
        }
    }

  /* Clear secrets from stack */
  volatile uint8_t *vw = write_secret;
  volatile uint8_t *vr = read_secret;
  for (size_t i = 0; i < sizeof (write_secret); i++)
    vw[i] = 0;
  for (size_t i = 0; i < sizeof (read_secret); i++)
    vr[i] = 0;
}

/* ============================================================================
 * Config defaults
 * ============================================================================
 */

void
SocketQUICTransportConfig_defaults (SocketQUICTransportConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->idle_timeout_ms = 30000;
  config->max_stream_data = 262144;
  config->initial_max_data = 1048576;
  config->initial_max_streams_bidi = 100;
  config->connect_timeout_ms = 5000;
  config->alpn = "h3";
  config->ca_file = NULL;
  config->verify_peer = 1;
}

/* ============================================================================
 * New
 * ============================================================================
 */

SocketQUICTransport_T
SocketQUICTransport_new (Arena_T arena, const SocketQUICTransportConfig *config)
{
  if (!arena)
    return NULL;

  SocketQUICTransport_T t
      = Arena_alloc (arena, sizeof (*t), __FILE__, __LINE__);
  memset (t, 0, sizeof (*t));
  t->arena = arena;

  if (config)
    t->config = *config;
  else
    SocketQUICTransportConfig_defaults (&t->config);

  /* Allocate packet buffers */
  t->send_buf
      = Arena_alloc (arena, TRANSPORT_SEND_BUF_SIZE, __FILE__, __LINE__);
  t->recv_buf
      = Arena_alloc (arena, TRANSPORT_RECV_BUF_SIZE, __FILE__, __LINE__);

  /* Initialize receive context */
  SocketQUICReceive_init (&t->recv_ctx);

  /* Initialize key update */
  SocketQUICKeyUpdate_init (&t->key_update);

  /* Initialize RTT state */
  SocketQUICLoss_init_rtt (&t->rtt);

  return t;
}

/* ============================================================================
 * Connect (blocking handshake)
 * ============================================================================
 */

int
SocketQUICTransport_connect (SocketQUICTransport_T t,
                             const char *host,
                             int port)
{
  if (!t || !host || t->connected || t->closed)
    return -1;

  /* Phase A: UDP socket setup */
  volatile int setup_ok = 0;
  TRY
  {
    t->socket = SocketDgram_new (AF_INET, 0);
    SocketDgram_setnonblocking (t->socket);
    SocketDgram_connect (t->socket, host, port);
    setup_ok = 1;
  }
  EXCEPT (SocketDgram_Failed)
  {
    setup_ok = 0;
  }
  END_TRY;

  if (!setup_ok)
    return -1;

  /* Generate random CIDs */
  SocketCrypto_random_bytes (t->scid.data, TRANSPORT_SCID_LEN);
  t->scid.len = TRANSPORT_SCID_LEN;
  SocketCrypto_random_bytes (t->dcid.data, TRANSPORT_DCID_LEN);
  t->dcid.len = TRANSPORT_DCID_LEN;

  /* Create QUIC connection */
  t->conn = SocketQUICConnection_new (t->arena, QUIC_CONN_ROLE_CLIENT);
  if (!t->conn)
    return -1;

  SocketQUICConnection_add_local_cid (t->conn, &t->scid);
  SocketQUICConnection_add_peer_cid (t->conn, &t->dcid);
  t->conn->initial_dcid = t->dcid;

  /* Create handshake context */
  t->handshake
      = SocketQUICHandshake_new (t->arena, t->conn, QUIC_CONN_ROLE_CLIENT);
  if (!t->handshake)
    return -1;

  /* Phase B: TLS setup */
  SocketQUICTransportParams_T local_params;
  memset (&local_params, 0, sizeof (local_params));
  local_params.max_idle_timeout = t->config.idle_timeout_ms;
  local_params.initial_max_data = t->config.initial_max_data;
  local_params.initial_max_stream_data_bidi_local = t->config.max_stream_data;
  local_params.initial_max_stream_data_bidi_remote = t->config.max_stream_data;
  local_params.initial_max_streams_bidi = t->config.initial_max_streams_bidi;
  local_params.initial_max_streams_uni = 3;

  SocketQUICHandshake_set_transport_params (t->handshake, &local_params);

  SocketQUICTLSConfig_T tls_config;
  memset (&tls_config, 0, sizeof (tls_config));
  tls_config.alpn = t->config.alpn ? t->config.alpn : "h3";
  tls_config.ca_file = t->config.ca_file;
  tls_config.verify_peer = t->config.verify_peer;

  if (SocketQUICTLS_init_context (t->handshake, &tls_config) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_create_ssl (t->handshake) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_set_local_transport_params (t->handshake) != QUIC_TLS_OK)
    return -1;

  /* Phase C: Initial packet */
  if (SocketQUICCrypto_derive_initial_keys (
          &t->dcid, QUIC_VERSION_1, &t->initial_keys)
      != QUIC_CRYPTO_OK)
    return -1;

  SocketQUICReceive_set_initial_keys (&t->recv_ctx, &t->initial_keys);

  /* Init ACK states */
  t->ack[QUIC_PN_SPACE_INITIAL] = SocketQUICAck_new (t->arena, 1, 0);
  t->ack[QUIC_PN_SPACE_HANDSHAKE] = SocketQUICAck_new (t->arena, 1, 0);
  t->ack[QUIC_PN_SPACE_APPLICATION]
      = SocketQUICAck_new (t->arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);

  /* Init loss detection */
  t->loss[QUIC_PN_SPACE_INITIAL] = SocketQUICLoss_new (t->arena, 1, 0);
  t->loss[QUIC_PN_SPACE_HANDSHAKE] = SocketQUICLoss_new (t->arena, 1, 0);
  t->loss[QUIC_PN_SPACE_APPLICATION]
      = SocketQUICLoss_new (t->arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);

  /* Drive TLS to produce ClientHello */
  SocketQUICTLS_do_handshake (t->handshake);

  /* Flush TLS output (sends ClientHello in Initial packet) */
  if (flush_tls_output (t) < 0)
    return -1;

  /* Phase D: Handshake loop */
  uint64_t deadline_us
      = now_us () + (uint64_t)t->config.connect_timeout_ms * 1000;

  while (!SocketQUICTLS_is_complete (t->handshake))
    {
      uint64_t current = now_us ();
      if (current >= deadline_us)
        return -1;

      int remaining_ms = (int)((deadline_us - current) / 1000);
      if (remaining_ms <= 0)
        remaining_ms = 1;

      /* Poll for UDP data */
      struct pollfd pfd;
      pfd.fd = SocketDgram_fd (t->socket);
      pfd.events = POLLIN;
      pfd.revents = 0;

      int poll_rc = poll (&pfd, 1, remaining_ms);
      if (poll_rc <= 0)
        continue;

      /* Receive packet */
      ssize_t nbytes
          = transport_recv_packet (t, t->recv_buf, TRANSPORT_RECV_BUF_SIZE);
      if (nbytes <= 0)
        continue;

      /* Decrypt and parse */
      SocketQUICReceiveResult_T result;
      memset (&result, 0, sizeof (result));
      SocketQUICReceive_Result recv_rc = SocketQUICReceive_packet (
          &t->recv_ctx, t->recv_buf, (size_t)nbytes, t->scid.len, 0, &result);

      if (recv_rc != QUIC_RECEIVE_OK)
        continue;

      /* Record received PN for ACK generation */
      if (t->ack[result.pn_space])
        SocketQUICAck_record_packet (
            t->ack[result.pn_space], result.packet_number, now_us (), 1);

      /* Process frames */
      process_frames (
          t, result.payload, result.payload_len, result.pn_space, now_us ());

      if (t->closed)
        return -1;

      /* Check and derive keys at new levels */
      check_and_derive_keys (t);

      /* Advance TLS */
      SocketQUICTLS_do_handshake (t->handshake);

      /* Flush any generated TLS data */
      flush_tls_output (t);

      /* Send ACKs */
      current = now_us ();
      for (int space = 0; space < QUIC_PN_SPACE_COUNT; space++)
        send_ack_if_needed (t, (SocketQUIC_PNSpace)space, current);
    }

  /* Phase E: Post-handshake validation */
  if (SocketQUICTLS_check_alpn_negotiated (t->handshake) != QUIC_TLS_OK)
    return -1;

  SocketQUICTLS_get_peer_params (t->handshake);

  /* Ensure we have 1-RTT keys */
  check_and_derive_keys (t);
  if (!t->app_keys_valid)
    return -1;

  /* Initialize flow control from peer params */
  const SocketQUICTransportParams_T *peer_params
      = SocketQUICHandshake_get_peer_params (t->handshake);
  if (peer_params)
    {
      t->flow = SocketQUICFlow_new (t->arena);
      if (t->flow)
        SocketQUICFlow_init (t->flow,
                             t->config.initial_max_data,
                             peer_params->initial_max_data,
                             peer_params->initial_max_streams_bidi,
                             peer_params->initial_max_streams_uni);
    }

  /* Update DCID if server provided a new one */
  if (t->handshake->conn->peer_cid_count > 0)
    t->dcid = t->handshake->conn->peer_cids[0];

  t->connected = 1;
  return 0;
}

/* ============================================================================
 * Close
 * ============================================================================
 */

int
SocketQUICTransport_close (SocketQUICTransport_T t)
{
  if (!t || t->closed)
    return -1;

  if (t->app_keys_valid)
    {
      /* Send CONNECTION_CLOSE */
      uint8_t close_buf[64];
      size_t close_len = SocketQUICFrame_encode_connection_close_app (
          0, NULL, close_buf, sizeof (close_buf));
      if (close_len > 0)
        build_and_send_1rtt_packet (t, close_buf, close_len);
    }

  t->closed = 1;
  t->connected = 0;

  /* Clean up UDP socket */
  if (t->socket)
    {
      SocketDgram_free (&t->socket);
      t->socket = NULL;
    }

  /* Clear key material */
  SocketQUICInitialKeys_clear (&t->initial_keys);
  SocketQUICPacketKeys_clear (&t->handshake_send_keys);
  SocketQUICPacketKeys_clear (&t->app_send_keys);
  SocketQUICKeyUpdate_clear (&t->key_update);

  /* Free handshake TLS resources */
  if (t->handshake)
    SocketQUICTLS_free (t->handshake);

  return 0;
}

/* ============================================================================
 * Send stream data
 * ============================================================================
 */

int
SocketQUICTransport_send_stream (SocketQUICTransport_T t,
                                 uint64_t stream_id,
                                 const uint8_t *data,
                                 size_t len,
                                 int fin)
{
  if (!t || !t->connected || t->closed)
    return -1;
  if (!data && len > 0)
    return -1;

  QUICStreamState *stream = find_or_create_stream (t, stream_id);
  if (!stream)
    return -1;

  /* Build STREAM frame */
  uint8_t frame_buf[TRANSPORT_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_stream (stream_id,
                                                    stream->send_offset,
                                                    data,
                                                    len,
                                                    fin,
                                                    frame_buf,
                                                    sizeof (frame_buf));
  if (frame_len == 0)
    return -1;

  stream->send_offset += len;

  return build_and_send_1rtt_packet (t, frame_buf, frame_len);
}

/* ============================================================================
 * Poll
 * ============================================================================
 */

int
SocketQUICTransport_poll (SocketQUICTransport_T t, int timeout_ms)
{
  if (!t || !t->connected || t->closed)
    return -1;

  struct pollfd pfd;
  pfd.fd = SocketDgram_fd (t->socket);
  pfd.events = POLLIN;
  pfd.revents = 0;

  int poll_rc = poll (&pfd, 1, timeout_ms);
  if (poll_rc <= 0)
    return 0;

  ssize_t nbytes
      = transport_recv_packet (t, t->recv_buf, TRANSPORT_RECV_BUF_SIZE);
  if (nbytes <= 0)
    return 0;

  SocketQUICReceiveResult_T result;
  memset (&result, 0, sizeof (result));
  SocketQUICReceive_Result recv_rc = SocketQUICReceive_packet (
      &t->recv_ctx, t->recv_buf, (size_t)nbytes, t->scid.len, 0, &result);

  if (recv_rc != QUIC_RECEIVE_OK)
    return 0;

  uint64_t current = now_us ();

  /* Record received PN */
  if (t->ack[result.pn_space])
    SocketQUICAck_record_packet (
        t->ack[result.pn_space], result.packet_number, current, 1);

  /* Process frames */
  int events = process_frames (
      t, result.payload, result.payload_len, result.pn_space, current);

  /* Send ACK if needed */
  current = now_us ();
  for (int space = 0; space < QUIC_PN_SPACE_COUNT; space++)
    send_ack_if_needed (t, (SocketQUIC_PNSpace)space, current);

  return events >= 0 ? events : 0;
}

/* ============================================================================
 * Stream callback
 * ============================================================================
 */

void
SocketQUICTransport_set_stream_callback (SocketQUICTransport_T t,
                                         SocketQUICTransport_StreamCB cb,
                                         void *userdata)
{
  if (!t)
    return;
  t->stream_cb = cb;
  t->stream_cb_userdata = userdata;
}

/* ============================================================================
 * Queries
 * ============================================================================
 */

int
SocketQUICTransport_is_connected (SocketQUICTransport_T t)
{
  return t && t->connected && !t->closed;
}

uint64_t
SocketQUICTransport_open_bidi_stream (SocketQUICTransport_T t)
{
  if (!t || !t->connected || t->closed)
    return UINT64_MAX;

  uint64_t id = t->next_bidi_id;
  t->next_bidi_id += 4;
  return id;
}

#endif /* SOCKET_HAS_TLS */
