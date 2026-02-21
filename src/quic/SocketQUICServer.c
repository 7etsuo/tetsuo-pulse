/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICServer.c
 * @brief QUIC server transport over UDP (RFC 9000).
 *
 * Multiplexes N QUIC connections over a single bound UDP socket.
 * Incoming packets are demuxed by DCID to route to the correct
 * per-connection state. Initial packets create new connections.
 */

#ifdef SOCKET_HAS_TLS

#include "quic/SocketQUICServer.h"

#include <arpa/inet.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "core/SocketUtil/Arithmetic.h"
#include "quic/SocketQUICAck.h"
#include "quic/SocketQUICConnection.h"
#include "quic/SocketQUICCrypto.h"
#include "quic/SocketQUICFlow.h"
#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICHandshake.h"
#include "quic/SocketQUICCongestion.h"
#include "quic/SocketQUICConstants.h"
#include "quic/SocketQUICError.h"
#include "quic/SocketQUICLoss.h"
#include "quic/SocketQUICPacket.h"
#include "quic/SocketQUICTLS.h"
#include "quic/SocketQUICTransportParams.h"
#include "quic/SocketQUICVarInt.h"
#include "quic/SocketQUICVersion.h"
#include "socket/SocketDgram.h"

#define SERVER_SEND_BUF_SIZE 1500
#define SERVER_RECV_BUF_SIZE SOCKET_QUIC_DEFAULT_RECV_BUF_SIZE
#define SERVER_MAX_STREAMS SOCKET_QUIC_DEFAULT_MAX_STREAMS
#define SERVER_MAX_STREAM_SEGMENTS SOCKET_QUIC_DEFAULT_MAX_STREAM_SEGMENTS
#define SERVER_SCID_LEN 8
#define SERVER_PN_LEN 4

typedef struct ServerStreamSegment
{
  uint64_t offset;
  uint64_t length;
  uint8_t *data;
  struct ServerStreamSegment *next;
} ServerStreamSegment_T;

typedef struct
{
  uint64_t stream_id;
  uint64_t send_offset;
  uint64_t recv_offset;
  uint64_t recv_highest;
  uint64_t final_size;
  ServerStreamSegment_T *segments;
  int segment_count;
  SocketQUICFlowStream_T flow_stream;
  int fin_received;
  int fin_delivered;
  int active;
} ServerStreamState;

struct QUICServerConn
{
  Arena_T arena;
  struct SocketQUICServer *server;

  /* QUIC protocol state */
  SocketQUICConnection_T conn;
  SocketQUICHandshake_T handshake;
  SocketQUICReceive_T recv_ctx;
  SocketQUICFlow_T flow;

  /* ACK generation (one per PN space) */
  SocketQUICAckState_T ack[QUIC_PN_SPACE_COUNT];

  /* Loss detection (one per PN space) */
  SocketQUICLossState_T loss[QUIC_PN_SPACE_COUNT];
  SocketQUICLossRTT_T rtt;

  /* Congestion control (RFC 9002 Section 7) */
  SocketQUICCongestion_T congestion;
  uint64_t prev_ecn_ce_count;

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

  /* Per-stream send offset tracking */
  ServerStreamState streams[SERVER_MAX_STREAMS];
  size_t stream_count;

  /* Connection IDs */
  SocketQUICConnectionID_T scid;
  SocketQUICConnectionID_T dcid;

  /* Peer address (for sendto) */
  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len;

  /* State */
  int connected;
  int closed;

  /* User data (for H3 layer to attach per-connection H3 state) */
  void *userdata;
};

struct SocketQUICServer
{
  Arena_T arena;
  SocketQUICServerConfig config;

  /* Bound UDP socket */
  SocketDgram_T socket;

  /* Connection list (simple array for V1) */
  QUICServerConn_T *connections;
  size_t conn_count;
  size_t conn_capacity;

  /* Shared buffers */
  uint8_t *send_buf;
  uint8_t *recv_buf;

  /* Callbacks */
  SocketQUICServer_ConnCB conn_cb;
  SocketQUICServer_StreamCB stream_cb;
  void *cb_userdata;

  /* State */
  int listening;
  int closed;
};


static void conn_close_with_error (QUICServerConn_T c,
                                   uint64_t error_code,
                                   uint64_t frame_type,
                                   const char *reason);

static uint64_t
peer_initial_stream_send_max (const SocketQUICTransportParams_T *peer_params,
                              uint64_t stream_id);

static int
server_sendto (SocketQUICServer_T server,
               const uint8_t *data,
               size_t len,
               const struct sockaddr *addr,
               socklen_t addr_len)
{
  int fd = SocketDgram_fd (server->socket);
  ssize_t sent = sendto (fd, data, len, 0, addr, addr_len);
  return sent >= 0 ? 0 : -1;
}

static ssize_t
server_recvfrom (SocketQUICServer_T server,
                 uint8_t *buf,
                 size_t len,
                 struct sockaddr_storage *addr,
                 socklen_t *addr_len)
{
  int fd = SocketDgram_fd (server->socket);
  *addr_len = sizeof (*addr);
  return recvfrom (fd, buf, len, 0, (struct sockaddr *)addr, addr_len);
}

static int
conn_send_packet (QUICServerConn_T c, const uint8_t *data, size_t len)
{
  return server_sendto (c->server,
                        data,
                        len,
                        (const struct sockaddr *)&c->peer_addr,
                        c->peer_addr_len);
}

static ServerStreamState *
conn_find_or_create_stream (QUICServerConn_T c, uint64_t stream_id)
{
  for (size_t i = 0; i < c->stream_count; i++)
    {
      if (c->streams[i].active && c->streams[i].stream_id == stream_id)
        return &c->streams[i];
    }

  if (c->stream_count >= SERVER_MAX_STREAMS)
    return NULL;

  ServerStreamState *s = &c->streams[c->stream_count++];
  memset (s, 0, sizeof (*s));
  s->stream_id = stream_id;
  s->send_offset = 0;
  s->recv_offset = 0;
  s->recv_highest = 0;
  s->final_size = UINT64_MAX;
  s->segments = NULL;
  s->segment_count = 0;
  s->fin_received = 0;
  s->fin_delivered = 0;
  s->active = 1;

  if (c->server->config.max_stream_data <= SIZE_MAX)
    {
      s->flow_stream = SocketQUICFlowStream_new (c->arena, stream_id);
      if (s->flow_stream)
        {
          SocketQUICFlowStream_init (
              s->flow_stream, stream_id, c->server->config.max_stream_data, 0);

          const SocketQUICTransportParams_T *peer_params = NULL;
          if (c->handshake)
            peer_params = SocketQUICHandshake_get_peer_params (c->handshake);
          if (peer_params)
            SocketQUICFlowStream_update_send_max (
                s->flow_stream,
                peer_initial_stream_send_max (peer_params, stream_id));
        }
    }

  return s;
}

static int
server_stream_deliver_chunk (QUICServerConn_T c,
                             ServerStreamState *s,
                             const uint8_t *data,
                             uint64_t length,
                             int *events)
{
  uint64_t new_offset;
  if (!socket_util_safe_add_u64 (s->recv_offset, length, &new_offset))
    return -1;

  int fin = 0;
  if (s->fin_received && !s->fin_delivered && s->final_size != UINT64_MAX
      && new_offset == s->final_size)
    {
      fin = 1;
      s->fin_delivered = 1;
    }

  if (c->server->stream_cb)
    {
      c->server->stream_cb (
          c, s->stream_id, data, (size_t)length, fin, c->server->cb_userdata);
      if (events)
        (*events)++;
    }

  s->recv_offset = new_offset;
  return 0;
}

static int
server_stream_buffer_segment (QUICServerConn_T c,
                              ServerStreamState *s,
                              uint64_t offset,
                              const uint8_t *data,
                              uint64_t length)
{
  if (length == 0)
    return 0;
  if (!data)
    return -1;
  if (s->segment_count >= SERVER_MAX_STREAM_SEGMENTS)
    return -1;
  if (length > SIZE_MAX)
    return -1;

  ServerStreamSegment_T *seg
      = Arena_alloc (c->arena, sizeof (*seg), __FILE__, __LINE__);
  memset (seg, 0, sizeof (*seg));
  seg->offset = offset;
  seg->length = length;
  seg->data = Arena_alloc (c->arena, (size_t)length, __FILE__, __LINE__);
  memcpy (seg->data, data, (size_t)length);

  seg->next = s->segments;
  s->segments = seg;
  s->segment_count++;
  return 0;
}

static int
server_stream_process_buffered (QUICServerConn_T c,
                                ServerStreamState *s,
                                int *events)
{
  int progress;
  do
    {
      progress = 0;
      ServerStreamSegment_T **prev = &s->segments;
      ServerStreamSegment_T *seg = s->segments;

      while (seg)
        {
          uint64_t seg_end;
          if (!socket_util_safe_add_u64 (seg->offset, seg->length, &seg_end))
            return -1;

          if (seg_end <= s->recv_offset)
            {
              *prev = seg->next;
              s->segment_count--;
              progress = 1;
              seg = *prev;
              continue;
            }

          if (seg->offset <= s->recv_offset && seg_end > s->recv_offset)
            {
              uint64_t skip = s->recv_offset - seg->offset;
              uint64_t deliver_len = seg_end - s->recv_offset;

              if (skip > SIZE_MAX || deliver_len > SIZE_MAX)
                return -1;

              const uint8_t *deliver_data = seg->data + (size_t)skip;
              if (server_stream_deliver_chunk (
                      c, s, deliver_data, deliver_len, events)
                  < 0)
                return -1;

              *prev = seg->next;
              s->segment_count--;
              progress = 1;
              seg = *prev;
              continue;
            }

          prev = &seg->next;
          seg = seg->next;
        }
    }
  while (progress);

  if (s->fin_received && !s->fin_delivered && s->final_size != UINT64_MAX
      && s->recv_offset == s->final_size)
    {
      if (c->server->stream_cb)
        {
          c->server->stream_cb (
              c, s->stream_id, NULL, 0, 1, c->server->cb_userdata);
          if (events)
            (*events)++;
        }
      s->fin_delivered = 1;
    }

  return 0;
}

static int
validate_stream_access (QUICServerConn_T c,
                        uint64_t stream_id,
                        uint64_t frame_type,
                        ServerStreamState **out)
{
  int initiator = (int)(stream_id & 0x01);
  int is_uni = (stream_id & 0x02) != 0;
  uint64_t seq = stream_id >> 2;

  if (initiator == 0)
    {
      uint64_t max_streams
          = is_uni ? 3 : c->server->config.initial_max_streams_bidi;
      if (seq >= max_streams)
        {
          conn_close_with_error (c,
                                 QUIC_STREAM_LIMIT_ERROR,
                                 frame_type,
                                 "Peer exceeded stream limit");
          return -1;
        }
    }

  if (is_uni && initiator == 1)
    {
      conn_close_with_error (c,
                             QUIC_STREAM_STATE_ERROR,
                             frame_type,
                             "STREAM on local unidirectional stream");
      return -1;
    }

  *out = conn_find_or_create_stream (c, stream_id);
  if (!*out)
    {
      conn_close_with_error (
          c, QUIC_STREAM_LIMIT_ERROR, frame_type, "Too many active streams");
      return -1;
    }

  return 0;
}

static int
validate_stream_offsets (QUICServerConn_T c,
                         ServerStreamState *s,
                         const SocketQUICFrameStream_T *sf,
                         uint64_t frame_type,
                         uint64_t *out_end)
{
  if (!socket_util_safe_add_u64 (sf->offset, sf->length, out_end))
    {
      conn_close_with_error (
          c, QUIC_FRAME_ENCODING_ERROR, frame_type, "STREAM offset overflow");
      return -1;
    }

  if (sf->has_fin)
    {
      if (s->fin_received && s->final_size != *out_end)
        {
          conn_close_with_error (
              c, QUIC_FINAL_SIZE_ERROR, frame_type, "Conflicting final size");
          return -1;
        }
      s->fin_received = 1;
      s->final_size = *out_end;
    }
  else if (s->fin_received && *out_end > s->final_size)
    {
      conn_close_with_error (
          c, QUIC_FINAL_SIZE_ERROR, frame_type, "Data exceeds final size");
      return -1;
    }

  if (*out_end > s->recv_highest)
    {
      uint64_t delta = *out_end - s->recv_highest;
      s->recv_highest = *out_end;

      if (delta > SIZE_MAX)
        {
          conn_close_with_error (
              c, QUIC_FLOW_CONTROL_ERROR, frame_type, "Flow delta overflow");
          return -1;
        }

      if (s->flow_stream
          && SocketQUICFlowStream_consume_recv (s->flow_stream, (size_t)delta)
                 != QUIC_FLOW_OK)
        {
          conn_close_with_error (c,
                                 QUIC_FLOW_CONTROL_ERROR,
                                 frame_type,
                                 "Stream flow control exceeded");
          return -1;
        }

      if (c->flow
          && SocketQUICFlow_consume_recv (c->flow, (size_t)delta)
                 != QUIC_FLOW_OK)
        {
          conn_close_with_error (c,
                                 QUIC_FLOW_CONTROL_ERROR,
                                 frame_type,
                                 "Connection flow control exceeded");
          return -1;
        }
    }

  return 0;
}

static int
deliver_stream_data (QUICServerConn_T c,
                     ServerStreamState *s,
                     const SocketQUICFrameStream_T *sf,
                     uint64_t frame_type,
                     int *events)
{
  uint64_t offset = sf->offset;
  uint64_t length = sf->length;
  const uint8_t *data = sf->data;

  if (offset < s->recv_offset)
    {
      uint64_t overlap = s->recv_offset - offset;
      if (overlap >= length)
        return server_stream_process_buffered (c, s, events);

      if (overlap > SIZE_MAX)
        return -1;
      data += (size_t)overlap;
      offset = s->recv_offset;
      length -= overlap;
    }

  if (offset == s->recv_offset && length > 0)
    {
      if (server_stream_deliver_chunk (c, s, data, length, events) < 0)
        return -1;
    }
  else if (length > 0)
    {
      if (server_stream_buffer_segment (c, s, offset, data, length) < 0)
        {
          conn_close_with_error (c,
                                 QUIC_PROTOCOL_VIOLATION,
                                 frame_type,
                                 "Too many buffered stream segments");
          return -1;
        }
    }

  return server_stream_process_buffered (c, s, events);
}

static int
handle_server_stream_frame (QUICServerConn_T c,
                            const SocketQUICFrameStream_T *sf,
                            uint64_t frame_type,
                            int *events)
{
  if (!c || !sf)
    return -1;

  ServerStreamState *s;
  if (validate_stream_access (c, sf->stream_id, frame_type, &s) < 0)
    return -1;

  uint64_t end;
  if (validate_stream_offsets (c, s, sf, frame_type, &end) < 0)
    return -1;

  return deliver_stream_data (c, s, sf, frame_type, events);
}

static uint64_t
peer_initial_stream_send_max (const SocketQUICTransportParams_T *peer_params,
                              uint64_t stream_id)
{
  if (!peer_params)
    return 0;

  /* Server transport: local-initiated streams have initiator bit 1. */
  int initiator = (int)(stream_id & 0x01);
  int is_uni = (stream_id & 0x02) != 0;

  if (is_uni)
    return initiator == 1 ? peer_params->initial_max_stream_data_uni : 0;

  return initiator == 1 ? peer_params->initial_max_stream_data_bidi_remote
                        : peer_params->initial_max_stream_data_bidi_local;
}

static int
build_and_send_1rtt_ex (QUICServerConn_T c,
                        const uint8_t *payload,
                        size_t payload_len,
                        int ack_eliciting,
                        int in_flight)
{
  if (!c->app_keys_valid)
    return -1;

  uint8_t *send_buf = c->server->send_buf;
  uint64_t pn = c->next_pn[QUIC_PN_SPACE_APPLICATION];
  uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, SERVER_PN_LEN);

  SocketQUICPacketHeader_T hdr;
  SocketQUICPacketHeader_init (&hdr);
  if (SocketQUICPacketHeader_build_short (&hdr,
                                          &c->dcid,
                                          0,
                                          c->key_update.key_phase,
                                          SERVER_PN_LEN,
                                          truncated_pn)
      != QUIC_PACKET_OK)
    return -1;

  size_t hdr_len
      = SocketQUICPacketHeader_serialize (&hdr, send_buf, SERVER_SEND_BUF_SIZE);
  if (hdr_len == 0)
    return -1;

  size_t pn_offset = hdr_len - SERVER_PN_LEN;

  if (hdr_len + payload_len + 16 > SERVER_SEND_BUF_SIZE)
    return -1;
  memcpy (send_buf + hdr_len, payload, payload_len);

  size_t ciphertext_len = SERVER_SEND_BUF_SIZE - hdr_len;
  if (SocketQUICCrypto_encrypt_payload (&c->app_send_keys,
                                        pn,
                                        send_buf,
                                        hdr_len,
                                        send_buf + hdr_len,
                                        payload_len,
                                        send_buf + hdr_len,
                                        &ciphertext_len)
      != QUIC_CRYPTO_OK)
    return -1;

  size_t pkt_len = hdr_len + ciphertext_len;

  /* Congestion window check (only for in-flight packets) */
  if (in_flight && c->congestion)
    {
      size_t bif
          = SocketQUICLoss_bytes_in_flight (c->loss[QUIC_PN_SPACE_APPLICATION]);
      if (!SocketQUICCongestion_can_send (c->congestion, bif, pkt_len))
        return -1;
    }

  if (SocketQUICCrypto_protect_header_ex (
          &c->app_send_keys, send_buf, pkt_len, pn_offset)
      != QUIC_CRYPTO_OK)
    return -1;

  /* Bound unacked tracking to avoid unbounded memory growth. */
  if (c->loss[QUIC_PN_SPACE_APPLICATION]
      && c->loss[QUIC_PN_SPACE_APPLICATION]->sent_count
             >= QUIC_LOSS_MAX_SENT_PACKETS)
    return -1;

  if (conn_send_packet (c, send_buf, pkt_len) < 0)
    return -1;

  /* Record sent packet for loss detection (RFC 9002) */
  uint64_t sent_time = Socket_get_monotonic_us ();
  if (SocketQUICLoss_on_packet_sent (c->loss[QUIC_PN_SPACE_APPLICATION],
                                     pn,
                                     sent_time,
                                     pkt_len,
                                     ack_eliciting,
                                     in_flight,
                                     0)
      != QUIC_LOSS_OK)
    return -1;

  c->next_pn[QUIC_PN_SPACE_APPLICATION]++;
  return 0;
}

static int
build_and_send_1rtt (QUICServerConn_T c,
                     const uint8_t *payload,
                     size_t payload_len)
{
  return build_and_send_1rtt_ex (c, payload, payload_len, 1, 1);
}

static void
conn_close_with_error (QUICServerConn_T c,
                       uint64_t error_code,
                       uint64_t frame_type,
                       const char *reason)
{
  if (!c || c->closed)
    return;

  if (c->app_keys_valid)
    {
      uint8_t close_buf[128];
      size_t close_len = SocketQUICFrame_encode_connection_close_transport (
          error_code, frame_type, reason, close_buf, sizeof (close_buf));
      if (close_len > 0)
        build_and_send_1rtt_ex (c, close_buf, close_len, 0, 0);
    }

  c->closed = 1;
  c->connected = 0;
}

static int
conn_send_ack_if_needed (QUICServerConn_T c,
                         SocketQUIC_PNSpace space,
                         uint64_t now)
{
  if (!c->ack[space])
    return 0;
  if (!SocketQUICAck_should_send (c->ack[space], now))
    return 0;

  uint8_t ack_buf[256];
  size_t ack_len = 0;
  if (SocketQUICAck_encode (
          c->ack[space], now, ack_buf, sizeof (ack_buf), &ack_len)
      != QUIC_ACK_OK)
    return -1;

  if (ack_len == 0)
    return 0;

  int rc = -1;
  if (space == QUIC_PN_SPACE_APPLICATION && c->app_keys_valid)
    rc = build_and_send_1rtt_ex (c, ack_buf, ack_len, 0, 0);

  if (rc == 0)
    SocketQUICAck_mark_sent (c->ack[space], now);

  return rc;
}

static void
server_acked_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  SocketQUICCongestion_AckCtx *sc = ctx;
  if (pkt->in_flight)
    sc->acked_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > sc->latest_acked_sent_time)
    sc->latest_acked_sent_time = pkt->sent_time_us;
}

static void
server_lost_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  SocketQUICCongestion_AckCtx *sc = ctx;
  if (pkt->in_flight)
    sc->lost_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > sc->latest_lost_sent_time)
    sc->latest_lost_sent_time = pkt->sent_time_us;
}

static void
process_ack_frame (QUICServerConn_T c,
                   const SocketQUICFrame_T *frame,
                   SocketQUIC_PNSpace space,
                   uint64_t now)
{
  if (!c->loss[space])
    return;

  SocketQUICCongestion_AckCtx actx = { 0 };
  size_t acked_count = 0, lost_count = 0;

  SocketQUICLoss_on_ack_received (c->loss[space],
                                  &c->rtt,
                                  &frame->data.ack,
                                  now,
                                  server_acked_cb,
                                  server_lost_cb,
                                  &actx,
                                  &acked_count,
                                  &lost_count);

  if (space == QUIC_PN_SPACE_APPLICATION)
    SocketQUICCongestion_process_ack (c->congestion,
                                      &actx,
                                      &c->rtt,
                                      c->loss[space],
                                      frame->data.ack.ecn_ce_count,
                                      frame->type == QUIC_FRAME_ACK_ECN,
                                      lost_count,
                                      &c->prev_ecn_ce_count);
}

static void
process_crypto_frame (QUICServerConn_T c,
                      const SocketQUICFrame_T *frame,
                      SocketQUIC_PNSpace space)
{
  SocketQUICCryptoLevel level;
  if (space == QUIC_PN_SPACE_INITIAL)
    level = QUIC_CRYPTO_LEVEL_INITIAL;
  else if (space == QUIC_PN_SPACE_HANDSHAKE)
    level = QUIC_CRYPTO_LEVEL_HANDSHAKE;
  else
    level = QUIC_CRYPTO_LEVEL_APPLICATION;

  SocketQUICTLS_provide_data (c->handshake,
                              level,
                              frame->data.crypto.data,
                              (size_t)frame->data.crypto.length);
}

static int
conn_process_frames (QUICServerConn_T c,
                     const uint8_t *payload,
                     size_t payload_len,
                     SocketQUICPacket_Type pkt_type,
                     SocketQUIC_PNSpace space,
                     uint64_t now)
{
  size_t offset = 0;
  int events = 0;
  int pkt_flags = SocketQUICFrame_packet_type_to_flags (pkt_type);

  while (offset < payload_len)
    {
      SocketQUICFrame_T frame;
      SocketQUICFrame_init (&frame);
      size_t consumed = 0;
      SocketQUICFrame_Result fr = SocketQUICFrame_parse_arena (
          NULL, payload + offset, payload_len - offset, &frame, &consumed);
      if (fr != QUIC_FRAME_OK)
        {
          SocketQUICFrame_free (&frame);
          break;
        }

      offset += consumed;

      if (SocketQUICFrame_validate (&frame, pkt_flags) != QUIC_FRAME_OK)
        {
          conn_close_with_error (c,
                                 QUIC_PROTOCOL_VIOLATION,
                                 frame.type,
                                 "Frame not allowed in packet type");
          SocketQUICFrame_free (&frame);
          return -1;
        }

      switch (frame.type)
        {
        case QUIC_FRAME_PADDING:
        case QUIC_FRAME_PING:
          break;

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
          process_ack_frame (c, &frame, space, now);
          break;

        case QUIC_FRAME_CRYPTO:
          process_crypto_frame (c, &frame, space);
          break;

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
          c->closed = 1;
          c->connected = 0;
          SocketQUICFrame_free (&frame);
          return -1;

        case QUIC_FRAME_MAX_DATA:
          if (c->flow)
            SocketQUICFlow_update_send_max (c->flow,
                                            frame.data.max_data.max_data);
          break;

        case QUIC_FRAME_MAX_STREAM_DATA:
          {
            ServerStreamState *s = conn_find_or_create_stream (
                c, frame.data.max_stream_data.stream_id);
            if (s && s->flow_stream)
              SocketQUICFlowStream_update_send_max (
                  s->flow_stream, frame.data.max_stream_data.max_data);
          }
          break;

        case QUIC_FRAME_MAX_STREAMS_BIDI:
          if (c->flow)
            SocketQUICFlow_update_max_streams_bidi (
                c->flow, frame.data.max_streams.max_streams);
          break;

        case QUIC_FRAME_MAX_STREAMS_UNI:
          if (c->flow)
            SocketQUICFlow_update_max_streams_uni (
                c->flow, frame.data.max_streams.max_streams);
          break;

        default:
          if (SocketQUICFrame_is_stream (frame.type))
            {
              if (handle_server_stream_frame (
                      c, &frame.data.stream, frame.type, &events)
                  < 0)
                {
                  SocketQUICFrame_free (&frame);
                  return -1;
                }
            }
          break;
        }

      SocketQUICFrame_free (&frame);
    }

  return events;
}

static int
conn_send_crypto_data (QUICServerConn_T c,
                       SocketQUICCryptoLevel level,
                       const uint8_t *data,
                       size_t len,
                       uint64_t crypto_offset)
{
  uint8_t *send_buf = c->server->send_buf;
  uint8_t frame_buf[SERVER_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_crypto (
      crypto_offset, data, len, frame_buf, sizeof (frame_buf));
  if (frame_len == 0)
    return -1;

  if (level == QUIC_CRYPTO_LEVEL_INITIAL)
    {
      uint64_t pn = c->next_pn[QUIC_PN_SPACE_INITIAL];
      uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, SERVER_PN_LEN);

      SocketQUICPacketHeader_T hdr;
      SocketQUICPacketHeader_init (&hdr);
      SocketQUICPacketHeader_build_initial (&hdr,
                                            QUIC_VERSION_1,
                                            &c->dcid,
                                            &c->scid,
                                            NULL,
                                            0,
                                            SERVER_PN_LEN,
                                            truncated_pn);

      size_t hdr_len = SocketQUICPacketHeader_serialize (
          &hdr, send_buf, SERVER_SEND_BUF_SIZE);
      if (hdr_len == 0)
        return -1;

      memcpy (send_buf + hdr_len, frame_buf, frame_len);
      size_t pkt_len = hdr_len + frame_len;

      /* Server Initial packets don't need 1200-byte padding */

      if (SocketQUICInitial_protect (
              send_buf, &pkt_len, hdr_len, &c->initial_keys, 0)
          != QUIC_INITIAL_OK)
        return -1;

      if (conn_send_packet (c, send_buf, pkt_len) < 0)
        return -1;

      c->next_pn[QUIC_PN_SPACE_INITIAL]++;
    }
  else if (level == QUIC_CRYPTO_LEVEL_HANDSHAKE)
    {
      if (!c->handshake_keys_valid)
        return -1;

      uint64_t pn = c->next_pn[QUIC_PN_SPACE_HANDSHAKE];
      uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, SERVER_PN_LEN);

      SocketQUICPacketHeader_T hdr;
      SocketQUICPacketHeader_init (&hdr);
      SocketQUICPacketHeader_build_handshake (&hdr,
                                              QUIC_VERSION_1,
                                              &c->dcid,
                                              &c->scid,
                                              SERVER_PN_LEN,
                                              truncated_pn);

      size_t hdr_len = SocketQUICPacketHeader_serialize (
          &hdr, send_buf, SERVER_SEND_BUF_SIZE);
      if (hdr_len == 0)
        return -1;

      size_t pn_offset = hdr_len - SERVER_PN_LEN;
      memcpy (send_buf + hdr_len, frame_buf, frame_len);

      size_t ciphertext_len = SERVER_SEND_BUF_SIZE - hdr_len;
      if (SocketQUICCrypto_encrypt_payload (&c->handshake_send_keys,
                                            pn,
                                            send_buf,
                                            hdr_len,
                                            send_buf + hdr_len,
                                            frame_len,
                                            send_buf + hdr_len,
                                            &ciphertext_len)
          != QUIC_CRYPTO_OK)
        return -1;

      size_t pkt_len = hdr_len + ciphertext_len;

      if (SocketQUICCrypto_protect_header_ex (
              &c->handshake_send_keys, send_buf, pkt_len, pn_offset)
          != QUIC_CRYPTO_OK)
        return -1;

      if (conn_send_packet (c, send_buf, pkt_len) < 0)
        return -1;

      SocketQUICHandshake_on_handshake_packet_sent (c->handshake);
      c->next_pn[QUIC_PN_SPACE_HANDSHAKE]++;
    }
  else if (level == QUIC_CRYPTO_LEVEL_APPLICATION)
    {
      return build_and_send_1rtt (c, frame_buf, frame_len);
    }

  return 0;
}

static int
conn_flush_tls_output (QUICServerConn_T c)
{
  SocketQUICCryptoLevel level;
  const uint8_t *data;
  size_t len;

  while (SocketQUICTLS_get_data (c->handshake, &level, &data, &len)
         == QUIC_TLS_OK)
    {
      uint64_t offset = c->handshake->crypto_streams[level].send_offset;

      if (conn_send_crypto_data (c, level, data, len, offset) < 0)
        {
          SocketQUICTLS_consume_data (c->handshake, level, len);
          return -1;
        }

      c->handshake->crypto_streams[level].send_offset += len;
      SocketQUICTLS_consume_data (c->handshake, level, len);
    }

  return 0;
}

static void
conn_check_and_derive_keys (QUICServerConn_T c)
{
  uint8_t write_secret[SOCKET_CRYPTO_SHA256_SIZE];
  uint8_t read_secret[SOCKET_CRYPTO_SHA256_SIZE];
  size_t secret_len = 0;

  /* Handshake keys */
  if (!c->handshake_keys_valid
      && SocketQUICHandshake_has_keys (c->handshake,
                                       QUIC_CRYPTO_LEVEL_HANDSHAKE))
    {
      if (SocketQUICTLS_get_traffic_secrets (c->handshake,
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
                                               &c->handshake_send_keys);
          SocketQUICCrypto_derive_packet_keys (
              read_secret, secret_len, QUIC_AEAD_AES_128_GCM, &hs_read_keys);
          SocketQUICReceive_set_handshake_keys (&c->recv_ctx, &hs_read_keys);
          c->handshake_keys_valid = 1;
        }
    }

  /* Application (1-RTT) keys */
  if (!c->app_keys_valid
      && SocketQUICHandshake_has_keys (c->handshake,
                                       QUIC_CRYPTO_LEVEL_APPLICATION))
    {
      if (SocketQUICTLS_get_traffic_secrets (c->handshake,
                                             QUIC_CRYPTO_LEVEL_APPLICATION,
                                             write_secret,
                                             read_secret,
                                             &secret_len)
          == QUIC_TLS_OK)
        {
          SocketQUICCrypto_derive_packet_keys (write_secret,
                                               secret_len,
                                               QUIC_AEAD_AES_128_GCM,
                                               &c->app_send_keys);
          SocketQUICKeyUpdate_set_initial_keys (&c->key_update,
                                                write_secret,
                                                read_secret,
                                                secret_len,
                                                QUIC_AEAD_AES_128_GCM);
          SocketQUICReceive_set_1rtt_keys (&c->recv_ctx, &c->key_update);
          c->app_keys_valid = 1;
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

static QUICServerConn_T
find_conn_by_dcid (SocketQUICServer_T server,
                   const uint8_t *dcid_data,
                   size_t dcid_len)
{
  for (size_t i = 0; i < server->conn_count; i++)
    {
      QUICServerConn_T c = server->connections[i];
      if (c && !c->closed && c->scid.len == dcid_len
          && memcmp (c->scid.data, dcid_data, dcid_len) == 0)
        return c;
    }
  return NULL;
}

static void
conn_apply_peer_transport_params (QUICServerConn_T c)
{
  const SocketQUICTransportParams_T *peer_params
      = SocketQUICHandshake_get_peer_params (c->handshake);
  if (!peer_params)
    return;

  if (c->flow)
    {
      SocketQUICFlow_update_send_max (c->flow, peer_params->initial_max_data);
      SocketQUICFlow_update_max_streams_bidi (
          c->flow, peer_params->initial_max_streams_bidi);
      SocketQUICFlow_update_max_streams_uni (
          c->flow, peer_params->initial_max_streams_uni);
    }

  for (size_t i = 0; i < c->stream_count; i++)
    {
      if (!c->streams[i].active || !c->streams[i].flow_stream)
        continue;
      uint64_t max_data
          = peer_initial_stream_send_max (peer_params, c->streams[i].stream_id);
      SocketQUICFlowStream_update_send_max (c->streams[i].flow_stream,
                                            max_data);
    }
}

static int
parse_initial_cids (const uint8_t *pkt,
                    size_t pkt_len,
                    const uint8_t **dcid_data,
                    uint8_t *dcid_len,
                    const uint8_t **scid_data,
                    uint8_t *scid_len)
{
  if (pkt_len < 7)
    return -1;

  size_t pos = 5;
  *dcid_len = pkt[pos++];
  if (pos + *dcid_len > pkt_len)
    return -1;
  *dcid_data = pkt + pos;
  pos += *dcid_len;

  if (pos >= pkt_len)
    return -1;
  *scid_len = pkt[pos++];
  if (pos + *scid_len > pkt_len)
    return -1;
  *scid_data = pkt + pos;

  return 0;
}

static int
init_conn_handshake_tls (QUICServerConn_T c,
                         SocketQUICServer_T server,
                         const uint8_t *dcid_data,
                         uint8_t dcid_len)
{
  c->conn = SocketQUICConnection_new (c->arena, QUIC_CONN_ROLE_SERVER);
  if (!c->conn)
    return -1;

  SocketQUICConnection_add_local_cid (c->conn, &c->scid);
  SocketQUICConnection_add_peer_cid (c->conn, &c->dcid);

  SocketQUICConnectionID_T client_initial_dcid;
  client_initial_dcid.len = dcid_len;
  if (dcid_len > 0)
    memcpy (client_initial_dcid.data, dcid_data, dcid_len);
  c->conn->initial_dcid = client_initial_dcid;

  c->handshake
      = SocketQUICHandshake_new (c->arena, c->conn, QUIC_CONN_ROLE_SERVER);
  if (!c->handshake)
    return -1;

  SocketQUICTransportParams_T local_params;
  memset (&local_params, 0, sizeof (local_params));
  local_params.max_idle_timeout = server->config.idle_timeout_ms;
  local_params.initial_max_data = server->config.initial_max_data;
  local_params.initial_max_stream_data_bidi_local
      = server->config.max_stream_data;
  local_params.initial_max_stream_data_bidi_remote
      = server->config.max_stream_data;
  local_params.initial_max_stream_data_uni = server->config.max_stream_data;
  local_params.initial_max_streams_bidi
      = server->config.initial_max_streams_bidi;
  local_params.initial_max_streams_uni = 3;

  SocketQUICHandshake_set_transport_params (c->handshake, &local_params);

  SocketQUICTLSConfig_T tls_config;
  memset (&tls_config, 0, sizeof (tls_config));
  tls_config.alpn = server->config.alpn ? server->config.alpn : "h3";
  tls_config.cert_file = server->config.cert_file;
  tls_config.key_file = server->config.key_file;

  if (SocketQUICTLS_init_context (c->handshake, &tls_config) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_create_ssl (c->handshake) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_set_local_transport_params (c->handshake) != QUIC_TLS_OK)
    return -1;

  if (SocketQUICCrypto_derive_initial_keys (
          &client_initial_dcid, QUIC_VERSION_1, &c->initial_keys)
      != QUIC_CRYPTO_OK)
    return -1;

  return 0;
}

static void
init_conn_protocol_state (QUICServerConn_T c, SocketQUICServer_T server)
{
  SocketQUICReceive_init (&c->recv_ctx);
  SocketQUICReceive_set_initial_keys (&c->recv_ctx, &c->initial_keys);

  c->ack[QUIC_PN_SPACE_INITIAL] = SocketQUICAck_new (c->arena, 1, 0);
  c->ack[QUIC_PN_SPACE_HANDSHAKE] = SocketQUICAck_new (c->arena, 1, 0);
  c->ack[QUIC_PN_SPACE_APPLICATION]
      = SocketQUICAck_new (c->arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);

  c->loss[QUIC_PN_SPACE_INITIAL] = SocketQUICLoss_new (c->arena, 1, 0);
  c->loss[QUIC_PN_SPACE_HANDSHAKE] = SocketQUICLoss_new (c->arena, 1, 0);
  c->loss[QUIC_PN_SPACE_APPLICATION]
      = SocketQUICLoss_new (c->arena, 0, QUIC_ACK_DEFAULT_MAX_DELAY_US);

  SocketQUICLoss_init_rtt (&c->rtt);
  SocketQUICKeyUpdate_init (&c->key_update);
  c->congestion = SocketQUICCongestion_new (c->arena, QUIC_MAX_DATAGRAM_SIZE);

  c->flow = SocketQUICFlow_new (c->arena);
  if (c->flow)
    SocketQUICFlow_init (c->flow, server->config.initial_max_data, 0, 0, 0);
}

static int
initial_decrypt_and_process (QUICServerConn_T c,
                             const uint8_t *pkt,
                             size_t pkt_len)
{
  SocketQUICReceiveResult_T result;
  memset (&result, 0, sizeof (result));
  SocketQUICReceive_Result recv_rc = SocketQUICReceive_packet (
      &c->recv_ctx, (uint8_t *)pkt, pkt_len, c->scid.len, 0, &result);

  if (recv_rc != QUIC_RECEIVE_OK)
    return -1;

  uint64_t now = Socket_get_monotonic_us ();
  if (c->ack[result.pn_space])
    SocketQUICAck_record_packet (
        c->ack[result.pn_space], result.packet_number, now, 1);

  int init_events = conn_process_frames (
      c, result.payload, result.payload_len, result.type, result.pn_space, now);
  if (init_events < 0)
    return -1;

  SocketQUICTLS_do_handshake (c->handshake);
  conn_check_and_derive_keys (c);
  conn_flush_tls_output (c);

  now = Socket_get_monotonic_us ();
  for (int space = 0; space < QUIC_PN_SPACE_COUNT; space++)
    conn_send_ack_if_needed (c, (SocketQUIC_PNSpace)space, now);

  if (SocketQUICTLS_is_complete (c->handshake))
    {
      conn_check_and_derive_keys (c);
      conn_apply_peer_transport_params (c);

      if (c->app_keys_valid)
        {
          uint8_t hd_frame[1] = { QUIC_FRAME_HANDSHAKE_DONE };
          build_and_send_1rtt (c, hd_frame, 1);
        }

      c->connected = 1;
    }

  return 0;
}

static QUICServerConn_T
handle_initial_packet (SocketQUICServer_T server,
                       const uint8_t *pkt,
                       size_t pkt_len,
                       const struct sockaddr_storage *peer_addr,
                       socklen_t peer_addr_len)
{
  if (server->conn_count >= server->conn_capacity)
    return NULL;

  const uint8_t *dcid_data;
  const uint8_t *scid_data;
  uint8_t dcid_len, scid_len;
  if (parse_initial_cids (
          pkt, pkt_len, &dcid_data, &dcid_len, &scid_data, &scid_len)
      < 0)
    return NULL;

  Arena_T conn_arena = Arena_new ();

  QUICServerConn_T c
      = Arena_alloc (conn_arena, sizeof (*c), __FILE__, __LINE__);
  memset (c, 0, sizeof (*c));
  c->arena = conn_arena;
  c->server = server;

  c->scid.len = dcid_len;
  if (dcid_len > 0)
    memcpy (c->scid.data, dcid_data, dcid_len);

  c->dcid.len = scid_len;
  if (scid_len > 0)
    memcpy (c->dcid.data, scid_data, scid_len);

  memcpy (&c->peer_addr, peer_addr, peer_addr_len);
  c->peer_addr_len = peer_addr_len;

  if (init_conn_handshake_tls (c, server, dcid_data, dcid_len) < 0)
    {
      Arena_dispose (&conn_arena);
      return NULL;
    }

  init_conn_protocol_state (c, server);

  if (initial_decrypt_and_process (c, pkt, pkt_len) < 0)
    {
      Arena_dispose (&conn_arena);
      return NULL;
    }

  server->connections[server->conn_count++] = c;

  return c;
}

static int
handle_existing_conn_packet (QUICServerConn_T c,
                             const uint8_t *pkt,
                             size_t pkt_len)
{
  SocketQUICReceiveResult_T result;
  memset (&result, 0, sizeof (result));
  SocketQUICReceive_Result recv_rc = SocketQUICReceive_packet (
      &c->recv_ctx, (uint8_t *)pkt, pkt_len, c->scid.len, 0, &result);

  if (recv_rc != QUIC_RECEIVE_OK)
    return 0;

  uint64_t now = Socket_get_monotonic_us ();

  /* Record PN for ACK */
  if (c->ack[result.pn_space])
    SocketQUICAck_record_packet (
        c->ack[result.pn_space], result.packet_number, now, 1);

  /* Process frames */
  int events = conn_process_frames (
      c, result.payload, result.payload_len, result.type, result.pn_space, now);

  if (events < 0 && !c->closed)
    {
      conn_close_with_error (
          c, QUIC_PROTOCOL_VIOLATION, 0, "Frame processing error");
      return -1;
    }

  if (c->closed)
    return events;

  /* Continue handshake if not complete */
  if (!SocketQUICTLS_is_complete (c->handshake))
    {
      SocketQUICTLS_do_handshake (c->handshake);
      conn_check_and_derive_keys (c);
      conn_flush_tls_output (c);

      if (SocketQUICTLS_is_complete (c->handshake) && !c->connected)
        {
          conn_check_and_derive_keys (c);
          SocketQUICTLS_get_peer_params (c->handshake);
          conn_apply_peer_transport_params (c);

          if (c->app_keys_valid)
            {
              uint8_t hd_frame[1] = { QUIC_FRAME_HANDSHAKE_DONE };
              build_and_send_1rtt (c, hd_frame, 1);
            }

          c->connected = 1;

          if (c->server->conn_cb)
            c->server->conn_cb (c, c->server->cb_userdata);
        }
    }

  /* Send ACKs */
  now = Socket_get_monotonic_us ();
  for (int space = 0; space < QUIC_PN_SPACE_COUNT; space++)
    conn_send_ack_if_needed (c, (SocketQUIC_PNSpace)space, now);

  return events;
}

void
SocketQUICServerConfig_defaults (SocketQUICServerConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->bind_addr = "0.0.0.0";
  config->port = SOCKET_DEFAULT_HTTPS_PORT;
  config->idle_timeout_ms = SOCKET_DEFAULT_IDLE_TIMEOUT_MS;
  config->max_stream_data = SOCKET_QUIC_DEFAULT_MAX_STREAM_DATA;
  config->initial_max_data = SOCKET_QUIC_DEFAULT_INITIAL_MAX_DATA;
  config->initial_max_streams_bidi = SOCKET_QUIC_DEFAULT_MAX_STREAMS_BIDI;
  config->cert_file = NULL;
  config->key_file = NULL;
  config->alpn = "h3";
  config->max_connections = SOCKET_QUIC_DEFAULT_MAX_CONNECTIONS;
}

SocketQUICServer_T
SocketQUICServer_new (Arena_T arena, const SocketQUICServerConfig *config)
{
  if (!arena || !config)
    return NULL;

  SocketQUICServer_T server
      = Arena_alloc (arena, sizeof (*server), __FILE__, __LINE__);
  memset (server, 0, sizeof (*server));
  server->arena = arena;
  server->config = *config;

  if (server->config.max_connections == 0)
    server->config.max_connections = SOCKET_QUIC_DEFAULT_MAX_CONNECTIONS;

  /* Allocate connection array */
  server->conn_capacity = server->config.max_connections;
  server->connections
      = Arena_alloc (arena,
                     server->conn_capacity * sizeof (QUICServerConn_T),
                     __FILE__,
                     __LINE__);
  memset (server->connections,
          0,
          server->conn_capacity * sizeof (QUICServerConn_T));
  server->conn_count = 0;

  /* Allocate shared buffers */
  server->send_buf
      = Arena_alloc (arena, SERVER_SEND_BUF_SIZE, __FILE__, __LINE__);
  server->recv_buf
      = Arena_alloc (arena, SERVER_RECV_BUF_SIZE, __FILE__, __LINE__);

  return server;
}

int
SocketQUICServer_listen (SocketQUICServer_T server)
{
  if (!server || server->listening || server->closed)
    return -1;

  if (!server->config.cert_file || !server->config.key_file)
    return -1;

  volatile int setup_ok = 0;
  TRY
  {
    server->socket = SocketDgram_new (AF_INET, 0);
    SocketDgram_setreuseaddr (server->socket);
    SocketDgram_setnonblocking (server->socket);
    SocketDgram_bind (
        server->socket, server->config.bind_addr, server->config.port);
    setup_ok = 1;
  }
  EXCEPT (SocketDgram_Failed)
  {
    setup_ok = 0;
  }
  END_TRY;

  if (!setup_ok)
    return -1;

  server->listening = 1;
  return 0;
}

int
SocketQUICServer_poll (SocketQUICServer_T server, int timeout_ms)
{
  if (!server || !server->listening || server->closed)
    return -1;

  struct pollfd pfd;
  pfd.fd = SocketDgram_fd (server->socket);
  pfd.events = POLLIN;
  pfd.revents = 0;

  int poll_rc = poll (&pfd, 1, timeout_ms);
  if (poll_rc <= 0)
    return 0;

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len = sizeof (peer_addr);
  ssize_t nbytes = server_recvfrom (server,
                                    server->recv_buf,
                                    SERVER_RECV_BUF_SIZE,
                                    &peer_addr,
                                    &peer_addr_len);
  if (nbytes <= 0)
    return 0;

  size_t pkt_len = (size_t)nbytes;

  /* Extract DCID from packet for routing */
  if (pkt_len < 1)
    return 0;

  uint8_t first_byte = server->recv_buf[0];
  int is_long_header = (first_byte & 0x80) != 0;

  const uint8_t *dcid_data = NULL;
  size_t dcid_len = 0;

  if (is_long_header)
    {
      /* Long header: flags(1) + version(4) + dcid_len(1) + dcid(...) */
      if (pkt_len < 6)
        return 0;
      dcid_len = server->recv_buf[5];
      if (pkt_len < 6 + dcid_len)
        return 0;
      dcid_data = server->recv_buf + 6;
    }
  else
    {
      /* Short header: flags(1) + dcid (fixed length) */
      /* For server, the DCID in short headers is our SCID, which is
       * SERVER_SCID_LEN. But we need to search all connections. */
      dcid_len = SERVER_SCID_LEN;
      if (pkt_len < 1 + dcid_len)
        return 0;
      dcid_data = server->recv_buf + 1;
    }

  /* Look up connection by DCID */
  QUICServerConn_T c = find_conn_by_dcid (server, dcid_data, dcid_len);

  if (c)
    {
      return handle_existing_conn_packet (c, server->recv_buf, pkt_len);
    }

  /* No existing connection — must be Initial packet */
  if (!is_long_header)
    return 0; /* Short header from unknown → drop */

  /* Check version field for Initial packet type */
  uint32_t version = ((uint32_t)server->recv_buf[1] << 24)
                     | ((uint32_t)server->recv_buf[2] << 16)
                     | ((uint32_t)server->recv_buf[3] << 8)
                     | (uint32_t)server->recv_buf[4];

  if (version == 0)
    return 0; /* Version negotiation — ignore */

  /* Check packet type (bits 4-5 of first byte for long header) */
  uint8_t pkt_type = (first_byte & 0x30) >> 4;
  if (pkt_type != QUIC_PACKET_TYPE_INITIAL)
    return 0; /* Not Initial → drop */

  QUICServerConn_T new_conn = handle_initial_packet (
      server, server->recv_buf, pkt_len, &peer_addr, peer_addr_len);

  if (new_conn && new_conn->connected && server->conn_cb)
    server->conn_cb (new_conn, server->cb_userdata);

  return new_conn ? 1 : 0;
}

void
SocketQUICServer_close (SocketQUICServer_T server)
{
  if (!server || server->closed)
    return;

  /* Close all connections */
  for (size_t i = 0; i < server->conn_count; i++)
    {
      QUICServerConn_T c = server->connections[i];
      if (c && !c->closed)
        {
          if (c->app_keys_valid)
            {
              uint8_t close_buf[64];
              size_t close_len = SocketQUICFrame_encode_connection_close_app (
                  0, NULL, close_buf, sizeof (close_buf));
              if (close_len > 0)
                build_and_send_1rtt (c, close_buf, close_len);
            }

          c->closed = 1;

          /* Clear key material */
          SocketQUICInitialKeys_clear (&c->initial_keys);
          SocketQUICPacketKeys_clear (&c->handshake_send_keys);
          SocketQUICPacketKeys_clear (&c->app_send_keys);
          SocketQUICKeyUpdate_clear (&c->key_update);

          if (c->handshake)
            SocketQUICTLS_free (c->handshake);

          Arena_dispose (&c->arena);
          server->connections[i] = NULL;
        }
    }

  server->conn_count = 0;

  /* Close UDP socket */
  if (server->socket)
    {
      SocketDgram_free (&server->socket);
      server->socket = NULL;
    }

  server->listening = 0;
  server->closed = 1;
}

void
SocketQUICServer_set_callbacks (SocketQUICServer_T server,
                                SocketQUICServer_ConnCB conn_cb,
                                SocketQUICServer_StreamCB stream_cb,
                                void *userdata)
{
  if (!server)
    return;
  server->conn_cb = conn_cb;
  server->stream_cb = stream_cb;
  server->cb_userdata = userdata;
}

int
SocketQUICServer_send_stream (QUICServerConn_T conn,
                              uint64_t stream_id,
                              const uint8_t *data,
                              size_t len,
                              int fin)
{
  if (!conn || !conn->connected || conn->closed)
    return -1;
  if (!data && len > 0)
    return -1;

  ServerStreamState *stream = conn_find_or_create_stream (conn, stream_id);
  if (!stream)
    return -1;

  /* Enforce peer-advertised flow control before sending. */
  if (conn->flow && !SocketQUICFlow_can_send (conn->flow, len))
    return -1;
  if (stream->flow_stream
      && !SocketQUICFlowStream_can_send (stream->flow_stream, len))
    return -1;

  uint8_t frame_buf[SERVER_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_stream (stream_id,
                                                    stream->send_offset,
                                                    data,
                                                    len,
                                                    fin,
                                                    frame_buf,
                                                    sizeof (frame_buf));
  if (frame_len == 0)
    return -1;

  if (build_and_send_1rtt (conn, frame_buf, frame_len) < 0)
    return -1;

  /* Update offsets and consume flow control only after successful send. */
  stream->send_offset += len;
  if (conn->flow)
    SocketQUICFlow_consume_send (conn->flow, len);
  if (stream->flow_stream)
    SocketQUICFlowStream_consume_send (stream->flow_stream, len);

  return 0;
}

int
SocketQUICServer_close_conn (QUICServerConn_T conn, uint64_t error_code)
{
  if (!conn || conn->closed)
    return -1;

  if (conn->app_keys_valid)
    {
      uint8_t close_buf[64];
      size_t close_len = SocketQUICFrame_encode_connection_close_app (
          error_code, NULL, close_buf, sizeof (close_buf));
      if (close_len > 0)
        build_and_send_1rtt (conn, close_buf, close_len);
    }

  conn->closed = 1;
  conn->connected = 0;

  /* Clear key material */
  SocketQUICInitialKeys_clear (&conn->initial_keys);
  SocketQUICPacketKeys_clear (&conn->handshake_send_keys);
  SocketQUICPacketKeys_clear (&conn->app_send_keys);
  SocketQUICKeyUpdate_clear (&conn->key_update);

  if (conn->handshake)
    SocketQUICTLS_free (conn->handshake);

  return 0;
}

size_t
SocketQUICServer_active_connections (SocketQUICServer_T server)
{
  if (!server)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < server->conn_count; i++)
    {
      if (server->connections[i] && !server->connections[i]->closed)
        count++;
    }
  return count;
}

#endif /* SOCKET_HAS_TLS */
