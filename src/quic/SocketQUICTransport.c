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
#include <stdlib.h>
#include <string.h>

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

#define TRANSPORT_SEND_BUF_SIZE 1500
#define TRANSPORT_RECV_BUF_SIZE SOCKET_QUIC_DEFAULT_RECV_BUF_SIZE
#define TRANSPORT_MAX_STREAMS SOCKET_QUIC_DEFAULT_MAX_STREAMS
#define TRANSPORT_MAX_STREAM_SEGMENTS SOCKET_QUIC_DEFAULT_MAX_STREAM_SEGMENTS
#define TRANSPORT_MAX_0RTT_BUFFER_BYTES (64 * 1024)
#define TRANSPORT_MAX_0RTT_BUFFER_ITEMS 256
#define TRANSPORT_MAX_SESSION_TICKET_SIZE (16 * 1024)
#define TRANSPORT_SCID_LEN 8
#define TRANSPORT_DCID_LEN 8
#define TRANSPORT_PN_LEN 4

typedef struct StreamSegment
{
  uint64_t offset;
  uint64_t length;
  uint8_t *data;
  struct StreamSegment *next;
} StreamSegment_T;

typedef struct EarlyStreamSend
{
  uint64_t stream_id;
  uint64_t offset;
  size_t len;
  int fin;
  uint8_t *data;
  struct EarlyStreamSend *next;
} EarlyStreamSend_T;

typedef struct
{
  uint64_t stream_id;
  uint64_t send_offset;
  uint64_t recv_offset;
  uint64_t recv_highest;
  uint64_t final_size;
  StreamSegment_T *segments;
  int segment_count;
  SocketQUICFlowStream_T flow_stream;
  uint64_t zero_rtt_send_offset_base;
  uint64_t zero_rtt_flow_consumed_base;
  int zero_rtt_sent;
  int fin_received;
  int fin_delivered;
  int active;
} QUICStreamState;

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

  /* Congestion control (RFC 9002 Section 7) */
  SocketQUICCongestion_T congestion;
  uint64_t prev_ecn_ce_count;

  /* Packet protection keys */
  SocketQUICInitialKeys_T initial_keys;
  SocketQUICPacketKeys_T handshake_send_keys;
  SocketQUICPacketKeys_T handshake_read_keys;
  SocketQUICPacketKeys_T app_send_keys;
  SocketQUICPacketKeys_T zero_rtt_send_keys;
  int handshake_keys_valid;
  int app_keys_valid;
  int zero_rtt_keys_valid;

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
  int connecting;
  int connected;
  int closed;

  /* Peer CONNECTION_CLOSE info (RFC 9000 §19.19) */
  uint64_t peer_close_error;
  int peer_close_is_app;
  int peer_close_received;

  /* 0-RTT resumption input (must be set before connect_start/connect) */
  uint8_t *resumption_ticket;
  size_t resumption_ticket_len;
  SocketQUICTransportParams_T resumption_peer_params;
  int resumption_peer_params_valid;
  char resumption_alpn[256];
  size_t resumption_alpn_len;

  /* Buffered 0-RTT stream sends for replay on rejection */
  EarlyStreamSend_T *zero_rtt_head;
  EarlyStreamSend_T *zero_rtt_tail;
  size_t zero_rtt_bytes;
  size_t zero_rtt_count;
  uint64_t zero_rtt_flow_consumed_base;
  int zero_rtt_flow_base_set;
};


static void transport_close_with_error (SocketQUICTransport_T t,
                                        uint64_t error_code,
                                        uint64_t frame_type,
                                        const char *reason);

static uint64_t
peer_initial_stream_send_max (const SocketQUICTransportParams_T *peer_params,
                              uint64_t stream_id);

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
  memset (s, 0, sizeof (*s));
  s->stream_id = stream_id;
  s->send_offset = 0;
  s->recv_offset = 0;
  s->recv_highest = 0;
  s->final_size = UINT64_MAX; /* Unknown until FIN */
  s->segments = NULL;
  s->segment_count = 0;
  s->zero_rtt_send_offset_base = 0;
  s->zero_rtt_flow_consumed_base = 0;
  s->zero_rtt_sent = 0;
  s->fin_received = 0;
  s->fin_delivered = 0;
  s->active = 1;

  /* Stream-level flow control:
   * recv_max_data uses our advertised initial window (config), send_max_data is
   * updated after handshake from peer transport params / MAX_STREAM_DATA. */
  if (t->config.max_stream_data <= SIZE_MAX)
    {
      s->flow_stream = SocketQUICFlowStream_new (t->arena, stream_id);
      if (s->flow_stream)
        {
          SocketQUICFlowStream_init (
              s->flow_stream, stream_id, t->config.max_stream_data, 0);

          const SocketQUICTransportParams_T *peer_params = NULL;
          if (t->handshake)
            {
              peer_params = SocketQUICHandshake_get_peer_params (t->handshake);
              if (!peer_params && t->handshake->zero_rtt.saved_params_valid)
                peer_params = &t->handshake->zero_rtt.saved_params;
            }
          if (peer_params)
            SocketQUICFlowStream_update_send_max (
                s->flow_stream,
                peer_initial_stream_send_max (peer_params, stream_id));
        }
    }

  return s;
}

static int
stream_deliver_chunk (SocketQUICTransport_T t,
                      QUICStreamState *s,
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

  if (t->stream_cb)
    {
      t->stream_cb (
          s->stream_id, data, (size_t)length, fin, t->stream_cb_userdata);
      if (events)
        (*events)++;
    }

  s->recv_offset = new_offset;
  return 0;
}

static int
stream_buffer_segment (SocketQUICTransport_T t,
                       QUICStreamState *s,
                       uint64_t offset,
                       const uint8_t *data,
                       uint64_t length)
{
  if (length == 0)
    return 0;
  if (!data)
    return -1;
  if (s->segment_count >= TRANSPORT_MAX_STREAM_SEGMENTS)
    return -1;
  if (length > SIZE_MAX)
    return -1;

  StreamSegment_T *seg
      = Arena_alloc (t->arena, sizeof (*seg), __FILE__, __LINE__);
  memset (seg, 0, sizeof (*seg));
  seg->offset = offset;
  seg->length = length;
  seg->data = Arena_alloc (t->arena, (size_t)length, __FILE__, __LINE__);
  memcpy (seg->data, data, (size_t)length);

  seg->next = s->segments;
  s->segments = seg;
  s->segment_count++;
  return 0;
}

static int
stream_process_buffered (SocketQUICTransport_T t,
                         QUICStreamState *s,
                         int *events)
{
  int progress;
  do
    {
      progress = 0;
      StreamSegment_T **prev = &s->segments;
      StreamSegment_T *seg = s->segments;

      while (seg)
        {
          uint64_t seg_end;
          if (!socket_util_safe_add_u64 (seg->offset, seg->length, &seg_end))
            return -1;

          /* Fully duplicate (already delivered) */
          if (seg_end <= s->recv_offset)
            {
              *prev = seg->next;
              s->segment_count--;
              progress = 1;
              seg = *prev;
              continue;
            }

          /* Segment overlaps next needed byte */
          if (seg->offset <= s->recv_offset && seg_end > s->recv_offset)
            {
              uint64_t skip = s->recv_offset - seg->offset;
              uint64_t deliver_len = seg_end - s->recv_offset;

              if (skip > SIZE_MAX || deliver_len > SIZE_MAX)
                return -1;

              const uint8_t *deliver_data = seg->data + (size_t)skip;
              if (stream_deliver_chunk (t, s, deliver_data, deliver_len, events)
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

  /* FIN-only completion */
  if (s->fin_received && !s->fin_delivered && s->final_size != UINT64_MAX
      && s->recv_offset == s->final_size)
    {
      if (t->stream_cb)
        {
          t->stream_cb (s->stream_id, NULL, 0, 1, t->stream_cb_userdata);
          if (events)
            (*events)++;
        }
      s->fin_delivered = 1;
    }

  return 0;
}

static int
stream_validate_limits (SocketQUICTransport_T t,
                        uint64_t stream_id,
                        uint64_t frame_type)
{
  int initiator = (int)(stream_id & 0x01);
  int is_uni = (stream_id & 0x02) != 0;
  uint64_t seq = stream_id >> 2;

  if (initiator == 1)
    {
      uint64_t max_streams = is_uni ? 3 : t->config.initial_max_streams_bidi;
      if (seq >= max_streams)
        {
          transport_close_with_error (t,
                                      QUIC_STREAM_LIMIT_ERROR,
                                      frame_type,
                                      "Peer exceeded stream limit");
          return -1;
        }
    }

  if (is_uni && initiator == 0)
    {
      transport_close_with_error (t,
                                  QUIC_STREAM_STATE_ERROR,
                                  frame_type,
                                  "STREAM on local unidirectional stream");
      return -1;
    }

  return 0;
}

static int
stream_track_final_size (SocketQUICTransport_T t,
                         QUICStreamState *s,
                         uint64_t end,
                         int has_fin,
                         uint64_t frame_type)
{
  if (has_fin)
    {
      if (s->fin_received && s->final_size != end)
        {
          transport_close_with_error (
              t, QUIC_FINAL_SIZE_ERROR, frame_type, "Conflicting final size");
          return -1;
        }
      s->fin_received = 1;
      s->final_size = end;
    }
  else if (s->fin_received && end > s->final_size)
    {
      transport_close_with_error (
          t, QUIC_FINAL_SIZE_ERROR, frame_type, "Data exceeds final size");
      return -1;
    }

  return 0;
}

static int
stream_consume_flow_control (SocketQUICTransport_T t,
                             QUICStreamState *s,
                             uint64_t end,
                             uint64_t frame_type)
{
  if (end <= s->recv_highest)
    return 0;

  uint64_t delta = end - s->recv_highest;
  s->recv_highest = end;

  if (delta > SIZE_MAX)
    {
      transport_close_with_error (
          t, QUIC_FLOW_CONTROL_ERROR, frame_type, "Flow delta overflow");
      return -1;
    }

  if (s->flow_stream
      && SocketQUICFlowStream_consume_recv (s->flow_stream, (size_t)delta)
             != QUIC_FLOW_OK)
    {
      transport_close_with_error (t,
                                  QUIC_FLOW_CONTROL_ERROR,
                                  frame_type,
                                  "Stream flow control exceeded");
      return -1;
    }

  if (t->flow
      && SocketQUICFlow_consume_recv (t->flow, (size_t)delta) != QUIC_FLOW_OK)
    {
      transport_close_with_error (t,
                                  QUIC_FLOW_CONTROL_ERROR,
                                  frame_type,
                                  "Connection flow control exceeded");
      return -1;
    }

  return 0;
}

static int
stream_trim_and_deliver (SocketQUICTransport_T t,
                         QUICStreamState *s,
                         uint64_t offset,
                         uint64_t length,
                         const uint8_t *data,
                         uint64_t frame_type,
                         int *events)
{
  if (offset < s->recv_offset)
    {
      uint64_t overlap = s->recv_offset - offset;
      if (overlap >= length)
        return stream_process_buffered (t, s, events);

      if (overlap > SIZE_MAX)
        return -1;
      data += (size_t)overlap;
      offset = s->recv_offset;
      length -= overlap;
    }

  if (offset == s->recv_offset && length > 0)
    {
      if (stream_deliver_chunk (t, s, data, length, events) < 0)
        return -1;
    }
  else if (length > 0)
    {
      if (stream_buffer_segment (t, s, offset, data, length) < 0)
        {
          transport_close_with_error (t,
                                      QUIC_PROTOCOL_VIOLATION,
                                      frame_type,
                                      "Too many buffered stream segments");
          return -1;
        }
    }

  return stream_process_buffered (t, s, events);
}

static int
handle_stream_frame (SocketQUICTransport_T t,
                     const SocketQUICFrameStream_T *sf,
                     uint64_t frame_type,
                     int *events)
{
  if (!t || !sf)
    return -1;

  if (stream_validate_limits (t, sf->stream_id, frame_type) < 0)
    return -1;

  QUICStreamState *s = find_or_create_stream (t, sf->stream_id);
  if (!s)
    {
      transport_close_with_error (
          t, QUIC_STREAM_LIMIT_ERROR, frame_type, "Too many active streams");
      return -1;
    }

  uint64_t end;
  if (!socket_util_safe_add_u64 (sf->offset, sf->length, &end))
    {
      transport_close_with_error (
          t, QUIC_FRAME_ENCODING_ERROR, frame_type, "STREAM offset overflow");
      return -1;
    }

  if (stream_track_final_size (t, s, end, sf->has_fin, frame_type) < 0)
    return -1;

  if (stream_consume_flow_control (t, s, end, frame_type) < 0)
    return -1;

  return stream_trim_and_deliver (
      t, s, sf->offset, sf->length, sf->data, frame_type, events);
}

static uint64_t
peer_initial_stream_send_max (const SocketQUICTransportParams_T *peer_params,
                              uint64_t stream_id)
{
  if (!peer_params)
    return 0;

  /* Client transport: local-initiated streams have initiator bit 0. */
  int initiator = (int)(stream_id & 0x01);
  int is_uni = (stream_id & 0x02) != 0;

  if (is_uni)
    return initiator == 0 ? peer_params->initial_max_stream_data_uni : 0;

  /* Bidirectional streams */
  return initiator == 0 ? peer_params->initial_max_stream_data_bidi_remote
                        : peer_params->initial_max_stream_data_bidi_local;
}

static void
zero_rtt_buffer_clear (SocketQUICTransport_T t)
{
  if (!t)
    return;

  EarlyStreamSend_T *cur = t->zero_rtt_head;
  while (cur)
    {
      EarlyStreamSend_T *next = cur->next;
      if (cur->data)
        free (cur->data);
      free (cur);
      cur = next;
    }

  t->zero_rtt_head = NULL;
  t->zero_rtt_tail = NULL;
  t->zero_rtt_bytes = 0;
  t->zero_rtt_count = 0;
  t->zero_rtt_flow_base_set = 0;
  t->zero_rtt_flow_consumed_base = 0;

  for (size_t i = 0; i < t->stream_count; i++)
    {
      if (!t->streams[i].active)
        continue;
      t->streams[i].zero_rtt_sent = 0;
      t->streams[i].zero_rtt_send_offset_base = 0;
      t->streams[i].zero_rtt_flow_consumed_base = 0;
    }
}

static int
zero_rtt_buffer_can_add (SocketQUICTransport_T t, size_t len)
{
  if (!t)
    return 0;
  if (t->zero_rtt_count >= TRANSPORT_MAX_0RTT_BUFFER_ITEMS)
    return 0;
  if (len > TRANSPORT_MAX_0RTT_BUFFER_BYTES)
    return 0;

  size_t new_total;
  if (t->zero_rtt_bytes > SIZE_MAX - len)
    return 0;
  new_total = t->zero_rtt_bytes + len;
  if (new_total > TRANSPORT_MAX_0RTT_BUFFER_BYTES)
    return 0;

  return 1;
}

static void
zero_rtt_rollback_send_state (SocketQUICTransport_T t)
{
  if (!t)
    return;

  if (t->flow && t->zero_rtt_flow_base_set)
    t->flow->send_consumed = t->zero_rtt_flow_consumed_base;

  for (size_t i = 0; i < t->stream_count; i++)
    {
      QUICStreamState *s = &t->streams[i];
      if (!s->active || !s->zero_rtt_sent)
        continue;

      s->send_offset = s->zero_rtt_send_offset_base;
      if (s->flow_stream)
        s->flow_stream->send_consumed = s->zero_rtt_flow_consumed_base;

      s->zero_rtt_sent = 0;
      s->zero_rtt_send_offset_base = 0;
      s->zero_rtt_flow_consumed_base = 0;
    }

  t->zero_rtt_flow_base_set = 0;
}

typedef enum
{
  QUIC_APP_PKT_1RTT,
  QUIC_APP_PKT_0RTT
} QuicAppPacketType;

static SocketQUICPacketKeys_T *
app_packet_select_keys (SocketQUICTransport_T t, QuicAppPacketType pkt_type)
{
  if (pkt_type == QUIC_APP_PKT_1RTT)
    {
      if (!t->app_keys_valid)
        return NULL;
      return &t->app_send_keys;
    }

  if (!t->zero_rtt_keys_valid)
    return NULL;
  if (!t->handshake || !SocketQUICHandshake_can_send_0rtt (t->handshake))
    return NULL;
  return &t->zero_rtt_send_keys;
}

static int
app_packet_build_header (SocketQUICTransport_T t,
                         QuicAppPacketType pkt_type,
                         uint32_t truncated_pn,
                         size_t *hdr_len_out)
{
  SocketQUICPacketHeader_T hdr;
  SocketQUICPacketHeader_init (&hdr);

  if (pkt_type == QUIC_APP_PKT_1RTT)
    {
      if (SocketQUICPacketHeader_build_short (&hdr,
                                              &t->dcid,
                                              0,
                                              t->key_update.key_phase,
                                              TRANSPORT_PN_LEN,
                                              truncated_pn)
          != QUIC_PACKET_OK)
        return -1;
    }
  else
    {
      if (SocketQUICPacketHeader_build_0rtt (&hdr,
                                             QUIC_VERSION_1,
                                             &t->dcid,
                                             &t->scid,
                                             TRANSPORT_PN_LEN,
                                             truncated_pn)
          != QUIC_PACKET_OK)
        return -1;
    }

  size_t hdr_len = SocketQUICPacketHeader_serialize (
      &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
  if (hdr_len == 0)
    return -1;

  *hdr_len_out = hdr_len;
  return 0;
}

static int
app_packet_encrypt_and_send (SocketQUICTransport_T t,
                             SocketQUICPacketKeys_T *keys,
                             uint64_t pn,
                             size_t hdr_len,
                             const uint8_t *payload,
                             size_t payload_len,
                             int ack_eliciting,
                             int in_flight)
{
  size_t pn_offset = hdr_len - TRANSPORT_PN_LEN;

  if (hdr_len + payload_len + 16 > TRANSPORT_SEND_BUF_SIZE)
    return -1;
  memcpy (t->send_buf + hdr_len, payload, payload_len);

  size_t ciphertext_len = TRANSPORT_SEND_BUF_SIZE - hdr_len;
  if (SocketQUICCrypto_encrypt_payload (keys,
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

  if (in_flight && t->congestion)
    {
      size_t bif
          = SocketQUICLoss_bytes_in_flight (t->loss[QUIC_PN_SPACE_APPLICATION]);
      if (!SocketQUICCongestion_can_send (t->congestion, bif, pkt_len))
        return -1;
    }

  if (SocketQUICCrypto_protect_header_ex (keys, t->send_buf, pkt_len, pn_offset)
      != QUIC_CRYPTO_OK)
    return -1;

  if (t->loss[QUIC_PN_SPACE_APPLICATION]
      && t->loss[QUIC_PN_SPACE_APPLICATION]->sent_count
             >= QUIC_LOSS_MAX_SENT_PACKETS)
    return -1;

  if (transport_send_packet (t, t->send_buf, pkt_len) < 0)
    return -1;

  uint64_t sent_time = Socket_get_monotonic_us ();
  if (SocketQUICLoss_on_packet_sent (t->loss[QUIC_PN_SPACE_APPLICATION],
                                     pn,
                                     sent_time,
                                     pkt_len,
                                     ack_eliciting,
                                     in_flight,
                                     0)
      != QUIC_LOSS_OK)
    return -1;

  t->next_pn[QUIC_PN_SPACE_APPLICATION]++;
  return 0;
}

static int
build_and_send_app_packet (SocketQUICTransport_T t,
                           QuicAppPacketType pkt_type,
                           const uint8_t *payload,
                           size_t payload_len,
                           int ack_eliciting,
                           int in_flight)
{
  SocketQUICPacketKeys_T *keys = app_packet_select_keys (t, pkt_type);
  if (!keys)
    return -1;

  uint64_t pn = t->next_pn[QUIC_PN_SPACE_APPLICATION];
  uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, TRANSPORT_PN_LEN);

  size_t hdr_len;
  if (app_packet_build_header (t, pkt_type, truncated_pn, &hdr_len) < 0)
    return -1;

  return app_packet_encrypt_and_send (
      t, keys, pn, hdr_len, payload, payload_len, ack_eliciting, in_flight);
}

static int
build_and_send_1rtt_packet (SocketQUICTransport_T t,
                            const uint8_t *payload,
                            size_t payload_len)
{
  return build_and_send_app_packet (
      t, QUIC_APP_PKT_1RTT, payload, payload_len, 1, 1);
}

static int
build_and_send_0rtt_packet (SocketQUICTransport_T t,
                            const uint8_t *payload,
                            size_t payload_len)
{
  return build_and_send_app_packet (
      t, QUIC_APP_PKT_0RTT, payload, payload_len, 1, 1);
}

static void
transport_close_with_error (SocketQUICTransport_T t,
                            uint64_t error_code,
                            uint64_t frame_type,
                            const char *reason)
{
  if (!t || t->closed)
    return;

  if (t->app_keys_valid)
    {
      uint8_t close_buf[128];
      size_t close_len = SocketQUICFrame_encode_connection_close_transport (
          error_code, frame_type, reason, close_buf, sizeof (close_buf));
      if (close_len > 0)
        build_and_send_app_packet (
            t, QUIC_APP_PKT_1RTT, close_buf, close_len, 0, 0);
    }

  t->closed = 1;
  t->connected = 0;
}

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
    rc = build_and_send_app_packet (
        t, QUIC_APP_PKT_1RTT, ack_buf, ack_len, 0, 0);

  if (rc == 0)
    SocketQUICAck_mark_sent (t->ack[space], now);

  return rc;
}

static void
transport_acked_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  SocketQUICCongestion_AckCtx *c = ctx;
  if (pkt->in_flight)
    c->acked_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > c->latest_acked_sent_time)
    c->latest_acked_sent_time = pkt->sent_time_us;
}

static void
transport_lost_cb (const SocketQUICLossSentPacket_T *pkt, void *ctx)
{
  SocketQUICCongestion_AckCtx *c = ctx;
  if (pkt->in_flight)
    c->lost_bytes += pkt->sent_bytes;
  if (pkt->sent_time_us > c->latest_lost_sent_time)
    c->latest_lost_sent_time = pkt->sent_time_us;
}

static void
process_ack_frame (SocketQUICTransport_T t,
                   const SocketQUICFrame_T *frame,
                   SocketQUIC_PNSpace space,
                   uint64_t now)
{
  if (!t->loss[space])
    return;

  SocketQUICCongestion_AckCtx actx = { 0 };
  size_t acked_count = 0, lost_count = 0;

  SocketQUICLoss_on_ack_received (t->loss[space],
                                  &t->rtt,
                                  &frame->data.ack,
                                  now,
                                  transport_acked_cb,
                                  transport_lost_cb,
                                  &actx,
                                  &acked_count,
                                  &lost_count);

  if (space == QUIC_PN_SPACE_APPLICATION)
    SocketQUICCongestion_process_ack (t->congestion,
                                      &actx,
                                      &t->rtt,
                                      t->loss[space],
                                      frame->data.ack.ecn_ce_count,
                                      frame->type == QUIC_FRAME_ACK_ECN,
                                      lost_count,
                                      &t->prev_ecn_ce_count);
}

static void
process_crypto_frame (SocketQUICTransport_T t,
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

  SocketQUICTLS_provide_data (t->handshake,
                              level,
                              frame->data.crypto.data,
                              (size_t)frame->data.crypto.length);
}

static void
process_connection_close_frame (SocketQUICTransport_T t,
                                const SocketQUICFrame_T *frame)
{
  t->peer_close_error = frame->data.connection_close.error_code;
  t->peer_close_is_app = frame->data.connection_close.is_app_error;
  t->peer_close_received = 1;
  t->closed = 1;
  t->connected = 0;
}

static void
process_flow_control_frame (SocketQUICTransport_T t,
                            const SocketQUICFrame_T *frame)
{
  switch (frame->type)
    {
    case QUIC_FRAME_MAX_DATA:
      if (t->flow)
        SocketQUICFlow_update_send_max (t->flow, frame->data.max_data.max_data);
      break;

    case QUIC_FRAME_MAX_STREAM_DATA:
      {
        QUICStreamState *s
            = find_or_create_stream (t, frame->data.max_stream_data.stream_id);
        if (s && s->flow_stream)
          SocketQUICFlowStream_update_send_max (
              s->flow_stream, frame->data.max_stream_data.max_data);
      }
      break;

    case QUIC_FRAME_MAX_STREAMS_BIDI:
      if (t->flow)
        SocketQUICFlow_update_max_streams_bidi (
            t->flow, frame->data.max_streams.max_streams);
      break;

    case QUIC_FRAME_MAX_STREAMS_UNI:
      if (t->flow)
        SocketQUICFlow_update_max_streams_uni (
            t->flow, frame->data.max_streams.max_streams);
      break;

    default:
      break;
    }
}

static int
process_frames (SocketQUICTransport_T t,
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
          transport_close_with_error (t,
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
          process_ack_frame (t, &frame, space, now);
          break;

        case QUIC_FRAME_CRYPTO:
          process_crypto_frame (t, &frame, space);
          break;

        case QUIC_FRAME_HANDSHAKE_DONE:
          SocketQUICHandshake_on_confirmed (t->handshake);
          break;

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
          process_connection_close_frame (t, &frame);
          SocketQUICFrame_free (&frame);
          return -1;

        case QUIC_FRAME_MAX_DATA:
        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_MAX_STREAMS_BIDI:
        case QUIC_FRAME_MAX_STREAMS_UNI:
          process_flow_control_frame (t, &frame);
          break;

        default:
          if (SocketQUICFrame_is_stream (frame.type))
            {
              if (handle_stream_frame (
                      t, &frame.data.stream, frame.type, &events)
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
send_crypto_initial (SocketQUICTransport_T t,
                     const uint8_t *frame_buf,
                     size_t frame_len)
{
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

  /* Pre-compute Length field (RFC 9000 §17.2):
   * Length = PN_bytes + plaintext_payload + AEAD_tag.
   * Use a 2-byte varint placeholder to get stable header size. */
  hdr.length = SOCKETQUICVARINT_MIN_2BYTE;
  size_t hdr_len = SocketQUICPacketHeader_serialize (
      &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
  if (hdr_len == 0)
    return -1;

  /* Compute padding so total packet >= 1200 bytes */
  size_t pad_needed = 0;
  if (hdr_len + frame_len + QUIC_INITIAL_TAG_LEN < QUIC_INITIAL_MIN_SIZE)
    pad_needed
        = QUIC_INITIAL_MIN_SIZE - hdr_len - frame_len - QUIC_INITIAL_TAG_LEN;

  /* Set the real Length and re-serialize */
  hdr.length = TRANSPORT_PN_LEN + frame_len + pad_needed + QUIC_INITIAL_TAG_LEN;
  hdr_len = SocketQUICPacketHeader_serialize (
      &hdr, t->send_buf, TRANSPORT_SEND_BUF_SIZE);
  if (hdr_len == 0)
    return -1;

  /* Copy CRYPTO frame into payload area */
  memcpy (t->send_buf + hdr_len, frame_buf, frame_len);
  size_t pkt_len = hdr_len + frame_len;

  /* Add PADDING frames (zero bytes) */
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
  return 0;
}

static int
send_crypto_handshake (SocketQUICTransport_T t,
                       const uint8_t *frame_buf,
                       size_t frame_len)
{
  if (!t->handshake_keys_valid)
    return -1;

  uint64_t pn = t->next_pn[QUIC_PN_SPACE_HANDSHAKE];
  uint32_t truncated_pn = SocketQUICPacket_encode_pn (pn, TRANSPORT_PN_LEN);

  SocketQUICPacketHeader_T hdr;
  SocketQUICPacketHeader_init (&hdr);
  SocketQUICPacketHeader_build_handshake (
      &hdr, QUIC_VERSION_1, &t->dcid, &t->scid, TRANSPORT_PN_LEN, truncated_pn);

  /* Set Length field: PN_bytes + plaintext + AEAD_tag */
  hdr.length = TRANSPORT_PN_LEN + frame_len + QUIC_INITIAL_TAG_LEN;
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
  return 0;
}

static int
send_crypto_data (SocketQUICTransport_T t,
                  SocketQUICCryptoLevel level,
                  const uint8_t *data,
                  size_t len,
                  uint64_t crypto_offset)
{
  uint8_t frame_buf[TRANSPORT_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_crypto (
      crypto_offset, data, len, frame_buf, sizeof (frame_buf));
  if (frame_len == 0)
    return -1;

  switch (level)
    {
    case QUIC_CRYPTO_LEVEL_INITIAL:
      return send_crypto_initial (t, frame_buf, frame_len);
    case QUIC_CRYPTO_LEVEL_HANDSHAKE:
      return send_crypto_handshake (t, frame_buf, frame_len);
    case QUIC_CRYPTO_LEVEL_APPLICATION:
      return build_and_send_1rtt_packet (t, frame_buf, frame_len);
    default:
      return -1;
    }
}

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

static SocketQUIC_AEAD
aead_from_secret_len (size_t secret_len)
{
  return secret_len == SOCKET_CRYPTO_SHA384_SIZE ? QUIC_AEAD_AES_256_GCM
                                                 : QUIC_AEAD_AES_128_GCM;
}

static void
check_and_derive_keys (SocketQUICTransport_T t)
{
  uint8_t write_secret[SOCKET_CRYPTO_SHA384_SIZE];
  uint8_t read_secret[SOCKET_CRYPTO_SHA384_SIZE];
  size_t secret_len = 0;

  /* If 0-RTT keys were discarded by the handshake state machine, discard our
   * derived packet keys too (RFC 9001 §4.9.3). */
  if (t->zero_rtt_keys_valid && t->handshake
      && !SocketQUICHandshake_can_send_0rtt (t->handshake))
    {
      SocketQUICPacketKeys_clear (&t->zero_rtt_send_keys);
      t->zero_rtt_keys_valid = 0;
    }

  /* 0-RTT keys (client only) */
  if (!t->zero_rtt_keys_valid && t->handshake
      && SocketQUICHandshake_has_keys (t->handshake, QUIC_CRYPTO_LEVEL_0RTT))
    {
      if (SocketQUICTLS_get_traffic_secrets (t->handshake,
                                             QUIC_CRYPTO_LEVEL_0RTT,
                                             write_secret,
                                             read_secret,
                                             &secret_len)
          == QUIC_TLS_OK)
        {
          SocketQUICCrypto_derive_packet_keys (
              write_secret,
              secret_len,
              aead_from_secret_len (secret_len),
              &t->zero_rtt_send_keys);
          t->zero_rtt_keys_valid = 1;
        }
    }

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
          SocketQUIC_AEAD aead = aead_from_secret_len (secret_len);
          SocketQUICCrypto_derive_packet_keys (
              write_secret, secret_len, aead, &t->handshake_send_keys);
          SocketQUICCrypto_derive_packet_keys (
              read_secret, secret_len, aead, &t->handshake_read_keys);
          SocketQUICReceive_set_handshake_keys (&t->recv_ctx,
                                                &t->handshake_read_keys);
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
          SocketQUIC_AEAD aead = aead_from_secret_len (secret_len);
          SocketQUICCrypto_derive_packet_keys (
              write_secret, secret_len, aead, &t->app_send_keys);
          SocketQUICKeyUpdate_set_initial_keys (
              &t->key_update, write_secret, read_secret, secret_len, aead);
          SocketQUICReceive_set_1rtt_keys (&t->recv_ctx, &t->key_update);
          t->app_keys_valid = 1;

          /* Client SHOULD discard 0-RTT keys as soon as 1-RTT keys are
           * installed (RFC 9001 §4.9.3). */
          SocketQUICHandshake_on_1rtt_keys_installed (t->handshake);
          if (t->zero_rtt_keys_valid)
            {
              SocketQUICPacketKeys_clear (&t->zero_rtt_send_keys);
              t->zero_rtt_keys_valid = 0;
            }
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

void
SocketQUICTransportConfig_defaults (SocketQUICTransportConfig *config)
{
  if (!config)
    return;
  memset (config, 0, sizeof (*config));
  config->idle_timeout_ms = SOCKET_DEFAULT_IDLE_TIMEOUT_MS;
  config->max_stream_data = SOCKET_QUIC_DEFAULT_MAX_STREAM_DATA;
  config->initial_max_data = SOCKET_QUIC_DEFAULT_INITIAL_MAX_DATA;
  config->initial_max_streams_bidi = SOCKET_QUIC_DEFAULT_MAX_STREAMS_BIDI;
  config->connect_timeout_ms = SOCKET_QUIC_DEFAULT_CONNECT_TIMEOUT_MS;
  config->alpn = "h3";
  config->ca_file = NULL;
  config->verify_peer = 1;
}

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

  /* Initialize congestion control (RFC 9002 Section 7) */
  t->congestion = SocketQUICCongestion_new (arena, QUIC_MAX_DATAGRAM_SIZE);

  /* Initialize connection-level flow control early so receive-side enforcement
   * is active during handshake/application. send_max_data/stream limits are
   * updated after peer transport params are known. */
  t->flow = SocketQUICFlow_new (arena);
  if (t->flow)
    SocketQUICFlow_init (t->flow, t->config.initial_max_data, 0, 0, 0);

  return t;
}

/**
 * @brief Complete TLS/0-RTT handshake setup after CID generation.
 *
 * Configures transport params, TLS context, and optionally 0-RTT state.
 * @return 0 on success, -1 on failure.
 */
static int
complete_handshake_setup (SocketQUICTransport_T t)
{
  SocketQUICTransportParams_T local_params;
  SocketQUICTransportParams_init (&local_params);
  local_params.max_idle_timeout = t->config.idle_timeout_ms;
  local_params.initial_max_data = t->config.initial_max_data;
  local_params.initial_max_stream_data_bidi_local = t->config.max_stream_data;
  local_params.initial_max_stream_data_bidi_remote = t->config.max_stream_data;
  local_params.initial_max_stream_data_uni = t->config.max_stream_data;
  local_params.initial_max_streams_bidi = t->config.initial_max_streams_bidi;
  local_params.initial_max_streams_uni = 3;

  /* RFC 9000 §7.3: initial_source_connection_id must match our SCID */
  local_params.initial_scid = t->scid;
  local_params.has_initial_scid = 1;

  SocketQUICHandshake_set_transport_params (t->handshake, &local_params);

  SocketQUICTLSConfig_T tls_config;
  memset (&tls_config, 0, sizeof (tls_config));
  tls_config.alpn = t->config.alpn ? t->config.alpn : "h3";
  tls_config.ca_file = t->config.ca_file;
  tls_config.verify_peer = t->config.verify_peer;
  tls_config.enable_0rtt = 0;

  int want_0rtt = 0;
  if (t->resumption_ticket && t->resumption_ticket_len > 0
      && t->resumption_peer_params_valid)
    {
      if (t->resumption_alpn_len == 0)
        want_0rtt = 1;
      else
        {
          size_t cfg_len = strlen (tls_config.alpn);
          if (cfg_len == t->resumption_alpn_len
              && memcmp (tls_config.alpn, t->resumption_alpn, cfg_len) == 0)
            want_0rtt = 1;
        }
    }

  if (want_0rtt)
    tls_config.enable_0rtt = 1;

  if (SocketQUICTLS_init_context (t->handshake, &tls_config) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_create_ssl (t->handshake) != QUIC_TLS_OK)
    return -1;
  if (SocketQUICTLS_set_local_transport_params (t->handshake) != QUIC_TLS_OK)
    return -1;

  if (want_0rtt)
    {
      if (SocketQUICTLS_set_session (
              t->handshake, t->resumption_ticket, t->resumption_ticket_len)
          == QUIC_TLS_OK)
        {
          SocketQUICHandshake_Result hr
              = SocketQUICHandshake_0rtt_set_ticket (t->handshake,
                                                     t->resumption_ticket,
                                                     t->resumption_ticket_len,
                                                     &t->resumption_peer_params,
                                                     t->resumption_alpn,
                                                     t->resumption_alpn_len);
          if (hr != QUIC_HANDSHAKE_OK)
            return -1;

          if (t->flow)
            {
              SocketQUICFlow_update_send_max (
                  t->flow, t->resumption_peer_params.initial_max_data);
              SocketQUICFlow_update_max_streams_bidi (
                  t->flow, t->resumption_peer_params.initial_max_streams_bidi);
              SocketQUICFlow_update_max_streams_uni (
                  t->flow, t->resumption_peer_params.initial_max_streams_uni);
            }
        }
    }

  return 0;
}

int
SocketQUICTransport_connect_start (SocketQUICTransport_T t,
                                   const char *host,
                                   int port)
{
  if (!t || !host || t->connected || t->connecting || t->closed)
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
    goto fail;

  SocketQUICConnection_add_local_cid (t->conn, &t->scid);
  SocketQUICConnection_add_peer_cid (t->conn, &t->dcid);
  t->conn->initial_dcid = t->dcid;

  /* Create handshake context */
  t->handshake
      = SocketQUICHandshake_new (t->arena, t->conn, QUIC_CONN_ROLE_CLIENT);
  if (!t->handshake)
    goto fail;

  /* Phase B: TLS and 0-RTT setup */
  if (complete_handshake_setup (t) < 0)
    goto fail;

  /* Phase C: Initial packet */
  if (SocketQUICCrypto_derive_initial_keys (
          &t->dcid, QUIC_VERSION_1, &t->initial_keys)
      != QUIC_CRYPTO_OK)
    goto fail;

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
  SocketQUICTLS_Result tls_rc = SocketQUICTLS_do_handshake (t->handshake);
  if (tls_rc == QUIC_TLS_ERROR_HANDSHAKE || tls_rc == QUIC_TLS_ERROR_ALERT)
    goto fail;
  check_and_derive_keys (t);

  /* Flush TLS output (sends ClientHello in Initial packet) */
  if (flush_tls_output (t) < 0)
    goto fail;

  t->connecting = 1;
  return 0;

fail:
  if (t->socket)
    SocketDgram_free (&t->socket);
  t->socket = NULL;
  return -1;
}

int
SocketQUICTransport_connect (SocketQUICTransport_T t,
                             const char *host,
                             int port)
{
  if (!t || !host || t->connected || t->connecting || t->closed)
    return -1;

  if (SocketQUICTransport_connect_start (t, host, port) < 0)
    return -1;

  uint64_t deadline_us = Socket_get_monotonic_us ()
                         + (uint64_t)t->config.connect_timeout_ms * 1000;

  while (!t->connected && !t->closed)
    {
      uint64_t current = Socket_get_monotonic_us ();
      if (current >= deadline_us)
        return -1;

      int remaining_ms = (int)((deadline_us - current) / 1000);
      if (remaining_ms <= 0)
        remaining_ms = 1;

      if (SocketQUICTransport_poll (t, remaining_ms) < 0)
        return -1;
    }

  return t->connected ? 0 : -1;
}

/**
 * @brief Release all owned resources (socket, keys, TLS, tickets).
 *
 * Safe to call multiple times — each resource is NULL-checked and
 * zeroed after release.  Called from both local-close and peer-close
 * paths so that SocketQUICTransport_close() never leaks.
 */
static void
transport_free_resources (SocketQUICTransport_T t)
{
  if (t->socket)
    {
      SocketDgram_free (&t->socket);
      t->socket = NULL;
    }

  zero_rtt_buffer_clear (t);
  if (t->resumption_ticket)
    {
      SocketCrypto_secure_clear (t->resumption_ticket,
                                 t->resumption_ticket_len);
      free (t->resumption_ticket);
      t->resumption_ticket = NULL;
      t->resumption_ticket_len = 0;
    }
  t->resumption_peer_params_valid = 0;
  t->resumption_alpn_len = 0;

  SocketQUICInitialKeys_clear (&t->initial_keys);
  SocketQUICPacketKeys_clear (&t->handshake_send_keys);
  SocketQUICPacketKeys_clear (&t->handshake_read_keys);
  SocketQUICPacketKeys_clear (&t->zero_rtt_send_keys);
  SocketQUICPacketKeys_clear (&t->app_send_keys);
  SocketQUICKeyUpdate_clear (&t->key_update);

  if (t->handshake)
    {
      SocketQUICTLS_free (t->handshake);
      t->handshake = NULL;
    }
}

int
SocketQUICTransport_close (SocketQUICTransport_T t)
{
  if (!t)
    return -1;

  /* Only send CONNECTION_CLOSE if we haven't already closed */
  if (!t->closed && t->app_keys_valid)
    {
      uint8_t close_buf[64];
      size_t close_len = SocketQUICFrame_encode_connection_close_app (
          0, NULL, close_buf, sizeof (close_buf));
      if (close_len > 0)
        build_and_send_1rtt_packet (t, close_buf, close_len);
    }

  t->closed = 1;
  t->connected = 0;
  t->connecting = 0;

  transport_free_resources (t);
  return 0;
}

static int
validate_send_preconditions (SocketQUICTransport_T t,
                             const uint8_t *data,
                             size_t len,
                             int use_0rtt,
                             int buffer_for_replay)
{
  if (!t || t->closed)
    return -1;
  if (!data && len > 0)
    return -1;

  if (use_0rtt)
    {
      if (!t->connecting || t->connected)
        return -1;
      if (!t->zero_rtt_keys_valid || !t->handshake
          || !SocketQUICHandshake_can_send_0rtt (t->handshake))
        return -1;
      if (buffer_for_replay && !zero_rtt_buffer_can_add (t, len))
        return -1;
    }
  else
    {
      if (!t->app_keys_valid)
        return -1;
    }

  return 0;
}

static EarlyStreamSend_T *
alloc_early_stream_pending (uint64_t stream_id,
                            uint64_t offset,
                            const uint8_t *data,
                            size_t len,
                            int fin)
{
  EarlyStreamSend_T *pending = malloc (sizeof (*pending));
  if (!pending)
    return NULL;
  memset (pending, 0, sizeof (*pending));
  pending->stream_id = stream_id;
  pending->offset = offset;
  pending->len = len;
  pending->fin = fin ? 1 : 0;
  pending->next = NULL;

  if (len > 0)
    {
      pending->data = malloc (len);
      if (!pending->data)
        {
          free (pending);
          return NULL;
        }
      memcpy (pending->data, data, len);
    }

  return pending;
}

static void
free_early_stream_pending (EarlyStreamSend_T *pending)
{
  if (!pending)
    return;
  free (pending->data);
  free (pending);
}

static void
commit_early_stream_pending (SocketQUICTransport_T t,
                             QUICStreamState *stream,
                             EarlyStreamSend_T *pending,
                             size_t len)
{
  if (!t->zero_rtt_flow_base_set && t->flow)
    {
      t->zero_rtt_flow_consumed_base = t->flow->send_consumed;
      t->zero_rtt_flow_base_set = 1;
    }

  if (!stream->zero_rtt_sent)
    {
      stream->zero_rtt_send_offset_base = stream->send_offset;
      if (stream->flow_stream)
        stream->zero_rtt_flow_consumed_base
            = stream->flow_stream->send_consumed;
      stream->zero_rtt_sent = 1;
    }

  if (!t->zero_rtt_head)
    t->zero_rtt_head = pending;
  else
    t->zero_rtt_tail->next = pending;
  t->zero_rtt_tail = pending;

  t->zero_rtt_bytes += len;
  t->zero_rtt_count++;
}

static int
transport_send_stream_common (SocketQUICTransport_T t,
                              uint64_t stream_id,
                              const uint8_t *data,
                              size_t len,
                              int fin,
                              int use_0rtt,
                              int buffer_for_replay)
{
  if (validate_send_preconditions (t, data, len, use_0rtt, buffer_for_replay)
      < 0)
    return -1;

  QUICStreamState *stream = find_or_create_stream (t, stream_id);
  if (!stream)
    return -1;

  if (t->flow && !SocketQUICFlow_can_send (t->flow, len))
    return -1;
  if (stream->flow_stream
      && !SocketQUICFlowStream_can_send (stream->flow_stream, len))
    return -1;

  uint64_t offset = stream->send_offset;

  EarlyStreamSend_T *pending = NULL;
  if (use_0rtt && buffer_for_replay)
    {
      pending = alloc_early_stream_pending (stream_id, offset, data, len, fin);
      if (!pending)
        return -1;
    }

  uint8_t frame_buf[TRANSPORT_SEND_BUF_SIZE];
  size_t frame_len = SocketQUICFrame_encode_stream (
      stream_id, offset, data, len, fin, frame_buf, sizeof (frame_buf));
  if (frame_len == 0)
    {
      free_early_stream_pending (pending);
      return -1;
    }

  int rc = use_0rtt ? build_and_send_0rtt_packet (t, frame_buf, frame_len)
                    : build_and_send_1rtt_packet (t, frame_buf, frame_len);
  if (rc < 0)
    {
      free_early_stream_pending (pending);
      return -1;
    }

  if (pending)
    commit_early_stream_pending (t, stream, pending, len);

  stream->send_offset += len;
  if (t->flow)
    SocketQUICFlow_consume_send (t->flow, len);
  if (stream->flow_stream)
    SocketQUICFlowStream_consume_send (stream->flow_stream, len);

  return 0;
}

int
SocketQUICTransport_send_stream (SocketQUICTransport_T t,
                                 uint64_t stream_id,
                                 const uint8_t *data,
                                 size_t len,
                                 int fin)
{
  if (!t || !t->connected || t->closed)
    return -1;

  return transport_send_stream_common (t, stream_id, data, len, fin, 0, 0);
}

int
SocketQUICTransport_send_stream_0rtt (SocketQUICTransport_T t,
                                      uint64_t stream_id,
                                      const uint8_t *data,
                                      size_t len,
                                      int fin)
{
  if (!t || t->connected || !t->connecting || t->closed)
    return -1;

  return transport_send_stream_common (t, stream_id, data, len, fin, 1, 1);
}

static int
zero_rtt_replay_buffer_as_1rtt (SocketQUICTransport_T t)
{
  if (!t || t->closed || !t->app_keys_valid)
    return -1;

  EarlyStreamSend_T *cur = t->zero_rtt_head;
  while (cur)
    {
      QUICStreamState *s = find_or_create_stream (t, cur->stream_id);
      if (!s)
        return -1;
      if (s->send_offset != cur->offset)
        return -1;

      if (transport_send_stream_common (
              t, cur->stream_id, cur->data, cur->len, cur->fin, 0, 0)
          < 0)
        return -1;

      cur = cur->next;
    }

  return 0;
}

/**
 * @brief Finalize handshake if TLS is complete.
 *
 * Validates ALPN, installs peer params, handles 0-RTT rejection/replay,
 * and transitions to connected state.
 * @return 0 on success, -1 on failure.
 */
static int
complete_handshake_if_ready (SocketQUICTransport_T t)
{
  if (!t->connecting || t->connected
      || !SocketQUICTLS_is_complete (t->handshake))
    return 0;

  if (SocketQUICTLS_check_alpn_negotiated (t->handshake) != QUIC_TLS_OK)
    return -1;

  if (SocketQUICTLS_get_peer_params (t->handshake) != QUIC_TLS_OK)
    return -1;

  check_and_derive_keys (t);
  if (!t->app_keys_valid)
    return -1;

  /* Process 0-RTT acceptance/rejection after handshake completion. */
  SocketQUICHandshake_Result hs_res
      = SocketQUICHandshake_process (t->handshake);
  if (hs_res != QUIC_HANDSHAKE_OK)
    return -1;

  /* Initialize flow control from peer params. */
  const SocketQUICTransportParams_T *peer_params
      = SocketQUICHandshake_get_peer_params (t->handshake);
  if (peer_params)
    {
      if (t->flow)
        {
          SocketQUICFlow_update_send_max (t->flow,
                                          peer_params->initial_max_data);
          SocketQUICFlow_update_max_streams_bidi (
              t->flow, peer_params->initial_max_streams_bidi);
          SocketQUICFlow_update_max_streams_uni (
              t->flow, peer_params->initial_max_streams_uni);
        }

      for (size_t i = 0; i < t->stream_count; i++)
        {
          if (!t->streams[i].active || !t->streams[i].flow_stream)
            continue;
          uint64_t max_data = peer_initial_stream_send_max (
              peer_params, t->streams[i].stream_id);
          SocketQUICFlowStream_update_send_max (t->streams[i].flow_stream,
                                                max_data);
        }
    }

  /* If 0-RTT was rejected, resend buffered early stream data as 1-RTT. */
  if (t->handshake->zero_rtt.state == QUIC_0RTT_STATE_REJECTED
      && t->zero_rtt_head)
    {
      if (t->loss[QUIC_PN_SPACE_APPLICATION])
        SocketQUICLoss_reset (t->loss[QUIC_PN_SPACE_APPLICATION]);

      zero_rtt_rollback_send_state (t);
      if (zero_rtt_replay_buffer_as_1rtt (t) < 0)
        return -1;
    }

  zero_rtt_buffer_clear (t);

  if (t->handshake->conn->peer_cid_count > 0)
    t->dcid = t->handshake->conn->peer_cids[0];

  t->connected = 1;
  t->connecting = 0;
  return 0;
}

static int
drive_client_handshake (SocketQUICTransport_T t,
                        const SocketQUICReceiveResult_T *result)
{
  if (!t->connecting || t->connected)
    return 0;

  /* RFC 9000 §7.2: adopt server's SCID as our DCID upon receiving
   * the first Initial or Handshake packet from the server. */
  if (result->scid.len > 0
      && (result->type == QUIC_PACKET_TYPE_INITIAL
          || result->type == QUIC_PACKET_TYPE_HANDSHAKE))
    {
      t->dcid = result->scid;
      SocketQUICConnection_update_dcid (t->handshake->conn, &result->scid);
    }

  check_and_derive_keys (t);

  SocketQUICTLS_Result tls_rc = SocketQUICTLS_do_handshake (t->handshake);
  if (tls_rc == QUIC_TLS_ERROR_HANDSHAKE || tls_rc == QUIC_TLS_ERROR_ALERT)
    return -1;

  check_and_derive_keys (t);
  return flush_tls_output (t);
}

int
SocketQUICTransport_poll (SocketQUICTransport_T t, int timeout_ms)
{
  if (!t || t->closed)
    return -1;
  if (!t->socket || (!t->connecting && !t->connected))
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

  /* Process potentially coalesced packets (RFC 9000 §12.2) */
  uint8_t *pkt_ptr = t->recv_buf;
  size_t remaining = (size_t)nbytes;
  int total_events = 0;

  while (remaining > 0)
    {
      SocketQUICReceiveResult_T result;
      memset (&result, 0, sizeof (result));
      SocketQUICReceive_Result recv_rc = SocketQUICReceive_packet (
          &t->recv_ctx, pkt_ptr, remaining, t->scid.len, 0, &result);

      if (recv_rc != QUIC_RECEIVE_OK)
        break;

      uint64_t current = Socket_get_monotonic_us ();

      /* Record received PN */
      if (t->ack[result.pn_space])
        SocketQUICAck_record_packet (
            t->ack[result.pn_space], result.packet_number, current, 1);

      /* Process frames */
      int events = process_frames (t,
                                   result.payload,
                                   result.payload_len,
                                   result.type,
                                   result.pn_space,
                                   current);
      if (events < 0)
        return -1;
      total_events += events;

      if (t->closed)
        return -1;

      if (drive_client_handshake (t, &result) < 0)
        return -1;

      /* Advance past this packet in the datagram */
      size_t consumed = result.consumed > 0 ? result.consumed : remaining;
      pkt_ptr += consumed;
      remaining -= consumed;
    }

  /* Check for handshake completion after processing all coalesced packets */
  if (complete_handshake_if_ready (t) < 0)
    return -1;

  /* Send ACK if needed */
  uint64_t current = Socket_get_monotonic_us ();
  for (int space = 0; space < QUIC_PN_SPACE_COUNT; space++)
    send_ack_if_needed (t, (SocketQUIC_PNSpace)space, current);

  return total_events;
}

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

int
SocketQUICTransport_is_connected (SocketQUICTransport_T t)
{
  return t && t->connected && !t->closed;
}

int
SocketQUICTransport_set_resumption_ticket (
    SocketQUICTransport_T t,
    const uint8_t *ticket,
    size_t ticket_len,
    const SocketQUICTransportParams_T *saved_peer_params,
    const char *alpn,
    size_t alpn_len)
{
  if (!t || t->connected || t->connecting || t->closed)
    return -1;
  if (!ticket || ticket_len == 0
      || ticket_len > TRANSPORT_MAX_SESSION_TICKET_SIZE)
    return -1;
  if (!saved_peer_params)
    return -1;
  if (alpn_len >= sizeof (t->resumption_alpn))
    return -1;
  if (alpn_len > 0 && !alpn)
    return -1;

  const char *cfg_alpn = t->config.alpn ? t->config.alpn : "h3";
  size_t cfg_alpn_len = strlen (cfg_alpn);
  if (alpn_len > 0)
    {
      if (cfg_alpn_len != alpn_len || memcmp (cfg_alpn, alpn, alpn_len) != 0)
        return -1;
    }

  uint8_t *copy = malloc (ticket_len);
  if (!copy)
    return -1;
  memcpy (copy, ticket, ticket_len);

  if (t->resumption_ticket)
    {
      SocketCrypto_secure_clear (t->resumption_ticket,
                                 t->resumption_ticket_len);
      free (t->resumption_ticket);
      t->resumption_ticket = NULL;
      t->resumption_ticket_len = 0;
    }

  t->resumption_ticket = copy;
  t->resumption_ticket_len = ticket_len;
  t->resumption_peer_params = *saved_peer_params;
  t->resumption_peer_params_valid = 1;

  if (alpn_len > 0)
    {
      memcpy (t->resumption_alpn, alpn, alpn_len);
      t->resumption_alpn_len = alpn_len;
    }
  else
    {
      t->resumption_alpn[0] = '\0';
      t->resumption_alpn_len = 0;
    }

  return 0;
}

int
SocketQUICTransport_export_resumption (SocketQUICTransport_T t,
                                       uint8_t *ticket,
                                       size_t *ticket_len,
                                       SocketQUICTransportParams_T *peer_params,
                                       char *alpn,
                                       size_t *alpn_len)
{
  if (!t || !t->connected || t->closed)
    return -1;
  if (!t->handshake || !ticket_len || !alpn_len)
    return -1;

  if (peer_params)
    {
      const SocketQUICTransportParams_T *pp
          = SocketQUICHandshake_get_peer_params (t->handshake);
      if (!pp)
        return -1;
      *peer_params = *pp;
    }

  const char *neg_alpn = NULL;
  size_t neg_alpn_len = 0;
  if (SocketQUICTLS_get_alpn (t->handshake, &neg_alpn, &neg_alpn_len)
      != QUIC_TLS_OK)
    return -1;

  if (alpn == NULL)
    {
      *alpn_len = neg_alpn_len;
    }
  else
    {
      if (*alpn_len < neg_alpn_len)
        {
          *alpn_len = neg_alpn_len;
          return -1;
        }
      memcpy (alpn, neg_alpn, neg_alpn_len);
      *alpn_len = neg_alpn_len;
    }

  SocketQUICTLS_Result tr
      = SocketQUICTLS_get_session_ticket (t->handshake, ticket, ticket_len);
  if (tr != QUIC_TLS_OK)
    return -1;

  return 0;
}

uint64_t
SocketQUICTransport_open_bidi_stream (SocketQUICTransport_T t)
{
  if (!t || !t->connected || t->closed)
    return UINT64_MAX;

  if (t->flow)
    {
      if (!SocketQUICFlow_can_open_stream_bidi (t->flow))
        return UINT64_MAX;
      if (SocketQUICFlow_open_stream_bidi (t->flow) != QUIC_FLOW_OK)
        return UINT64_MAX;
    }

  uint64_t id = t->next_bidi_id;
  t->next_bidi_id += 4;
  return id;
}

int
SocketQUICTransport_peer_close_received (SocketQUICTransport_T t)
{
  if (!t)
    return 0;
  return t->peer_close_received;
}

uint64_t
SocketQUICTransport_peer_close_error (SocketQUICTransport_T t)
{
  if (!t)
    return 0;
  return t->peer_close_error;
}

int
SocketQUICTransport_peer_close_is_app (SocketQUICTransport_T t)
{
  if (!t)
    return 0;
  return t->peer_close_is_app;
}

#endif /* SOCKET_HAS_TLS */
