/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETQUICFRAME_INCLUDED
#define SOCKETQUICFRAME_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "quic/SocketQUICPacket.h"

#define QUIC_FRAME_ACK_MAX_RANGES 256
#define QUIC_FRAME_HEADER_MAX_SIZE 32

typedef enum {
  QUIC_FRAME_PADDING = 0x00, QUIC_FRAME_PING = 0x01,
  QUIC_FRAME_ACK = 0x02, QUIC_FRAME_ACK_ECN = 0x03,
  QUIC_FRAME_RESET_STREAM = 0x04, QUIC_FRAME_STOP_SENDING = 0x05,
  QUIC_FRAME_CRYPTO = 0x06, QUIC_FRAME_NEW_TOKEN = 0x07,
  QUIC_FRAME_STREAM = 0x08, QUIC_FRAME_STREAM_MAX = 0x0f,
  QUIC_FRAME_MAX_DATA = 0x10, QUIC_FRAME_MAX_STREAM_DATA = 0x11,
  QUIC_FRAME_MAX_STREAMS_BIDI = 0x12, QUIC_FRAME_MAX_STREAMS_UNI = 0x13,
  QUIC_FRAME_DATA_BLOCKED = 0x14, QUIC_FRAME_STREAM_DATA_BLOCKED = 0x15,
  QUIC_FRAME_STREAMS_BLOCKED_BIDI = 0x16, QUIC_FRAME_STREAMS_BLOCKED_UNI = 0x17,
  QUIC_FRAME_NEW_CONNECTION_ID = 0x18, QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19,
  QUIC_FRAME_PATH_CHALLENGE = 0x1a, QUIC_FRAME_PATH_RESPONSE = 0x1b,
  QUIC_FRAME_CONNECTION_CLOSE = 0x1c, QUIC_FRAME_CONNECTION_CLOSE_APP = 0x1d,
  QUIC_FRAME_HANDSHAKE_DONE = 0x1e,
  QUIC_FRAME_DATAGRAM = 0x30, QUIC_FRAME_DATAGRAM_LEN = 0x31
} SocketQUICFrame_Type;

#define QUIC_FRAME_STREAM_FIN 0x01
#define QUIC_FRAME_STREAM_LEN 0x02
#define QUIC_FRAME_STREAM_OFF 0x04

typedef enum {
  QUIC_FRAME_OK = 0, QUIC_FRAME_ERROR_NULL, QUIC_FRAME_ERROR_TRUNCATED,
  QUIC_FRAME_ERROR_INVALID, QUIC_FRAME_ERROR_TYPE, QUIC_FRAME_ERROR_PACKET_TYPE,
  QUIC_FRAME_ERROR_VARINT, QUIC_FRAME_ERROR_STREAM_ID,
  QUIC_FRAME_ERROR_OVERFLOW, QUIC_FRAME_ERROR_ACK_RANGE
} SocketQUICFrame_Result;

typedef enum {
  QUIC_PKT_INITIAL = 0x01, QUIC_PKT_0RTT = 0x02,
  QUIC_PKT_HANDSHAKE = 0x04, QUIC_PKT_1RTT = 0x08
} SocketQUICFrame_PacketFlag;

typedef struct SocketQUICFrameAckRange {
  uint64_t gap; uint64_t length;
} SocketQUICFrameAckRange_T;

typedef struct SocketQUICFrameAck {
  uint64_t largest_ack; uint64_t ack_delay; uint64_t range_count;
  uint64_t first_range; uint64_t ect0_count; uint64_t ect1_count;
  uint64_t ecn_ce_count; SocketQUICFrameAckRange_T *ranges;
  size_t ranges_capacity;
} SocketQUICFrameAck_T;

typedef struct SocketQUICFrameStream {
  uint64_t stream_id; uint64_t offset; uint64_t length;
  const uint8_t *data; int has_fin; int has_length; int has_offset;
} SocketQUICFrameStream_T;

typedef struct SocketQUICFrameCrypto {
  uint64_t offset; uint64_t length; const uint8_t *data;
} SocketQUICFrameCrypto_T;

typedef struct SocketQUICFrameResetStream {
  uint64_t stream_id; uint64_t error_code; uint64_t final_size;
} SocketQUICFrameResetStream_T;

typedef struct SocketQUICFrameStopSending {
  uint64_t stream_id; uint64_t error_code;
} SocketQUICFrameStopSending_T;

typedef struct SocketQUICFrameNewToken {
  uint64_t token_length; const uint8_t *token;
} SocketQUICFrameNewToken_T;

typedef struct SocketQUICFrameMaxData {
  uint64_t max_data;
} SocketQUICFrameMaxData_T;

typedef struct SocketQUICFrameMaxStreamData {
  uint64_t stream_id; uint64_t max_data;
} SocketQUICFrameMaxStreamData_T;

typedef struct SocketQUICFrameMaxStreams {
  uint64_t max_streams; int is_bidi;
} SocketQUICFrameMaxStreams_T;

typedef struct SocketQUICFrameDataBlocked {
  uint64_t limit;
} SocketQUICFrameDataBlocked_T;

typedef struct SocketQUICFrameStreamDataBlocked {
  uint64_t stream_id; uint64_t limit;
} SocketQUICFrameStreamDataBlocked_T;

typedef struct SocketQUICFrameStreamsBlocked {
  uint64_t limit; int is_bidi;
} SocketQUICFrameStreamsBlocked_T;

typedef struct SocketQUICFrameNewConnectionID {
  uint64_t sequence; uint64_t retire_prior_to; uint8_t cid_length;
  uint8_t cid[20]; uint8_t stateless_reset_token[16];
} SocketQUICFrameNewConnectionID_T;

typedef struct SocketQUICFrameRetireConnectionID {
  uint64_t sequence;
} SocketQUICFrameRetireConnectionID_T;

typedef struct SocketQUICFramePathChallenge {
  uint8_t data[8];
} SocketQUICFramePathChallenge_T;

typedef struct SocketQUICFramePathResponse {
  uint8_t data[8];
} SocketQUICFramePathResponse_T;

typedef struct SocketQUICFrameConnectionClose {
  uint64_t error_code; uint64_t frame_type; uint64_t reason_length;
  const uint8_t *reason; int is_app_error;
} SocketQUICFrameConnectionClose_T;

typedef struct SocketQUICFrameDatagram {
  uint64_t length; const uint8_t *data; int has_length;
} SocketQUICFrameDatagram_T;

typedef union SocketQUICFrameData {
  SocketQUICFrameAck_T ack;
  SocketQUICFrameStream_T stream;
  SocketQUICFrameCrypto_T crypto;
  SocketQUICFrameResetStream_T reset_stream;
  SocketQUICFrameStopSending_T stop_sending;
  SocketQUICFrameNewToken_T new_token;
  SocketQUICFrameMaxData_T max_data;
  SocketQUICFrameMaxStreamData_T max_stream_data;
  SocketQUICFrameMaxStreams_T max_streams;
  SocketQUICFrameDataBlocked_T data_blocked;
  SocketQUICFrameStreamDataBlocked_T stream_data_blocked;
  SocketQUICFrameStreamsBlocked_T streams_blocked;
  SocketQUICFrameNewConnectionID_T new_connection_id;
  SocketQUICFrameRetireConnectionID_T retire_connection_id;
  SocketQUICFramePathChallenge_T path_challenge;
  SocketQUICFramePathResponse_T path_response;
  SocketQUICFrameConnectionClose_T connection_close;
  SocketQUICFrameDatagram_T datagram;
} SocketQUICFrameData_T;

typedef struct SocketQUICFrame {
  uint64_t type; SocketQUICFrameData_T data; size_t wire_length;
} SocketQUICFrame_T;

extern void SocketQUICFrame_init(SocketQUICFrame_T *frame);
extern SocketQUICFrame_Result SocketQUICFrame_parse(const uint8_t *data, size_t len, SocketQUICFrame_T *frame, size_t *consumed);
extern SocketQUICFrame_Result SocketQUICFrame_parse_arena(Arena_T arena, const uint8_t *data, size_t len, SocketQUICFrame_T *frame, size_t *consumed);
extern void SocketQUICFrame_free(SocketQUICFrame_T *frame);
extern SocketQUICFrame_Result SocketQUICFrame_validate(const SocketQUICFrame_T *frame, int pkt_flags);
extern int SocketQUICFrame_packet_type_to_flags(SocketQUICPacket_Type pkt_type);
extern int SocketQUICFrame_is_ack_eliciting(uint64_t frame_type);
static inline int SocketQUICFrame_is_stream(uint64_t frame_type) {
  return frame_type >= QUIC_FRAME_STREAM && frame_type <= QUIC_FRAME_STREAM_MAX;
}
static inline int SocketQUICFrame_stream_flags(uint64_t frame_type) {
  return (int)(frame_type & 0x07);
}
extern const char *SocketQUICFrame_type_string(uint64_t frame_type);
extern const char *SocketQUICFrame_result_string(SocketQUICFrame_Result result);
extern int SocketQUICFrame_allowed_packets(uint64_t frame_type);

/* CONNECTION_CLOSE frame encoding (RFC 9000 Section 19.19) */
extern size_t SocketQUICFrame_encode_connection_close_transport(
    uint64_t error_code, uint64_t frame_type,
    const char *reason, uint8_t *out, size_t out_len);

extern size_t SocketQUICFrame_encode_connection_close_app(
    uint64_t error_code, const char *reason,
    uint8_t *out, size_t out_len);

#endif /* SOCKETQUICFRAME_INCLUDED */
