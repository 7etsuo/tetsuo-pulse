/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICFrame.c
 * @brief QUIC Frame Parsing and Validation (RFC 9000 Section 12).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Frame Validation Table (RFC 9000 Table 3)
 * ============================================================================
 * Maps frame types to allowed packet types.
 */

/* All packet types */
#define PKT_ALL (QUIC_PKT_INITIAL | QUIC_PKT_0RTT | QUIC_PKT_HANDSHAKE | QUIC_PKT_1RTT)

/* Initial, Handshake, 1-RTT (not 0-RTT) */
#define PKT_IH1 (QUIC_PKT_INITIAL | QUIC_PKT_HANDSHAKE | QUIC_PKT_1RTT)

/* 0-RTT and 1-RTT only */
#define PKT_01 (QUIC_PKT_0RTT | QUIC_PKT_1RTT)

/* 1-RTT only */
#define PKT_1 (QUIC_PKT_1RTT)

/* RFC 9000 Section 10.3: Stateless Reset Token size */
#define QUIC_STATELESS_RESET_TOKEN_SIZE 16

/**
 * @brief Frame type to allowed packet types mapping.
 */
static const struct
{
  uint64_t type;
  int allowed;
} frame_validation_table[] = {
  { QUIC_FRAME_PADDING,               PKT_ALL },
  { QUIC_FRAME_PING,                  PKT_ALL },
  { QUIC_FRAME_ACK,                   PKT_IH1 },
  { QUIC_FRAME_ACK_ECN,               PKT_IH1 },
  { QUIC_FRAME_RESET_STREAM,          PKT_01  },
  { QUIC_FRAME_STOP_SENDING,          PKT_01  },
  { QUIC_FRAME_CRYPTO,                PKT_ALL & ~QUIC_PKT_0RTT },
  { QUIC_FRAME_NEW_TOKEN,             PKT_1   },
  { QUIC_FRAME_STREAM,                PKT_01  },
  { QUIC_FRAME_MAX_DATA,              PKT_01  },
  { QUIC_FRAME_MAX_STREAM_DATA,       PKT_01  },
  { QUIC_FRAME_MAX_STREAMS_BIDI,      PKT_01  },
  { QUIC_FRAME_MAX_STREAMS_UNI,       PKT_01  },
  { QUIC_FRAME_DATA_BLOCKED,          PKT_01  },
  { QUIC_FRAME_STREAM_DATA_BLOCKED,   PKT_01  },
  { QUIC_FRAME_STREAMS_BLOCKED_BIDI,  PKT_01  },
  { QUIC_FRAME_STREAMS_BLOCKED_UNI,   PKT_01  },
  { QUIC_FRAME_NEW_CONNECTION_ID,     PKT_01  },
  { QUIC_FRAME_RETIRE_CONNECTION_ID,  PKT_01  },
  { QUIC_FRAME_PATH_CHALLENGE,        PKT_01  },
  { QUIC_FRAME_PATH_RESPONSE,         PKT_1   },
  { QUIC_FRAME_CONNECTION_CLOSE,      PKT_ALL },
  { QUIC_FRAME_CONNECTION_CLOSE_APP,  PKT_01  },
  { QUIC_FRAME_HANDSHAKE_DONE,        PKT_1   },
  { QUIC_FRAME_DATAGRAM,              PKT_01  },
  { QUIC_FRAME_DATAGRAM_LEN,          PKT_01  },
  { 0, 0 } /* Sentinel */
};

/* ============================================================================
 * Helper: Decode varint with bounds check
 * ============================================================================
 */

static SocketQUICFrame_Result
decode_varint (const uint8_t *data, size_t len, size_t *pos,
               uint64_t *value)
{
  if (*pos >= len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  size_t consumed;
  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data + *pos, len - *pos, value, &consumed);

  if (res == QUIC_VARINT_INCOMPLETE)
    return QUIC_FRAME_ERROR_TRUNCATED;
  if (res != QUIC_VARINT_OK)
    return QUIC_FRAME_ERROR_VARINT;

  *pos += consumed;
  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse PADDING frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_padding (const uint8_t *data, size_t len, size_t *pos,
               SocketQUICFrame_T *frame)
{
  (void)data;
  (void)len;
  (void)pos;
  (void)frame;

  /* PADDING is just the type byte, already consumed */
  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse PING frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_ping (const uint8_t *data, size_t len, size_t *pos,
            SocketQUICFrame_T *frame)
{
  (void)data;
  (void)len;
  (void)pos;
  (void)frame;

  /* PING is just the type byte, already consumed */
  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse ACK frames
 * ============================================================================
 */

/**
 * @brief Parse basic ACK fields (largest_ack, ack_delay, range_count,
 *        first_range)
 *
 * Extracts the mandatory ACK frame fields and validates the first range.
 *
 * @param data Frame data buffer
 * @param len Buffer length
 * @param pos Current position (updated on success)
 * @param ack ACK frame structure to populate
 * @return QUIC_FRAME_OK on success, error code otherwise
 */
static SocketQUICFrame_Result
parse_ack_basic_fields (const uint8_t *data, size_t len, size_t *pos,
                        SocketQUICFrameAck_T *ack)
{
  SocketQUICFrame_Result res;

  /* Largest Acknowledged */
  res = decode_varint (data, len, pos, &ack->largest_ack);
  if (res != QUIC_FRAME_OK)
    return res;

  /* ACK Delay */
  res = decode_varint (data, len, pos, &ack->ack_delay);
  if (res != QUIC_FRAME_OK)
    return res;

  /* ACK Range Count */
  res = decode_varint (data, len, pos, &ack->range_count);
  if (res != QUIC_FRAME_OK)
    return res;

  /* First ACK Range */
  res = decode_varint (data, len, pos, &ack->first_range);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Validate first range */
  if (ack->first_range > ack->largest_ack)
    return QUIC_FRAME_ERROR_ACK_RANGE;

  return QUIC_FRAME_OK;
}

/**
 * @brief Parse additional ACK ranges with memory allocation
 *
 * Allocates and parses the gap/length pairs for additional ACK ranges.
 * Includes overflow protection and range count validation.
 *
 * @param data Frame data buffer
 * @param len Buffer length
 * @param pos Current position (updated on success)
 * @param ack ACK frame structure (range_count must be set)
 * @param arena Optional arena for allocation (NULL for malloc)
 * @return QUIC_FRAME_OK on success, error code otherwise
 */
static SocketQUICFrame_Result
parse_ack_ranges (const uint8_t *data, size_t len, size_t *pos,
                  SocketQUICFrameAck_T *ack, Arena_T arena)
{
  SocketQUICFrame_Result res;

  if (ack->range_count == 0)
    return QUIC_FRAME_OK;

  /* RFC 9000 allows arbitrary ACK ranges, but we limit to 256 to prevent
   * DoS attacks via excessive memory allocation and parsing overhead */
  if (ack->range_count > QUIC_FRAME_ACK_MAX_RANGES)
    return QUIC_FRAME_ERROR_ACK_RANGE;

  /* Overflow check: ensure range_count * sizeof doesn't wrap */
  if (ack->range_count > SIZE_MAX / sizeof (SocketQUICFrameAckRange_T))
    return QUIC_FRAME_ERROR_OVERFLOW;

  size_t range_size = (size_t)ack->range_count * sizeof (SocketQUICFrameAckRange_T);
  if (arena)
    ack->ranges = Arena_alloc (arena, range_size, __FILE__, __LINE__);
  else
    ack->ranges = malloc (range_size);

  if (!ack->ranges)
    return QUIC_FRAME_ERROR_INVALID;

  ack->ranges_capacity = (size_t)ack->range_count;

  for (uint64_t i = 0; i < ack->range_count; i++)
    {
      res = decode_varint (data, len, pos, &ack->ranges[i].gap);
      if (res != QUIC_FRAME_OK)
        return res;
      res = decode_varint (data, len, pos, &ack->ranges[i].length);
      if (res != QUIC_FRAME_OK)
        return res;
    }

  return QUIC_FRAME_OK;
}

/**
 * @brief Parse ACK or ACK_ECN frame (internal)
 *
 * Orchestrates the parsing of ACK frames by delegating to specialized
 * helper functions for each component. For ACK_ECN frames, inlines the
 * three ECN counter varint decodes directly.
 *
 * @param data Frame data buffer
 * @param len Buffer length
 * @param pos Current position (updated on success)
 * @param frame Frame structure (type must be set)
 * @param arena Optional arena for range allocation (NULL for malloc)
 * @return QUIC_FRAME_OK on success, error code otherwise
 */
static SocketQUICFrame_Result
parse_ack_internal (const uint8_t *data, size_t len, size_t *pos,
                    SocketQUICFrame_T *frame, Arena_T arena)
{
  SocketQUICFrameAck_T *ack = &frame->data.ack;
  SocketQUICFrame_Result res;

  /* Parse basic ACK fields */
  res = parse_ack_basic_fields (data, len, pos, ack);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Parse additional ACK ranges */
  res = parse_ack_ranges (data, len, pos, ack, arena);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Early exit if not ACK_ECN */
  if (frame->type != QUIC_FRAME_ACK_ECN)
    return QUIC_FRAME_OK;

  /* Parse ECN counts (inlined for performance) */
  res = decode_varint (data, len, pos, &ack->ect0_count);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &ack->ect1_count);
  if (res != QUIC_FRAME_OK)
    return res;

  return decode_varint (data, len, pos, &ack->ecn_ce_count);
}

static SocketQUICFrame_Result
parse_ack (const uint8_t *data, size_t len, size_t *pos,
           SocketQUICFrame_T *frame)
{
  return parse_ack_internal (data, len, pos, frame, NULL);
}

/* ============================================================================
 * Parse RESET_STREAM frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_reset_stream (const uint8_t *data, size_t len, size_t *pos,
                    SocketQUICFrame_T *frame)
{
  SocketQUICFrameResetStream_T *rs = &frame->data.reset_stream;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &rs->stream_id);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &rs->error_code);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &rs->final_size);
  if (res != QUIC_FRAME_OK)
    return res;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse STOP_SENDING frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_stop_sending (const uint8_t *data, size_t len, size_t *pos,
                    SocketQUICFrame_T *frame)
{
  SocketQUICFrameStopSending_T *ss = &frame->data.stop_sending;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &ss->stream_id);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &ss->error_code);
  if (res != QUIC_FRAME_OK)
    return res;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse CRYPTO frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_crypto (const uint8_t *data, size_t len, size_t *pos,
              SocketQUICFrame_T *frame)
{
  SocketQUICFrameCrypto_T *crypto = &frame->data.crypto;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &crypto->offset);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &crypto->length);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Validate data length */
  if (*pos + crypto->length > len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  /* Prevent overflow on 32-bit systems */
  if (crypto->length > SIZE_MAX)
    return QUIC_FRAME_ERROR_OVERFLOW;

  crypto->data = data + *pos;
  *pos += (size_t)crypto->length;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse NEW_TOKEN frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_new_token (const uint8_t *data, size_t len, size_t *pos,
                 SocketQUICFrame_T *frame)
{
  SocketQUICFrameNewToken_T *nt = &frame->data.new_token;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &nt->token_length);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Empty token is invalid */
  if (nt->token_length == 0)
    return QUIC_FRAME_ERROR_INVALID;

  if (*pos + nt->token_length > len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  /* Prevent overflow on 32-bit systems */
  if (nt->token_length > SIZE_MAX)
    return QUIC_FRAME_ERROR_OVERFLOW;

  nt->token = data + *pos;
  *pos += (size_t)nt->token_length;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse STREAM frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_stream (const uint8_t *data, size_t len, size_t *pos,
              SocketQUICFrame_T *frame)
{
  SocketQUICFrameStream_T *stream = &frame->data.stream;
  SocketQUICFrame_Result res;
  int flags = SocketQUICFrame_stream_flags (frame->type);

  stream->has_fin = (flags & QUIC_FRAME_STREAM_FIN) != 0;
  stream->has_length = (flags & QUIC_FRAME_STREAM_LEN) != 0;
  stream->has_offset = (flags & QUIC_FRAME_STREAM_OFF) != 0;

  res = decode_varint (data, len, pos, &stream->stream_id);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Handle offset with early initialization */
  stream->offset = 0;
  if (stream->has_offset)
    {
      res = decode_varint (data, len, pos, &stream->offset);
      if (res != QUIC_FRAME_OK)
        return res;
    }

  /* Handle length with early initialization */
  if (!stream->has_length)
    {
      stream->length = len - *pos;
    }
  else
    {
      res = decode_varint (data, len, pos, &stream->length);
      if (res != QUIC_FRAME_OK)
        return res;

      if (*pos + stream->length > len)
        return QUIC_FRAME_ERROR_TRUNCATED;

      /* Prevent overflow on 32-bit systems (CWE-190, CWE-681) */
      if (stream->length > SIZE_MAX)
        return QUIC_FRAME_ERROR_OVERFLOW;
    }

  stream->data = data + *pos;
  *pos += (size_t)stream->length;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse MAX_DATA frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_max_data (const uint8_t *data, size_t len, size_t *pos,
                SocketQUICFrame_T *frame)
{
  return decode_varint (data, len, pos, &frame->data.max_data.max_data);
}

/* ============================================================================
 * Parse MAX_STREAM_DATA frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_max_stream_data (const uint8_t *data, size_t len, size_t *pos,
                       SocketQUICFrame_T *frame)
{
  SocketQUICFrameMaxStreamData_T *msd = &frame->data.max_stream_data;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &msd->stream_id);
  if (res != QUIC_FRAME_OK)
    return res;

  return decode_varint (data, len, pos, &msd->max_data);
}

/* ============================================================================
 * Parse MAX_STREAMS frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_max_streams (const uint8_t *data, size_t len, size_t *pos,
                   SocketQUICFrame_T *frame)
{
  SocketQUICFrameMaxStreams_T *ms = &frame->data.max_streams;
  ms->is_bidi = (frame->type == QUIC_FRAME_MAX_STREAMS_BIDI);
  return decode_varint (data, len, pos, &ms->max_streams);
}

/* ============================================================================
 * Parse DATA_BLOCKED frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_data_blocked (const uint8_t *data, size_t len, size_t *pos,
                    SocketQUICFrame_T *frame)
{
  return decode_varint (data, len, pos, &frame->data.data_blocked.limit);
}

/* ============================================================================
 * Parse STREAM_DATA_BLOCKED frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_stream_data_blocked (const uint8_t *data, size_t len, size_t *pos,
                           SocketQUICFrame_T *frame)
{
  SocketQUICFrameStreamDataBlocked_T *sdb = &frame->data.stream_data_blocked;
  SocketQUICFrame_Result res;

  res = decode_varint (data, len, pos, &sdb->stream_id);
  if (res != QUIC_FRAME_OK)
    return res;

  return decode_varint (data, len, pos, &sdb->limit);
}

/* ============================================================================
 * Parse STREAMS_BLOCKED frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_streams_blocked (const uint8_t *data, size_t len, size_t *pos,
                       SocketQUICFrame_T *frame)
{
  SocketQUICFrameStreamsBlocked_T *sb = &frame->data.streams_blocked;
  sb->is_bidi = (frame->type == QUIC_FRAME_STREAMS_BLOCKED_BIDI);
  return decode_varint (data, len, pos, &sb->limit);
}

/* ============================================================================
 * Parse NEW_CONNECTION_ID frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_new_connection_id (const uint8_t *data, size_t len, size_t *pos,
                         SocketQUICFrame_T *frame)
{
  SocketQUICFrameNewConnectionID_T *ncid = &frame->data.new_connection_id;
  SocketQUICFrame_Result res;
  uint64_t cid_len;

  res = decode_varint (data, len, pos, &ncid->sequence);
  if (res != QUIC_FRAME_OK)
    return res;

  res = decode_varint (data, len, pos, &ncid->retire_prior_to);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Validate retire_prior_to <= sequence */
  if (ncid->retire_prior_to > ncid->sequence)
    return QUIC_FRAME_ERROR_INVALID;

  /* Connection ID length (1 byte) */
  if (*pos >= len)
    return QUIC_FRAME_ERROR_TRUNCATED;
  cid_len = data[*pos];
  (*pos)++;

  /* Validate CID length (1-20 bytes, 0 not allowed for NEW_CONNECTION_ID) */
  if (cid_len < 1 || cid_len > 20)
    return QUIC_FRAME_ERROR_INVALID;

  ncid->cid_length = (uint8_t)cid_len;

  /* Connection ID */
  if (*pos + cid_len > len)
    return QUIC_FRAME_ERROR_TRUNCATED;
  memcpy (ncid->cid, data + *pos, (size_t)cid_len);
  *pos += (size_t)cid_len;

  /* Stateless Reset Token */
  if (*pos + QUIC_STATELESS_RESET_TOKEN_SIZE > len)
    return QUIC_FRAME_ERROR_TRUNCATED;
  memcpy (ncid->stateless_reset_token, data + *pos, QUIC_STATELESS_RESET_TOKEN_SIZE);
  *pos += QUIC_STATELESS_RESET_TOKEN_SIZE;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse RETIRE_CONNECTION_ID frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_retire_connection_id (const uint8_t *data, size_t len, size_t *pos,
                            SocketQUICFrame_T *frame)
{
  return decode_varint (data, len, pos,
                        &frame->data.retire_connection_id.sequence);
}

/* ============================================================================
 * Parse PATH_CHALLENGE frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_path_challenge (const uint8_t *data, size_t len, size_t *pos,
                      SocketQUICFrame_T *frame)
{
  if (*pos + QUIC_PATH_DATA_SIZE > len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  memcpy (frame->data.path_challenge.data, data + *pos, QUIC_PATH_DATA_SIZE);
  *pos += QUIC_PATH_DATA_SIZE;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse PATH_RESPONSE frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_path_response (const uint8_t *data, size_t len, size_t *pos,
                     SocketQUICFrame_T *frame)
{
  if (*pos + QUIC_PATH_DATA_SIZE > len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  memcpy (frame->data.path_response.data, data + *pos, QUIC_PATH_DATA_SIZE);
  *pos += QUIC_PATH_DATA_SIZE;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse CONNECTION_CLOSE frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_connection_close (const uint8_t *data, size_t len, size_t *pos,
                        SocketQUICFrame_T *frame)
{
  SocketQUICFrameConnectionClose_T *cc = &frame->data.connection_close;
  SocketQUICFrame_Result res;

  cc->is_app_error = (frame->type == QUIC_FRAME_CONNECTION_CLOSE_APP);

  res = decode_varint (data, len, pos, &cc->error_code);
  if (res != QUIC_FRAME_OK)
    return res;

  /* QUIC layer close includes frame type */
  if (!cc->is_app_error)
    {
      res = decode_varint (data, len, pos, &cc->frame_type);
      if (res != QUIC_FRAME_OK)
        return res;
    }
  else
    cc->frame_type = 0;

  res = decode_varint (data, len, pos, &cc->reason_length);
  if (res != QUIC_FRAME_OK)
    return res;

  if (*pos + cc->reason_length > len)
    return QUIC_FRAME_ERROR_TRUNCATED;

  /* Prevent overflow on 32-bit systems */
  if (cc->reason_length > SIZE_MAX)
    return QUIC_FRAME_ERROR_OVERFLOW;

  cc->reason = (cc->reason_length > 0) ? (data + *pos) : NULL;
  *pos += (size_t)cc->reason_length;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse HANDSHAKE_DONE frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_handshake_done (const uint8_t *data, size_t len, size_t *pos,
                      SocketQUICFrame_T *frame)
{
  (void)data;
  (void)len;
  (void)pos;
  (void)frame;

  /* HANDSHAKE_DONE is just the type byte */
  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Parse DATAGRAM frames
 * ============================================================================
 */

static SocketQUICFrame_Result
parse_datagram (const uint8_t *data, size_t len, size_t *pos,
                SocketQUICFrame_T *frame)
{
  SocketQUICFrameDatagram_T *dg = &frame->data.datagram;

  dg->has_length = (frame->type == QUIC_FRAME_DATAGRAM_LEN);

  /* Set default length with early initialization */
  dg->length = len - *pos;

  if (dg->has_length)
    {
      SocketQUICFrame_Result res = decode_varint (data, len, pos, &dg->length);
      if (res != QUIC_FRAME_OK)
        return res;

      if (*pos + dg->length > len)
        return QUIC_FRAME_ERROR_TRUNCATED;
    }

  /* Prevent overflow on 32-bit systems */
  if (dg->length > SIZE_MAX)
    return QUIC_FRAME_ERROR_OVERFLOW;

  dg->data = data + *pos;
  *pos += (size_t)dg->length;

  return QUIC_FRAME_OK;
}

/* ============================================================================
 * Frame Parser Dispatch Table
 * ============================================================================
 */

typedef SocketQUICFrame_Result (*frame_parser_fn) (const uint8_t *data,
                                                    size_t len, size_t *pos,
                                                    SocketQUICFrame_T *frame);

/* Maximum frame type value (DATAGRAM_LEN = 0x31) */
#define QUIC_FRAME_TYPE_MAX 0x32

/**
 * @brief Direct lookup array for O(1) frame parser dispatch.
 *
 * RFC 9000 Section 12.4 defines QUIC frame types in a relatively dense space:
 * - 0x00-0x1e: Standard frames
 * - 0x30-0x31: DATAGRAM extension frames
 *
 * This array provides constant-time dispatch instead of linear search through
 * 21 parser entries. Memory cost: 400 bytes (50 x 8-byte pointers).
 */
static frame_parser_fn parser_dispatch_array[QUIC_FRAME_TYPE_MAX] = { NULL };

/**
 * @brief Initialize frame parser dispatch array.
 *
 * This function is called automatically before main() via GCC constructor
 * attribute. It populates the dispatch array with function pointers for
 * all supported frame types.
 */
static void __attribute__ ((constructor))
init_parser_dispatch_array (void)
{
  /* Single-type mappings */
  parser_dispatch_array[QUIC_FRAME_PADDING] = parse_padding;
  parser_dispatch_array[QUIC_FRAME_PING] = parse_ping;
  parser_dispatch_array[QUIC_FRAME_RESET_STREAM] = parse_reset_stream;
  parser_dispatch_array[QUIC_FRAME_STOP_SENDING] = parse_stop_sending;
  parser_dispatch_array[QUIC_FRAME_CRYPTO] = parse_crypto;
  parser_dispatch_array[QUIC_FRAME_NEW_TOKEN] = parse_new_token;
  parser_dispatch_array[QUIC_FRAME_MAX_DATA] = parse_max_data;
  parser_dispatch_array[QUIC_FRAME_MAX_STREAM_DATA] = parse_max_stream_data;
  parser_dispatch_array[QUIC_FRAME_DATA_BLOCKED] = parse_data_blocked;
  parser_dispatch_array[QUIC_FRAME_STREAM_DATA_BLOCKED]
      = parse_stream_data_blocked;
  parser_dispatch_array[QUIC_FRAME_NEW_CONNECTION_ID] = parse_new_connection_id;
  parser_dispatch_array[QUIC_FRAME_RETIRE_CONNECTION_ID]
      = parse_retire_connection_id;
  parser_dispatch_array[QUIC_FRAME_PATH_CHALLENGE] = parse_path_challenge;
  parser_dispatch_array[QUIC_FRAME_PATH_RESPONSE] = parse_path_response;
  parser_dispatch_array[QUIC_FRAME_HANDSHAKE_DONE] = parse_handshake_done;

  /* ACK frames (0x02-0x03) */
  parser_dispatch_array[QUIC_FRAME_ACK] = parse_ack;
  parser_dispatch_array[QUIC_FRAME_ACK_ECN] = parse_ack;

  /* STREAM frames (0x08-0x0f) */
  for (uint64_t i = QUIC_FRAME_STREAM; i <= QUIC_FRAME_STREAM_MAX; i++)
    parser_dispatch_array[i] = parse_stream;

  /* MAX_STREAMS frames (0x12-0x13) */
  parser_dispatch_array[QUIC_FRAME_MAX_STREAMS_BIDI] = parse_max_streams;
  parser_dispatch_array[QUIC_FRAME_MAX_STREAMS_UNI] = parse_max_streams;

  /* STREAMS_BLOCKED frames (0x16-0x17) */
  parser_dispatch_array[QUIC_FRAME_STREAMS_BLOCKED_BIDI] = parse_streams_blocked;
  parser_dispatch_array[QUIC_FRAME_STREAMS_BLOCKED_UNI] = parse_streams_blocked;

  /* CONNECTION_CLOSE frames (0x1c-0x1d) */
  parser_dispatch_array[QUIC_FRAME_CONNECTION_CLOSE] = parse_connection_close;
  parser_dispatch_array[QUIC_FRAME_CONNECTION_CLOSE_APP]
      = parse_connection_close;

  /* DATAGRAM frames (0x30-0x31) */
  parser_dispatch_array[QUIC_FRAME_DATAGRAM] = parse_datagram;
  parser_dispatch_array[QUIC_FRAME_DATAGRAM_LEN] = parse_datagram;
}

/**
 * @brief Dispatch frame parser based on frame type.
 *
 * Performs O(1) lookup in pre-initialized dispatch array. Replaces previous
 * O(n) linear search through parser table.
 *
 * @param type   QUIC frame type (from variable-length integer)
 * @param data   Raw packet data
 * @param len    Total data length
 * @param pos    Current parse position (updated by parser)
 * @param frame  Output frame structure
 * @return       QUIC_FRAME_OK or error code
 */
static SocketQUICFrame_Result
dispatch_frame_parser (uint64_t type, const uint8_t *data, size_t len,
                       size_t *pos, SocketQUICFrame_T *frame)
{
  /* Bounds check: reject types outside dispatch array */
  if (type >= QUIC_FRAME_TYPE_MAX)
    return QUIC_FRAME_ERROR_TYPE;

  /* Lookup parser for this frame type */
  frame_parser_fn parser = parser_dispatch_array[type];
  if (parser == NULL)
    return QUIC_FRAME_ERROR_TYPE;

  /* Dispatch to type-specific parser */
  return parser (data, len, pos, frame);
}

/* ============================================================================
 * Public Functions
 * ============================================================================
 */

void
SocketQUICFrame_init (SocketQUICFrame_T *frame)
{
  if (frame)
    memset (frame, 0, sizeof (*frame));
}

SocketQUICFrame_Result
SocketQUICFrame_parse (const uint8_t *data, size_t len,
                       SocketQUICFrame_T *frame, size_t *consumed)
{
  if (!data || !frame || !consumed)
    return QUIC_FRAME_ERROR_NULL;

  SocketQUICFrame_init (frame);
  size_t pos = 0;

  /* Decode frame type */
  SocketQUICFrame_Result res = decode_varint (data, len, &pos, &frame->type);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Dispatch to type-specific parser via table lookup */
  res = dispatch_frame_parser (frame->type, data, len, &pos, frame);

  if (res == QUIC_FRAME_OK)
    {
      frame->wire_length = pos;
      *consumed = pos;
    }

  return res;
}

SocketQUICFrame_Result
SocketQUICFrame_parse_arena (Arena_T arena, const uint8_t *data, size_t len,
                             SocketQUICFrame_T *frame, size_t *consumed)
{
  if (!data || !frame || !consumed)
    return QUIC_FRAME_ERROR_NULL;

  SocketQUICFrame_init (frame);
  size_t pos = 0;

  /* Decode frame type */
  SocketQUICFrame_Result res = decode_varint (data, len, &pos, &frame->type);
  if (res != QUIC_FRAME_OK)
    return res;

  /* Only ACK needs special arena handling */
  uint64_t type = frame->type;

  if (type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN)
    res = parse_ack_internal (data, len, &pos, frame, arena);
  else
    {
      /* Use standard parser for non-ACK frames */
      size_t temp_consumed;
      res = SocketQUICFrame_parse (data, len, frame, &temp_consumed);
      if (res == QUIC_FRAME_OK)
        pos = temp_consumed;
      return res;
    }

  if (res == QUIC_FRAME_OK)
    {
      frame->wire_length = pos;
      *consumed = pos;
    }

  return res;
}

void
SocketQUICFrame_free (SocketQUICFrame_T *frame)
{
  if (!frame)
    return;

  /* Free ACK ranges if heap-allocated */
  if ((frame->type == QUIC_FRAME_ACK || frame->type == QUIC_FRAME_ACK_ECN)
      && frame->data.ack.ranges)
    {
      free (frame->data.ack.ranges);
      frame->data.ack.ranges = NULL;
    }
}

SocketQUICFrame_Result
SocketQUICFrame_validate (const SocketQUICFrame_T *frame, int pkt_flags)
{
  if (!frame)
    return QUIC_FRAME_ERROR_NULL;

  int allowed = SocketQUICFrame_allowed_packets (frame->type);
  if ((allowed & pkt_flags) == 0)
    return QUIC_FRAME_ERROR_PACKET_TYPE;

  return QUIC_FRAME_OK;
}

int
SocketQUICFrame_packet_type_to_flags (SocketQUICPacket_Type pkt_type)
{
  switch (pkt_type)
    {
    case QUIC_PACKET_TYPE_INITIAL:
      return QUIC_PKT_INITIAL;
    case QUIC_PACKET_TYPE_0RTT:
      return QUIC_PKT_0RTT;
    case QUIC_PACKET_TYPE_HANDSHAKE:
      return QUIC_PKT_HANDSHAKE;
    case QUIC_PACKET_TYPE_1RTT:
      return QUIC_PKT_1RTT;
    default:
      return 0;
    }
}

int
SocketQUICFrame_is_ack_eliciting (uint64_t frame_type)
{
  /* ACK, PADDING, and CONNECTION_CLOSE are not ACK-eliciting */
  if (frame_type == QUIC_FRAME_ACK || frame_type == QUIC_FRAME_ACK_ECN)
    return 0;
  if (frame_type == QUIC_FRAME_PADDING)
    return 0;
  if (frame_type == QUIC_FRAME_CONNECTION_CLOSE
      || frame_type == QUIC_FRAME_CONNECTION_CLOSE_APP)
    return 0;

  return 1;
}

int
SocketQUICFrame_allowed_packets (uint64_t frame_type)
{
  /* Handle STREAM range */
  if (SocketQUICFrame_is_stream (frame_type))
    return PKT_01;

  /* Look up in validation table */
  for (size_t i = 0; frame_validation_table[i].allowed != 0; i++)
    {
      if (frame_validation_table[i].type == frame_type)
        return frame_validation_table[i].allowed;
    }

  /* Unknown frame type - not allowed anywhere */
  return 0;
}

/**
 * @brief Frame type to name mapping table.
 */
static const struct
{
  uint64_t type;
  const char *name;
} frame_type_names[] = {
  { QUIC_FRAME_PADDING,               "PADDING" },
  { QUIC_FRAME_PING,                  "PING" },
  { QUIC_FRAME_ACK,                   "ACK" },
  { QUIC_FRAME_ACK_ECN,               "ACK_ECN" },
  { QUIC_FRAME_RESET_STREAM,          "RESET_STREAM" },
  { QUIC_FRAME_STOP_SENDING,          "STOP_SENDING" },
  { QUIC_FRAME_CRYPTO,                "CRYPTO" },
  { QUIC_FRAME_NEW_TOKEN,             "NEW_TOKEN" },
  { QUIC_FRAME_MAX_DATA,              "MAX_DATA" },
  { QUIC_FRAME_MAX_STREAM_DATA,       "MAX_STREAM_DATA" },
  { QUIC_FRAME_MAX_STREAMS_BIDI,      "MAX_STREAMS_BIDI" },
  { QUIC_FRAME_MAX_STREAMS_UNI,       "MAX_STREAMS_UNI" },
  { QUIC_FRAME_DATA_BLOCKED,          "DATA_BLOCKED" },
  { QUIC_FRAME_STREAM_DATA_BLOCKED,   "STREAM_DATA_BLOCKED" },
  { QUIC_FRAME_STREAMS_BLOCKED_BIDI,  "STREAMS_BLOCKED_BIDI" },
  { QUIC_FRAME_STREAMS_BLOCKED_UNI,   "STREAMS_BLOCKED_UNI" },
  { QUIC_FRAME_NEW_CONNECTION_ID,     "NEW_CONNECTION_ID" },
  { QUIC_FRAME_RETIRE_CONNECTION_ID,  "RETIRE_CONNECTION_ID" },
  { QUIC_FRAME_PATH_CHALLENGE,        "PATH_CHALLENGE" },
  { QUIC_FRAME_PATH_RESPONSE,         "PATH_RESPONSE" },
  { QUIC_FRAME_CONNECTION_CLOSE,      "CONNECTION_CLOSE" },
  { QUIC_FRAME_CONNECTION_CLOSE_APP,  "CONNECTION_CLOSE_APP" },
  { QUIC_FRAME_HANDSHAKE_DONE,        "HANDSHAKE_DONE" },
  { QUIC_FRAME_DATAGRAM,              "DATAGRAM" },
  { QUIC_FRAME_DATAGRAM_LEN,          "DATAGRAM_LEN" },
  { 0, NULL } /* Sentinel */
};

const char *
SocketQUICFrame_type_string (uint64_t frame_type)
{
  /* Handle STREAM type range (0x08-0x0f) */
  if (SocketQUICFrame_is_stream (frame_type))
    return "STREAM";

  /* Table lookup */
  for (size_t i = 0; frame_type_names[i].name != NULL; i++)
    {
      if (frame_type_names[i].type == frame_type)
        return frame_type_names[i].name;
    }

  return "UNKNOWN";
}

const char *
SocketQUICFrame_result_string (SocketQUICFrame_Result result)
{
  switch (result)
    {
    case QUIC_FRAME_OK:
      return "OK";
    case QUIC_FRAME_ERROR_NULL:
      return "NULL pointer";
    case QUIC_FRAME_ERROR_TRUNCATED:
      return "Truncated input";
    case QUIC_FRAME_ERROR_INVALID:
      return "Invalid frame format";
    case QUIC_FRAME_ERROR_TYPE:
      return "Unknown frame type";
    case QUIC_FRAME_ERROR_PACKET_TYPE:
      return "Frame not allowed in packet type";
    case QUIC_FRAME_ERROR_VARINT:
      return "Variable integer decode error";
    case QUIC_FRAME_ERROR_STREAM_ID:
      return "Invalid stream ID";
    case QUIC_FRAME_ERROR_OVERFLOW:
      return "Integer overflow";
    case QUIC_FRAME_ERROR_ACK_RANGE:
      return "Invalid ACK range";
    default:
      return "Unknown error";
    }
}
