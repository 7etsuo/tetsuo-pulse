/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketWS-frame.c - WebSocket Frame Processing (RFC 6455 Section 5)
 *
 * Frame parsing, serialization, and optimized XOR masking.
 *
 * Frame Format (RFC 6455 Section 5.2):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 * |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 * | |1|2|3|       |K|             |                               |
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |     Extended payload length continued, if payload len == 127  |
 * +-------------------------------+-------------------------------+
 * |                               |Masking-key, if MASK set to 1  |
 * +-------------------------------+-------------------------------+
 * | Masking-key (continued)       |          Payload Data         |
 * +-------------------------------- - - - - - - - - - - - - - - - +
 *
 * Module Reuse:
 * - SocketCrypto_random_bytes(): Generate mask keys
 * - SocketBuf: Circular buffer I/O
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-private.h"

/** RFC 6455: MSB of 64-bit payload length must be 0 */
#define SOCKETWS_PAYLOAD_MSB_MASK (1ULL << 63)


/* XOR Masking Helpers */
static void
ws_mask_unaligned_bytes (unsigned char *data,
                         size_t len,
                         const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                         size_t start_offset);
static void
ws_mask_aligned_block (uint64_t *data, size_t count, uint64_t mask64);
static uint64_t
ws_build_mask64 (const unsigned char mask[SOCKETWS_MASK_KEY_SIZE]);

/* Header Buffer Helpers */

/* Frame Header Parsing Helpers */
static SocketWS_Error ws_parse_basic_header (SocketWS_FrameParse *frame);
static SocketWS_Error
ws_validate_frame_header (const SocketWS_FrameParse *frame);
static void ws_determine_header_length (SocketWS_FrameParse *frame);
static void ws_transition_to_payload (SocketWS_FrameParse *frame);
static SocketWS_Error ws_parse_extended_length (SocketWS_FrameParse *frame);
static void ws_extract_mask_key (SocketWS_FrameParse *frame);
static SocketWS_Error ws_process_header_state (SocketWS_FrameParse *frame,
                                               const unsigned char **data,
                                               size_t *len,
                                               size_t *consumed);
static SocketWS_Error ws_process_extended_len_state (SocketWS_FrameParse *frame,
                                                     const unsigned char **data,
                                                     size_t *len,
                                                     size_t *consumed);
static SocketWS_Error ws_process_mask_key_state (SocketWS_FrameParse *frame,
                                                 const unsigned char **data,
                                                 size_t *len,
                                                 size_t *consumed);

/* Frame Header Building Helpers */
static size_t ws_encode_payload_length (unsigned char *header,
                                        size_t offset,
                                        int masked,
                                        uint64_t payload_len);
static size_t ws_encode_extended_length (unsigned char *header,
                                         size_t offset,
                                         uint64_t len,
                                         unsigned char code);

/* Mask Key Helpers */
static int ws_ensure_mask_key (SocketWS_T ws,
                               unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE],
                               int *masked);

/* Send Buffer Helpers */
static int ws_write_to_send_buffer (SocketWS_T ws,
                                    const void *data,
                                    size_t len,
                                    const char *what);
static int ws_write_frame_header (SocketWS_T ws,
                                  int fin,
                                  SocketWS_Opcode opcode,
                                  int masked,
                                  const unsigned char *mask_key,
                                  uint64_t payload_len);
static int ws_write_masked_payload (SocketWS_T ws,
                                    const unsigned char *data,
                                    size_t len,
                                    const unsigned char *mask_key);

/* Receive Frame Helpers */
static int ws_recv_control_payload (SocketWS_T ws, size_t available);
static int ws_recv_data_payload (SocketWS_T ws, size_t to_read);
static int ws_finalize_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out);
static int ws_check_payload_size (SocketWS_T ws);
static int ws_process_payload (SocketWS_T ws);
static int ws_validate_frame_masking (SocketWS_T ws);
static int
ws_parse_frame_header_if_needed (SocketWS_T ws, SocketWS_FrameParse *frame_out);

static uint64_t
ws_build_mask64 (const unsigned char mask[SOCKETWS_MASK_KEY_SIZE])
{
  uint32_t mask32;

  mask32 = ((uint32_t)mask[0]) | ((uint32_t)mask[1] << 8)
           | ((uint32_t)mask[2] << 16) | ((uint32_t)mask[3] << 24);

  return ((uint64_t)mask32) | ((uint64_t)mask32 << 32);
}

static void
ws_mask_unaligned_bytes (unsigned char *data,
                         size_t len,
                         const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                         size_t start_offset)
{
  size_t i;

  for (i = 0; i < len; i++)
    data[i] ^= mask[(start_offset + i) & SOCKETWS_MASK_KEY_INDEX_MASK];
}

static void
ws_mask_aligned_block (uint64_t *data, size_t count, uint64_t mask64)
{
  while (count--)
    *data++ ^= mask64;
}

void
ws_mask_payload (unsigned char *data,
                 size_t len,
                 const unsigned char mask[SOCKETWS_MASK_KEY_SIZE])
{
  size_t aligned_start;
  size_t aligned_end;
  uint64_t mask64;

  if (!data || len == 0 || !mask)
    return;

  /* Calculate aligned region boundaries */
  aligned_start
      = (SOCKETWS_XOR_ALIGN_SIZE - ((uintptr_t)data & SOCKETWS_XOR_ALIGN_MASK))
        & SOCKETWS_XOR_ALIGN_MASK;
  if (aligned_start > len)
    aligned_start = len;

  /* Mask initial unaligned bytes */
  ws_mask_unaligned_bytes (data, aligned_start, mask, 0);

  if (aligned_start >= len)
    return;

  /* Calculate end of aligned region */
  aligned_end = aligned_start
                + ((len - aligned_start) & ~(size_t)SOCKETWS_XOR_ALIGN_MASK);

  /* Mask aligned 64-bit blocks */
  mask64 = ws_build_mask64 (mask);
  ws_mask_aligned_block ((uint64_t *)(data + aligned_start),
                         (aligned_end - aligned_start) >> 3,
                         mask64);

  /* Mask trailing unaligned bytes */
  ws_mask_unaligned_bytes (data + aligned_end,
                           len - aligned_end,
                           mask,
                           aligned_end & SOCKETWS_MASK_KEY_INDEX_MASK);
}

size_t
ws_mask_payload_offset (unsigned char *data,
                        size_t len,
                        const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                        size_t offset)
{
  if (!data || len == 0 || !mask)
    return offset;

  ws_mask_unaligned_bytes (data, len, mask, offset);

  return (offset + len) & SOCKETWS_MASK_KEY_INDEX_MASK;
}

static SocketWS_Error
ws_read_header_to_target (SocketWS_FrameParse *frame,
                          const unsigned char **data,
                          size_t *len,
                          size_t *consumed,
                          size_t target)
{
  size_t need = target - frame->header_len;
  if (need == 0)
    return WS_OK;

  size_t copy_len = (need < *len) ? need : *len;
  memcpy (frame->header_buf + frame->header_len, *data, copy_len);
  frame->header_len += copy_len;
  *data += copy_len;
  *len -= copy_len;
  *consumed += copy_len;

  return (frame->header_len < target) ? WS_ERROR_WOULD_BLOCK : WS_OK;
}

static SocketWS_Error
ws_parse_basic_header (SocketWS_FrameParse *frame)
{
  unsigned char b0 = frame->header_buf[0];
  unsigned char b1 = frame->header_buf[1];

  frame->fin = (b0 & SOCKETWS_FIN_BIT) != 0;
  frame->rsv1 = (b0 & SOCKETWS_RSV1_BIT) != 0;
  frame->rsv2 = (b0 & SOCKETWS_RSV2_BIT) != 0;
  frame->rsv3 = (b0 & SOCKETWS_RSV3_BIT) != 0;
  frame->opcode = (SocketWS_Opcode)(b0 & SOCKETWS_OPCODE_MASK);
  frame->masked = (b1 & SOCKETWS_MASK_BIT) != 0;
  frame->payload_len = b1 & SOCKETWS_PAYLOAD_LEN_MASK;

  return WS_OK;
}

static SocketWS_Error
ws_validate_frame_header (const SocketWS_FrameParse *frame)
{
  /* RSV2 and RSV3 must be 0 (RSV1 used for compression) */
  if (frame->rsv2 || frame->rsv3)
    return WS_ERROR_PROTOCOL;

  /* Validate opcode */
  if (!ws_is_valid_opcode (frame->opcode))
    return WS_ERROR_PROTOCOL;

  /* Control frame constraints (RFC 6455 Section 5.5) */
  if (ws_is_control_opcode (frame->opcode))
    {
      if (!frame->fin)
        return WS_ERROR_PROTOCOL;
      if (frame->payload_len > SOCKETWS_MAX_CONTROL_PAYLOAD)
        return WS_ERROR_PROTOCOL;
      if (frame->rsv1)
        return WS_ERROR_PROTOCOL;
    }

  return WS_OK;
}

static void
ws_transition_to_payload (SocketWS_FrameParse *frame)
{
  frame->state = WS_FRAME_STATE_PAYLOAD;
  frame->payload_received = 0;
}

static void
ws_determine_header_length (SocketWS_FrameParse *frame)
{
  if (frame->payload_len == SOCKETWS_EXTENDED_LEN_16
      || frame->payload_len == SOCKETWS_EXTENDED_LEN_64)
    {
      size_t ext_size = (frame->payload_len == SOCKETWS_EXTENDED_LEN_16)
                            ? SOCKETWS_EXTENDED_LEN_16_SIZE
                            : SOCKETWS_EXTENDED_LEN_64_SIZE;
      frame->header_needed = SOCKETWS_BASE_HEADER_SIZE + ext_size;
      frame->state = WS_FRAME_STATE_EXTENDED_LEN;
    }
  else if (frame->masked)
    {
      frame->header_needed = SOCKETWS_BASE_HEADER_SIZE + SOCKETWS_MASK_KEY_SIZE;
      frame->state = WS_FRAME_STATE_MASK_KEY;
    }
  else
    {
      ws_transition_to_payload (frame);
    }
}

static SocketWS_Error
ws_parse_extended_length (SocketWS_FrameParse *frame)
{
  size_t offset = SOCKETWS_BASE_HEADER_SIZE;
  int bytes = (frame->payload_len == SOCKETWS_EXTENDED_LEN_16)
                  ? SOCKETWS_EXTENDED_LEN_16_SIZE
                  : SOCKETWS_EXTENDED_LEN_64_SIZE;
  frame->payload_len = 0;
  for (int i = 0; i < bytes; i++)
    {
      frame->payload_len
          = (frame->payload_len << 8) | frame->header_buf[offset + i];
    }
  if (bytes == SOCKETWS_EXTENDED_LEN_64_SIZE
      && (frame->payload_len & SOCKETWS_PAYLOAD_MSB_MASK))
    return WS_ERROR_PROTOCOL;
  return WS_OK;
}

static void
ws_extract_mask_key (SocketWS_FrameParse *frame)
{
  memcpy (frame->mask_key,
          frame->header_buf + frame->header_needed - SOCKETWS_MASK_KEY_SIZE,
          SOCKETWS_MASK_KEY_SIZE);
}

static SocketWS_Error
ws_process_header_state (SocketWS_FrameParse *frame,
                         const unsigned char **data,
                         size_t *len,
                         size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (
      frame, data, len, consumed, SOCKETWS_BASE_HEADER_SIZE);
  if (err != WS_OK)
    return err;

  ws_parse_basic_header (frame);

  err = ws_validate_frame_header (frame);
  if (err != WS_OK)
    return err;

  ws_determine_header_length (frame);

  return (frame->state == WS_FRAME_STATE_PAYLOAD) ? WS_OK
                                                  : WS_ERROR_WOULD_BLOCK;
}

static SocketWS_Error
ws_process_extended_len_state (SocketWS_FrameParse *frame,
                               const unsigned char **data,
                               size_t *len,
                               size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (
      frame, data, len, consumed, frame->header_needed);
  if (err != WS_OK)
    return err;

  err = ws_parse_extended_length (frame);
  if (err != WS_OK)
    return err;

  if (frame->masked)
    {
      frame->header_needed += SOCKETWS_MASK_KEY_SIZE;
      frame->state = WS_FRAME_STATE_MASK_KEY;
      return WS_ERROR_WOULD_BLOCK;
    }

  ws_transition_to_payload (frame);
  return WS_OK;
}

static SocketWS_Error
ws_process_mask_key_state (SocketWS_FrameParse *frame,
                           const unsigned char **data,
                           size_t *len,
                           size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (
      frame, data, len, consumed, frame->header_needed);
  if (err != WS_OK)
    return err;

  ws_extract_mask_key (frame);

  ws_transition_to_payload (frame);
  return WS_OK;
}

SocketWS_Error
ws_frame_parse_header (SocketWS_FrameParse *frame,
                       const unsigned char *data,
                       size_t len,
                       size_t *consumed)
{
  SocketWS_Error err;

  assert (frame);
  assert (consumed);

  *consumed = 0;

  if (len == 0)
    return WS_ERROR_WOULD_BLOCK;

  while (len > 0)
    {
      switch (frame->state)
        {
        case WS_FRAME_STATE_HEADER:
          err = ws_process_header_state (frame, &data, &len, consumed);
          if (err != WS_ERROR_WOULD_BLOCK)
            return err;
          break;

        case WS_FRAME_STATE_EXTENDED_LEN:
          err = ws_process_extended_len_state (frame, &data, &len, consumed);
          if (err != WS_ERROR_WOULD_BLOCK)
            return err;
          break;

        case WS_FRAME_STATE_MASK_KEY:
          err = ws_process_mask_key_state (frame, &data, &len, consumed);
          if (err != WS_ERROR_WOULD_BLOCK)
            return err;
          break;

        case WS_FRAME_STATE_PAYLOAD:
        case WS_FRAME_STATE_COMPLETE:
          return WS_OK;
        }
    }

  return WS_ERROR_WOULD_BLOCK;
}

static size_t
ws_encode_extended_length (unsigned char *header,
                           size_t offset,
                           uint64_t len,
                           unsigned char code)
{
  /* Extract the length indicator (126 or 127) ignoring the mask bit */
  unsigned char len_indicator = code & 0x7F;

  header[offset++] = code;
  int bytes = (len_indicator == SOCKETWS_EXTENDED_LEN_16)
                  ? SOCKETWS_EXTENDED_LEN_16_SIZE
                  : SOCKETWS_EXTENDED_LEN_64_SIZE;
  for (int i = 0; i < bytes; i++)
    {
      header[offset++] = (len >> ((bytes - 1 - i) * 8)) & 0xFF;
    }
  return offset;
}

static size_t
ws_encode_payload_length (unsigned char *header,
                          size_t offset,
                          int masked,
                          uint64_t payload_len)
{
  unsigned char mask_bit = masked ? SOCKETWS_MASK_BIT : 0;

  if (payload_len <= SOCKETWS_MAX_7BIT_PAYLOAD)
    {
      header[offset++] = mask_bit | (unsigned char)payload_len;
    }
  else if (payload_len <= SOCKETWS_MAX_16BIT_PAYLOAD)
    {
      /* Extended 16-bit length: second byte has MASK bit + 126 */
      offset = ws_encode_extended_length (
          header, offset, payload_len, mask_bit | SOCKETWS_EXTENDED_LEN_16);
    }
  else
    {
      /* Extended 64-bit length: second byte has MASK bit + 127 */
      offset = ws_encode_extended_length (
          header, offset, payload_len, mask_bit | SOCKETWS_EXTENDED_LEN_64);
    }

  return offset;
}

size_t
ws_frame_build_header (unsigned char *header,
                       int fin,
                       SocketWS_Opcode opcode,
                       int masked,
                       const unsigned char *mask_key,
                       uint64_t payload_len)
{
  size_t offset = 0;

  assert (header);

  /* First byte: FIN + RSV + opcode */
  header[offset++]
      = (fin ? SOCKETWS_FIN_BIT : 0) | (opcode & SOCKETWS_OPCODE_MASK);

  /* Second byte and extended length */
  offset = ws_encode_payload_length (header, offset, masked, payload_len);

  /* Mask key (if masked) */
  if (masked && mask_key)
    {
      memcpy (header + offset, mask_key, SOCKETWS_MASK_KEY_SIZE);
      offset += SOCKETWS_MASK_KEY_SIZE;
    }

  return offset;
}

static int
ws_ensure_mask_key (SocketWS_T ws,
                    unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE],
                    int *masked)
{
  *masked = ws_requires_masking (ws);

  if (*masked)
    {
      if (SocketCrypto_random_bytes (mask_key, SOCKETWS_MASK_KEY_SIZE) != 0)
        {
          ws_set_error (ws, WS_ERROR, "Failed to generate mask key");
          return -1;
        }
    }

  return 0;
}

static int
ws_write_to_send_buffer (SocketWS_T ws,
                         const void *data,
                         size_t len,
                         const char *what)
{
  size_t written;

  written = SocketBuf_write (ws->send_buf, data, len);
  if (written != len)
    {
      ws_set_error (ws, WS_ERROR, "Send buffer overflow (%s)", what);
      return -1;
    }

  return 0;
}

static int
ws_write_frame_header (SocketWS_T ws,
                       int fin,
                       SocketWS_Opcode opcode,
                       int masked,
                       const unsigned char *mask_key,
                       uint64_t payload_len)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  size_t header_len;

  header_len = ws_frame_build_header (
      header, fin, opcode, masked, mask_key, payload_len);

  return ws_write_to_send_buffer (ws, header, header_len, "header");
}

static int
ws_write_masked_payload (SocketWS_T ws,
                         const unsigned char *data,
                         size_t len,
                         const unsigned char *mask_key)
{
  unsigned char *chunk_buf;
  size_t offset = 0;
  int masked = (mask_key != NULL);

  if (len == 0)
    return 0;

  chunk_buf = ALLOC (ws->arena, SOCKETWS_SEND_CHUNK_SIZE);
  if (!chunk_buf)
    {
      ws_set_error (ws, WS_ERROR, "Failed to allocate chunk buffer");
      return -1;
    }

  while (offset < len)
    {
      size_t remaining = len - offset;
      size_t to_write = (remaining < SOCKETWS_SEND_CHUNK_SIZE)
                            ? remaining
                            : SOCKETWS_SEND_CHUNK_SIZE;

      memcpy (chunk_buf, data + offset, to_write);

      if (masked)
        ws_mask_payload_offset (chunk_buf,
                                to_write,
                                mask_key,
                                offset & SOCKETWS_MASK_KEY_INDEX_MASK);

      if (ws_write_to_send_buffer (ws, chunk_buf, to_write, "payload") < 0)
        return -1;

      offset += to_write;
    }

  return 0;
}

int
ws_send_control_frame (SocketWS_T ws,
                       SocketWS_Opcode opcode,
                       const unsigned char *payload,
                       size_t len)
{
  unsigned char masked_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE];
  int masked;

  assert (ws);
  assert (ws_is_control_opcode (opcode));

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    {
      ws_set_error (
          ws, WS_ERROR_PROTOCOL, "Control frame payload too large: %zu", len);
      return -1;
    }

  if (ws_ensure_mask_key (ws, mask_key, &masked) < 0)
    return -1;

  if (ws_write_frame_header (ws, 1, opcode, masked, mask_key, len) < 0)
    return -1;

  if (payload && len > 0)
    {
      memcpy (masked_payload, payload, len);
      if (masked)
        ws_mask_payload (masked_payload, len, mask_key);

      if (ws_write_to_send_buffer (ws, masked_payload, len, "payload") < 0)
        return -1;
    }

  ws_flush_send_buffer (ws);
  return 0;
}

int
ws_send_data_frame (SocketWS_T ws,
                    SocketWS_Opcode opcode,
                    const unsigned char *data,
                    size_t len,
                    int fin)
{
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE];
  int masked;

  assert (ws);

  /* Check frame size limit */
  if (len > ws->config.max_frame_size)
    {
      ws_set_error (ws,
                    WS_ERROR_FRAME_TOO_LARGE,
                    "Frame too large: %zu > %zu",
                    len,
                    ws->config.max_frame_size);
      return -1;
    }

  if (ws_ensure_mask_key (ws, mask_key, &masked) < 0)
    return -1;

#ifdef SOCKETWS_HAS_DEFLATE
  /* Compress if enabled (permessage-deflate) */
  if (ws->compression_enabled && ws_is_data_opcode (opcode))
    {
      size_t original_len = len;
      unsigned char *compressed = NULL;
      size_t compressed_len = 0;

      if (ws_compress_message (ws, data, len, &compressed, &compressed_len)
          == 0)
        {
          data = compressed;
          len = compressed_len;

          /* Check if compression caused expansion beyond frame size limit.
           * DEFLATE can slightly expand incompressible data. */
          if (len > ws->config.max_frame_size)
            {
              ws_set_error (
                  ws,
                  WS_ERROR_FRAME_TOO_LARGE,
                  "Compressed frame too large: %zu > %zu (original %zu)",
                  len,
                  ws->config.max_frame_size,
                  original_len);
              return -1;
            }
        }
    }
#endif

  if (ws_write_frame_header (ws, fin, opcode, masked, mask_key, len) < 0)
    return -1;

  if (ws_write_masked_payload (ws, data, len, masked ? mask_key : NULL) < 0)
    return -1;

  ws_flush_send_buffer (ws);
  return 0;
}

static void
ws_read_and_unmask_chunk (SocketWS_T ws, unsigned char *buf, size_t len);

static int
ws_recv_control_payload (SocketWS_T ws, size_t available)
{
  unsigned char control_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t payload_remaining = ws->frame.payload_len - ws->frame.payload_received;
  size_t to_read
      = (available < payload_remaining) ? available : payload_remaining;

  if (to_read > SOCKETWS_MAX_CONTROL_PAYLOAD)
    to_read = SOCKETWS_MAX_CONTROL_PAYLOAD;

  ws_read_and_unmask_chunk (ws, control_payload, to_read);

  if (ws->frame.payload_received < ws->frame.payload_len)
    return -2;

  int result = ws_handle_control_frame (
      ws, ws->frame.opcode, control_payload, (size_t)ws->frame.payload_len);

  ws_frame_reset (&ws->frame);
  return (result < 0) ? -1 : 0;
}

static int
ws_recv_data_payload (SocketWS_T ws, size_t to_read)
{
  unsigned char *payload_buf = ALLOC (ws->arena, to_read);
  if (!payload_buf)
    {
      ws_set_error (ws, WS_ERROR, "Failed to allocate payload buffer");
      return -1;
    }

  ws_read_and_unmask_chunk (ws, payload_buf, to_read);

  /* Set message type on first fragment */
  if (ws->message.fragment_count == 0 && ws_is_data_opcode (ws->frame.opcode))
    {
      ws->message.type = ws->frame.opcode;
      ws->message.compressed = ws->frame.rsv1;
    }

  int is_text = (ws->message.type == WS_OPCODE_TEXT);
  return ws_message_append (ws, payload_buf, to_read, is_text);
}

static int
ws_finalize_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out)
{
  frame_out->state = WS_FRAME_STATE_COMPLETE;

  int ret = -2;
  if (ws->frame.fin)
    {
      if (ws_message_finalize (ws) < 0)
        ret = -1;
      else
        ret = 1;
    }

  ws_frame_reset (&ws->frame);
  return ret;
}

static void
ws_read_and_unmask_chunk (SocketWS_T ws, unsigned char *buf, size_t len)
{
  SocketBuf_read (ws->recv_buf, buf, len);

  size_t offset = ws->frame.payload_received;
  if (ws->frame.masked)
    {
      ws_mask_payload_offset (
          buf, len, ws->frame.mask_key, offset & SOCKETWS_MASK_KEY_INDEX_MASK);
    }

  ws->frame.payload_received += len;
}

static int
ws_check_payload_size (SocketWS_T ws)
{
  if (ws->frame.payload_len > ws->config.max_frame_size)
    {
      ws_set_error (ws,
                    WS_ERROR_FRAME_TOO_LARGE,
                    "Frame payload too large: %llu > %zu",
                    (unsigned long long)ws->frame.payload_len,
                    ws->config.max_frame_size);
      return -1;
    }
  return 0;
}

static int
ws_process_payload (SocketWS_T ws)
{
  size_t available;
  const unsigned char *data;
  size_t payload_remaining;
  size_t to_read;

  if (ws->frame.payload_received >= ws->frame.payload_len)
    return 0;

  available = SocketBuf_available (ws->recv_buf);
  if (available == 0)
    return -2;

  data = SocketBuf_readptr (ws->recv_buf, &available);
  (void)data; /* Used only for available check */

  payload_remaining = ws->frame.payload_len - ws->frame.payload_received;
  to_read = (available < payload_remaining) ? available : payload_remaining;

  if (ws_is_control_opcode (ws->frame.opcode))
    {
      /* Control frames (PING/PONG/CLOSE) have max 125 bytes payload and must be
       * processed atomically. Avoid partial reads into a temporary buffer,
       * which would corrupt payload content if it arrives split across TCP
       * segments. */
      if (available < payload_remaining)
        return -2;
      return ws_recv_control_payload (ws, available);
    }

  return ws_recv_data_payload (ws, to_read);
}

static int
ws_validate_frame_masking (SocketWS_T ws)
{
  int skip_masking_validation = 0;

  /* Validate masking:
   * RFC 6455 (TCP): Client -> Server MUST be masked, Server -> Client MUST NOT
   * RFC 8441 (HTTP/2): No masking required (transport provides security)
   *
   * Check if using H2 transport - if so, skip masking validation entirely */
  if (ws->transport
      && SocketWS_Transport_type (ws->transport) == SOCKETWS_TRANSPORT_H2STREAM)
    skip_masking_validation = 1;

  if (!skip_masking_validation)
    {
      /* RFC 6455 masking rules apply */
      if ((ws->role == WS_ROLE_SERVER && !ws->frame.masked)
          || (ws->role == WS_ROLE_CLIENT && ws->frame.masked))
        {
          ws_set_error (ws,
                        WS_ERROR_PROTOCOL,
                        "Invalid frame masking: role=%s received %s frame",
                        ws->role == WS_ROLE_SERVER ? "server" : "client",
                        ws->frame.masked ? "masked" : "unmasked");
          /* Send protocol error close per RFC 6455 */
          (void)ws_send_close (
              ws, WS_CLOSE_PROTOCOL_ERROR, "Masking violation");
          return -1;
        }
    }

  return 0;
}

static int
ws_parse_frame_header_if_needed (SocketWS_T ws, SocketWS_FrameParse *frame_out)
{
  size_t available;
  const unsigned char *data;
  size_t consumed;
  SocketWS_Error err;

  /* Parse header if not complete */
  if (ws->frame.state != WS_FRAME_STATE_PAYLOAD
      && ws->frame.state != WS_FRAME_STATE_COMPLETE)
    {
      available = SocketBuf_available (ws->recv_buf);
      if (available == 0)
        return -2;

      data = SocketBuf_readptr (ws->recv_buf, &available);
      if (!data)
        return -2;

      err = ws_frame_parse_header (&ws->frame, data, available, &consumed);
      SocketBuf_consume (ws->recv_buf, consumed);

      if (err == WS_ERROR_WOULD_BLOCK)
        return -2;
      if (err != WS_OK)
        {
          ws_set_error (ws, err, "Frame header parse error");
          return -1;
        }
    }

  *frame_out = ws->frame;
  return 0;
}

int
ws_recv_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out)
{
  int result;
  bool is_control_frame;

  assert (ws);
  assert (frame_out);

  ws_fill_recv_buffer (ws);

  result = ws_parse_frame_header_if_needed (ws, frame_out);
  if (result != 0)
    return result;

  is_control_frame = ws_is_control_opcode (ws->frame.opcode);

  if (ws_validate_frame_masking (ws) < 0)
    return -1;

  if (ws_check_payload_size (ws) < 0)
    return -1;

  result = ws_process_payload (ws);
  if (result == -1)
    return -1;

  *frame_out = ws->frame;

  if (result == -2)
    return -2;
  if (result == 0 && is_control_frame)
    return 0;

  if (ws->frame.payload_received >= ws->frame.payload_len)
    return ws_finalize_frame (ws, frame_out);

  return -2;
}
