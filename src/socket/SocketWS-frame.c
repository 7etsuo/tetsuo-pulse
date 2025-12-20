/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketWS-frame.c - WebSocket Frame Processing (RFC 6455 Section 5)
 *
 * Part of the Socket Library
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

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/** RFC 6455: MSB of 64-bit payload length must be 0 */
#define SOCKETWS_PAYLOAD_MSB_MASK (1ULL << 63)



/* ============================================================================
 * Static Helper Function Declarations
 * ============================================================================
 */

/* XOR Masking Helpers */
static void
ws_mask_unaligned_bytes (unsigned char *data, size_t len,
                         const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                         size_t start_offset);
static void ws_mask_aligned_block (uint64_t *data, size_t count,
                                   uint64_t mask64);
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
                                               size_t *len, size_t *consumed);
static SocketWS_Error
ws_process_extended_len_state (SocketWS_FrameParse *frame,
                               const unsigned char **data, size_t *len,
                               size_t *consumed);
static SocketWS_Error ws_process_mask_key_state (SocketWS_FrameParse *frame,
                                                 const unsigned char **data,
                                                 size_t *len,
                                                 size_t *consumed);

/* Frame Header Building Helpers */
static size_t ws_encode_payload_length (unsigned char *header, size_t offset,
                                        int masked, uint64_t payload_len);
static size_t ws_encode_extended_length (unsigned char *header, size_t offset, uint64_t len, unsigned char code);

/* Mask Key Helpers */
static int ws_ensure_mask_key (SocketWS_T ws,
                               unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE],
                               int *masked);

/* Send Buffer Helpers */
static int ws_write_to_send_buffer (SocketWS_T ws, const void *data,
                                    size_t len, const char *what);
static int ws_write_frame_header (SocketWS_T ws, int fin,
                                  SocketWS_Opcode opcode, int masked,
                                  const unsigned char *mask_key,
                                  uint64_t payload_len);
static int ws_write_masked_payload (SocketWS_T ws, const unsigned char *data,
                                    size_t len, const unsigned char *mask_key);

/* Receive Frame Helpers */
static int ws_recv_control_payload (SocketWS_T ws, size_t available);
static int ws_recv_data_payload (SocketWS_T ws, size_t to_read);
static int ws_finalize_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out);
static int ws_check_payload_size (SocketWS_T ws);
static int ws_process_payload (SocketWS_T ws);

/* ============================================================================
 * XOR Masking - Helper Functions
 * ============================================================================
 */

/**
 * ws_build_mask64 - Build 64-bit mask from 4-byte key
 * @mask: 4-byte mask key
 *
 * Returns: 64-bit mask with key repeated twice
 */
static uint64_t
ws_build_mask64 (const unsigned char mask[SOCKETWS_MASK_KEY_SIZE])
{
  uint32_t mask32;

  mask32 = ((uint32_t)mask[0]) | ((uint32_t)mask[1] << 8)
           | ((uint32_t)mask[2] << 16) | ((uint32_t)mask[3] << 24);

  return ((uint64_t)mask32) | ((uint64_t)mask32 << 32);
}

/**
 * ws_mask_unaligned_bytes - XOR mask bytes one at a time
 * @data: Data buffer (modified in place)
 * @len: Number of bytes to mask
 * @mask: 4-byte mask key
 * @start_offset: Starting offset into mask key
 */
static void
ws_mask_unaligned_bytes (unsigned char *data, size_t len,
                         const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                         size_t start_offset)
{
  size_t i;

  for (i = 0; i < len; i++)
    data[i] ^= mask[(start_offset + i) & SOCKETWS_MASK_KEY_INDEX_MASK];
}

/**
 * ws_mask_aligned_block - XOR mask 64-bit aligned blocks
 * @data: 64-bit aligned data pointer
 * @count: Number of 64-bit blocks to mask
 * @mask64: 64-bit mask (4-byte key repeated twice)
 */
static void
ws_mask_aligned_block (uint64_t *data, size_t count, uint64_t mask64)
{
  while (count--)
    *data++ ^= mask64;
}

/* ============================================================================
 * XOR Masking - Public Functions
 * ============================================================================
 */

/**
 * ws_mask_payload - Apply XOR mask to payload (optimized)
 * @data: Data buffer (modified in place)
 * @len: Data length
 * @mask: 4-byte mask key
 *
 * Uses 8-byte aligned XOR for performance on modern CPUs.
 * Falls back to byte-by-byte for unaligned portions.
 */
void
ws_mask_payload (unsigned char *data, size_t len,
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
                         (aligned_end - aligned_start) >> 3, mask64);

  /* Mask trailing unaligned bytes */
  ws_mask_unaligned_bytes (data + aligned_end, len - aligned_end, mask,
                           aligned_end & SOCKETWS_MASK_KEY_INDEX_MASK);
}

/**
 * ws_mask_payload_offset - Apply XOR mask with starting offset
 * @data: Data buffer
 * @len: Data length
 * @mask: 4-byte mask key
 * @offset: Starting offset into mask (for continuation)
 *
 * Returns: New offset for next call (offset + len) % 4
 */
size_t
ws_mask_payload_offset (unsigned char *data, size_t len,
                        const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                        size_t offset)
{
  if (!data || len == 0 || !mask)
    return offset;

  ws_mask_unaligned_bytes (data, len, mask, offset);

  return (offset + len) & SOCKETWS_MASK_KEY_INDEX_MASK;
}

/* ============================================================================
 * Header Buffer Helpers
 * ============================================================================
 */

static SocketWS_Error
ws_read_header_to_target (SocketWS_FrameParse *frame,
                          const unsigned char **data, size_t *len,
                          size_t *consumed, size_t target)
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

/* ============================================================================
 * Frame Header Parsing - State Handler Functions
 * ============================================================================
 */

/**
 * ws_parse_basic_header - Parse first 2 bytes of frame header
 * @frame: Frame parsing state (header_buf must have 2+ bytes)
 *
 * Extracts FIN, RSV bits, opcode, MASK bit, and initial payload length.
 *
 * Returns: WS_OK (always succeeds if called with valid data)
 */
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

/**
 * ws_validate_frame_header - Validate parsed frame header fields
 * @frame: Frame parsing state with parsed fields
 *
 * Returns: WS_OK if valid, WS_ERROR_PROTOCOL if invalid
 */
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

/**
 * ws_transition_to_payload - Transition frame state to payload reading
 * @frame: Frame parsing state
 */
static void
ws_transition_to_payload (SocketWS_FrameParse *frame)
{
  frame->state = WS_FRAME_STATE_PAYLOAD;
  frame->payload_received = 0;
}

/**
 * ws_determine_header_length - Calculate total header size
 * @frame: Frame parsing state
 *
 * Sets header_needed and transitions to appropriate state.
 */
static void
ws_determine_header_length (SocketWS_FrameParse *frame)
{
  if (frame->payload_len == SOCKETWS_EXTENDED_LEN_16 ||
      frame->payload_len == SOCKETWS_EXTENDED_LEN_64)
    {
      size_t ext_size = (frame->payload_len == SOCKETWS_EXTENDED_LEN_16) ?
                        SOCKETWS_EXTENDED_LEN_16_SIZE : SOCKETWS_EXTENDED_LEN_64_SIZE;
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

/**
 * ws_parse_extended_length - Parse 16-bit or 64-bit extended length
 * @frame: Frame parsing state with complete extended length bytes
 *
 * Returns: WS_OK if valid, WS_ERROR_PROTOCOL if MSB set in 64-bit length
 */
static SocketWS_Error
ws_parse_extended_length (SocketWS_FrameParse *frame)
{
  size_t offset = SOCKETWS_BASE_HEADER_SIZE;
  int bytes = (frame->payload_len == SOCKETWS_EXTENDED_LEN_16) ? 2 : SOCKETWS_EXTENDED_LEN_64_SIZE;
  frame->payload_len = 0;
  for (int i = 0; i < bytes; i++)
    {
      frame->payload_len = (frame->payload_len << 8) | frame->header_buf[offset + i];
    }
  if (bytes == SOCKETWS_EXTENDED_LEN_64_SIZE && (frame->payload_len & SOCKETWS_PAYLOAD_MSB_MASK))
    return WS_ERROR_PROTOCOL;
  return WS_OK;
}

/**
 * ws_extract_mask_key - Extract 4-byte mask key from header
 * @frame: Frame parsing state with complete mask key bytes
 */
static void
ws_extract_mask_key (SocketWS_FrameParse *frame)
{
  memcpy (frame->mask_key,
          frame->header_buf + frame->header_needed - SOCKETWS_MASK_KEY_SIZE,
          SOCKETWS_MASK_KEY_SIZE);
}

/**
 * ws_process_header_state - Process WS_FRAME_STATE_HEADER
 * @frame: Frame parsing state
 * @data: Pointer to input data pointer
 * @len: Pointer to remaining length
 * @consumed: Pointer to consumed count
 *
 * Returns: WS_OK to continue, WS_ERROR_WOULD_BLOCK, or error
 */
static SocketWS_Error
ws_process_header_state (SocketWS_FrameParse *frame,
                         const unsigned char **data, size_t *len,
                         size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (frame, data, len, consumed,
                                  SOCKETWS_BASE_HEADER_SIZE);
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

/**
 * ws_process_extended_len_state - Process WS_FRAME_STATE_EXTENDED_LEN
 * @frame: Frame parsing state
 * @data: Pointer to input data pointer
 * @len: Pointer to remaining length
 * @consumed: Pointer to consumed count
 *
 * Returns: WS_OK to continue, WS_ERROR_WOULD_BLOCK, or error
 */
static SocketWS_Error
ws_process_extended_len_state (SocketWS_FrameParse *frame,
                               const unsigned char **data, size_t *len,
                               size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (frame, data, len, consumed,
                                  frame->header_needed);
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

/**
 * ws_process_mask_key_state - Process WS_FRAME_STATE_MASK_KEY
 * @frame: Frame parsing state
 * @data: Pointer to input data pointer
 * @len: Pointer to remaining length
 * @consumed: Pointer to consumed count
 *
 * Returns: WS_OK when complete, WS_ERROR_WOULD_BLOCK if need more
 */
static SocketWS_Error
ws_process_mask_key_state (SocketWS_FrameParse *frame,
                           const unsigned char **data, size_t *len,
                           size_t *consumed)
{
  SocketWS_Error err;

  err = ws_read_header_to_target (frame, data, len, consumed,
                                  frame->header_needed);
  if (err != WS_OK)
    return err;

  ws_extract_mask_key (frame);

  ws_transition_to_payload (frame);
  return WS_OK;
}

/* ============================================================================
 * Frame Header Parsing - Main Function
 * ============================================================================
 */

/**
 * ws_frame_parse_header - Parse frame header incrementally
 * @frame: Frame parsing state
 * @data: Input data
 * @len: Input length
 * @consumed: Output - bytes consumed
 *
 * Returns: WS_OK if complete, WS_ERROR_WOULD_BLOCK if need more, or error
 */
SocketWS_Error
ws_frame_parse_header (SocketWS_FrameParse *frame, const unsigned char *data,
                       size_t len, size_t *consumed)
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

/* ============================================================================
 * Frame Header Building - Helper Functions
 * ============================================================================
 */

/**
 * ws_encode_64bit_length - Encode 64-bit payload length in network byte order
 * @header: Output buffer (must have 8 bytes available at offset)
 * @offset: Starting offset in header
 * @payload_len: Payload length to encode
 */
static size_t
ws_encode_extended_length (unsigned char *header, size_t offset, uint64_t len, unsigned char code)
{
  header[offset++] = code;
  int bytes = (code == SOCKETWS_EXTENDED_LEN_16) ? 2 : SOCKETWS_EXTENDED_LEN_64_SIZE;
  for (int i = 0; i < bytes; i++)
    {
      header[offset++] = (len >> ((bytes - 1 - i) * 8)) & 0xFF;
    }
  return offset;
}

/**
 * ws_encode_payload_length - Encode payload length into header
 * @header: Output buffer
 * @offset: Current offset in header
 * @masked: Whether MASK bit should be set
 * @payload_len: Payload length to encode
 *
 * Returns: New offset after writing length bytes
 */
static size_t
ws_encode_payload_length (unsigned char *header, size_t offset, int masked,
                          uint64_t payload_len)
{
  unsigned char mask_bit = masked ? SOCKETWS_MASK_BIT : 0;

  if (payload_len <= SOCKETWS_MAX_7BIT_PAYLOAD)
    {
      header[offset++] = mask_bit | (unsigned char)payload_len;
    }
  else if (payload_len <= SOCKETWS_MAX_16BIT_PAYLOAD)
    {
      offset = ws_encode_extended_length (header, offset, payload_len, SOCKETWS_EXTENDED_LEN_16);
    }
  else
    {
      offset = ws_encode_extended_length (header, offset, payload_len, SOCKETWS_EXTENDED_LEN_64);
    }

  return offset;
}

/* ============================================================================
 * Frame Header Building - Main Function
 * ============================================================================
 */

/**
 * ws_frame_build_header - Build frame header
 * @header: Output buffer (at least SOCKETWS_MAX_HEADER_SIZE)
 * @fin: Final fragment flag
 * @opcode: Frame opcode
 * @masked: Whether to mask (client = yes)
 * @mask_key: 4-byte mask key (only if masked)
 * @payload_len: Payload length
 *
 * Returns: Header length written
 */
size_t
ws_frame_build_header (unsigned char *header, int fin, SocketWS_Opcode opcode,
                       int masked, const unsigned char *mask_key,
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

/* ============================================================================
 * Mask Key Helpers
 * ============================================================================
 */

/**
 * ws_ensure_mask_key - Generate mask key if client role
 * @ws: WebSocket context
 * @mask_key: Output buffer for mask key
 * @masked: Output - set to 1 if client, 0 if server
 *
 * Clients must mask, servers must not mask.
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_ensure_mask_key (SocketWS_T ws,
                    unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE],
                    int *masked)
{
  *masked = (ws->role == WS_ROLE_CLIENT);

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

/* ============================================================================
 * Send Buffer - Helper Functions
 * ============================================================================
 */

/**
 * ws_write_to_send_buffer - Write data to send buffer with error handling
 * @ws: WebSocket context
 * @data: Data to write
 * @len: Length of data
 * @what: Description for error message
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_to_send_buffer (SocketWS_T ws, const void *data, size_t len,
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

/**
 * ws_write_frame_header - Build and write frame header to send buffer
 * @ws: WebSocket context
 * @fin: Final fragment flag
 * @opcode: Frame opcode
 * @masked: Whether to mask
 * @mask_key: 4-byte mask key (only if masked)
 * @payload_len: Payload length
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_frame_header (SocketWS_T ws, int fin, SocketWS_Opcode opcode,
                       int masked, const unsigned char *mask_key,
                       uint64_t payload_len)
{
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  size_t header_len;

  header_len = ws_frame_build_header (header, fin, opcode, masked, mask_key,
                                      payload_len);

  return ws_write_to_send_buffer (ws, header, header_len, "header");
}

/**
 * ws_write_masked_payload - Write payload with masking in chunks
 * @ws: WebSocket context
 * @data: Payload data
 * @len: Payload length
 * @mask_key: 4-byte mask key (NULL if not masked)
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_masked_payload (SocketWS_T ws, const unsigned char *data, size_t len,
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
        ws_mask_payload_offset (chunk_buf, to_write, mask_key,
                                offset & SOCKETWS_MASK_KEY_INDEX_MASK);

      if (ws_write_to_send_buffer (ws, chunk_buf, to_write, "payload") < 0)
        return -1;

      offset += to_write;
    }

  return 0;
}

/* ============================================================================
 * Frame Sending - Control Frames
 * ============================================================================
 */

/**
 * ws_send_control_frame - Send a control frame
 * @ws: WebSocket context
 * @opcode: Control frame opcode (CLOSE, PING, PONG)
 * @payload: Payload data (may be NULL)
 * @len: Payload length (max 125)
 *
 * Returns: 0 on success, -1 on error
 */
int
ws_send_control_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                       const unsigned char *payload, size_t len)
{
  unsigned char masked_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE];
  int masked;

  assert (ws);
  assert (ws_is_control_opcode (opcode));

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    {
      ws_set_error (ws, WS_ERROR_PROTOCOL,
                    "Control frame payload too large: %zu", len);
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

/* ============================================================================
 * Frame Sending - Data Frames
 * ============================================================================
 */

/**
 * ws_send_data_frame - Send a data frame
 * @ws: WebSocket context
 * @opcode: Data frame opcode (TEXT, BINARY, CONTINUATION)
 * @data: Payload data
 * @len: Payload length
 * @fin: Final fragment flag
 *
 * Returns: 0 on success, -1 on error
 */
int
ws_send_data_frame (SocketWS_T ws, SocketWS_Opcode opcode,
                    const unsigned char *data, size_t len, int fin)
{
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE];
  int masked;

  assert (ws);

  /* Check frame size limit */
  if (len > ws->config.max_frame_size)
    {
      ws_set_error (ws, WS_ERROR_FRAME_TOO_LARGE, "Frame too large: %zu > %zu",
                    len, ws->config.max_frame_size);
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
                  ws, WS_ERROR_FRAME_TOO_LARGE,
                  "Compressed frame too large: %zu > %zu (original %zu)", len,
                  ws->config.max_frame_size, original_len);
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

/* ============================================================================
 * Frame Receiving - Helper Functions
 * ============================================================================
 */

/**
 * ws_recv_control_payload - Receive and process control frame payload
 * @ws: WebSocket context
 * @available: Bytes available in receive buffer
 *
 * Returns: 0 if control frame handled, -1 on error, -2 if need more data
 */
static void ws_read_and_unmask_chunk (SocketWS_T ws, unsigned char *buf,
                                      size_t len);

static int
ws_recv_control_payload (SocketWS_T ws, size_t available)
{
  unsigned char control_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t payload_remaining
      = ws->frame.payload_len - ws->frame.payload_received;
  size_t to_read
      = (available < payload_remaining) ? available : payload_remaining;

  if (to_read > SOCKETWS_MAX_CONTROL_PAYLOAD)
    to_read = SOCKETWS_MAX_CONTROL_PAYLOAD;

  ws_read_and_unmask_chunk (ws, control_payload, to_read);

  if (ws->frame.payload_received < ws->frame.payload_len)
    return -2;

  int result = ws_handle_control_frame (ws, ws->frame.opcode, control_payload,
                                        (size_t)ws->frame.payload_len);

  ws_frame_reset (&ws->frame);
  return (result < 0) ? -1 : 0;
}

/**
 * ws_recv_data_payload - Receive data frame payload chunk
 * @ws: WebSocket context
 * @to_read: Bytes to read
 *
 * Returns: 0 on success, -1 on error
 */
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

/**
 * ws_finalize_frame - Handle frame completion
 * @ws: WebSocket context
 * @frame_out: Output frame info
 *
 * Returns: 1 if data frame ready, -1 on error, -2 if need more data
 */
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

/**
 * ws_read_and_unmask_chunk - Read chunk from recv buf and unmask if needed
 * @ws: WebSocket context
 * @buf: Output buffer for chunk
 * @len: Number of bytes to read
 *
 * Assumes SocketBuf_available >= len.
 * Updates frame.payload_received.
 */
static void
ws_read_and_unmask_chunk (SocketWS_T ws, unsigned char *buf, size_t len)
{
  SocketBuf_read (ws->recv_buf, buf, len);

  size_t offset = ws->frame.payload_received;
  if (ws->frame.masked)
    {
      ws_mask_payload_offset (buf, len, ws->frame.mask_key,
                              offset & SOCKETWS_MASK_KEY_INDEX_MASK);
    }

  ws->frame.payload_received += len;
}

/**
 * ws_check_payload_size - Validate frame payload against configured limit
 * @ws: WebSocket context
 *
 * Returns: 0 if valid, -1 if too large
 */
static int
ws_check_payload_size (SocketWS_T ws)
{
  if (ws->frame.payload_len > ws->config.max_frame_size)
    {
      ws_set_error (ws, WS_ERROR_FRAME_TOO_LARGE,
                    "Frame payload too large: %llu > %zu",
                    (unsigned long long)ws->frame.payload_len,
                    ws->config.max_frame_size);
      return -1;
    }
  return 0;
}

/**
 * ws_process_payload - Read and process frame payload
 * @ws: WebSocket context
 *
 * Returns: 0 if control frame handled, -1 on error, -2 if need more data
 */
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

/* ============================================================================
 * Frame Receiving - Main Function
 * ============================================================================
 */

/**
 * ws_recv_frame - Receive and process next frame
 * @ws: WebSocket context
 * @frame_out: Output frame info (payload points to internal buffer)
 *
 * Returns: 1 if data frame received, 0 if control frame handled,
 *          -1 on error, -2 if would block
 */
int
ws_recv_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out)
{
  size_t available;
  const unsigned char *data;
  size_t consumed;
  SocketWS_Error err;
  int result;

  assert (ws);
  assert (frame_out);

  ws_fill_recv_buffer (ws);

  available = SocketBuf_available (ws->recv_buf);
  if (available == 0)
    return -2;

  data = SocketBuf_readptr (ws->recv_buf, &available);
  if (!data)
    return -2;

  /* Parse header if not complete */
  if (ws->frame.state != WS_FRAME_STATE_PAYLOAD
      && ws->frame.state != WS_FRAME_STATE_COMPLETE)
    {
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
  bool is_control_frame = ws_is_control_opcode (ws->frame.opcode);

  /* Validate masking per RFC 6455 Section 5.3:
   * - Client -> Server frames MUST be masked (server receives masked=1)
   * - Server -> Client frames MUST NOT be masked (client receives masked=0) */
  if ((ws->role == WS_ROLE_SERVER && !ws->frame.masked)
      || (ws->role == WS_ROLE_CLIENT && ws->frame.masked))
    {
      ws_set_error (
          ws, WS_ERROR_PROTOCOL,
          "Invalid frame masking: role=%s received %s frame",
          ws->role == WS_ROLE_SERVER ? "server" : "client",
          ws->frame.masked ? "masked" : "unmasked");
      /* Send protocol error close per RFC 6455 */
      (void)ws_send_close (ws, WS_CLOSE_PROTOCOL_ERROR, "Masking violation");
      return -1;
    }

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
