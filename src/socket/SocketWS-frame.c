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
 * Static Helper Function Declarations
 * ============================================================================ */

/* XOR Masking Helpers */
static void ws_mask_unaligned_bytes (unsigned char *data, size_t len,
                                     const unsigned char mask[SOCKETWS_MASK_KEY_SIZE],
                                     size_t start_offset);
static void ws_mask_aligned_block (uint64_t *data, size_t count, uint64_t mask64);
static uint64_t ws_build_mask64 (const unsigned char mask[SOCKETWS_MASK_KEY_SIZE]);

/* Frame Header Parsing Helpers */
static SocketWS_Error ws_parse_basic_header (SocketWS_FrameParse *frame);
static SocketWS_Error ws_validate_frame_header (const SocketWS_FrameParse *frame);
static void ws_determine_header_length (SocketWS_FrameParse *frame);
static SocketWS_Error ws_parse_extended_length (SocketWS_FrameParse *frame);
static void ws_extract_mask_key (SocketWS_FrameParse *frame);

/* Frame Header Building Helpers */
static size_t ws_encode_payload_length (unsigned char *header, size_t offset,
                                        int masked, uint64_t payload_len);

/* Send Buffer Helpers */
static int ws_generate_mask_key (unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE]);
static int ws_write_to_send_buffer (SocketWS_T ws, const void *data, size_t len,
                                    const char *what);
static int ws_write_frame_header (SocketWS_T ws, int fin, SocketWS_Opcode opcode,
                                  int masked, const unsigned char *mask_key,
                                  uint64_t payload_len);

/* Receive Frame Helpers */
static int ws_recv_control_payload (SocketWS_T ws, const unsigned char *data,
                                    size_t available);
static int ws_recv_data_payload (SocketWS_T ws, const unsigned char *data,
                                 size_t to_read);
static int ws_finalize_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out);

/* ============================================================================
 * XOR Masking - Helper Functions
 * ============================================================================ */

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
 * ============================================================================ */

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
  aligned_end
      = aligned_start
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
 * Frame Header Parsing - Helper Functions
 * ============================================================================ */

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
  frame->opcode = (SocketWS_Opcode) (b0 & SOCKETWS_OPCODE_MASK);
  frame->masked = (b1 & SOCKETWS_MASK_BIT) != 0;
  frame->payload_len = b1 & SOCKETWS_PAYLOAD_LEN_MASK;

  return WS_OK;
}

/**
 * ws_validate_frame_header - Validate parsed frame header fields
 * @frame: Frame parsing state with parsed fields
 *
 * Validates reserved bits, opcode, and control frame constraints.
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
      /* Control frames must not be fragmented */
      if (!frame->fin)
        return WS_ERROR_PROTOCOL;

      /* Control frame payload max 125 bytes */
      if (frame->payload_len > SOCKETWS_MAX_CONTROL_PAYLOAD)
        return WS_ERROR_PROTOCOL;

      /* RSV1 must not be set on control frames */
      if (frame->rsv1)
        return WS_ERROR_PROTOCOL;
    }

  return WS_OK;
}

/**
 * ws_determine_header_length - Calculate total header size
 * @frame: Frame parsing state
 *
 * Sets header_needed and transitions to appropriate state based on
 * payload length encoding.
 */
static void
ws_determine_header_length (SocketWS_FrameParse *frame)
{
  if (frame->payload_len == SOCKETWS_EXTENDED_LEN_16)
    {
      frame->header_needed
          = SOCKETWS_BASE_HEADER_SIZE + SOCKETWS_EXTENDED_LEN_16_SIZE;
      frame->state = WS_FRAME_STATE_EXTENDED_LEN;
    }
  else if (frame->payload_len == SOCKETWS_EXTENDED_LEN_64)
    {
      frame->header_needed
          = SOCKETWS_BASE_HEADER_SIZE + SOCKETWS_EXTENDED_LEN_64_SIZE;
      frame->state = WS_FRAME_STATE_EXTENDED_LEN;
    }
  else
    {
      /* 7-bit payload length is final */
      if (frame->masked)
        {
          frame->header_needed
              = SOCKETWS_BASE_HEADER_SIZE + SOCKETWS_MASK_KEY_SIZE;
          frame->state = WS_FRAME_STATE_MASK_KEY;
        }
      else
        {
          frame->state = WS_FRAME_STATE_PAYLOAD;
          frame->payload_received = 0;
        }
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
  int i;

  if (frame->payload_len == SOCKETWS_EXTENDED_LEN_16)
    {
      /* 16-bit network byte order */
      frame->payload_len = ((uint64_t)frame->header_buf[offset] << 8)
                           | (uint64_t)frame->header_buf[offset + 1];
    }
  else
    {
      /* 64-bit network byte order */
      frame->payload_len = 0;
      for (i = 0; i < SOCKETWS_EXTENDED_LEN_64_SIZE; i++)
        {
          frame->payload_len <<= 8;
          frame->payload_len |= frame->header_buf[offset + i];
        }

      /* MSB must be 0 (RFC 6455) */
      if (frame->payload_len & (1ULL << 63))
        return WS_ERROR_PROTOCOL;
    }

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

/* ============================================================================
 * Frame Header Parsing - Main Function
 * ============================================================================ */

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
  size_t need;
  size_t copy_len;
  SocketWS_Error err;

  assert (frame);
  assert (consumed);

  *consumed = 0;

  if (len == 0)
    return WS_ERROR_WOULD_BLOCK;

  /* State machine for incremental header parsing */
  while (len > 0)
    {
      switch (frame->state)
        {
        case WS_FRAME_STATE_HEADER:
          need = SOCKETWS_BASE_HEADER_SIZE - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < SOCKETWS_BASE_HEADER_SIZE)
            return WS_ERROR_WOULD_BLOCK;

          ws_parse_basic_header (frame);

          err = ws_validate_frame_header (frame);
          if (err != WS_OK)
            return err;

          ws_determine_header_length (frame);

          if (frame->state == WS_FRAME_STATE_PAYLOAD)
            return WS_OK;
          break;

        case WS_FRAME_STATE_EXTENDED_LEN:
          need = frame->header_needed - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < frame->header_needed)
            return WS_ERROR_WOULD_BLOCK;

          err = ws_parse_extended_length (frame);
          if (err != WS_OK)
            return err;

          if (frame->masked)
            {
              frame->header_needed += SOCKETWS_MASK_KEY_SIZE;
              frame->state = WS_FRAME_STATE_MASK_KEY;
            }
          else
            {
              frame->state = WS_FRAME_STATE_PAYLOAD;
              frame->payload_received = 0;
              return WS_OK;
            }
          break;

        case WS_FRAME_STATE_MASK_KEY:
          need = frame->header_needed - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < frame->header_needed)
            return WS_ERROR_WOULD_BLOCK;

          ws_extract_mask_key (frame);

          frame->state = WS_FRAME_STATE_PAYLOAD;
          frame->payload_received = 0;
          return WS_OK;

        case WS_FRAME_STATE_PAYLOAD:
        case WS_FRAME_STATE_COMPLETE:
          return WS_OK;
        }
    }

  return WS_ERROR_WOULD_BLOCK;
}

/* ============================================================================
 * Frame Header Building - Helper Functions
 * ============================================================================ */

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
  if (payload_len <= SOCKETWS_MAX_7BIT_PAYLOAD)
    {
      header[offset++]
          = (masked ? SOCKETWS_MASK_BIT : 0) | (unsigned char)payload_len;
    }
  else if (payload_len <= SOCKETWS_MAX_16BIT_PAYLOAD)
    {
      header[offset++] = (masked ? SOCKETWS_MASK_BIT : 0) | SOCKETWS_EXTENDED_LEN_16;
      header[offset++] = (payload_len >> 8) & 0xFF;
      header[offset++] = payload_len & 0xFF;
    }
  else
    {
      header[offset++] = (masked ? SOCKETWS_MASK_BIT : 0) | SOCKETWS_EXTENDED_LEN_64;
      header[offset++] = (payload_len >> 56) & 0xFF;
      header[offset++] = (payload_len >> 48) & 0xFF;
      header[offset++] = (payload_len >> 40) & 0xFF;
      header[offset++] = (payload_len >> 32) & 0xFF;
      header[offset++] = (payload_len >> 24) & 0xFF;
      header[offset++] = (payload_len >> 16) & 0xFF;
      header[offset++] = (payload_len >> 8) & 0xFF;
      header[offset++] = payload_len & 0xFF;
    }

  return offset;
}

/* ============================================================================
 * Frame Header Building - Main Function
 * ============================================================================ */

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
  header[offset++] = (fin ? SOCKETWS_FIN_BIT : 0) | (opcode & SOCKETWS_OPCODE_MASK);

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
 * Send Buffer - Helper Functions
 * ============================================================================ */

/**
 * ws_generate_mask_key - Generate random 4-byte mask key
 * @mask_key: Output buffer for mask key
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_generate_mask_key (unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE])
{
  return SocketCrypto_random_bytes (mask_key, SOCKETWS_MASK_KEY_SIZE);
}

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

  header_len
      = ws_frame_build_header (header, fin, opcode, masked, mask_key, payload_len);

  return ws_write_to_send_buffer (ws, header, header_len, "header");
}

/* ============================================================================
 * Frame Sending - Control Frames
 * ============================================================================ */

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
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE] = { 0 };
  int masked;

  assert (ws);
  assert (ws_is_control_opcode (opcode));

  if (len > SOCKETWS_MAX_CONTROL_PAYLOAD)
    {
      ws_set_error (ws, WS_ERROR_PROTOCOL,
                    "Control frame payload too large: %zu", len);
      return -1;
    }

  /* Client always masks, server never masks */
  masked = (ws->role == WS_ROLE_CLIENT);

  /* Generate mask key if client */
  if (masked && ws_generate_mask_key (mask_key) != 0)
    {
      ws_set_error (ws, WS_ERROR, "Failed to generate mask key");
      return -1;
    }

  /* Write frame header */
  if (ws_write_frame_header (ws, 1, opcode, masked, mask_key, len) < 0)
    return -1;

  /* Copy, mask, and write payload */
  if (payload && len > 0)
    {
      memcpy (masked_payload, payload, len);
      if (masked)
        ws_mask_payload (masked_payload, len, mask_key);

      if (ws_write_to_send_buffer (ws, masked_payload, len, "payload") < 0)
        return -1;
    }

  /* Try to flush immediately */
  ws_flush_send_buffer (ws);

  return 0;
}

/* ============================================================================
 * Frame Sending - Data Frames
 * ============================================================================ */

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
  unsigned char mask_key[SOCKETWS_MASK_KEY_SIZE] = { 0 };
  int masked;
  size_t offset = 0;
  unsigned char *chunk_buf = NULL;

  assert (ws);

  /* Check frame size limit */
  if (len > ws->config.max_frame_size)
    {
      ws_set_error (ws, WS_ERROR_FRAME_TOO_LARGE, "Frame too large: %zu > %zu",
                    len, ws->config.max_frame_size);
      return -1;
    }

  /* Client always masks, server never masks */
  masked = (ws->role == WS_ROLE_CLIENT);

  /* Generate mask key if client */
  if (masked && ws_generate_mask_key (mask_key) != 0)
    {
      ws_set_error (ws, WS_ERROR, "Failed to generate mask key");
      return -1;
    }

  /* Compress if enabled (permessage-deflate) */
#ifdef SOCKETWS_HAS_DEFLATE
  if (ws->compression_enabled && ws_is_data_opcode (opcode))
    {
      unsigned char *compressed = NULL;
      size_t compressed_len = 0;

      if (ws_compress_message (ws, data, len, &compressed, &compressed_len)
          == 0)
        {
          data = compressed;
          len = compressed_len;
          /* RSV1 bit will be set in header for compressed frames */
        }
      /* On compression failure, send uncompressed */
    }
#endif

  /* Write frame header */
  if (ws_write_frame_header (ws, fin, opcode, masked, mask_key, len) < 0)
    return -1;

  /* Write payload in chunks, masking if needed */
  if (len > 0)
    {
      chunk_buf = ALLOC (ws->arena, SOCKETWS_SEND_CHUNK_SIZE);
      if (!chunk_buf)
        {
          ws_set_error (ws, WS_ERROR, "Failed to allocate chunk buffer");
          return -1;
        }

      while (offset < len)
        {
          size_t remaining = len - offset;
          size_t to_write
              = (remaining < SOCKETWS_SEND_CHUNK_SIZE) ? remaining
                                                       : SOCKETWS_SEND_CHUNK_SIZE;

          memcpy (chunk_buf, data + offset, to_write);

          if (masked)
            ws_mask_payload_offset (chunk_buf, to_write, mask_key,
                                    offset & SOCKETWS_MASK_KEY_INDEX_MASK);

          if (ws_write_to_send_buffer (ws, chunk_buf, to_write, "payload") < 0)
            return -1;

          offset += to_write;
        }
    }

  /* Try to flush */
  ws_flush_send_buffer (ws);

  return 0;
}

/* ============================================================================
 * Frame Receiving - Helper Functions
 * ============================================================================ */

/**
 * ws_recv_control_payload - Receive and process control frame payload
 * @ws: WebSocket context
 * @data: Available data from receive buffer
 * @available: Bytes available
 *
 * Returns: 0 if control frame handled, -1 on error, -2 if need more data
 */
static int
ws_recv_control_payload (SocketWS_T ws, const unsigned char *data,
                         size_t available)
{
  unsigned char control_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  size_t payload_remaining;
  size_t to_read;

  (void)data; /* Used for available check */

  payload_remaining = ws->frame.payload_len - ws->frame.payload_received;
  to_read = (available < payload_remaining) ? available : payload_remaining;

  if (to_read > SOCKETWS_MAX_CONTROL_PAYLOAD)
    to_read = SOCKETWS_MAX_CONTROL_PAYLOAD;

  SocketBuf_read (ws->recv_buf, control_payload, to_read);

  /* Unmask if masked */
  if (ws->frame.masked)
    ws_mask_payload_offset (control_payload, to_read, ws->frame.mask_key,
                            (size_t)ws->frame.payload_received);

  ws->frame.payload_received += to_read;

  if (ws->frame.payload_received >= ws->frame.payload_len)
    {
      /* Control frame complete - handle it */
      int result = ws_handle_control_frame (ws, ws->frame.opcode,
                                            control_payload,
                                            (size_t)ws->frame.payload_len);

      ws_frame_reset (&ws->frame);
      return (result < 0) ? -1 : 0;
    }

  return -2; /* Need more data */
}

/**
 * ws_recv_data_payload - Receive data frame payload chunk
 * @ws: WebSocket context
 * @data: Available data from receive buffer
 * @to_read: Bytes to read
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_recv_data_payload (SocketWS_T ws, const unsigned char *data, size_t to_read)
{
  unsigned char *payload_buf;
  int is_text;

  (void)data; /* Data is read from recv_buf */

  payload_buf = ALLOC (ws->arena, to_read);
  if (!payload_buf)
    {
      ws_set_error (ws, WS_ERROR, "Failed to allocate payload buffer");
      return -1;
    }

  SocketBuf_read (ws->recv_buf, payload_buf, to_read);

  /* Unmask if masked */
  if (ws->frame.masked)
    ws_mask_payload_offset (payload_buf, to_read, ws->frame.mask_key,
                            (size_t)ws->frame.payload_received);

  ws->frame.payload_received += to_read;

  /* Set message type on first fragment */
  if (ws->message.fragment_count == 0 && ws_is_data_opcode (ws->frame.opcode))
    {
      ws->message.type = ws->frame.opcode;
      ws->message.compressed = ws->frame.rsv1;
    }

  /* Append to message */
  is_text = (ws->message.type == WS_OPCODE_TEXT);
  return ws_message_append (ws, payload_buf, to_read, is_text);
}

/**
 * ws_finalize_frame - Handle frame completion
 * @ws: WebSocket context
 * @frame_out: Output frame info
 *
 * Returns: 1 if data frame ready, -1 on error
 */
static int
ws_finalize_frame (SocketWS_T ws, SocketWS_FrameParse *frame_out)
{
  frame_out->state = WS_FRAME_STATE_COMPLETE;

  /* If FIN set, message is complete */
  if (ws->frame.fin)
    {
      if (ws_message_finalize (ws) < 0)
        return -1;

      ws_frame_reset (&ws->frame);
      return 1;
    }

  /* Reset frame state for next fragment */
  ws_frame_reset (&ws->frame);
  return -2; /* Need more data for message completion */
}

/* ============================================================================
 * Frame Receiving - Main Function
 * ============================================================================ */

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
  size_t payload_remaining;
  size_t to_read;

  assert (ws);
  assert (frame_out);

  /* Fill receive buffer if possible */
  ws_fill_recv_buffer (ws);

  /* Get available data from receive buffer */
  available = SocketBuf_available (ws->recv_buf);
  if (available == 0)
    return -2; /* Would block */

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

  /* Copy frame state to output */
  *frame_out = ws->frame;

  /* Check payload size limit */
  if (ws->frame.payload_len > ws->config.max_frame_size)
    {
      ws_set_error (ws, WS_ERROR_FRAME_TOO_LARGE,
                    "Frame payload too large: %llu > %zu",
                    (unsigned long long)ws->frame.payload_len,
                    ws->config.max_frame_size);
      return -1;
    }

  /* Read payload if needed */
  if (ws->frame.payload_received < ws->frame.payload_len)
    {
      available = SocketBuf_available (ws->recv_buf);
      if (available == 0)
        return -2;

      data = SocketBuf_readptr (ws->recv_buf, &available);
      payload_remaining = ws->frame.payload_len - ws->frame.payload_received;
      to_read = (available < payload_remaining) ? available : payload_remaining;

      /* Handle control vs data frames differently */
      if (ws_is_control_opcode (ws->frame.opcode))
        return ws_recv_control_payload (ws, data, available);
      else
        {
          if (ws_recv_data_payload (ws, data, to_read) < 0)
            return -1;
        }
    }

  /* Check if frame is complete */
  if (ws->frame.payload_received >= ws->frame.payload_len)
    return ws_finalize_frame (ws, frame_out);

  return -2; /* Need more data */
}
