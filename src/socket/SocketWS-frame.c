/**
 * SocketWS-frame.c - WebSocket Frame Processing (RFC 6455 Section 5)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
 * Optimized XOR Masking
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
ws_mask_payload (unsigned char *data, size_t len, const unsigned char mask[4])
{
  size_t i;
  uint64_t mask64;
  uint32_t mask32;
  size_t aligned_start;
  size_t aligned_end;

  if (!data || len == 0 || !mask)
    return;

  /* Build 32-bit and 64-bit masks */
  mask32 = ((uint32_t)mask[0]) | ((uint32_t)mask[1] << 8)
           | ((uint32_t)mask[2] << 16) | ((uint32_t)mask[3] << 24);
  mask64 = ((uint64_t)mask32) | ((uint64_t)mask32 << 32);

  /* Process initial unaligned bytes */
  aligned_start = (8 - ((uintptr_t)data & 7)) & 7;
  if (aligned_start > len)
    aligned_start = len;

  for (i = 0; i < aligned_start; i++)
    data[i] ^= mask[i & 3];

  if (aligned_start >= len)
    return;

  /* Calculate aligned region */
  aligned_end = aligned_start + ((len - aligned_start) & ~7ULL);

  /* Process 8 bytes at a time with 64-bit XOR */
  {
    uint64_t *p64 = (uint64_t *)(data + aligned_start);
    size_t count = (aligned_end - aligned_start) >> 3;

    while (count--)
      *p64++ ^= mask64;
  }

  /* Process trailing bytes */
  for (i = aligned_end; i < len; i++)
    data[i] ^= mask[i & 3];
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
                        const unsigned char mask[4], size_t offset)
{
  size_t i;

  if (!data || len == 0 || !mask)
    return offset;

  /* Simple byte-by-byte with offset - used for streaming */
  for (i = 0; i < len; i++)
    data[i] ^= mask[(offset + i) & 3];

  return (offset + len) & 3;
}

/* ============================================================================
 * Frame Header Parsing
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
  unsigned char b0, b1;
  size_t offset;

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
          /* Need at least 2 bytes for basic header */
          need = 2 - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < 2)
            return WS_ERROR_WOULD_BLOCK;

          /* Parse first two bytes */
          b0 = frame->header_buf[0];
          b1 = frame->header_buf[1];

          frame->fin = (b0 >> 7) & 1;
          frame->rsv1 = (b0 >> 6) & 1;
          frame->rsv2 = (b0 >> 5) & 1;
          frame->rsv3 = (b0 >> 4) & 1;
          frame->opcode = (SocketWS_Opcode)(b0 & 0x0F);
          frame->masked = (b1 >> 7) & 1;
          frame->payload_len = b1 & 0x7F;

          /* Validate reserved bits (RSV1 = compression, others must be 0) */
          if (frame->rsv2 || frame->rsv3)
            return WS_ERROR_PROTOCOL;

          /* Validate opcode */
          if (!ws_is_valid_opcode (frame->opcode))
            return WS_ERROR_PROTOCOL;

          /* Control frames have restrictions */
          if (ws_is_control_opcode (frame->opcode))
            {
              /* Control frames must not be fragmented */
              if (!frame->fin)
                return WS_ERROR_PROTOCOL;
              /* Control frame payload max 125 */
              if (frame->payload_len > SOCKETWS_MAX_CONTROL_PAYLOAD)
                return WS_ERROR_PROTOCOL;
              /* RSV1 must not be set on control frames */
              if (frame->rsv1)
                return WS_ERROR_PROTOCOL;
            }

          /* Determine header length based on payload length encoding */
          if (frame->payload_len == 126)
            {
              frame->header_needed = 2 + 2; /* 2 base + 2 extended */
              frame->state = WS_FRAME_STATE_EXTENDED_LEN;
            }
          else if (frame->payload_len == 127)
            {
              frame->header_needed = 2 + 8; /* 2 base + 8 extended */
              frame->state = WS_FRAME_STATE_EXTENDED_LEN;
            }
          else
            {
              /* 7-bit payload length is final */
              if (frame->masked)
                {
                  frame->header_needed = 2 + 4; /* Need mask key */
                  frame->state = WS_FRAME_STATE_MASK_KEY;
                }
              else
                {
                  frame->state = WS_FRAME_STATE_PAYLOAD;
                  frame->payload_received = 0;
                  return WS_OK;
                }
            }
          break;

        case WS_FRAME_STATE_EXTENDED_LEN:
          /* Read extended length bytes */
          need = frame->header_needed - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < frame->header_needed)
            return WS_ERROR_WOULD_BLOCK;

          /* Parse extended length */
          offset = 2;
          if (frame->payload_len == 126)
            {
              /* 16-bit network byte order */
              frame->payload_len
                  = ((uint64_t)frame->header_buf[offset] << 8)
                    | (uint64_t)frame->header_buf[offset + 1];
            }
          else
            {
              /* 64-bit network byte order */
              frame->payload_len = 0;
              for (int i = 0; i < 8; i++)
                {
                  frame->payload_len <<= 8;
                  frame->payload_len |= frame->header_buf[offset + i];
                }

              /* MSB must be 0 (RFC 6455) */
              if (frame->payload_len & (1ULL << 63))
                return WS_ERROR_PROTOCOL;
            }

          /* Now read mask key if needed */
          if (frame->masked)
            {
              frame->header_needed += 4;
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
          /* Read mask key (4 bytes) */
          need = frame->header_needed - frame->header_len;
          copy_len = (need < len) ? need : len;

          memcpy (frame->header_buf + frame->header_len, data, copy_len);
          frame->header_len += copy_len;
          data += copy_len;
          len -= copy_len;
          *consumed += copy_len;

          if (frame->header_len < frame->header_needed)
            return WS_ERROR_WOULD_BLOCK;

          /* Extract mask key (last 4 bytes of header) */
          memcpy (frame->mask_key, frame->header_buf + frame->header_needed - 4,
                  4);

          frame->state = WS_FRAME_STATE_PAYLOAD;
          frame->payload_received = 0;
          return WS_OK;

        case WS_FRAME_STATE_PAYLOAD:
        case WS_FRAME_STATE_COMPLETE:
          /* Header already parsed */
          return WS_OK;
        }
    }

  return WS_ERROR_WOULD_BLOCK;
}

/* ============================================================================
 * Frame Header Building
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
  header[offset++] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);

  /* Second byte: MASK + payload length */
  if (payload_len <= 125)
    {
      header[offset++] = (masked ? 0x80 : 0x00) | (unsigned char)payload_len;
    }
  else if (payload_len <= 65535)
    {
      header[offset++] = (masked ? 0x80 : 0x00) | 126;
      header[offset++] = (payload_len >> 8) & 0xFF;
      header[offset++] = payload_len & 0xFF;
    }
  else
    {
      header[offset++] = (masked ? 0x80 : 0x00) | 127;
      header[offset++] = (payload_len >> 56) & 0xFF;
      header[offset++] = (payload_len >> 48) & 0xFF;
      header[offset++] = (payload_len >> 40) & 0xFF;
      header[offset++] = (payload_len >> 32) & 0xFF;
      header[offset++] = (payload_len >> 24) & 0xFF;
      header[offset++] = (payload_len >> 16) & 0xFF;
      header[offset++] = (payload_len >> 8) & 0xFF;
      header[offset++] = payload_len & 0xFF;
    }

  /* Mask key (if masked) */
  if (masked && mask_key)
    {
      memcpy (header + offset, mask_key, 4);
      offset += 4;
    }

  return offset;
}

/* ============================================================================
 * Frame Sending
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
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  unsigned char masked_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];
  unsigned char mask_key[4];
  size_t header_len;
  int masked;
  size_t written;

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
  if (masked)
    {
      if (SocketCrypto_random_bytes (mask_key, 4) != 0)
        {
          ws_set_error (ws, WS_ERROR, "Failed to generate mask key");
          return -1;
        }
    }

  /* Build header */
  header_len
      = ws_frame_build_header (header, 1, opcode, masked, mask_key, len);

  /* Copy and mask payload if needed */
  if (payload && len > 0)
    {
      memcpy (masked_payload, payload, len);
      if (masked)
        ws_mask_payload (masked_payload, len, mask_key);
    }

  /* Write header to send buffer */
  written = SocketBuf_write (ws->send_buf, header, header_len);
  if (written != header_len)
    {
      ws_set_error (ws, WS_ERROR, "Send buffer overflow (header)");
      return -1;
    }

  /* Write payload to send buffer */
  if (len > 0)
    {
      written = SocketBuf_write (ws->send_buf, masked_payload, len);
      if (written != len)
        {
          ws_set_error (ws, WS_ERROR, "Send buffer overflow (payload)");
          return -1;
        }
    }

  /* Try to flush immediately */
  ws_flush_send_buffer (ws);

  return 0;
}

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
  unsigned char header[SOCKETWS_MAX_HEADER_SIZE];
  unsigned char mask_key[4];
  size_t header_len;
  int masked;
  size_t written;
  size_t chunk_size;
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
  if (masked)
    {
      if (SocketCrypto_random_bytes (mask_key, 4) != 0)
        {
          ws_set_error (ws, WS_ERROR, "Failed to generate mask key");
          return -1;
        }
    }

  /* TODO: Handle compression if enabled */
#ifdef SOCKETWS_HAS_DEFLATE
  /* Compression would be applied here */
#endif

  /* Build header */
  header_len
      = ws_frame_build_header (header, fin, opcode, masked, mask_key, len);

  /* Write header */
  written = SocketBuf_write (ws->send_buf, header, header_len);
  if (written != header_len)
    {
      ws_set_error (ws, WS_ERROR, "Send buffer overflow (header)");
      return -1;
    }

  /* Write payload in chunks, masking if needed */
  if (len > 0)
    {
      chunk_size = 8192; /* Process in 8KB chunks */
      chunk_buf = ALLOC (ws->arena, chunk_size);
      if (!chunk_buf)
        {
          ws_set_error (ws, WS_ERROR, "Failed to allocate chunk buffer");
          return -1;
        }

      while (offset < len)
        {
          size_t remaining = len - offset;
          size_t to_write = (remaining < chunk_size) ? remaining : chunk_size;

          memcpy (chunk_buf, data + offset, to_write);

          if (masked)
            ws_mask_payload_offset (chunk_buf, to_write, mask_key,
                                    offset & 3);

          written = SocketBuf_write (ws->send_buf, chunk_buf, to_write);
          if (written != to_write)
            {
              ws_set_error (ws, WS_ERROR, "Send buffer overflow (payload)");
              return -1;
            }

          offset += to_write;
        }
    }

  /* Try to flush */
  ws_flush_send_buffer (ws);

  return 0;
}

/* ============================================================================
 * Frame Receiving
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
  size_t payload_available;
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

  /* Read payload */
  if (ws->frame.payload_received < ws->frame.payload_len)
    {
      available = SocketBuf_available (ws->recv_buf);
      if (available == 0)
        return -2;

      data = SocketBuf_readptr (ws->recv_buf, &available);
      payload_available = ws->frame.payload_len - ws->frame.payload_received;
      to_read = (available < payload_available) ? available : payload_available;

      /* For control frames, process immediately */
      if (ws_is_control_opcode (ws->frame.opcode))
        {
          unsigned char control_payload[SOCKETWS_MAX_CONTROL_PAYLOAD];

          if (to_read > SOCKETWS_MAX_CONTROL_PAYLOAD)
            to_read = SOCKETWS_MAX_CONTROL_PAYLOAD;

          SocketBuf_read (ws->recv_buf, control_payload, to_read);

          /* Unmask if masked */
          if (ws->frame.masked)
            ws_mask_payload_offset (control_payload, to_read,
                                    ws->frame.mask_key,
                                    (size_t)ws->frame.payload_received);

          ws->frame.payload_received += to_read;

          if (ws->frame.payload_received >= ws->frame.payload_len)
            {
              /* Control frame complete - handle it */
              int result = ws_handle_control_frame (
                  ws, ws->frame.opcode, control_payload,
                  (size_t)ws->frame.payload_len);

              ws_frame_reset (&ws->frame);
              return (result < 0) ? -1 : 0;
            }

          return -2; /* Need more data */
        }
      else
        {
          /* Data frame - append to message assembly */
          unsigned char *payload_buf;

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
          if (ws->message.fragment_count == 0
              && ws_is_data_opcode (ws->frame.opcode))
            {
              ws->message.type = ws->frame.opcode;
              ws->message.compressed = ws->frame.rsv1;
            }

          /* Append to message */
          int is_text = (ws->message.type == WS_OPCODE_TEXT);
          if (ws_message_append (ws, payload_buf, to_read, is_text) < 0)
            return -1;
        }
    }

  /* Check if frame is complete */
  if (ws->frame.payload_received >= ws->frame.payload_len)
    {
      frame_out->state = WS_FRAME_STATE_COMPLETE;

      /* If FIN set, message is complete */
      if (ws->frame.fin)
        {
          /* Finalize message */
          if (ws_message_finalize (ws) < 0)
            return -1;

          /* Return 1 to indicate data frame ready */
          ws_frame_reset (&ws->frame);
          return 1;
        }

      /* Reset frame state for next fragment */
      ws_frame_reset (&ws->frame);
    }

  return -2; /* Need more data */
}

