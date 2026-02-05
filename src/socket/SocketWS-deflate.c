/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketWS-deflate.c - WebSocket Compression Extension (RFC 7692)
 *
 * Implements permessage-deflate compression extension for WebSocket.
 * Only compiled when SOCKETWS_HAS_DEFLATE is defined.
 *
 * Two implementations:
 * - Native DEFLATE (SOCKETWS_HAS_NATIVE_DEFLATE): Built-in RFC 1951 codec
 * - zlib fallback: Uses external zlib library
 *
 * RFC 7692 specifies:
 * - Per-message compression using DEFLATE (RFC 1951)
 * - RSV1 bit indicates compressed message
 * - Context takeover (optional) for better compression
 * - Configurable window bits (8-15)
 *
 * Security Notes:
 * - Decompression bounded by config.max_message_size to prevent bombs
 * - Integer overflows prevented with SocketSecurity safe ops
 * - Trailer handling per RFC 7692: remove on compress, add on decompress
 */

#include "socket/SocketWS-private.h"

#ifdef SOCKETWS_HAS_DEFLATE

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"

/** Initial buffer size for compression */
#define WS_DEFLATE_INITIAL_BUF_SIZE (16 * 1024)

/** Growth factor for buffer reallocation */
#define WS_DEFLATE_BUF_GROWTH 2

/** Minimum valid window bits (RFC 7692) */
#define WS_DEFLATE_MIN_WINDOW_BITS 8

/** Maximum valid window bits (RFC 7692) */
#define WS_DEFLATE_MAX_WINDOW_BITS 15

/** Padding overhead for initial compress buffer */
#define WS_DEFLATE_HEADER_PADDING 64

/** Size of RFC 7692 trailer bytes */
#define WS_DEFLATE_TRAILER_SIZE 4

/** Decompression expansion estimate multiplier */
#define WS_DEFLATE_EXPANSION_FACTOR 4

/** Fallback buffer size when decompression size estimation overflows */
#define WS_DEFLATE_OVERFLOW_FALLBACK_MAX (SIZE_MAX / 2)

/* RFC 7692: The trailer bytes (0x00 0x00 0xff 0xff) MUST be removed
 * from the compressed data before sending, and added back on receiving. */
static const unsigned char WS_DEFLATE_TRAILER[WS_DEFLATE_TRAILER_SIZE]
    = { 0x00, 0x00, 0xFF, 0xFF };

static int
validate_window_bits (int bits)
{
  if (bits < WS_DEFLATE_MIN_WINDOW_BITS || bits > WS_DEFLATE_MAX_WINDOW_BITS)
    return -1;
  return bits;
}

static int
validate_and_store_window_bits (SocketWS_T ws, int bits, const char *type_name)
{
  int validated = validate_window_bits (bits);
  if (validated < 0)
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Invalid %s: %d", type_name, bits);
      return -1;
    }
  return validated;
}

/*
 * ============================================================================
 * Native DEFLATE Implementation (RFC 1951)
 * ============================================================================
 */
#ifdef SOCKETWS_HAS_NATIVE_DEFLATE

#include "deflate/SocketDeflate.h"

static size_t
calculate_buffer_size (size_t input_len, int is_decompress)
{
  size_t buf_size;
  if (is_decompress)
    {
      if (!SocketSecurity_check_multiply (
              input_len, WS_DEFLATE_EXPANSION_FACTOR, &buf_size))
        {
          buf_size = WS_DEFLATE_OVERFLOW_FALLBACK_MAX;
        }
    }
  else
    {
      buf_size = SocketDeflate_compress_bound (input_len);
      /* Add extra space for trailer removal */
      if (!SocketSecurity_check_add (
              buf_size, WS_DEFLATE_HEADER_PADDING, &buf_size))
        {
          buf_size = input_len + WS_DEFLATE_HEADER_PADDING;
        }
    }
  if (buf_size < WS_DEFLATE_INITIAL_BUF_SIZE)
    buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;
  return buf_size;
}

static unsigned char *
grow_arena_buffer (Arena_T arena,
                   unsigned char *old_buf,
                   size_t used,
                   size_t new_size)
{
  unsigned char *new_buf;

  if (!SocketSecurity_check_size (new_size))
    return NULL;
  new_buf = ALLOC (arena, new_size);
  if (!new_buf)
    return NULL;

  if (used > 0)
    memcpy (new_buf, old_buf, used);

  return new_buf;
}

static void
remove_deflate_trailer (unsigned char *buf, size_t *len)
{
  assert (buf);
  assert (len);

  if (*len >= WS_DEFLATE_TRAILER_SIZE
      && memcmp (buf + *len - WS_DEFLATE_TRAILER_SIZE,
                 WS_DEFLATE_TRAILER,
                 WS_DEFLATE_TRAILER_SIZE)
             == 0)
    {
      *len -= WS_DEFLATE_TRAILER_SIZE;
    }
}

static unsigned char *
append_deflate_trailer (Arena_T arena,
                        const unsigned char *input,
                        size_t input_len,
                        size_t *output_len)
{
  unsigned char *buf;

  if (!SocketSecurity_check_add (
          input_len, WS_DEFLATE_TRAILER_SIZE, output_len))
    return NULL;

  buf = ALLOC (arena, *output_len);
  if (!buf)
    return NULL;

  memcpy (buf, input, input_len);
  memcpy (buf + input_len, WS_DEFLATE_TRAILER, WS_DEFLATE_TRAILER_SIZE);

  return buf;
}

static int
should_reset_context (const SocketWS_T ws, int is_deflate)
{
  assert (ws);

  int client_no = ws->compression.client_no_context_takeover;
  int server_no = ws->compression.server_no_context_takeover;

  if (ws->role == WS_ROLE_CLIENT)
    return is_deflate ? client_no : server_no;
  else
    return is_deflate ? server_no : client_no;
}

int
ws_compression_init (SocketWS_T ws)
{
  int deflate_bits;
  int inflate_bits;

  assert (ws);

  memset (&ws->compression, 0, sizeof (ws->compression));

  /* Validate window bits from negotiation */
  deflate_bits = validate_and_store_window_bits (
      ws, ws->handshake.client_max_window_bits, "client_max_window_bits");
  if (deflate_bits < 0)
    return -1;

  inflate_bits = validate_and_store_window_bits (
      ws, ws->handshake.server_max_window_bits, "server_max_window_bits");
  if (inflate_bits < 0)
    return -1;

  /* Store settings */
  ws->compression.server_no_context_takeover
      = ws->handshake.server_no_context_takeover;
  ws->compression.client_no_context_takeover
      = ws->handshake.client_no_context_takeover;
  ws->compression.server_max_window_bits = inflate_bits;
  ws->compression.client_max_window_bits = deflate_bits;

  /* Note: Native DEFLATE uses 15-bit window. Log warning if smaller requested.
   */
  if (deflate_bits < WS_DEFLATE_MAX_WINDOW_BITS
      || inflate_bits < WS_DEFLATE_MAX_WINDOW_BITS)
    {
      SocketLog_emitf (SOCKET_LOG_WARN,
                       SOCKET_LOG_COMPONENT,
                       "Window bits < 15 requested (deflate=%d, inflate=%d); "
                       "native DEFLATE uses 15-bit window",
                       deflate_bits,
                       inflate_bits);
    }

  /* Create deflater with default compression level (6) */
  ws->compression.deflater
      = SocketDeflate_Deflater_new (ws->arena, DEFLATE_LEVEL_DEFAULT);
  if (!ws->compression.deflater)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to create deflater");
      return -1;
    }
  ws->compression.deflate_initialized = 1;

  /* Create inflater with max_output = max_message_size for bomb protection */
  ws->compression.inflater
      = SocketDeflate_Inflater_new (ws->arena, ws->config.max_message_size);
  if (!ws->compression.inflater)
    {
      ws->compression.deflate_initialized = 0;
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to create inflater");
      return -1;
    }
  ws->compression.inflate_initialized = 1;

  SocketLog_emitf (SOCKET_LOG_DEBUG,
                   SOCKET_LOG_COMPONENT,
                   "Native DEFLATE compression initialized");

  return 0;
}

void
ws_compression_free (SocketWS_T ws)
{
  assert (ws);

  /* Native DEFLATE uses Arena allocation - no explicit free needed.
   * Just clear initialized flags. */
  ws->compression.deflate_initialized = 0;
  ws->compression.inflate_initialized = 0;
}

int
ws_compress_message (SocketWS_T ws,
                     const unsigned char *input,
                     size_t input_len,
                     unsigned char **output,
                     size_t *output_len)
{
  SocketDeflate_Result res;
  size_t buf_size;
  size_t consumed, written;
  unsigned char *buf;

  assert (ws);
  assert (output);
  assert (output_len);

  if (!ws->compression.deflate_initialized)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Deflater not initialized");
      return -1;
    }

  /* Allocate output buffer */
  buf_size = calculate_buffer_size (input_len, 0 /* compress */);
  if (!SocketSecurity_check_size (buf_size))
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Buffer size exceeds security limit");
      return -1;
    }
  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to allocate buffer");
      return -1;
    }

  /* Feed input to deflater */
  res = SocketDeflate_Deflater_deflate (ws->compression.deflater,
                                        input,
                                        input_len,
                                        &consumed,
                                        buf,
                                        buf_size,
                                        &written);
  if (res != DEFLATE_OK)
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Deflate failed: %s",
                    SocketDeflate_result_string (res));
      return -1;
    }

  /* Check all input was consumed */
  if (consumed != input_len)
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Deflate incomplete: consumed %zu of %zu",
                    consumed,
                    input_len);
      return -1;
    }

  /* Finish/sync flush based on context takeover setting */
  if (should_reset_context (ws, 1 /* deflate */))
    {
      /* No context takeover: finish with final block (BFINAL=1) */
      size_t finish_written;
      res = SocketDeflate_Deflater_finish (ws->compression.deflater,
                                           buf + written,
                                           buf_size - written,
                                           &finish_written);
      if (res != DEFLATE_OK)
        {
          ws_set_error (ws,
                        WS_ERROR_COMPRESSION,
                        "Deflate finish failed: %s",
                        SocketDeflate_result_string (res));
          return -1;
        }
      written += finish_written;

      /* Reset deflater for next message */
      SocketDeflate_Deflater_reset (ws->compression.deflater);
    }
  else
    {
      /* Context takeover: sync flush with BFINAL=0 */
      size_t flush_written;
      res = SocketDeflate_Deflater_sync_flush (ws->compression.deflater,
                                               buf + written,
                                               buf_size - written,
                                               &flush_written);
      if (res != DEFLATE_OK)
        {
          ws_set_error (ws,
                        WS_ERROR_COMPRESSION,
                        "Deflate sync_flush failed: %s",
                        SocketDeflate_result_string (res));
          return -1;
        }
      written += flush_written;
    }

  /* Remove RFC 7692 trailer (0x00 0x00 0xFF 0xFF) */
  remove_deflate_trailer (buf, &written);

  *output = buf;
  *output_len = written;

  return 0;
}

/*
 * Grow the inflate output buffer, enforcing max_message_size.
 * Returns 0 on success (buf and buf_size updated), -1 on error.
 */
static int
ws_inflate_grow_buffer (SocketWS_T ws,
                        unsigned char **buf,
                        size_t *buf_size,
                        size_t total_written)
{
  size_t new_size;

  if (!SocketSecurity_check_multiply (
          *buf_size, WS_DEFLATE_BUF_GROWTH, &new_size))
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Buffer growth overflow");
      return -1;
    }

  if (new_size > ws->config.max_message_size)
    new_size = ws->config.max_message_size;

  if (new_size <= *buf_size)
    {
      ws_set_error (
          ws, WS_ERROR_MESSAGE_TOO_LARGE, "Decompressed message too large");
      return -1;
    }

  unsigned char *new_buf
      = grow_arena_buffer (ws->arena, *buf, total_written, new_size);
  if (!new_buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to grow buffer");
      return -1;
    }

  *buf = new_buf;
  *buf_size = new_size;
  return 0;
}

int
ws_decompress_message (SocketWS_T ws,
                       const unsigned char *input,
                       size_t input_len,
                       unsigned char **output,
                       size_t *output_len)
{
  SocketDeflate_Result res;
  size_t buf_size;
  size_t consumed, written, total_written;
  unsigned char *buf;
  unsigned char *input_with_trailer;
  size_t input_with_trailer_len;

  assert (ws);
  assert (output);
  assert (output_len);

  if (!ws->compression.inflate_initialized)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Inflater not initialized");
      return -1;
    }

  /* Append RFC 7692 trailer */
  input_with_trailer = append_deflate_trailer (
      ws->arena, input, input_len, &input_with_trailer_len);
  if (!input_with_trailer)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to append trailer");
      return -1;
    }

  /* Allocate output buffer */
  buf_size = calculate_buffer_size (input_len, 1 /* decompress */);
  if (!SocketSecurity_check_size (buf_size))
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Buffer size exceeds security limit");
      return -1;
    }

  if (buf_size > ws->config.max_message_size)
    buf_size = ws->config.max_message_size;

  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to allocate buffer");
      return -1;
    }

  /* Inflate loop with buffer growth */
  total_written = 0;
  size_t input_remaining = input_with_trailer_len;
  const unsigned char *input_ptr = input_with_trailer;

  while (input_remaining > 0)
    {
      res = SocketDeflate_Inflater_inflate (ws->compression.inflater,
                                            input_ptr,
                                            input_remaining,
                                            &consumed,
                                            buf + total_written,
                                            buf_size - total_written,
                                            &written);

      total_written += written;
      input_ptr += consumed;
      input_remaining -= consumed;

      if (res == DEFLATE_OK)
        break;

      if (res == DEFLATE_INCOMPLETE && consumed == 0 && written == 0)
        {
          ws_set_error (
              ws, WS_ERROR_COMPRESSION, "Inflate incomplete: no progress");
          return -1;
        }

      if (res == DEFLATE_OUTPUT_FULL)
        {
          if (ws_inflate_grow_buffer (ws, &buf, &buf_size, total_written) != 0)
            return -1;
          continue;
        }

      if (res == DEFLATE_ERROR_BOMB)
        {
          ws_set_error (
              ws, WS_ERROR_MESSAGE_TOO_LARGE, "Decompression bomb detected");
          return -1;
        }

      if (res != DEFLATE_OK && res != DEFLATE_INCOMPLETE)
        {
          ws_set_error (ws,
                        WS_ERROR_COMPRESSION,
                        "Inflate failed: %s",
                        SocketDeflate_result_string (res));
          return -1;
        }
    }

  if (should_reset_context (ws, 0 /* inflate */))
    SocketDeflate_Inflater_reset (ws->compression.inflater);

  *output = buf;
  *output_len = total_written;

  return 0;
}

#else /* zlib-based implementation */
/*
 * ============================================================================
 * zlib Implementation (Fallback)
 * ============================================================================
 */

#include <zlib.h>

/** Default compression level */
#define WS_DEFLATE_LEVEL Z_DEFAULT_COMPRESSION

/** Default memory level for deflate */
#define WS_DEFLATE_MEMLEVEL 8

static int
init_zlib_stream (z_stream *strm, int window_bits, int is_deflate)
{
  assert (strm);
  strm->zalloc = Z_NULL;
  strm->zfree = Z_NULL;
  strm->opaque = Z_NULL;
  if (!is_deflate)
    {
      strm->avail_in = 0;
      strm->next_in = Z_NULL;
    }

  /* Use negative window bits to get raw deflate (no zlib header) */
  if (is_deflate)
    {
      return deflateInit2 (strm,
                           WS_DEFLATE_LEVEL,
                           Z_DEFLATED,
                           -window_bits,
                           WS_DEFLATE_MEMLEVEL,
                           Z_DEFAULT_STRATEGY);
    }
  else
    {
      return inflateInit2 (strm, -window_bits);
    }
}

static size_t
calculate_zlib_buffer_size (size_t input_len, int is_decompress)
{
  size_t buf_size;
  if (is_decompress)
    {
      if (!SocketSecurity_check_multiply (
              input_len, WS_DEFLATE_EXPANSION_FACTOR, &buf_size))
        {
          buf_size = WS_DEFLATE_OVERFLOW_FALLBACK_MAX;
        }
    }
  else
    {
      if (!SocketSecurity_check_add (
              input_len, WS_DEFLATE_HEADER_PADDING, &buf_size))
        {
          buf_size = input_len;
        }
    }
  if (buf_size < WS_DEFLATE_INITIAL_BUF_SIZE)
    buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;
  return buf_size;
}

static unsigned char *
grow_arena_buffer_zlib (Arena_T arena,
                        unsigned char *old_buf,
                        size_t used,
                        size_t new_size)
{
  unsigned char *new_buf;

  if (!SocketSecurity_check_size (new_size))
    return NULL;
  new_buf = ALLOC (arena, new_size);
  if (!new_buf)
    return NULL;

  if (used > 0)
    memcpy (new_buf, old_buf, used);

  return new_buf;
}

static void
remove_deflate_trailer_zlib (unsigned char *buf, size_t *len)
{
  assert (buf);
  assert (len);

  if (*len >= WS_DEFLATE_TRAILER_SIZE
      && memcmp (buf + *len - WS_DEFLATE_TRAILER_SIZE,
                 WS_DEFLATE_TRAILER,
                 WS_DEFLATE_TRAILER_SIZE)
             == 0)
    {
      *len -= WS_DEFLATE_TRAILER_SIZE;
    }
}

static unsigned char *
append_deflate_trailer_zlib (Arena_T arena,
                             const unsigned char *input,
                             size_t input_len,
                             size_t *output_len)
{
  unsigned char *buf;

  if (!SocketSecurity_check_add (
          input_len, WS_DEFLATE_TRAILER_SIZE, output_len))
    return NULL;

  buf = ALLOC (arena, *output_len);
  if (!buf)
    return NULL;

  memcpy (buf, input, input_len);
  memcpy (buf + input_len, WS_DEFLATE_TRAILER, WS_DEFLATE_TRAILER_SIZE);

  return buf;
}

static int
should_reset_zlib_context (const SocketWS_T ws, int is_deflate)
{
  assert (ws);

  int client_no = ws->compression.client_no_context_takeover;
  int server_no = ws->compression.server_no_context_takeover;

  if (ws->role == WS_ROLE_CLIENT)
    return is_deflate ? client_no : server_no;
  else
    return is_deflate ? server_no : client_no;
}

static int
try_grow_zlib_buffer (SocketWS_T ws,
                      z_stream *strm,
                      unsigned char **buf,
                      size_t *buf_size,
                      size_t total_out,
                      int is_decompress)
{
  size_t new_size;

  if (!SocketSecurity_check_multiply (
          *buf_size, WS_DEFLATE_BUF_GROWTH, &new_size))
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Buffer growth multiplication overflow");
      return -1;
    }

  if (is_decompress)
    {
      size_t max_allowed = ws->config.max_message_size;
      if (new_size > max_allowed)
        new_size = max_allowed;
      if (new_size <= *buf_size)
        {
          ws_set_error (
              ws, WS_ERROR_MESSAGE_TOO_LARGE, "Decompressed message too large");
          return -1;
        }
    }
  else
    {
      if (!SocketSecurity_check_size (new_size))
        {
          ws_set_error (ws,
                        WS_ERROR_COMPRESSION,
                        "Buffer size exceeds security limit: %zu",
                        new_size);
          return -1;
        }
    }

  unsigned char *new_buf
      = grow_arena_buffer_zlib (ws->arena, *buf, total_out, new_size);
  if (!new_buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to grow buffer");
      return -1;
    }

  *buf = new_buf;
  *buf_size = new_size;
  strm->next_out = *buf + total_out;

  size_t avail = *buf_size - total_out;
  if (avail > UINT_MAX)
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Buffer size %zu exceeds zlib limit %u",
                    avail,
                    UINT_MAX);
      return -1;
    }
  strm->avail_out = (uInt)avail;

  return 0;
}

static int
is_flush_complete (int flush_type, int ret, const z_stream *strm)
{
  if (flush_type == Z_FINISH && ret == Z_STREAM_END)
    return 1;
  if (flush_type == Z_SYNC_FLUSH && ret == Z_OK && strm->avail_in == 0)
    return 1;
  if (ret != Z_OK)
    return 1;
  return 0;
}

static int
compress_flush_phase (SocketWS_T ws,
                      z_stream *strm,
                      unsigned char **buf,
                      size_t *buf_size,
                      size_t *total_out,
                      int flush_type)
{
  int ret;

  while (1)
    {
      ret = deflate (strm, flush_type);

      if (ret == Z_STREAM_ERROR)
        {
          ws_set_error (
              ws, WS_ERROR_COMPRESSION, "deflate flush phase failed: %d", ret);
          return -1;
        }
      if (flush_type == Z_FINISH && ret != Z_OK && ret != Z_STREAM_END)
        {
          ws_set_error (
              ws, WS_ERROR_COMPRESSION, "deflate finish incomplete: %d", ret);
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      if (strm->avail_out == 0)
        {
          if (try_grow_zlib_buffer (
                  ws, strm, buf, buf_size, *total_out, 0 /* compress */)
              < 0)
            return -1;
        }

      if (is_flush_complete (flush_type, ret, strm))
        break;
    }

  *total_out = *buf_size - strm->avail_out;
  return 0;
}

static int
compress_loop (SocketWS_T ws,
               z_stream *strm,
               unsigned char **buf,
               size_t *buf_size,
               size_t *total_out)
{
  int ret;

  /* Data compression phase with Z_NO_FLUSH */
  while (strm->avail_in > 0)
    {
      ret = deflate (strm, Z_NO_FLUSH);
      if (ret == Z_STREAM_ERROR)
        {
          ws_set_error (
              ws, WS_ERROR_COMPRESSION, "deflate data phase failed: %d", ret);
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      int needs_growth = (strm->avail_out == 0 && strm->avail_in > 0);
      if (!needs_growth)
        continue;

      if (try_grow_zlib_buffer (
              ws, strm, buf, buf_size, *total_out, 0 /* compress */)
          < 0)
        return -1;
    }

  /* Flush phase */
  int flush_type = should_reset_zlib_context (ws, 1 /* deflate */)
                       ? Z_FINISH
                       : Z_SYNC_FLUSH;
  return compress_flush_phase (ws, strm, buf, buf_size, total_out, flush_type);
}

static int
decompress_loop (SocketWS_T ws,
                 z_stream *strm,
                 unsigned char **buf,
                 size_t *buf_size,
                 size_t *total_out)
{
  int ret;

  do
    {
      ret = inflate (strm, Z_SYNC_FLUSH);

      if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
          ws_set_error (ws,
                        WS_ERROR_COMPRESSION,
                        "inflate failed: %d (%s)",
                        ret,
                        strm->msg ? strm->msg : "unknown");
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      if (strm->avail_out != 0 || ret == Z_STREAM_END)
        continue;

      if (try_grow_zlib_buffer (
              ws, strm, buf, buf_size, *total_out, 1 /* decompress */)
          < 0)
        return -1;
    }
  while (strm->avail_in > 0 && ret != Z_STREAM_END);

  *total_out = *buf_size - strm->avail_out;

  if (strm->avail_in > 0)
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Incomplete decompression: remaining avail_in=%u",
                    (unsigned)strm->avail_in);
      return -1;
    }
  return 0;
}

static int
check_zlib_size_limit (SocketWS_T ws, size_t size, const char *type_name)
{
  if (size > UINT_MAX)
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "%s size %zu exceeds zlib limit %u",
                    type_name,
                    size,
                    UINT_MAX);
      return -1;
    }
  return 0;
}

int
ws_compression_init (SocketWS_T ws)
{
  int ret;
  int deflate_bits;
  int inflate_bits;

  assert (ws);

  memset (&ws->compression, 0, sizeof (ws->compression));

  /* Validate window bits from negotiation */
  deflate_bits = validate_and_store_window_bits (
      ws, ws->handshake.client_max_window_bits, "client_max_window_bits");
  if (deflate_bits < 0)
    return -1;

  inflate_bits = validate_and_store_window_bits (
      ws, ws->handshake.server_max_window_bits, "server_max_window_bits");
  if (inflate_bits < 0)
    return -1;

  /* Store settings */
  ws->compression.server_no_context_takeover
      = ws->handshake.server_no_context_takeover;
  ws->compression.client_no_context_takeover
      = ws->handshake.client_no_context_takeover;
  ws->compression.server_max_window_bits = inflate_bits;
  ws->compression.client_max_window_bits = deflate_bits;

  /* Initialize deflate stream */
  ret = init_zlib_stream (
      &ws->compression.deflate_stream, deflate_bits, 1 /* deflate */);
  if (ret != Z_OK)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "deflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.deflate_initialized = 1;

  /* Initialize inflate stream */
  ret = init_zlib_stream (
      &ws->compression.inflate_stream, inflate_bits, 0 /* inflate */);
  if (ret != Z_OK)
    {
      deflateEnd (&ws->compression.deflate_stream);
      ws->compression.deflate_initialized = 0;
      ws_set_error (ws, WS_ERROR_COMPRESSION, "inflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.inflate_initialized = 1;

  SocketLog_emitf (SOCKET_LOG_DEBUG,
                   SOCKET_LOG_COMPONENT,
                   "Compression initialized: deflate=%d bits, inflate=%d bits",
                   deflate_bits,
                   inflate_bits);

  return 0;
}

typedef int (*zlib_cleanup_fn) (z_stream *);

static void
cleanup_zlib_context (z_stream *strm, int *initialized, zlib_cleanup_fn cleanup)
{
  if (!*initialized)
    return;

  cleanup (strm);
  *initialized = 0;
}

void
ws_compression_free (SocketWS_T ws)
{
  assert (ws);

  static const zlib_cleanup_fn cleanup_fn[]
      = { [0] = inflateEnd, [1] = deflateEnd };

  struct
  {
    z_stream *strm;
    int *initialized;
    int is_deflate;
  } contexts[] = {
    { &ws->compression.deflate_stream,
      &ws->compression.deflate_initialized,
      1 },
    { &ws->compression.inflate_stream, &ws->compression.inflate_initialized, 0 }
  };

  for (size_t i = 0; i < sizeof (contexts) / sizeof (contexts[0]); i++)
    {
      cleanup_zlib_context (contexts[i].strm,
                            contexts[i].initialized,
                            cleanup_fn[contexts[i].is_deflate]);
    }
}

int
ws_compress_message (SocketWS_T ws,
                     const unsigned char *input,
                     size_t input_len,
                     unsigned char **output,
                     size_t *output_len)
{
  z_stream *strm;
  size_t total_out = 0;
  size_t buf_size;
  unsigned char *buf;

  assert (ws);
  assert (output);
  assert (output_len);

  if (!ws->compression.deflate_initialized)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Deflate not initialized");
      return -1;
    }

  strm = &ws->compression.deflate_stream;

  /* Allocate output buffer */
  buf_size = calculate_zlib_buffer_size (input_len, 0 /* compress */);
  if (!SocketSecurity_check_size (buf_size))
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Compress buffer size exceeds security limit: %zu",
                    buf_size);
      return -1;
    }
  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Failed to allocate output buffer");
      return -1;
    }

  /* Set up zlib stream */
  if (check_zlib_size_limit (ws, input_len, "Input") < 0)
    return -1;
  if (check_zlib_size_limit (ws, buf_size, "Buffer") < 0)
    return -1;

  strm->next_in = (Bytef *)input;
  strm->avail_in = (uInt)input_len;
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  /* Compress with Z_SYNC_FLUSH */
  if (compress_loop (ws, strm, &buf, &buf_size, &total_out) < 0)
    return -1;

  /* Remove RFC 7692 trailer */
  remove_deflate_trailer_zlib (buf, &total_out);

  /* Reset context if no context takeover */
  if (should_reset_zlib_context (ws, 1 /* deflate */))
    deflateReset (strm);

  *output = buf;
  *output_len = total_out;

  return 0;
}

int
ws_decompress_message (SocketWS_T ws,
                       const unsigned char *input,
                       size_t input_len,
                       unsigned char **output,
                       size_t *output_len)
{
  z_stream *strm;
  size_t total_out = 0;
  size_t buf_size;
  unsigned char *buf;
  unsigned char *input_with_trailer;
  size_t input_with_trailer_len;

  assert (ws);
  assert (output);
  assert (output_len);

  if (!ws->compression.inflate_initialized)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Inflate not initialized");
      return -1;
    }

  strm = &ws->compression.inflate_stream;

  /* Append RFC 7692 trailer */
  input_with_trailer = append_deflate_trailer_zlib (
      ws->arena, input, input_len, &input_with_trailer_len);
  if (!input_with_trailer)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to append trailer");
      return -1;
    }

  /* Allocate output buffer */
  buf_size = calculate_zlib_buffer_size (input_len, 1 /* decompress */);
  if (!SocketSecurity_check_size (buf_size))
    {
      ws_set_error (ws,
                    WS_ERROR_COMPRESSION,
                    "Decompress buffer size exceeds security limit: %zu",
                    buf_size);
      return -1;
    }

  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (
          ws, WS_ERROR_COMPRESSION, "Failed to allocate output buffer");
      return -1;
    }

  /* Set up zlib stream */
  if (check_zlib_size_limit (ws, input_with_trailer_len, "Input") < 0)
    return -1;
  if (check_zlib_size_limit (ws, buf_size, "Buffer") < 0)
    return -1;

  strm->next_in = (unsigned char *)input_with_trailer;
  strm->avail_in = (uInt)input_with_trailer_len;
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  /* Decompress */
  if (decompress_loop (ws, strm, &buf, &buf_size, &total_out) < 0)
    return -1;

  /* Check decompressed size against limit */
  if (total_out > ws->config.max_message_size)
    {
      ws_set_error (ws,
                    WS_ERROR_MESSAGE_TOO_LARGE,
                    "Decompressed message exceeds max size: %zu > %zu",
                    total_out,
                    ws->config.max_message_size);
      return -1;
    }

  /* Reset context if no context takeover */
  if (should_reset_zlib_context (ws, 0 /* inflate */))
    inflateReset (strm);

  *output = buf;
  *output_len = total_out;

  return 0;
}

#endif /* SOCKETWS_HAS_NATIVE_DEFLATE */

#endif /* SOCKETWS_HAS_DEFLATE */
