/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketWS-deflate.c - WebSocket Compression Extension (RFC 7692)
 *
 * Implements permessage-deflate compression extension for WebSocket.
 * Only compiled when SOCKETWS_HAS_DEFLATE is defined (requires zlib).
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
 * - BFINAL=1 block ensured with Z_FINISH when no context takeover
 * - Trailer hack used for zlib compatibility; app responsible for BREACH
 *   mitigation (random padding)
 */

#include "socket/SocketWS-private.h"

#ifdef SOCKETWS_HAS_DEFLATE

#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"

/** Default compression level */
#define WS_DEFLATE_LEVEL Z_DEFAULT_COMPRESSION

/** Default memory level for deflate */
#define WS_DEFLATE_MEMLEVEL 8

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
init_zlib_stream (z_stream *strm, int window_bits, int is_deflate)
{
  assert (strm);
  strm->zalloc = Z_NULL;
  strm->zfree = Z_NULL;
  strm->opaque = Z_NULL;
  if (!is_deflate) {
    strm->avail_in = 0;
    strm->next_in = Z_NULL;
  }

  /* Use negative window bits to get raw deflate (no zlib header) */
  if (is_deflate) {
    return deflateInit2 (strm, WS_DEFLATE_LEVEL, Z_DEFLATED, -window_bits,
                         WS_DEFLATE_MEMLEVEL, Z_DEFAULT_STRATEGY);
  } else {
    return inflateInit2 (strm, -window_bits);
  }
}



static size_t
calculate_zlib_buffer_size (size_t input_len, int is_decompress)
{
  size_t buf_size;
  if (is_decompress) {
    if (!SocketSecurity_check_multiply (input_len, WS_DEFLATE_EXPANSION_FACTOR,
                                        &buf_size)) {
      buf_size = SIZE_MAX / 2; // fallback on overflow
    }
  } else {
    if (!SocketSecurity_check_add (input_len, WS_DEFLATE_HEADER_PADDING,
                                   &buf_size)) {
      buf_size = input_len; // fallback
    }
  }
  if (buf_size < WS_DEFLATE_INITIAL_BUF_SIZE)
    buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;
  return buf_size;
}



static unsigned char *
grow_arena_buffer (Arena_T arena, unsigned char *old_buf, size_t old_size,
                   size_t used, size_t new_size)
{
  unsigned char *new_buf;

  (void)old_size; /* Arena doesn't support realloc, we allocate fresh */

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
      && memcmp (buf + *len - WS_DEFLATE_TRAILER_SIZE, WS_DEFLATE_TRAILER,
                 WS_DEFLATE_TRAILER_SIZE)
             == 0)
    {
      *len -= WS_DEFLATE_TRAILER_SIZE;
    }
}

static unsigned char *
append_deflate_trailer (Arena_T arena, const unsigned char *input,
                        size_t input_len, size_t *output_len)
{
  unsigned char *buf;

  *output_len = input_len + WS_DEFLATE_TRAILER_SIZE;
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

  if (ws->role == WS_ROLE_CLIENT) {
    return is_deflate ? client_no : server_no;
  } else {
    return is_deflate ? server_no : client_no;
  }
}



static int
try_grow_zlib_buffer (SocketWS_T ws, z_stream *strm, unsigned char **buf,
                      size_t *buf_size, size_t total_out, int is_decompress)
{
  size_t new_size;

  if (!SocketSecurity_check_multiply (*buf_size, WS_DEFLATE_BUF_GROWTH,
                                      &new_size))
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Buffer growth multiplication overflow");
      return -1;
    }

  if (is_decompress)
    {
      size_t max_allowed = ws->config.max_message_size;
      if (new_size > max_allowed)
        new_size = max_allowed;
      if (new_size <= *buf_size)
        {
          ws_set_error (ws, WS_ERROR_MESSAGE_TOO_LARGE,
                        "Decompressed message too large");
          return -1;
        }
    }
  else
    {
      if (!SocketSecurity_check_size (new_size))
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION,
                        "Buffer size exceeds security limit: %zu", new_size);
          return -1;
        }
    }

  unsigned char *new_buf
      = grow_arena_buffer (ws->arena, *buf, *buf_size, total_out, new_size);
  if (!new_buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to grow buffer");
      return -1;
    }

  *buf = new_buf;
  *buf_size = new_size;
  strm->next_out = *buf + total_out;
  strm->avail_out = (uInt)(*buf_size - total_out);

  return 0;
}



static int
compress_loop (SocketWS_T ws, z_stream *strm, unsigned char **buf,
               size_t *buf_size, size_t *total_out)
{
  int ret;

  /* Data compression phase with Z_NO_FLUSH */
  do
    {
      ret = deflate (strm, Z_NO_FLUSH);
      if (ret == Z_STREAM_ERROR)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION,
                        "deflate data phase failed: %d", ret);
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      /* Grow buffer if needed */
      if (strm->avail_out == 0 && strm->avail_in > 0)
        {
          if (try_grow_zlib_buffer (ws, strm, buf, buf_size, *total_out, 0 /* compress */)
              < 0)
            return -1;
        }
    }
  while (strm->avail_in > 0);

  /* Flush phase to output remaining data and end block for BFINAL=1 */
  int flush_type = should_reset_zlib_context (ws, 1 /* deflate */) ? Z_FINISH : Z_SYNC_FLUSH;
  int finished = 0;

  while (!finished)
    {
      ret = deflate (strm, flush_type);
      if (ret == Z_STREAM_ERROR)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION,
                        "deflate flush phase failed: %d", ret);
          return -1;
        }
      if (flush_type == Z_FINISH && ret != Z_OK && ret != Z_STREAM_END)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION,
                        "deflate finish incomplete: %d", ret);
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      /* Grow buffer if needed during flush */
      if (strm->avail_out == 0)
        {
          if (try_grow_zlib_buffer (ws, strm, buf, buf_size, *total_out, 0 /* compress */)
              < 0)
            return -1;
        }

      if (flush_type == Z_FINISH && ret == Z_STREAM_END)
        finished = 1;
      else if (flush_type == Z_SYNC_FLUSH && ret == Z_OK
               && strm->avail_in == 0)
        finished = 1;
      else if (ret != Z_OK)
        finished = 1;
    }

  *total_out = *buf_size - strm->avail_out;
  return 0;
}



static int
decompress_loop (SocketWS_T ws, z_stream *strm, unsigned char **buf,
                 size_t *buf_size, size_t *total_out)
{
  int ret;

  do
    {
      ret = inflate (strm, Z_SYNC_FLUSH);

      if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION, "inflate failed: %d (%s)",
                        ret, strm->msg ? strm->msg : "unknown");
          return -1;
        }

      *total_out = *buf_size - strm->avail_out;

      /* Grow buffer if needed */
      if (strm->avail_out == 0 && ret != Z_STREAM_END)
        {
          if (try_grow_zlib_buffer (ws, strm, buf, buf_size, *total_out, 1 /* decompress */)
              < 0)
            return -1;
        }
    }
  while (strm->avail_in > 0 && ret != Z_STREAM_END);

  *total_out = *buf_size - strm->avail_out;

  /* Ensure all input consumed (trailer processed) */
  if (strm->avail_in > 0)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Incomplete decompression: remaining avail_in=%u",
                    (unsigned)strm->avail_in);
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
  deflate_bits = validate_window_bits (ws->handshake.client_max_window_bits);
  if (deflate_bits < 0)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Invalid client_max_window_bits: %d",
                    ws->handshake.client_max_window_bits);
      return -1;
    }
  inflate_bits = validate_window_bits (ws->handshake.server_max_window_bits);
  if (inflate_bits < 0)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Invalid server_max_window_bits: %d",
                    ws->handshake.server_max_window_bits);
      return -1;
    }

  /* Store settings */
  ws->compression.server_no_context_takeover
      = ws->handshake.server_no_context_takeover;
  ws->compression.client_no_context_takeover
      = ws->handshake.client_no_context_takeover;
  ws->compression.server_max_window_bits = inflate_bits;
  ws->compression.client_max_window_bits = deflate_bits;

  /* Initialize deflate stream */
  ret = init_zlib_stream (&ws->compression.deflate_stream, deflate_bits, 1 /* deflate */);
  if (ret != Z_OK)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "deflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.deflate_initialized = 1;

  /* Initialize inflate stream */
  ret = init_zlib_stream (&ws->compression.inflate_stream, inflate_bits, 0 /* inflate */);
  if (ret != Z_OK)
    {
      deflateEnd (&ws->compression.deflate_stream);
      ws->compression.deflate_initialized = 0;
      ws_set_error (ws, WS_ERROR_COMPRESSION, "inflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.inflate_initialized = 1;

  /* Temporary buffers removed as unused in full-message ops; add back for
   * incremental if needed */

  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                   "Compression initialized: deflate=%d bits, inflate=%d bits",
                   deflate_bits, inflate_bits);

  return 0;
}

void
ws_compression_free (SocketWS_T ws)
{
  assert (ws);

  struct {
    z_stream *strm;
    int *initialized;
    int is_deflate;
  } contexts[] = {
    { &ws->compression.deflate_stream, &ws->compression.deflate_initialized, 1 },
    { &ws->compression.inflate_stream, &ws->compression.inflate_initialized, 0 }
  };

  for (size_t i = 0; i < sizeof(contexts)/sizeof(contexts[0]); i++) {
    if (*contexts[i].initialized) {
      if (contexts[i].is_deflate) {
        deflateEnd (contexts[i].strm);
      } else {
        inflateEnd (contexts[i].strm);
      }
      *contexts[i].initialized = 0;
    }
  }

  /* Buffers not allocated; no action needed */
}

int
ws_compress_message (SocketWS_T ws, const unsigned char *input,
                     size_t input_len, unsigned char **output,
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
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Compress buffer size exceeds security limit: %zu",
                    buf_size);
      return -1;
    }
  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate output buffer");
      return -1;
    }

  /* Set up zlib stream */
  strm->next_in = (Bytef *)input;
  strm->avail_in = (uInt)input_len;
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  /* Compress with Z_SYNC_FLUSH */
  if (compress_loop (ws, strm, &buf, &buf_size, &total_out) < 0)
    return -1;

  /* Remove RFC 7692 trailer */
  remove_deflate_trailer (buf, &total_out);

  /* Reset context if no context takeover */
  if (should_reset_zlib_context (ws, 1 /* deflate */))
    deflateReset (strm);

  *output = buf;
  *output_len = total_out;

  return 0;
}

int
ws_decompress_message (SocketWS_T ws, const unsigned char *input,
                       size_t input_len, unsigned char **output,
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
  size_t trailer_len;
  if (!SocketSecurity_check_add (input_len, WS_DEFLATE_TRAILER_SIZE,
                                 &trailer_len)
      || !SocketSecurity_check_size (trailer_len))
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Trailer size invalid/overflow: input_len=%zu", input_len);
      return -1;
    }
  input_with_trailer = append_deflate_trailer (ws->arena, input, input_len,
                                               &input_with_trailer_len);
  if (!input_with_trailer || input_with_trailer_len != trailer_len)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "Failed to append trailer");
      return -1;
    }

  /* Allocate output buffer */
  buf_size = calculate_zlib_buffer_size (input_len, 1 /* decompress */);
  if (!SocketSecurity_check_size (buf_size))
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Decompress buffer size exceeds security limit: %zu",
                    buf_size);
      return -1;
    }
  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate output buffer");
      return -1;
    }

  /* Set up zlib stream */
  strm->next_in = input_with_trailer;
  strm->avail_in = (uInt)input_with_trailer_len;
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  /* Decompress */
  if (decompress_loop (ws, strm, &buf, &buf_size, &total_out) < 0)
    return -1;

  /* Check decompressed size against limit to prevent bombs */
  if (total_out > ws->config.max_message_size)
    {
      ws_set_error (ws, WS_ERROR_MESSAGE_TOO_LARGE,
                    "Decompressed message exceeds max size: %zu > %zu",
                    total_out, ws->config.max_message_size);
      return -1;
    }

  /* Reset context if no context takeover */
  if (should_reset_zlib_context (ws, 0 /* inflate */))
    inflateReset (strm);

  *output = buf;
  *output_len = total_out;

  return 0;
}

#endif /* SOCKETWS_HAS_DEFLATE */
