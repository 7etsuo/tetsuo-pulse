/**
 * SocketWS-deflate.c - WebSocket Compression Extension (RFC 7692)
 *
 * Part of the Socket Library
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
 * Pattern follows SocketHTTP1-compress.c for consistency.
 */

#include "socket/SocketWS-private.h"

#ifdef SOCKETWS_HAS_DEFLATE

#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "core/Arena.h"
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Default compression level */
#define WS_DEFLATE_LEVEL Z_DEFAULT_COMPRESSION

/** Default memory level for deflate */
#define WS_DEFLATE_MEMLEVEL 8

/** Initial buffer size for compression */
#define WS_DEFLATE_INITIAL_BUF_SIZE (16 * 1024)

/** Growth factor for buffer reallocation */
#define WS_DEFLATE_BUF_GROWTH 2

/**
 * RFC 7692: The trailer bytes (0x00 0x00 0xff 0xff) MUST be removed
 * from the compressed data before sending, and added back on receiving.
 */
static const unsigned char WS_DEFLATE_TRAILER[4] = { 0x00, 0x00, 0xFF, 0xFF };

/* ============================================================================
 * Initialization
 * ============================================================================ */

/**
 * ws_compression_init - Initialize compression context
 * @ws: WebSocket context
 *
 * Initializes zlib deflate and inflate streams with negotiated parameters.
 *
 * Returns: 0 on success, -1 on error
 */
int
ws_compression_init (SocketWS_T ws)
{
  int ret;
  int deflate_window_bits;
  int inflate_window_bits;

  assert (ws);

  memset (&ws->compression, 0, sizeof (ws->compression));

  /* Determine window bits based on negotiation */
  deflate_window_bits = ws->handshake.client_max_window_bits;
  if (deflate_window_bits < 8 || deflate_window_bits > 15)
    deflate_window_bits = SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;

  inflate_window_bits = ws->handshake.server_max_window_bits;
  if (inflate_window_bits < 8 || inflate_window_bits > 15)
    inflate_window_bits = SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;

  /* Store settings */
  ws->compression.server_no_context_takeover
      = ws->handshake.server_no_context_takeover;
  ws->compression.client_no_context_takeover
      = ws->handshake.client_no_context_takeover;
  ws->compression.server_max_window_bits = inflate_window_bits;
  ws->compression.client_max_window_bits = deflate_window_bits;

  /* Initialize deflate stream
   * Use negative window bits to get raw deflate (no zlib header) */
  ws->compression.deflate_stream.zalloc = Z_NULL;
  ws->compression.deflate_stream.zfree = Z_NULL;
  ws->compression.deflate_stream.opaque = Z_NULL;

  ret = deflateInit2 (&ws->compression.deflate_stream, WS_DEFLATE_LEVEL,
                      Z_DEFLATED,
                      -deflate_window_bits, /* Negative = raw deflate */
                      WS_DEFLATE_MEMLEVEL, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION, "deflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.deflate_initialized = 1;

  /* Initialize inflate stream */
  ws->compression.inflate_stream.zalloc = Z_NULL;
  ws->compression.inflate_stream.zfree = Z_NULL;
  ws->compression.inflate_stream.opaque = Z_NULL;
  ws->compression.inflate_stream.avail_in = 0;
  ws->compression.inflate_stream.next_in = Z_NULL;

  ret = inflateInit2 (&ws->compression.inflate_stream,
                      -inflate_window_bits); /* Negative = raw deflate */
  if (ret != Z_OK)
    {
      deflateEnd (&ws->compression.deflate_stream);
      ws->compression.deflate_initialized = 0;
      ws_set_error (ws, WS_ERROR_COMPRESSION, "inflateInit2 failed: %d", ret);
      return -1;
    }
  ws->compression.inflate_initialized = 1;

  /* Allocate temporary buffers */
  ws->compression.deflate_buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;
  ws->compression.deflate_buf
      = ALLOC (ws->arena, ws->compression.deflate_buf_size);
  if (!ws->compression.deflate_buf)
    {
      ws_compression_free (ws);
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate deflate buffer");
      return -1;
    }

  ws->compression.inflate_buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;
  ws->compression.inflate_buf
      = ALLOC (ws->arena, ws->compression.inflate_buf_size);
  if (!ws->compression.inflate_buf)
    {
      ws_compression_free (ws);
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate inflate buffer");
      return -1;
    }

  SocketLog_emit (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                  "Compression initialized: deflate=%d bits, inflate=%d bits",
                  deflate_window_bits, inflate_window_bits);

  return 0;
}

/**
 * ws_compression_free - Free compression context
 * @ws: WebSocket context
 */
void
ws_compression_free (SocketWS_T ws)
{
  assert (ws);

  if (ws->compression.deflate_initialized)
    {
      deflateEnd (&ws->compression.deflate_stream);
      ws->compression.deflate_initialized = 0;
    }

  if (ws->compression.inflate_initialized)
    {
      inflateEnd (&ws->compression.inflate_stream);
      ws->compression.inflate_initialized = 0;
    }

  /* Buffers are arena-allocated, no need to free */
  ws->compression.deflate_buf = NULL;
  ws->compression.inflate_buf = NULL;
}

/* ============================================================================
 * Compression
 * ============================================================================ */

/**
 * ws_compress_message - Compress message data
 * @ws: WebSocket context
 * @input: Input data
 * @input_len: Input length
 * @output: Output buffer (arena allocated)
 * @output_len: Output length
 *
 * Compresses data using DEFLATE and removes the trailing 4 bytes
 * (0x00 0x00 0xFF 0xFF) per RFC 7692.
 *
 * Returns: 0 on success, -1 on error
 */
int
ws_compress_message (SocketWS_T ws, const unsigned char *input,
                     size_t input_len, unsigned char **output,
                     size_t *output_len)
{
  z_stream *strm;
  int ret;
  size_t total_out;
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

  /* Calculate initial buffer size (compression may expand small data) */
  buf_size = input_len + 64;
  if (buf_size < WS_DEFLATE_INITIAL_BUF_SIZE)
    buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;

  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate output buffer");
      return -1;
    }

  /* Set up input */
  strm->next_in = (Bytef *)input;
  strm->avail_in = (uInt)input_len;

  /* Set up output */
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  total_out = 0;

  /* Compress with Z_SYNC_FLUSH to produce the required trailer */
  do
    {
      ret = deflate (strm, Z_SYNC_FLUSH);
      if (ret == Z_STREAM_ERROR)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION, "deflate failed: %d", ret);
          return -1;
        }

      total_out = buf_size - strm->avail_out;

      /* Grow buffer if needed */
      if (strm->avail_out == 0 && strm->avail_in > 0)
        {
          size_t new_size = buf_size * WS_DEFLATE_BUF_GROWTH;
          unsigned char *new_buf = ALLOC (ws->arena, new_size);
          if (!new_buf)
            {
              ws_set_error (ws, WS_ERROR_COMPRESSION,
                            "Failed to grow output buffer");
              return -1;
            }
          memcpy (new_buf, buf, total_out);
          buf = new_buf;
          buf_size = new_size;
          strm->next_out = buf + total_out;
          strm->avail_out = (uInt)(buf_size - total_out);
        }
    }
  while (strm->avail_in > 0);

  /* Update total output */
  total_out = buf_size - strm->avail_out;

  /* Remove trailing 0x00 0x00 0xFF 0xFF per RFC 7692 */
  if (total_out >= 4
      && memcmp (buf + total_out - 4, WS_DEFLATE_TRAILER, 4) == 0)
    {
      total_out -= 4;
    }

  /* Reset deflate state if no context takeover */
  if (ws->role == WS_ROLE_CLIENT)
    {
      if (ws->compression.client_no_context_takeover)
        deflateReset (strm);
    }
  else
    {
      if (ws->compression.server_no_context_takeover)
        deflateReset (strm);
    }

  *output = buf;
  *output_len = total_out;

  return 0;
}

/* ============================================================================
 * Decompression
 * ============================================================================ */

/**
 * ws_decompress_message - Decompress message data
 * @ws: WebSocket context
 * @input: Compressed input
 * @input_len: Input length
 * @output: Output buffer (arena allocated)
 * @output_len: Output length
 *
 * Appends the trailing 4 bytes (0x00 0x00 0xFF 0xFF) before decompression
 * per RFC 7692.
 *
 * Returns: 0 on success, -1 on error
 */
int
ws_decompress_message (SocketWS_T ws, const unsigned char *input,
                       size_t input_len, unsigned char **output,
                       size_t *output_len)
{
  z_stream *strm;
  int ret;
  size_t total_out;
  size_t buf_size;
  unsigned char *buf;
  unsigned char *input_with_trailer = NULL;
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

  /* Append trailer per RFC 7692 */
  input_with_trailer_len = input_len + 4;
  input_with_trailer = ALLOC (ws->arena, input_with_trailer_len);
  if (!input_with_trailer)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate input buffer");
      return -1;
    }
  memcpy (input_with_trailer, input, input_len);
  memcpy (input_with_trailer + input_len, WS_DEFLATE_TRAILER, 4);

  /* Estimate output size (decompression typically expands) */
  buf_size = input_len * 4;
  if (buf_size < WS_DEFLATE_INITIAL_BUF_SIZE)
    buf_size = WS_DEFLATE_INITIAL_BUF_SIZE;

  buf = ALLOC (ws->arena, buf_size);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_COMPRESSION,
                    "Failed to allocate output buffer");
      return -1;
    }

  /* Set up input */
  strm->next_in = input_with_trailer;
  strm->avail_in = (uInt)input_with_trailer_len;

  /* Set up output */
  strm->next_out = buf;
  strm->avail_out = (uInt)buf_size;

  total_out = 0;

  /* Decompress */
  do
    {
      ret = inflate (strm, Z_SYNC_FLUSH);

      if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
          ws_set_error (ws, WS_ERROR_COMPRESSION, "inflate failed: %d (%s)",
                        ret, strm->msg ? strm->msg : "unknown");
          return -1;
        }

      total_out = buf_size - strm->avail_out;

      /* Grow buffer if needed */
      if (strm->avail_out == 0 && ret != Z_STREAM_END)
        {
          size_t new_size = buf_size * WS_DEFLATE_BUF_GROWTH;

          /* Enforce max message size */
          if (new_size > ws->config.max_message_size)
            new_size = ws->config.max_message_size;

          if (new_size <= buf_size)
            {
              ws_set_error (ws, WS_ERROR_MESSAGE_TOO_LARGE,
                            "Decompressed message too large");
              return -1;
            }

          unsigned char *new_buf = ALLOC (ws->arena, new_size);
          if (!new_buf)
            {
              ws_set_error (ws, WS_ERROR_COMPRESSION,
                            "Failed to grow output buffer");
              return -1;
            }
          memcpy (new_buf, buf, total_out);
          buf = new_buf;
          buf_size = new_size;
          strm->next_out = buf + total_out;
          strm->avail_out = (uInt)(buf_size - total_out);
        }
    }
  while (strm->avail_in > 0 && ret != Z_STREAM_END);

  /* Update total output */
  total_out = buf_size - strm->avail_out;

  /* Reset inflate state if no context takeover */
  if (ws->role == WS_ROLE_CLIENT)
    {
      if (ws->compression.server_no_context_takeover)
        inflateReset (strm);
    }
  else
    {
      if (ws->compression.client_no_context_takeover)
        inflateReset (strm);
    }

  *output = buf;
  *output_len = total_out;

  return 0;
}

#endif /* SOCKETWS_HAS_DEFLATE */

