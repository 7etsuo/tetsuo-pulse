/**
 * SocketHTTP1-compress.c - HTTP/1.1 Content Encoding Support
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements RFC 9110 Section 8.4 content coding:
 * - gzip (RFC 1952) via zlib
 * - deflate (RFC 1951) via zlib
 * - br (Brotli, RFC 7932) via libbrotli (optional)
 *
 * This file is only compiled when ENABLE_HTTP_COMPRESSION is ON.
 *
 * Design note: This module uses return codes (not exceptions) for error
 * handling, matching the underlying zlib/brotli library patterns.
 */

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"

#ifdef SOCKETHTTP1_HAS_COMPRESSION

#include <assert.h>
#include <limits.h>



#ifdef SOCKETHTTP1_HAS_ZLIB
#include <zlib.h>
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

/* ============================================================================
 * Compression Constants
 * ============================================================================ */

#ifdef SOCKETHTTP1_HAS_ZLIB

/** zlib window bits for gzip format (15 + 16 = 31 for auto header detection) */
#define ZLIB_WINDOW_BITS_GZIP 31

/** zlib window bits for raw deflate (negative disables header) */
#define ZLIB_WINDOW_BITS_DEFLATE (-15)

/** zlib default memory level (1-9, 8 is default) */
#define ZLIB_MEM_LEVEL_DEFAULT 8

/** zlib compression level: fastest */
#define ZLIB_LEVEL_FAST 1

/** zlib compression level: best compression */
#define ZLIB_LEVEL_BEST 9

#endif /* SOCKETHTTP1_HAS_ZLIB */

#ifdef SOCKETHTTP1_HAS_BROTLI

/** Brotli quality: fastest (1-11 scale) */
#define BROTLI_QUALITY_FAST 1

/** Brotli quality: balanced (default) */
#define BROTLI_QUALITY_DEFAULT 6

/** Brotli quality: best compression */
#define BROTLI_QUALITY_BEST 11

#endif /* SOCKETHTTP1_HAS_BROTLI */

/* ============================================================================
 * Decoder Structure
 * ============================================================================ */

struct SocketHTTP1_Decoder
{
  SocketHTTP_Coding coding;
  Arena_T arena;

  union
  {
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib;
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliDecoderState *brotli;
#endif
    int dummy; /* Placeholder if no compression available */
  } state;

  int initialized;
  int finished;
};

/* ============================================================================
 * Encoder Structure
 * ============================================================================ */

struct SocketHTTP1_Encoder
{
  SocketHTTP_Coding coding;
  Arena_T arena;
  SocketHTTP1_CompressLevel level;

  union
  {
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib;
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliEncoderState *brotli;
#endif
    int dummy;
  } state;

  int initialized;
  int finished;
};

/* ============================================================================
 * Static Helper Functions
 * ============================================================================ */

/**
 * is_supported_coding - Check if coding is supported for compression
 * @coding: Content coding to check
 *
 * Returns: 1 if supported, 0 otherwise
 */
static int
is_supported_coding (SocketHTTP_Coding coding)
{
#ifdef SOCKETHTTP1_HAS_ZLIB
  if (coding == HTTP_CODING_GZIP || coding == HTTP_CODING_DEFLATE)
    return 1;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
  if (coding == HTTP_CODING_BR)
    return 1;
#endif

  return 0;
}

#ifdef SOCKETHTTP1_HAS_ZLIB

/**
 * get_zlib_window_bits - Get window bits for coding type
 * @coding: GZIP or DEFLATE
 *
 * Returns: Window bits value for inflateInit2/deflateInit2
 */
static int
get_zlib_window_bits (SocketHTTP_Coding coding)
{
  return (coding == HTTP_CODING_GZIP) ? ZLIB_WINDOW_BITS_GZIP
                                      : ZLIB_WINDOW_BITS_DEFLATE;
}

/**
 * map_compress_level_to_zlib - Map our level enum to zlib level
 * @level: SocketHTTP1_CompressLevel
 *
 * Returns: zlib compression level (1-9 or Z_DEFAULT_COMPRESSION)
 */
static int
map_compress_level_to_zlib (SocketHTTP1_CompressLevel level)
{
  switch (level)
    {
    case HTTP1_COMPRESS_FAST:
      return ZLIB_LEVEL_FAST;
    case HTTP1_COMPRESS_BEST:
      return ZLIB_LEVEL_BEST;
    default:
      return Z_DEFAULT_COMPRESSION;
    }
}

/**
 * zlib_set_input - Set zlib stream input buffer
 * @s: z_stream pointer
 * @input: Input buffer pointer
 * @avail_in: Number of input bytes available
 *
 * Sets next_in and avail_in safely.
 * Thread-safe: No (modifies stream)
 */
static void
zlib_set_input (z_stream *s, Bytef *input, uInt avail_in)
{
  s->next_in = input;
  s->avail_in = avail_in;
}

/**
 * zlib_set_output - Set zlib stream output buffer
 * @s: z_stream pointer
 * @output: Output buffer pointer
 * @avail_out: Output buffer space available
 *
 * Sets next_out and avail_out safely.
 * Thread-safe: No (modifies stream)
 */
static void
zlib_set_output (z_stream *s, Bytef *output, uInt avail_out)
{
  s->next_out = output;
  s->avail_out = avail_out;
}

/**
 * init_zlib_decoder - Initialize zlib inflate stream
 * @decoder: Decoder instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_zlib_decoder (SocketHTTP1_Decoder_T decoder)
{
  int window_bits;

  window_bits = get_zlib_window_bits (decoder->coding);

  if (inflateInit2 (&decoder->state.zlib, window_bits) != Z_OK)
    return 0;

  decoder->initialized = 1;
  return 1;
}

/**
 * init_zlib_encoder - Initialize zlib deflate stream
 * @encoder: Encoder instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_zlib_encoder (SocketHTTP1_Encoder_T encoder)
{
  int zlib_level;
  int window_bits;

  zlib_level = map_compress_level_to_zlib (encoder->level);
  window_bits = get_zlib_window_bits (encoder->coding);

  if (deflateInit2 (&encoder->state.zlib, zlib_level, Z_DEFLATED, window_bits,
                    ZLIB_MEM_LEVEL_DEFAULT, Z_DEFAULT_STRATEGY)
      != Z_OK)
    return 0;

  encoder->initialized = 1;
  return 1;
}

/**
 * cleanup_zlib_decoder - Clean up zlib inflate stream
 * @decoder: Decoder instance
 */
static void
cleanup_zlib_decoder (SocketHTTP1_Decoder_T decoder)
{
  inflateEnd (&decoder->state.zlib);
}

/**
 * cleanup_zlib_encoder - Clean up zlib deflate stream
 * @encoder: Encoder instance
 */
static void
cleanup_zlib_encoder (SocketHTTP1_Encoder_T encoder)
{
  deflateEnd (&encoder->state.zlib);
}

/**
 * decode_zlib - Decode data using zlib inflate
 * @decoder: Decoder instance
 * @input: Input buffer
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Output buffer
 * @output_len: Output buffer size
 * @written: Output - bytes written
 *
 * Returns: HTTP1_OK, HTTP1_INCOMPLETE, or HTTP1_ERROR
 */
static SocketHTTP1_Result
decode_zlib (SocketHTTP1_Decoder_T decoder, const unsigned char *input,
             size_t input_len, size_t *consumed, unsigned char *output,
             size_t output_len, size_t *written)
{
  int ret;

  zlib_set_input (&decoder->state.zlib, (Bytef *)input, (uInt)input_len);
  zlib_set_output (&decoder->state.zlib, output, (uInt)output_len);

  ret = inflate (&decoder->state.zlib, Z_NO_FLUSH);

  *consumed = input_len - decoder->state.zlib.avail_in;
  *written = output_len - decoder->state.zlib.avail_out;

  if (ret == Z_STREAM_END)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return HTTP1_INCOMPLETE;

  return HTTP1_ERROR;
}

/**
 * finish_zlib_decode - Finish zlib decoding
 * @decoder: Decoder instance
 * @output: Output buffer
 * @output_len: Buffer size
 * @written: Output - bytes written
 *
 * Returns: HTTP1_OK, HTTP1_INCOMPLETE, or HTTP1_ERROR
 */
static SocketHTTP1_Result
finish_zlib_decode (SocketHTTP1_Decoder_T decoder, unsigned char *output,
                    size_t output_len, size_t *written)
{
  int ret;

  decoder->state.zlib.next_in = NULL;
  decoder->state.zlib.avail_in = 0;
  zlib_set_output (&decoder->state.zlib, output, (uInt)output_len);

  ret = inflate (&decoder->state.zlib, Z_FINISH);

  *written = output_len - decoder->state.zlib.avail_out;

  if (ret == Z_STREAM_END)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return HTTP1_INCOMPLETE;

  return HTTP1_ERROR;
}

/**
 * encode_zlib - Encode data using zlib deflate
 * @encoder: Encoder instance
 * @input: Input buffer
 * @input_len: Input length
 * @output: Output buffer
 * @output_len: Buffer size
 * @flush: Flush mode
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
encode_zlib (SocketHTTP1_Encoder_T encoder, const unsigned char *input,
             size_t input_len, unsigned char *output, size_t output_len,
             int flush)
{
  int ret;
  int zlib_flush;

  zlib_flush = flush ? Z_SYNC_FLUSH : Z_NO_FLUSH;

  zlib_set_input (&encoder->state.zlib, (Bytef *)input, (uInt)input_len);
  zlib_set_output (&encoder->state.zlib, output, (uInt)output_len);

  ret = deflate (&encoder->state.zlib, zlib_flush);

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return (ssize_t)(output_len - encoder->state.zlib.avail_out);

  return -1;
}

/**
 * finish_zlib_encode - Finish zlib encoding
 * @encoder: Encoder instance
 * @output: Output buffer
 * @output_len: Buffer size
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
finish_zlib_encode (SocketHTTP1_Encoder_T encoder, unsigned char *output,
                    size_t output_len)
{
  int ret;
  size_t produced;

  encoder->state.zlib.next_in = NULL;
  encoder->state.zlib.avail_in = 0;
  zlib_set_output (&encoder->state.zlib, output, (uInt)output_len);

  ret = deflate (&encoder->state.zlib, Z_FINISH);

  produced = output_len - encoder->state.zlib.avail_out;

  if (ret == Z_STREAM_END)
    {
      encoder->finished = 1;
      return (ssize_t)produced;
    }

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return (ssize_t)produced;

  return -1;
}

#endif /* SOCKETHTTP1_HAS_ZLIB */

#ifdef SOCKETHTTP1_HAS_BROTLI

/**
 * map_compress_level_to_brotli - Map our level enum to brotli quality
 * @level: SocketHTTP1_CompressLevel
 *
 * Returns: Brotli quality (1-11)
 */
static int
map_compress_level_to_brotli (SocketHTTP1_CompressLevel level)
{
  switch (level)
    {
    case HTTP1_COMPRESS_FAST:
      return BROTLI_QUALITY_FAST;
    case HTTP1_COMPRESS_BEST:
      return BROTLI_QUALITY_BEST;
    default:
      return BROTLI_QUALITY_DEFAULT;
    }
}

/**
 * init_brotli_decoder - Initialize Brotli decoder
 * @decoder: Decoder instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_brotli_decoder (SocketHTTP1_Decoder_T decoder)
{
  decoder->state.brotli = BrotliDecoderCreateInstance (NULL, NULL, NULL);
  if (!decoder->state.brotli)
    return 0;

  decoder->initialized = 1;
  return 1;
}

/**
 * init_brotli_encoder - Initialize Brotli encoder
 * @encoder: Encoder instance
 *
 * Returns: 1 on success, 0 on failure
 */
static int
init_brotli_encoder (SocketHTTP1_Encoder_T encoder)
{
  int quality;

  encoder->state.brotli = BrotliEncoderCreateInstance (NULL, NULL, NULL);
  if (!encoder->state.brotli)
    return 0;

  quality = map_compress_level_to_brotli (encoder->level);
  BrotliEncoderSetParameter (encoder->state.brotli, BROTLI_PARAM_QUALITY,
                             (uint32_t)quality);

  encoder->initialized = 1;
  return 1;
}

/**
 * cleanup_brotli_decoder - Clean up Brotli decoder
 * @decoder: Decoder instance
 */
static void
cleanup_brotli_decoder (SocketHTTP1_Decoder_T decoder)
{
  if (decoder->state.brotli)
    BrotliDecoderDestroyInstance (decoder->state.brotli);
}

/**
 * cleanup_brotli_encoder - Clean up Brotli encoder
 * @encoder: Encoder instance
 */
static void
cleanup_brotli_encoder (SocketHTTP1_Encoder_T encoder)
{
  if (encoder->state.brotli)
    BrotliEncoderDestroyInstance (encoder->state.brotli);
}

/**
 * decode_brotli - Decode data using Brotli
 * @decoder: Decoder instance
 * @input: Input buffer
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Output buffer
 * @output_len: Buffer size
 * @written: Output - bytes written
 *
 * Returns: HTTP1_OK, HTTP1_INCOMPLETE, or HTTP1_ERROR
 */
static SocketHTTP1_Result
decode_brotli (SocketHTTP1_Decoder_T decoder, const unsigned char *input,
               size_t input_len, size_t *consumed, unsigned char *output,
               size_t output_len, size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in;
  size_t avail_out;
  const uint8_t *next_in;
  uint8_t *next_out;

  avail_in = input_len;
  avail_out = output_len;
  next_in = input;
  next_out = output_len > 0 ? (uint8_t *)output : NULL;

  ret = BrotliDecoderDecompressStream (decoder->state.brotli, &avail_in,
                                       &next_in, &avail_out, &next_out, NULL);

  *consumed = input_len - avail_in;
  *written = output_len - avail_out;

  if (ret == BROTLI_DECODER_RESULT_SUCCESS)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }

  if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
      || ret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
    return HTTP1_INCOMPLETE;

  return HTTP1_ERROR;
}

/**
 * finish_brotli_decode - Finish Brotli decoding after all input processed
 * @decoder: Decoder instance
 * @output: Output buffer for any remaining decompressed data
 * @output_len: Output buffer size
 * @written: Output - bytes written to output buffer
 *
 * Calls BrotliDecoderDecompressStream with zero input to drain final output.
 * May return HTTP1_INCOMPLETE if more output space needed (call again).
 *
 * Returns: HTTP1_OK on stream complete, HTTP1_INCOMPLETE if needs more output,
 *          HTTP1_ERROR on decode error
 */
static SocketHTTP1_Result
finish_brotli_decode (SocketHTTP1_Decoder_T decoder, unsigned char *output,
                      size_t output_len, size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in = 0;
  size_t avail_out = output_len;
  const uint8_t *next_in = NULL;
  uint8_t *next_out = output_len > 0 ? output : NULL;
  ret = BrotliDecoderDecompressStream (decoder->state.brotli, &avail_in, &next_in,
                                       &avail_out, &next_out, NULL);
  *written = output_len - avail_out;
  if (ret == BROTLI_DECODER_RESULT_SUCCESS)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }
  if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT ||
      ret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
    return HTTP1_INCOMPLETE;
  return HTTP1_ERROR;
}

/**
 * encode_brotli - Encode data using Brotli
 * @encoder: Encoder instance
 * @input: Input buffer
 * @input_len: Input length
 * @output: Output buffer
 * @output_len: Buffer size
 * @flush: Flush mode
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
encode_brotli (SocketHTTP1_Encoder_T encoder, const unsigned char *input,
               size_t input_len, unsigned char *output, size_t output_len,
               int flush)
{
  size_t avail_in;
  size_t avail_out;
  const uint8_t *next_in;
  uint8_t *next_out;
  BrotliEncoderOperation op;

  avail_in = input_len;
  avail_out = output_len;
  next_in = input;
  next_out = output_len > 0 ? (uint8_t *)output : NULL;
  op = flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;

  if (!BrotliEncoderCompressStream (encoder->state.brotli, op, &avail_in,
                                    &next_in, &avail_out, &next_out, NULL))
    return -1;

  return (ssize_t)(output_len - avail_out);
}

/**
 * finish_brotli_encode - Finish Brotli encoding
 * @encoder: Encoder instance
 * @output: Output buffer
 * @output_len: Buffer size
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
finish_brotli_encode (SocketHTTP1_Encoder_T encoder, unsigned char *output,
                      size_t output_len)
{
  size_t avail_in;
  size_t avail_out;
  const uint8_t *next_in;
  uint8_t *next_out;

  avail_in = 0;
  avail_out = output_len;
  next_in = NULL;
  next_out = output_len > 0 ? (uint8_t *)output : NULL;

  if (!BrotliEncoderCompressStream (encoder->state.brotli,
                                    BROTLI_OPERATION_FINISH, &avail_in,
                                    &next_in, &avail_out, &next_out, NULL))
    return -1;

  if (BrotliEncoderIsFinished (encoder->state.brotli))
    encoder->finished = 1;

  return (ssize_t)(output_len - avail_out);
}

#endif /* SOCKETHTTP1_HAS_BROTLI */

/* ============================================================================
 * Decoder Implementation
 * ============================================================================ */

SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding, Arena_T arena)
{
  SocketHTTP1_Decoder_T decoder;

  assert (arena);

  if (!is_supported_coding (coding))
    return NULL;

  decoder = CALLOC (arena, 1, sizeof (*decoder));
  if (!decoder)
    return NULL;

  decoder->coding = coding;
  decoder->arena = arena;

  switch (coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      if (!init_zlib_decoder (decoder))
        return NULL;
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      if (!init_brotli_decoder (decoder))
        return NULL;
      break;
#endif

    default:
      return NULL;
    }

  return decoder;
}

void
SocketHTTP1_Decoder_free (SocketHTTP1_Decoder_T *decoder)
{
  SocketHTTP1_Decoder_T d;

  if (!decoder || !*decoder)
    return;

  d = *decoder;

  if (d->initialized)
    {
      switch (d->coding)
        {
#ifdef SOCKETHTTP1_HAS_ZLIB
        case HTTP_CODING_GZIP:
        case HTTP_CODING_DEFLATE:
          cleanup_zlib_decoder (d);
          break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
        case HTTP_CODING_BR:
          cleanup_brotli_decoder (d);
          break;
#endif

        default:
          break;
        }
    }

  /* Arena handles memory */
  *decoder = NULL;
}

SocketHTTP1_Result
SocketHTTP1_Decoder_decode (SocketHTTP1_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            size_t *consumed, unsigned char *output,
                            size_t output_len, size_t *written)
{
  assert (decoder);
  assert (input || input_len == 0);
  assert (consumed);
  assert (output || output_len == 0);
  assert (written);

  *consumed = 0;
  *written = 0;

  if (decoder->finished)
    return HTTP1_OK;

  if (input_len > UINT_MAX || output_len > UINT_MAX)
    {
      return HTTP1_ERROR;
    }

  if (!decoder->initialized)
    return HTTP1_ERROR;

  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return decode_zlib (decoder, input, input_len, consumed, output,
                          output_len, written);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return decode_brotli (decoder, input, input_len, consumed, output,
                            output_len, written);
#endif

    default:
      return HTTP1_ERROR;
    }
}

SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output, size_t output_len,
                            size_t *written)
{
  assert (decoder);
  assert (output || output_len == 0);
  assert (written);

  *written = 0;

  if (decoder->finished)
    return HTTP1_OK;

  if (output_len > UINT_MAX)
    return HTTP1_ERROR;

  if (!decoder->initialized)
    return HTTP1_ERROR;

  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return finish_zlib_decode (decoder, output, output_len, written);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return finish_brotli_decode (decoder, output, output_len, written);
#endif

    default:
      return HTTP1_ERROR;
    }
}

/* ============================================================================
 * Encoder Implementation
 * ============================================================================ */

SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level, Arena_T arena)
{
  SocketHTTP1_Encoder_T encoder;

  assert (arena);

  if (!is_supported_coding (coding))
    return NULL;

  encoder = CALLOC (arena, 1, sizeof (*encoder));
  if (!encoder)
    return NULL;

  encoder->coding = coding;
  encoder->arena = arena;
  encoder->level = level;

  switch (coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      if (!init_zlib_encoder (encoder))
        return NULL;
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      if (!init_brotli_encoder (encoder))
        return NULL;
      break;
#endif

    default:
      return NULL;
    }

  return encoder;
}

void
SocketHTTP1_Encoder_free (SocketHTTP1_Encoder_T *encoder)
{
  SocketHTTP1_Encoder_T e;

  if (!encoder || !*encoder)
    return;

  e = *encoder;

  if (e->initialized)
    {
      switch (e->coding)
        {
#ifdef SOCKETHTTP1_HAS_ZLIB
        case HTTP_CODING_GZIP:
        case HTTP_CODING_DEFLATE:
          cleanup_zlib_encoder (e);
          break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
        case HTTP_CODING_BR:
          cleanup_brotli_encoder (e);
          break;
#endif

        default:
          break;
        }
    }

  *encoder = NULL;
}

ssize_t
SocketHTTP1_Encoder_encode (SocketHTTP1_Encoder_T encoder,
                            const unsigned char *input, size_t input_len,
                            unsigned char *output, size_t output_len,
                            int flush)
{
  assert (encoder);
  assert (input || input_len == 0);
  assert (output || output_len == 0);

  if (encoder->finished)
    return 0;

  if (input_len > UINT_MAX || output_len > UINT_MAX)
    return -1;

  if (!encoder->initialized)
    return -1;

  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return encode_zlib (encoder, input, input_len, output, output_len,
                          flush);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return encode_brotli (encoder, input, input_len, output, output_len,
                            flush);
#endif

    default:
      return -1;
    }
}

ssize_t
SocketHTTP1_Encoder_finish (SocketHTTP1_Encoder_T encoder,
                            unsigned char *output, size_t output_len)
{
  assert (encoder);
  assert (output || output_len == 0);

  if (encoder->finished)
    return 0;

  if (output_len > UINT_MAX)
    return -1;

  if (!encoder->initialized)
    return -1;

  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return finish_zlib_encode (encoder, output, output_len);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return finish_brotli_encode (encoder, output, output_len);
#endif

    default:
      return -1;
    }
}

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

/* Stub implementations when compression is disabled */

/* Empty file when compression not enabled */

#endif /* SOCKETHTTP1_HAS_COMPRESSION */
