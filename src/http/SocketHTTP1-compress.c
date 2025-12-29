/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTP1-compress.c - HTTP/1.1 Content Encoding (RFC 9110 Section 8.4)
 * Supports gzip (RFC 1952), deflate (RFC 1951), and Brotli (RFC 7932).
 * Only compiled when ENABLE_HTTP_COMPRESSION is ON.
 * Uses return codes (not exceptions) to match underlying zlib/brotli patterns.
 */

/* System headers first */
#include <assert.h>
#include <limits.h>

/* Project headers */
#include "core/SocketSecurity.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP1.h"

#if SOCKETHTTP1_HAS_COMPRESSION

/* Compression library headers (conditional) */
#ifdef SOCKETHTTP1_HAS_ZLIB
#include <zlib.h>
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

/* Module type alias following C Interfaces and Implementations pattern */
#define T_DECODER SocketHTTP1_Decoder_T
#define T_ENCODER SocketHTTP1_Encoder_T

#ifdef SOCKETHTTP1_HAS_ZLIB

/** zlib window bits for gzip format (15 + 16 = 31 for auto header detection)
 */
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

/* Decoder state for gzip/deflate/brotli decompression */
struct SocketHTTP1_Decoder
{
  SocketHTTP_Coding coding;         /**< Content coding type (gzip/deflate/br) */
  Arena_T arena;                    /**< Memory arena for allocations */

  union
  {
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib;                  /**< zlib inflate stream state */
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliDecoderState *brotli;     /**< Brotli decoder instance */
#endif
    int dummy;                      /**< Placeholder if no compression */
  } state;

  int initialized;                  /**< Backend initialized flag */
  int finished;                     /**< Decompression complete flag */
  size_t total_decompressed;        /**< Running total of output bytes */
  size_t max_decompressed_size;     /**< Limit for zip bomb protection */
};

/* Encoder state for gzip/deflate/brotli compression */
struct SocketHTTP1_Encoder
{
  SocketHTTP_Coding coding;             /**< Content coding type */
  Arena_T arena;                        /**< Memory arena for allocations */
  SocketHTTP1_CompressLevel level;      /**< Compression level (fast/default/best) */

  union
  {
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib;                      /**< zlib deflate stream state */
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliEncoderState *brotli;         /**< Brotli encoder instance */
#endif
    int dummy;                          /**< Placeholder if no compression */
  } state;

  int initialized;                      /**< Backend initialized flag */
  int finished;                         /**< Compression complete flag */
  size_t total_encoded;                 /**< Running total of output bytes */
  size_t max_encoded_size;              /**< Optional output size limit */
};

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

  (void)coding;
  return 0;
}

static int
check_buffer_limits (size_t input_len, size_t output_len)
{
  return (input_len <= UINT_MAX && output_len <= UINT_MAX);
}

static SocketHTTP1_Result
check_decode_output_limits (size_t total, size_t output_len, size_t max_size)
{
  size_t potential;

  if (output_len == 0)
    return HTTP1_OK;

  if (!SocketSecurity_check_size (output_len))
    return HTTP1_ERROR;

  if (!SocketSecurity_check_add (total, output_len, &potential))
    return HTTP1_ERROR_BODY_TOO_LARGE; /* Overflow */

  if (max_size != SIZE_MAX && potential > max_size)
    return HTTP1_ERROR_BODY_TOO_LARGE;

  return HTTP1_OK;
}

static SocketHTTP1_Result
update_decode_total (size_t *total, size_t written, size_t max_size)
{
  *total += written;
  if (max_size != SIZE_MAX && *total > max_size)
    return HTTP1_ERROR_BODY_TOO_LARGE;
  return HTTP1_OK;
}

static int
check_encode_output_limits (size_t total, size_t output_len, size_t max_size)
{
  size_t potential;

  if (output_len == 0)
    return 1;

  if (!SocketSecurity_check_size (output_len))
    return 0;

  if (!SocketSecurity_check_add (total, output_len, &potential))
    return 0; /* Overflow */

  if (max_size != SIZE_MAX && potential > max_size)
    return 0;

  return 1;
}

static int
update_encode_total (size_t *total, size_t produced, size_t max_size)
{
  *total += produced;
  if (max_size != SIZE_MAX && *total > max_size)
    return 0;
  return 1;
}

/* Default maximum decompressed size (100MB) for zip bomb protection */
#define HTTP1_DEFAULT_MAX_DECOMPRESSED_SIZE (100 * 1024 * 1024)

static size_t
get_effective_max_decompressed_size (const SocketHTTP1_Config *cfg)
{
  if (cfg == NULL || cfg->max_decompressed_size == 0)
    return HTTP1_DEFAULT_MAX_DECOMPRESSED_SIZE;
  return cfg->max_decompressed_size;
}

static size_t
get_effective_max_encoded_size (const SocketHTTP1_Config *cfg)
{
  (void)cfg; /* Currently unused, reserved for future configuration */
  return SIZE_MAX;
}

#ifdef SOCKETHTTP1_HAS_ZLIB

static int
get_zlib_window_bits (SocketHTTP_Coding coding)
{
  return (coding == HTTP_CODING_GZIP) ? ZLIB_WINDOW_BITS_GZIP
                                      : ZLIB_WINDOW_BITS_DEFLATE;
}

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

static int
init_zlib_decoder (SocketHTTP1_Decoder_T decoder)
{
  int window_bits = get_zlib_window_bits (decoder->coding);

  if (inflateInit2 (&decoder->state.zlib, window_bits) != Z_OK)
    return 0;

  decoder->initialized = 1;
  return 1;
}

static int
init_zlib_encoder (SocketHTTP1_Encoder_T encoder)
{
  int zlib_level = map_compress_level_to_zlib (encoder->level);
  int window_bits = get_zlib_window_bits (encoder->coding);

  if (deflateInit2 (&encoder->state.zlib, zlib_level, Z_DEFLATED, window_bits,
                    ZLIB_MEM_LEVEL_DEFAULT, Z_DEFAULT_STRATEGY)
      != Z_OK)
    return 0;

  encoder->initialized = 1;
  return 1;
}

static void
cleanup_zlib_decoder (SocketHTTP1_Decoder_T decoder)
{
  inflateEnd (&decoder->state.zlib);
}

static void
cleanup_zlib_encoder (SocketHTTP1_Encoder_T encoder)
{
  deflateEnd (&encoder->state.zlib);
}

static SocketHTTP1_Result
decode_zlib (SocketHTTP1_Decoder_T decoder, const unsigned char *input,
             size_t input_len, size_t *consumed, unsigned char *output,
             size_t output_len, size_t *written)
{
  int ret;
  z_stream *s = &decoder->state.zlib;

  s->next_in = (Bytef *)input;
  s->avail_in = (uInt)input_len;
  s->next_out = output;
  s->avail_out = (uInt)output_len;

  ret = inflate (s, Z_NO_FLUSH);

  *consumed = input_len - s->avail_in;
  *written = output_len - s->avail_out;

  if (ret == Z_STREAM_END)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return HTTP1_INCOMPLETE;

  return HTTP1_ERROR;
}

static SocketHTTP1_Result
finish_zlib_decode (SocketHTTP1_Decoder_T decoder, unsigned char *output,
                    size_t output_len, size_t *written)
{
  int ret;
  z_stream *s = &decoder->state.zlib;

  s->next_in = NULL;
  s->avail_in = 0;
  s->next_out = output;
  s->avail_out = (uInt)output_len;

  ret = inflate (s, Z_FINISH);

  *written = output_len - s->avail_out;

  if (ret == Z_STREAM_END)
    {
      decoder->finished = 1;
      return HTTP1_OK;
    }

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return HTTP1_INCOMPLETE;

  return HTTP1_ERROR;
}

static ssize_t
encode_zlib (SocketHTTP1_Encoder_T encoder, const unsigned char *input,
             size_t input_len, unsigned char *output, size_t output_len,
             int flush)
{
  int ret;
  int zlib_flush = flush ? Z_SYNC_FLUSH : Z_NO_FLUSH;
  z_stream *s = &encoder->state.zlib;

  s->next_in = (Bytef *)input;
  s->avail_in = (uInt)input_len;
  s->next_out = output;
  s->avail_out = (uInt)output_len;

  ret = deflate (s, zlib_flush);

  if (ret == Z_OK || ret == Z_BUF_ERROR)
    return (ssize_t)(output_len - s->avail_out);

  return -1;
}

static ssize_t
finish_zlib_encode (SocketHTTP1_Encoder_T encoder, unsigned char *output,
                    size_t output_len)
{
  int ret;
  size_t produced;
  z_stream *s = &encoder->state.zlib;

  s->next_in = NULL;
  s->avail_in = 0;
  s->next_out = output;
  s->avail_out = (uInt)output_len;

  ret = deflate (s, Z_FINISH);

  produced = output_len - s->avail_out;

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

static int
init_brotli_decoder (SocketHTTP1_Decoder_T decoder)
{
  decoder->state.brotli = BrotliDecoderCreateInstance (NULL, NULL, NULL);
  if (!decoder->state.brotli)
    return 0;

  decoder->initialized = 1;
  return 1;
}

static int
init_brotli_encoder (SocketHTTP1_Encoder_T encoder)
{
  int quality = map_compress_level_to_brotli (encoder->level);

  encoder->state.brotli = BrotliEncoderCreateInstance (NULL, NULL, NULL);
  if (!encoder->state.brotli)
    return 0;

  BrotliEncoderSetParameter (encoder->state.brotli, BROTLI_PARAM_QUALITY,
                             (uint32_t)quality);

  encoder->initialized = 1;
  return 1;
}

static void
cleanup_brotli_decoder (SocketHTTP1_Decoder_T decoder)
{
  if (decoder->state.brotli)
    BrotliDecoderDestroyInstance (decoder->state.brotli);
}

static void
cleanup_brotli_encoder (SocketHTTP1_Encoder_T encoder)
{
  if (encoder->state.brotli)
    BrotliEncoderDestroyInstance (encoder->state.brotli);
}

static SocketHTTP1_Result
decode_brotli (SocketHTTP1_Decoder_T decoder, const unsigned char *input,
               size_t input_len, size_t *consumed, unsigned char *output,
               size_t output_len, size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in = input_len;
  size_t avail_out = output_len;
  const uint8_t *next_in = input;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;

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

static SocketHTTP1_Result
finish_brotli_decode (SocketHTTP1_Decoder_T decoder, unsigned char *output,
                      size_t output_len, size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in = 0;
  size_t avail_out = output_len;
  const uint8_t *next_in = NULL;
  uint8_t *next_out = output_len > 0 ? output : NULL;

  ret = BrotliDecoderDecompressStream (decoder->state.brotli, &avail_in,
                                       &next_in, &avail_out, &next_out, NULL);
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

static ssize_t
encode_brotli (SocketHTTP1_Encoder_T encoder, const unsigned char *input,
               size_t input_len, unsigned char *output, size_t output_len,
               int flush)
{
  size_t avail_in = input_len;
  size_t avail_out = output_len;
  const uint8_t *next_in = input;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;
  BrotliEncoderOperation op
      = flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;

  if (!BrotliEncoderCompressStream (encoder->state.brotli, op, &avail_in,
                                    &next_in, &avail_out, &next_out, NULL))
    return -1;

  return (ssize_t)(output_len - avail_out);
}

static ssize_t
finish_brotli_encode (SocketHTTP1_Encoder_T encoder, unsigned char *output,
                      size_t output_len)
{
  size_t avail_in = 0;
  size_t avail_out = output_len;
  const uint8_t *next_in = NULL;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;

  if (!BrotliEncoderCompressStream (encoder->state.brotli,
                                    BROTLI_OPERATION_FINISH, &avail_in,
                                    &next_in, &avail_out, &next_out, NULL))
    return -1;

  if (BrotliEncoderIsFinished (encoder->state.brotli))
    encoder->finished = 1;

  return (ssize_t)(output_len - avail_out);
}

#endif /* SOCKETHTTP1_HAS_BROTLI */

static int
init_decoder_backend (SocketHTTP1_Decoder_T decoder)
{
  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return init_zlib_decoder (decoder);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return init_brotli_decoder (decoder);
#endif

    default:
      return 0;
    }
}

static void
cleanup_decoder_backend (SocketHTTP1_Decoder_T decoder)
{
  if (!decoder->initialized)
    return;

  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      cleanup_zlib_decoder (decoder);
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      cleanup_brotli_decoder (decoder);
      break;
#endif

    default:
      break;
    }
}

static SocketHTTP1_Result
dispatch_decode (SocketHTTP1_Decoder_T decoder, const unsigned char *input,
                 size_t input_len, size_t *consumed, unsigned char *output,
                 size_t output_len, size_t *written)
{
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

static SocketHTTP1_Result
dispatch_decode_finish (SocketHTTP1_Decoder_T decoder, unsigned char *output,
                        size_t output_len, size_t *written)
{
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

static int
init_encoder_backend (SocketHTTP1_Encoder_T encoder)
{
  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return init_zlib_encoder (encoder);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return init_brotli_encoder (encoder);
#endif

    default:
      return 0;
    }
}

static void
cleanup_encoder_backend (SocketHTTP1_Encoder_T encoder)
{
  if (!encoder->initialized)
    return;

  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      cleanup_zlib_encoder (encoder);
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      cleanup_brotli_encoder (encoder);
      break;
#endif

    default:
      break;
    }
}

static ssize_t
dispatch_encode (SocketHTTP1_Encoder_T encoder, const unsigned char *input,
                 size_t input_len, unsigned char *output, size_t output_len,
                 int flush)
{
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

static ssize_t
dispatch_encode_finish (SocketHTTP1_Encoder_T encoder, unsigned char *output,
                        size_t output_len)
{
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

SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding,
                         const SocketHTTP1_Config *cfg, Arena_T arena)
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
  decoder->max_decompressed_size = get_effective_max_decompressed_size (cfg);

  if (!init_decoder_backend (decoder))
    return NULL;

  return decoder;
}

void
SocketHTTP1_Decoder_free (SocketHTTP1_Decoder_T *decoder)
{
  if (!decoder || !*decoder)
    return;

  cleanup_decoder_backend (*decoder);

  /* Arena handles memory */
  *decoder = NULL;
}

SocketHTTP1_Result
SocketHTTP1_Decoder_decode (SocketHTTP1_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            size_t *consumed, unsigned char *output,
                            size_t output_len, size_t *written)
{
  SocketHTTP1_Result res;
  SocketHTTP1_Result limit_res;

  assert (decoder);
  assert (input || input_len == 0);
  assert (consumed);
  assert (output || output_len == 0);
  assert (written);

  *consumed = 0;
  *written = 0;

  if (decoder->finished)
    return HTTP1_OK;

  if (!check_buffer_limits (input_len, output_len))
    return HTTP1_ERROR;

  limit_res = check_decode_output_limits (decoder->total_decompressed,
                                          output_len,
                                          decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  if (!decoder->initialized)
    return HTTP1_ERROR;

  res = dispatch_decode (decoder, input, input_len, consumed, output,
                         output_len, written);

  limit_res = update_decode_total (&decoder->total_decompressed, *written,
                                   decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  return res;
}

SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output, size_t output_len,
                            size_t *written)
{
  SocketHTTP1_Result res;
  SocketHTTP1_Result limit_res;

  assert (decoder);
  assert (output || output_len == 0);
  assert (written);

  *written = 0;

  if (decoder->finished)
    return HTTP1_OK;

  if (output_len > UINT_MAX)
    return HTTP1_ERROR;

  limit_res = check_decode_output_limits (decoder->total_decompressed,
                                          output_len,
                                          decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  if (!decoder->initialized)
    return HTTP1_ERROR;

  res = dispatch_decode_finish (decoder, output, output_len, written);

  limit_res = update_decode_total (&decoder->total_decompressed, *written,
                                   decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  return res;
}

SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level,
                         const SocketHTTP1_Config *cfg, Arena_T arena)
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
  encoder->max_encoded_size = get_effective_max_encoded_size (cfg);

  if (!init_encoder_backend (encoder))
    return NULL;

  return encoder;
}

void
SocketHTTP1_Encoder_free (SocketHTTP1_Encoder_T *encoder)
{
  if (!encoder || !*encoder)
    return;

  cleanup_encoder_backend (*encoder);

  *encoder = NULL;
}

ssize_t
SocketHTTP1_Encoder_encode (SocketHTTP1_Encoder_T encoder,
                            const unsigned char *input, size_t input_len,
                            unsigned char *output, size_t output_len,
                            int flush)
{
  ssize_t res;

  assert (encoder);
  assert (input || input_len == 0);
  assert (output || output_len == 0);

  if (encoder->finished)
    return 0;

  if (!check_buffer_limits (input_len, output_len))
    return -1;

  if (!check_encode_output_limits (encoder->total_encoded, output_len,
                                   encoder->max_encoded_size))
    return -1;

  if (!encoder->initialized)
    return -1;

  res = dispatch_encode (encoder, input, input_len, output, output_len, flush);

  if (res > 0)
    {
      if (!update_encode_total (&encoder->total_encoded, (size_t)res,
                                encoder->max_encoded_size))
        return -1;
    }

  return res;
}

ssize_t
SocketHTTP1_Encoder_finish (SocketHTTP1_Encoder_T encoder,
                            unsigned char *output, size_t output_len)
{
  ssize_t res;

  assert (encoder);
  assert (output || output_len == 0);

  if (encoder->finished)
    return 0;

  if (output_len > UINT_MAX)
    return -1;

  if (!check_encode_output_limits (encoder->total_encoded, output_len,
                                   encoder->max_encoded_size))
    return -1;

  if (!encoder->initialized)
    return -1;

  res = dispatch_encode_finish (encoder, output, output_len);

  if (res > 0)
    {
      if (!update_encode_total (&encoder->total_encoded, (size_t)res,
                                encoder->max_encoded_size))
        return -1;
    }

  return res;
}

#undef T_DECODER
#undef T_ENCODER

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

/* Empty file when compression not enabled */

#endif /* SOCKETHTTP1_HAS_COMPRESSION */
