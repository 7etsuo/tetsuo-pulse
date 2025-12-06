/**
 * SocketHTTP1-compress.c - HTTP/1.1 Content Encoding Support
 *
 * Part of the Socket Library
 *
 * Implements RFC 9110 Section 8.4 content coding:
 * - gzip (RFC 1952) via zlib
 * - deflate (RFC 1951) via zlib
 * - br (Brotli, RFC 7932) via libbrotli (optional)
 *
 * This file is only compiled when ENABLE_HTTP_COMPRESSION is ON.
 */

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"

#ifdef SOCKETHTTP1_HAS_COMPRESSION

#include <assert.h>
#include <string.h>

#ifdef SOCKETHTTP1_HAS_ZLIB
#include <zlib.h>
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

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
 * Decoder Implementation
 * ============================================================================ */

SocketHTTP1_Decoder_T
SocketHTTP1_Decoder_new (SocketHTTP_Coding coding, Arena_T arena)
{
  SocketHTTP1_Decoder_T decoder;
#ifdef SOCKETHTTP1_HAS_ZLIB
  int window_bits;
#endif

  assert (arena);

  /* Validate coding */
  if (coding != HTTP_CODING_GZIP && coding != HTTP_CODING_DEFLATE
      && coding != HTTP_CODING_BR)
    {
      return NULL;
    }

  decoder = Arena_alloc (arena, sizeof (*decoder), __FILE__, __LINE__);
  if (!decoder)
    return NULL;

  memset (decoder, 0, sizeof (*decoder));
  decoder->coding = coding;
  decoder->arena = arena;

  switch (coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
      /* gzip: 15 + 16 = 31 for automatic header detection */
      window_bits = 15 + 16;
      memset (&decoder->state.zlib, 0, sizeof (decoder->state.zlib));
      if (inflateInit2 (&decoder->state.zlib, window_bits) != Z_OK)
        {
          return NULL;
        }
      decoder->initialized = 1;
      break;

    case HTTP_CODING_DEFLATE:
      /* deflate: -15 for raw deflate, 15 for zlib wrapper */
      /* Try raw deflate first, as some servers send raw deflate */
      window_bits = -15;
      memset (&decoder->state.zlib, 0, sizeof (decoder->state.zlib));
      if (inflateInit2 (&decoder->state.zlib, window_bits) != Z_OK)
        {
          return NULL;
        }
      decoder->initialized = 1;
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      decoder->state.brotli = BrotliDecoderCreateInstance (NULL, NULL, NULL);
      if (!decoder->state.brotli)
        {
          return NULL;
        }
      decoder->initialized = 1;
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
  if (!decoder || !*decoder)
    return;

  SocketHTTP1_Decoder_T d = *decoder;

  if (d->initialized)
    {
      switch (d->coding)
        {
#ifdef SOCKETHTTP1_HAS_ZLIB
        case HTTP_CODING_GZIP:
        case HTTP_CODING_DEFLATE:
          inflateEnd (&d->state.zlib);
          break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
        case HTTP_CODING_BR:
          if (d->state.brotli)
            {
              BrotliDecoderDestroyInstance (d->state.brotli);
            }
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

  if (!decoder->initialized)
    return HTTP1_ERROR;

  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      {
        int ret;

        decoder->state.zlib.next_in = (Bytef *)input;
        decoder->state.zlib.avail_in = (uInt)input_len;
        decoder->state.zlib.next_out = output;
        decoder->state.zlib.avail_out = (uInt)output_len;

        ret = inflate (&decoder->state.zlib, Z_NO_FLUSH);

        *consumed = input_len - decoder->state.zlib.avail_in;
        *written = output_len - decoder->state.zlib.avail_out;

        if (ret == Z_STREAM_END)
          {
            decoder->finished = 1;
            return HTTP1_OK;
          }
        else if (ret == Z_OK || ret == Z_BUF_ERROR)
          {
            return HTTP1_INCOMPLETE;
          }
        else
          {
            return HTTP1_ERROR;
          }
      }
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      {
        BrotliDecoderResult ret;
        size_t avail_in = input_len;
        size_t avail_out = output_len;
        const uint8_t *next_in = input;
        uint8_t *next_out = output;

        ret = BrotliDecoderDecompressStream (decoder->state.brotli, &avail_in,
                                             &next_in, &avail_out, &next_out,
                                             NULL);

        *consumed = input_len - avail_in;
        *written = output_len - avail_out;

        if (ret == BROTLI_DECODER_RESULT_SUCCESS)
          {
            decoder->finished = 1;
            return HTTP1_OK;
          }
        else if (ret == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
                 || ret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT)
          {
            return HTTP1_INCOMPLETE;
          }
        else
          {
            return HTTP1_ERROR;
          }
      }
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

  if (!decoder->initialized)
    return HTTP1_ERROR;

  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      {
        int ret;

        decoder->state.zlib.next_in = NULL;
        decoder->state.zlib.avail_in = 0;
        decoder->state.zlib.next_out = output;
        decoder->state.zlib.avail_out = (uInt)output_len;

        ret = inflate (&decoder->state.zlib, Z_FINISH);

        *written = output_len - decoder->state.zlib.avail_out;

        if (ret == Z_STREAM_END)
          {
            decoder->finished = 1;
            return HTTP1_OK;
          }
        else if (ret == Z_OK || ret == Z_BUF_ERROR)
          {
            return HTTP1_INCOMPLETE;
          }
        else
          {
            return HTTP1_ERROR;
          }
      }
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      {
        if (BrotliDecoderIsFinished (decoder->state.brotli))
          {
            decoder->finished = 1;
            return HTTP1_OK;
          }
        return HTTP1_INCOMPLETE;
      }
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
#ifdef SOCKETHTTP1_HAS_ZLIB
  int zlib_level;
  int window_bits;
#endif

  assert (arena);

  if (coding != HTTP_CODING_GZIP && coding != HTTP_CODING_DEFLATE
      && coding != HTTP_CODING_BR)
    {
      return NULL;
    }

  encoder = Arena_alloc (arena, sizeof (*encoder), __FILE__, __LINE__);
  if (!encoder)
    return NULL;

  memset (encoder, 0, sizeof (*encoder));
  encoder->coding = coding;
  encoder->arena = arena;
  encoder->level = level;

  switch (coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
      /* Map our level to zlib level */
      zlib_level = (level == HTTP1_COMPRESS_FAST)      ? 1
                   : (level == HTTP1_COMPRESS_BEST)    ? 9
                                                       : Z_DEFAULT_COMPRESSION;
      /* gzip: 15 + 16 for gzip header */
      window_bits = 15 + 16;
      memset (&encoder->state.zlib, 0, sizeof (encoder->state.zlib));
      if (deflateInit2 (&encoder->state.zlib, zlib_level, Z_DEFLATED,
                        window_bits, 8, Z_DEFAULT_STRATEGY)
          != Z_OK)
        {
          return NULL;
        }
      encoder->initialized = 1;
      break;

    case HTTP_CODING_DEFLATE:
      zlib_level = (level == HTTP1_COMPRESS_FAST)      ? 1
                   : (level == HTTP1_COMPRESS_BEST)    ? 9
                                                       : Z_DEFAULT_COMPRESSION;
      /* Raw deflate: -15 */
      window_bits = -15;
      memset (&encoder->state.zlib, 0, sizeof (encoder->state.zlib));
      if (deflateInit2 (&encoder->state.zlib, zlib_level, Z_DEFLATED,
                        window_bits, 8, Z_DEFAULT_STRATEGY)
          != Z_OK)
        {
          return NULL;
        }
      encoder->initialized = 1;
      break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      {
        int quality = (level == HTTP1_COMPRESS_FAST)    ? 1
                      : (level == HTTP1_COMPRESS_BEST)  ? 11
                                                        : 6;
        encoder->state.brotli
            = BrotliEncoderCreateInstance (NULL, NULL, NULL);
        if (!encoder->state.brotli)
          {
            return NULL;
          }
        BrotliEncoderSetParameter (encoder->state.brotli,
                                   BROTLI_PARAM_QUALITY, quality);
        encoder->initialized = 1;
      }
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
  if (!encoder || !*encoder)
    return;

  SocketHTTP1_Encoder_T e = *encoder;

  if (e->initialized)
    {
      switch (e->coding)
        {
#ifdef SOCKETHTTP1_HAS_ZLIB
        case HTTP_CODING_GZIP:
        case HTTP_CODING_DEFLATE:
          deflateEnd (&e->state.zlib);
          break;
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
        case HTTP_CODING_BR:
          if (e->state.brotli)
            {
              BrotliEncoderDestroyInstance (e->state.brotli);
            }
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

  if (!encoder->initialized)
    return -1;

  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      {
        int ret;
        int zlib_flush = flush ? Z_SYNC_FLUSH : Z_NO_FLUSH;

        encoder->state.zlib.next_in = (Bytef *)input;
        encoder->state.zlib.avail_in = (uInt)input_len;
        encoder->state.zlib.next_out = output;
        encoder->state.zlib.avail_out = (uInt)output_len;

        ret = deflate (&encoder->state.zlib, zlib_flush);

        if (ret == Z_OK || ret == Z_BUF_ERROR)
          {
            return (ssize_t)(output_len - encoder->state.zlib.avail_out);
          }
        else
          {
            return -1;
          }
      }
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      {
        size_t avail_in = input_len;
        size_t avail_out = output_len;
        const uint8_t *next_in = input;
        uint8_t *next_out = output;
        BrotliEncoderOperation op
            = flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;

        if (!BrotliEncoderCompressStream (encoder->state.brotli, op, &avail_in,
                                          &next_in, &avail_out, &next_out,
                                          NULL))
          {
            return -1;
          }

        return (ssize_t)(output_len - avail_out);
      }
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

  if (!encoder->initialized)
    return -1;

  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_ZLIB
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      {
        int ret;
        size_t produced = 0;

        encoder->state.zlib.next_in = NULL;
        encoder->state.zlib.avail_in = 0;
        encoder->state.zlib.next_out = output;
        encoder->state.zlib.avail_out = (uInt)output_len;

        ret = deflate (&encoder->state.zlib, Z_FINISH);

        produced = output_len - encoder->state.zlib.avail_out;

        if (ret == Z_STREAM_END)
          {
            encoder->finished = 1;
            return (ssize_t)produced;
          }
        else if (ret == Z_OK || ret == Z_BUF_ERROR)
          {
            /* Need more output space */
            return (ssize_t)produced;
          }
        else
          {
            return -1;
          }
      }
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      {
        size_t avail_in = 0;
        size_t avail_out = output_len;
        const uint8_t *next_in = NULL;
        uint8_t *next_out = output;

        if (!BrotliEncoderCompressStream (
                encoder->state.brotli, BROTLI_OPERATION_FINISH, &avail_in,
                &next_in, &avail_out, &next_out, NULL))
          {
            return -1;
          }

        if (BrotliEncoderIsFinished (encoder->state.brotli))
          {
            encoder->finished = 1;
          }

        return (ssize_t)(output_len - avail_out);
      }
#endif

    default:
      return -1;
    }
}

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

/* Stub implementations when compression is disabled */

/* Empty file when compression not enabled */

#endif /* SOCKETHTTP1_HAS_COMPRESSION */

