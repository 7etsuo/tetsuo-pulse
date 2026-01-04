/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file StreamingCurl_decomp.c
 * @brief Content decompression wrapper for curl module.
 *
 * Implements automatic decompression for HTTP responses:
 * - gzip (deflate with gzip header)
 * - deflate (raw deflate)
 * - br (Brotli compression)
 *
 * Requires SOCKETHTTP1_HAS_COMPRESSION to be defined for actual
 * decompression. When not available, passes data through unchanged.
 */

#include "curl/StreamingCurl-private.h"
#include "curl/StreamingCurl.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Decompression context for streaming decompression.
 */
typedef struct CurlDecompressor
{
  SocketHTTP_Coding coding; /**< Content encoding type */
  Arena_T arena;            /**< Memory arena */
  int initialized;          /**< Decoder initialized */
#if SOCKETHTTP1_HAS_COMPRESSION
  SocketHTTP1_Decoder_T decoder; /**< HTTP/1.1 decoder */
#endif
} CurlDecompressor;

/**
 * @brief Create a new decompressor.
 *
 * @param encoding Content-Encoding header value
 * @param arena Memory arena
 * @return New decompressor, or NULL on error
 */
CurlDecompressor *
curl_decompressor_new (const char *encoding, Arena_T arena)
{
  if (!arena)
    return NULL;

  CurlDecompressor *decomp = CALLOC (arena, 1, sizeof (CurlDecompressor));
  decomp->arena = arena;
  decomp->initialized = 0;

  /* Determine coding type */
  if (!encoding || *encoding == '\0')
    {
      decomp->coding = HTTP_CODING_IDENTITY;
    }
  else
    {
      decomp->coding = SocketHTTP_coding_parse (encoding, strlen (encoding));
    }

  return decomp;
}

/**
 * @brief Initialize decoder on first use.
 *
 * @param decomp Decompressor
 * @return 0 on success, -1 on error
 */
static int
curl_decompressor_init (CurlDecompressor *decomp)
{
  if (!decomp || decomp->initialized)
    return 0;

  /* Identity encoding - no decoder needed */
  if (decomp->coding == HTTP_CODING_IDENTITY)
    {
      decomp->initialized = 1;
      return 0;
    }

#if SOCKETHTTP1_HAS_COMPRESSION
  decomp->decoder
      = SocketHTTP1_Decoder_new (decomp->coding, NULL, decomp->arena);
  if (!decomp->decoder)
    return -1;
#endif

  decomp->initialized = 1;
  return 0;
}

/**
 * @brief Decompress data.
 *
 * @param decomp Decompressor
 * @param input Compressed input
 * @param input_len Input length
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Output bytes written
 * @return 0 on success, -1 on error
 */
int
curl_decompressor_decompress (CurlDecompressor *decomp,
                              const unsigned char *input, size_t input_len,
                              unsigned char *output, size_t output_len,
                              size_t *bytes_written)
{
  if (!decomp || !output || !bytes_written)
    return -1;

  *bytes_written = 0;

  /* Initialize on first use */
  if (!decomp->initialized)
    {
      if (curl_decompressor_init (decomp) != 0)
        return -1;
    }

  /* Identity encoding - pass through */
  if (decomp->coding == HTTP_CODING_IDENTITY)
    {
      size_t copy_len = input_len > output_len ? output_len : input_len;
      if (input && copy_len > 0)
        {
          memcpy (output, input, copy_len);
        }
      *bytes_written = copy_len;
      return 0;
    }

#if SOCKETHTTP1_HAS_COMPRESSION
  if (!decomp->decoder)
    return -1;

  size_t consumed;
  SocketHTTP1_Result res = SocketHTTP1_Decoder_decode (
      decomp->decoder, input, input_len, &consumed, output, output_len,
      bytes_written);

  if (res != HTTP1_OK && res != HTTP1_INCOMPLETE)
    return -1;

  return 0;
#else
  /* No compression support - pass through */
  size_t copy_len = input_len > output_len ? output_len : input_len;
  if (input && copy_len > 0)
    {
      memcpy (output, input, copy_len);
    }
  *bytes_written = copy_len;
  return 0;
#endif
}

/**
 * @brief Finish decompression and get remaining data.
 *
 * @param decomp Decompressor
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Output bytes written
 * @return 0 on success, -1 on error
 */
int
curl_decompressor_finish (CurlDecompressor *decomp, unsigned char *output,
                          size_t output_len, size_t *bytes_written)
{
  if (!decomp || !output || !bytes_written)
    return -1;

  *bytes_written = 0;

  if (!decomp->initialized || decomp->coding == HTTP_CODING_IDENTITY)
    {
      (void)output_len; /* Unused for identity encoding */
      return 0;
    }

#if SOCKETHTTP1_HAS_COMPRESSION
  if (!decomp->decoder)
    return 0;

  SocketHTTP1_Result res = SocketHTTP1_Decoder_finish (
      decomp->decoder, output, output_len, bytes_written);

  if (res != HTTP1_OK && res != HTTP1_INCOMPLETE)
    return -1;

  return 0;
#else
  return 0;
#endif
}

/**
 * @brief Free decompressor resources.
 *
 * @param decomp Pointer to decompressor (set to NULL)
 */
void
curl_decompressor_free (CurlDecompressor **decomp)
{
  if (!decomp || !*decomp)
    return;

#if SOCKETHTTP1_HAS_COMPRESSION
  if ((*decomp)->decoder)
    {
      SocketHTTP1_Decoder_free (&(*decomp)->decoder);
    }
#endif

  *decomp = NULL;
}

/**
 * @brief Check if decompressor is for identity encoding.
 *
 * @param decomp Decompressor
 * @return 1 if identity, 0 otherwise
 */
int
curl_decompressor_is_identity (CurlDecompressor *decomp)
{
  if (!decomp)
    return 1;

  return decomp->coding == HTTP_CODING_IDENTITY;
}

/**
 * @brief Get coding type name.
 *
 * @param decomp Decompressor
 * @return Static string name
 */
const char *
curl_decompressor_coding_name (CurlDecompressor *decomp)
{
  if (!decomp)
    return "identity";

  switch (decomp->coding)
    {
    case HTTP_CODING_IDENTITY:
      return "identity";
    case HTTP_CODING_GZIP:
      return "gzip";
    case HTTP_CODING_DEFLATE:
      return "deflate";
    case HTTP_CODING_BR:
      return "br";
    default:
      return "unknown";
    }
}

/**
 * @brief Create decompressor for session based on Content-Encoding.
 *
 * @param session Session
 * @return New decompressor, or NULL if not needed/error
 */
CurlDecompressor *
curl_session_create_decompressor (CurlSession_T session)
{
  if (!session || !session->response.headers)
    return NULL;

  /* Check if auto-decompress is enabled */
  if (!session->options.auto_decompress)
    return NULL;

  /* Get Content-Encoding header */
  const char *encoding
      = SocketHTTP_Headers_get (session->response.headers, "Content-Encoding");
  if (!encoding)
    return NULL;

  /* Skip if identity encoding */
  if (strcasecmp (encoding, "identity") == 0)
    return NULL;

  return curl_decompressor_new (encoding, session->request_arena);
}

/**
 * @brief Decompress body data with session's decompressor.
 *
 * @param session Session
 * @param decomp Decompressor (may be NULL)
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @param output_len Output buffer size
 * @param bytes_written Bytes written to output
 * @return 0 on success, -1 on error
 */
int
curl_session_decompress (CurlSession_T session, CurlDecompressor *decomp,
                         const unsigned char *input, size_t input_len,
                         unsigned char *output, size_t output_len,
                         size_t *bytes_written)
{
  (void)session; /* May be used for error reporting in future */

  if (!bytes_written)
    return -1;

  /* No decompressor - pass through */
  if (!decomp)
    {
      size_t copy_len = input_len > output_len ? output_len : input_len;
      if (input && copy_len > 0)
        {
          memcpy (output, input, copy_len);
        }
      *bytes_written = copy_len;
      return 0;
    }

  return curl_decompressor_decompress (decomp, input, input_len, output,
                                       output_len, bytes_written);
}

/**
 * @brief Check if Content-Encoding indicates compression.
 *
 * @param headers Response headers
 * @return 1 if compressed, 0 otherwise
 */
int
curl_is_content_compressed (SocketHTTP_Headers_T headers)
{
  if (!headers)
    return 0;

  const char *encoding = SocketHTTP_Headers_get (headers, "Content-Encoding");
  if (!encoding)
    return 0;

  /* Check for known compression types */
  if (strcasecmp (encoding, "gzip") == 0)
    return 1;
  if (strcasecmp (encoding, "deflate") == 0)
    return 1;
  if (strcasecmp (encoding, "br") == 0)
    return 1;

  return 0;
}

/**
 * @brief Parse Content-Encoding to coding type.
 *
 * @param encoding Content-Encoding header value
 * @return Coding type
 */
SocketHTTP_Coding
curl_parse_content_encoding (const char *encoding)
{
  if (!encoding)
    return HTTP_CODING_IDENTITY;

  return SocketHTTP_coding_parse (encoding, strlen (encoding));
}
