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
#include <stdio.h>
#include <string.h>

/* Project headers */
#include "core/SocketSecurity.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP1.h"

#if SOCKETHTTP1_HAS_COMPRESSION

/* Native DEFLATE header (conditional) */
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
#include "deflate/SocketDeflate.h"
#endif

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

/**
 * @brief Maximum buffer size for compression/decompression operations.
 *
 * zlib's z_stream structure uses uInt (unsigned int) for avail_in and avail_out
 * fields, limiting buffer sizes to UINT_MAX bytes. This constant documents
 * this API constraint and is used for runtime validation before casts.
 *
 * For Brotli operations (which use size_t natively and don't have this limit),
 * we enforce the same constraint for consistent API behavior across all codecs.
 *
 * @see zlib.h: typedef unsigned int uInt;
 * @see Lines 277-278, 309, 341-342, 365 (zlib assertions)
 * @see Lines 831, 941 (encoder/decoder finish validation)
 */
#define ZLIB_MAX_BUFFER_SIZE UINT_MAX

/* Decoder state for gzip/deflate/brotli decompression */
struct SocketHTTP1_Decoder
{
  SocketHTTP_Coding coding; /**< Content coding type (gzip/deflate/br) */
  Arena_T arena;            /**< Memory arena for allocations */

  union
  {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    struct
    {
      SocketDeflate_Inflater_T inflater; /**< Native DEFLATE inflater */
      uint32_t crc;                      /**< Running CRC32 for gzip */
      size_t total_out;                  /**< For gzip ISIZE verification */
      int header_parsed;                 /**< gzip header parsed flag */
      int is_gzip;                       /**< gzip vs raw deflate */
      int zlib_wrapped;                  /**< Auto-detected zlib wrapper */
      int trailer_verified;   /**< Trailer verified for this member */
      uint8_t trailer_buf[8]; /**< Buffer for gzip trailer */
      size_t trailer_pos;     /**< Position in trailer buffer */
    } native;
#endif
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib; /**< zlib inflate stream state */
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliDecoderState *brotli; /**< Brotli decoder instance */
#endif
    int dummy; /**< Placeholder if no compression */
  } state;

  int initialized;              /**< Backend initialized flag */
  int finished;                 /**< Decompression complete flag */
  size_t total_decompressed;    /**< Running total of output bytes */
  size_t max_decompressed_size; /**< Limit for zip bomb protection */
};

/* Encoder state for gzip/deflate/brotli compression */
struct SocketHTTP1_Encoder
{
  SocketHTTP_Coding coding;        /**< Content coding type */
  Arena_T arena;                   /**< Memory arena for allocations */
  SocketHTTP1_CompressLevel level; /**< Compression level (fast/default/best) */

  union
  {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    struct
    {
      SocketDeflate_Deflater_T deflater; /**< Native DEFLATE deflater */
      uint32_t crc;                      /**< Running CRC32 for gzip */
      size_t total_in;                   /**< Original size for gzip trailer */
      int is_gzip;                       /**< gzip vs raw deflate */
      int header_written;                /**< gzip header written flag */
    } native;
#endif
#ifdef SOCKETHTTP1_HAS_ZLIB
    z_stream zlib; /**< zlib deflate stream state */
#endif
#ifdef SOCKETHTTP1_HAS_BROTLI
    BrotliEncoderState *brotli; /**< Brotli encoder instance */
#endif
    int dummy; /**< Placeholder if no compression */
  } state;

  int initialized;         /**< Backend initialized flag */
  int finished;            /**< Compression complete flag */
  size_t total_encoded;    /**< Running total of output bytes */
  size_t max_encoded_size; /**< Optional output size limit */
};

static int
is_supported_coding (SocketHTTP_Coding coding)
{
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
  if (coding == HTTP_CODING_GZIP || coding == HTTP_CODING_DEFLATE)
    return 1;
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
  return (input_len <= ZLIB_MAX_BUFFER_SIZE
          && output_len <= ZLIB_MAX_BUFFER_SIZE);
}

/** Result codes for generic size limit validation */
typedef enum
{
  SIZE_LIMIT_OK = 0,         /**< No errors, within limits */
  SIZE_LIMIT_ERROR_SIZE,     /**< Invalid size value */
  SIZE_LIMIT_ERROR_OVERFLOW, /**< Addition would overflow */
  SIZE_LIMIT_ERROR_EXCEEDED  /**< Exceeds maximum allowed size */
} size_limit_result_t;

/** Generic size limit validation logic.
 *
 * Validates that adding output_len to total stays within max_size bounds
 * without overflow. This is the single source of truth for size validation
 * used by both encode and decode paths.
 *
 * @param total Current accumulated size
 * @param output_len Size to be added
 * @param max_size Maximum allowed total (SIZE_MAX means no limit)
 * @return Size limit validation result
 */
static size_limit_result_t
check_size_limits_generic (size_t total, size_t output_len, size_t max_size)
{
  size_t potential;

  if (output_len == 0)
    return SIZE_LIMIT_OK;

  if (!SocketSecurity_check_size (output_len))
    return SIZE_LIMIT_ERROR_SIZE;

  if (!SocketSecurity_check_add (total, output_len, &potential))
    return SIZE_LIMIT_ERROR_OVERFLOW;

  if (max_size != SIZE_MAX && potential > max_size)
    return SIZE_LIMIT_ERROR_EXCEEDED;

  return SIZE_LIMIT_OK;
}

/** Check decode output limits (returns SocketHTTP1_Result).
 *
 * Wrapper that converts generic size validation to decode-specific result type.
 */
static SocketHTTP1_Result
check_decode_output_limits (size_t total, size_t output_len, size_t max_size)
{
  switch (check_size_limits_generic (total, output_len, max_size))
    {
    case SIZE_LIMIT_OK:
      return HTTP1_OK;
    case SIZE_LIMIT_ERROR_SIZE:
      return HTTP1_ERROR;
    case SIZE_LIMIT_ERROR_OVERFLOW:
    case SIZE_LIMIT_ERROR_EXCEEDED:
      return HTTP1_ERROR_BODY_TOO_LARGE;
    }
  return HTTP1_ERROR; /* Unreachable, silence compiler warning */
}

/** Update decode total and check limits (returns SocketHTTP1_Result).
 *
 * Updates the running total and validates it stays within max_size.
 * Uses overflow-safe addition to prevent wraparound attacks.
 */
static SocketHTTP1_Result
update_decode_total (size_t *total, size_t written, size_t max_size)
{
  if (!SocketSecurity_check_add (*total, written, total))
    return HTTP1_ERROR_BODY_TOO_LARGE;
  if (max_size != SIZE_MAX && *total > max_size)
    return HTTP1_ERROR_BODY_TOO_LARGE;
  return HTTP1_OK;
}

/** Check encode output limits (returns int: 1=ok, 0=error).
 *
 * Wrapper that converts generic size validation to encode-specific result type.
 */
static int
check_encode_output_limits (size_t total, size_t output_len, size_t max_size)
{
  return check_size_limits_generic (total, output_len, max_size)
                 == SIZE_LIMIT_OK
             ? 1
             : 0;
}

/** Update encode total and check limits (returns int: 1=ok, 0=error).
 *
 * Updates the running total and validates it stays within max_size.
 * Uses overflow-safe addition to prevent wraparound attacks.
 */
static int
update_encode_total (size_t *total, size_t produced, size_t max_size)
{
  if (!SocketSecurity_check_add (*total, produced, total))
    return 0;
  if (max_size != SIZE_MAX && *total > max_size)
    return 0;
  return 1;
}

static size_t
get_effective_max_decompressed_size (const SocketHTTP1_Config *cfg)
{
  if (cfg == NULL || cfg->max_decompressed_size == 0)
    return SOCKET_SECURITY_MAX_DECOMPRESSED_SIZE;
  return cfg->max_decompressed_size;
}

#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE

/**
 * Map HTTP compression level to DEFLATE level.
 */
static int
map_compress_level_to_native (SocketHTTP1_CompressLevel level)
{
  switch (level)
    {
    case HTTP1_COMPRESS_FAST:
      return DEFLATE_LEVEL_FAST;
    case HTTP1_COMPRESS_BEST:
      return DEFLATE_LEVEL_BEST;
    default:
      return DEFLATE_LEVEL_DEFAULT;
    }
}

/**
 * Detect zlib-wrapped DEFLATE (RFC 1950 wrapper around RFC 1951).
 *
 * Many servers incorrectly send zlib-wrapped data for Content-Encoding:
 * deflate, even though RFC 2616 specifies raw DEFLATE (RFC 1951). This
 * function detects the zlib header to allow auto-handling.
 *
 * Per RFC 1950 Section 2.2:
 * - CMF byte: low 4 bits = compression method (8 = deflate)
 *             high 4 bits = window size (0-7 for 32KB max)
 * - FLG byte: FCHECK bits such that (CMF * 256 + FLG) % 31 == 0
 *
 * @param data  Input buffer (at least 2 bytes)
 * @param len   Length of input buffer
 * @return 1 if zlib wrapper detected, 0 otherwise
 */
static int
detect_zlib_wrapper (const uint8_t *data, size_t len)
{
  uint16_t header;

  if (len < 2)
    return 0;

  /* Check compression method (low 4 bits of CMF must be 8 for deflate) */
  if ((data[0] & 0x0F) != 8)
    return 0;

  /* Check window size (high 4 bits of CMF <= 7 for 32KB window) */
  if ((data[0] & 0xF0) > 0x70)
    return 0;

  /* Verify zlib header checksum: (CMF * 256 + FLG) % 31 == 0 */
  header = ((uint16_t)data[0] << 8) | data[1];
  return (header % 31 == 0);
}

static int
init_native_deflate_decoder (SocketHTTP1_Decoder_T decoder)
{
  /* Initialize fixed Huffman tables (required for decoding fixed blocks) */
  if (SocketDeflate_fixed_tables_init (decoder->arena) != DEFLATE_OK)
    return 0;

  /* Initialize the inflater with bomb protection limit */
  decoder->state.native.inflater = SocketDeflate_Inflater_new (
      decoder->arena, decoder->max_decompressed_size);
  if (!decoder->state.native.inflater)
    return 0;

  decoder->state.native.crc = 0;
  decoder->state.native.total_out = 0;
  decoder->state.native.header_parsed = 0;
  decoder->state.native.is_gzip = (decoder->coding == HTTP_CODING_GZIP);
  decoder->state.native.zlib_wrapped = 0;
  decoder->state.native.trailer_verified = 0;
  decoder->state.native.trailer_pos = 0;
  decoder->initialized = 1;

  return 1;
}

static int
init_native_deflate_encoder (SocketHTTP1_Encoder_T encoder)
{
  int level = map_compress_level_to_native (encoder->level);

  encoder->state.native.deflater
      = SocketDeflate_Deflater_new (encoder->arena, level);
  if (!encoder->state.native.deflater)
    return 0;

  encoder->state.native.crc = 0;
  encoder->state.native.total_in = 0;
  encoder->state.native.is_gzip = (encoder->coding == HTTP_CODING_GZIP);
  encoder->state.native.header_written = 0;
  encoder->initialized = 1;

  return 1;
}

static void
cleanup_native_decoder (SocketHTTP1_Decoder_T decoder)
{
  /* Arena handles memory cleanup - nothing to do */
  (void)decoder;
}

static void
cleanup_native_encoder (SocketHTTP1_Encoder_T encoder)
{
  /* Arena handles memory cleanup - nothing to do */
  (void)encoder;
}

/**
 * Write gzip header to output buffer.
 *
 * Minimal gzip header per RFC 1952:
 * - ID1, ID2: 0x1F, 0x8B (magic)
 * - CM: 8 (deflate)
 * - FLG: 0 (no optional fields)
 * - MTIME: 0 (no timestamp)
 * - XFL: 0
 * - OS: 255 (unknown)
 *
 * @param output     Output buffer (must have at least 10 bytes)
 * @param output_len Output buffer size
 * @return Bytes written (10), or 0 if buffer too small
 */
static size_t
write_gzip_header (uint8_t *output, size_t output_len)
{
  if (output_len < GZIP_HEADER_MIN_SIZE)
    return 0;

  output[0] = GZIP_MAGIC_0;
  output[1] = GZIP_MAGIC_1;
  output[2] = GZIP_METHOD_DEFLATE;
  output[3] = 0; /* FLG */
  output[4] = 0; /* MTIME[0] */
  output[5] = 0; /* MTIME[1] */
  output[6] = 0; /* MTIME[2] */
  output[7] = 0; /* MTIME[3] */
  output[8] = 0; /* XFL */
  output[9] = GZIP_OS_UNKNOWN;

  return GZIP_HEADER_MIN_SIZE;
}

/**
 * Write gzip trailer to output buffer.
 *
 * @param output     Output buffer (must have at least 8 bytes)
 * @param output_len Output buffer size
 * @param crc        CRC32 of uncompressed data
 * @param size       Original size (mod 2^32) of uncompressed data
 * @return Bytes written (8), or 0 if buffer too small
 */
static size_t
write_gzip_trailer (uint8_t *output,
                    size_t output_len,
                    uint32_t crc,
                    uint32_t size)
{
  if (output_len < GZIP_TRAILER_SIZE)
    return 0;

  /* CRC32 (little-endian) */
  output[0] = (uint8_t)(crc & 0xFF);
  output[1] = (uint8_t)((crc >> 8) & 0xFF);
  output[2] = (uint8_t)((crc >> 16) & 0xFF);
  output[3] = (uint8_t)((crc >> 24) & 0xFF);

  /* ISIZE (little-endian) */
  output[4] = (uint8_t)(size & 0xFF);
  output[5] = (uint8_t)((size >> 8) & 0xFF);
  output[6] = (uint8_t)((size >> 16) & 0xFF);
  output[7] = (uint8_t)((size >> 24) & 0xFF);

  return GZIP_TRAILER_SIZE;
}

/**
 * Parse gzip header from input data.
 *
 * @return Header size on success, 0 if incomplete, -1 on error
 */
static int
parse_gzip_header (const uint8_t *data, size_t len)
{
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result res;

  res = SocketDeflate_gzip_parse_header (data, len, &header);
  if (res == DEFLATE_INCOMPLETE)
    return 0;
  if (res != DEFLATE_OK)
    return -1;

  return (int)header.header_size;
}

/**
 * Collect trailer bytes after DEFLATE stream completes.
 * For gzip: 8 bytes (CRC32 + ISIZE)
 * For zlib: 4 bytes (Adler-32)
 *
 * @return Bytes consumed from input
 */
static size_t
collect_trailer_bytes (SocketHTTP1_Decoder_T decoder,
                       const uint8_t *data,
                       size_t len)
{
  size_t trailer_size = decoder->state.native.is_gzip ? GZIP_TRAILER_SIZE : 4;
  size_t need = trailer_size - decoder->state.native.trailer_pos;
  size_t take = (len < need) ? len : need;

  memcpy (decoder->state.native.trailer_buf + decoder->state.native.trailer_pos,
          data,
          take);
  decoder->state.native.trailer_pos += take;

  return take;
}

/**
 * Check if more gzip members follow after current trailer.
 * Per RFC 1952 Section 2.2, members are concatenated with no delimiter.
 *
 * @param data    Input buffer positioned after current trailer
 * @param len     Remaining bytes in buffer
 * @return 1 if next member detected, 0 if end of stream, -1 if incomplete
 */
static int
check_next_gzip_member (const uint8_t *data, size_t len)
{
  if (len == 0)
    return 0; /* No more data - end of stream */
  if (len < 2)
    return -1; /* Need at least 2 bytes to check magic */
  if (data[0] == GZIP_MAGIC_0 && data[1] == GZIP_MAGIC_1)
    return 1; /* Next member found */
  return 0;   /* Not gzip magic - end of stream or garbage */
}

/**
 * Reset decoder state for next gzip member.
 * Called after successfully verifying a member's trailer.
 */
static void
reset_for_next_member (SocketHTTP1_Decoder_T decoder)
{
  /* Reset per-member state */
  decoder->state.native.crc = 0;
  decoder->state.native.total_out = 0;
  decoder->state.native.header_parsed = 0;
  decoder->state.native.trailer_verified = 0;
  decoder->state.native.trailer_pos = 0;

  /* Reset inflater for new DEFLATE stream */
  SocketDeflate_Inflater_reset (decoder->state.native.inflater);
}

/**
 * Verify gzip trailer (CRC32 and ISIZE).
 *
 * @return 1 on success, 0 if incomplete, -1 on verification failure
 */
static int
verify_gzip_trailer (SocketHTTP1_Decoder_T decoder)
{
  uint32_t stored_crc, stored_size;
  const uint8_t *trailer = decoder->state.native.trailer_buf;

  if (decoder->state.native.trailer_pos < GZIP_TRAILER_SIZE)
    return 0; /* Need more trailer bytes */

  /* Extract CRC32 (little-endian) */
  stored_crc = (uint32_t)trailer[0] | ((uint32_t)trailer[1] << 8)
               | ((uint32_t)trailer[2] << 16) | ((uint32_t)trailer[3] << 24);

  /* Extract ISIZE (little-endian, original size mod 2^32) */
  stored_size = (uint32_t)trailer[4] | ((uint32_t)trailer[5] << 8)
                | ((uint32_t)trailer[6] << 16) | ((uint32_t)trailer[7] << 24);

  /* Verify CRC32 */
  if (stored_crc != decoder->state.native.crc)
    return -1;

  /* Verify ISIZE (mod 2^32) */
  if (stored_size != (uint32_t)decoder->state.native.total_out)
    return -1;

  return 1;
}

/**
 * decode_native_parse_header - Parse gzip/zlib header if not yet parsed
 *
 * Checks header_parsed flag and returns immediately if already done.
 * Advances *data_ptr and *data_len_ptr past the header on success.
 *
 * Returns: 0 on success, 1 if incomplete (need more data), -1 on error
 */
static int
decode_native_parse_header (SocketHTTP1_Decoder_T decoder,
                            const uint8_t **data_ptr,
                            size_t *data_len_ptr,
                            size_t *consumed)
{
  int header_size = 0;

  if (decoder->state.native.header_parsed)
    return 0;

  if (decoder->state.native.is_gzip)
    {
      header_size = parse_gzip_header (*data_ptr, *data_len_ptr);
      if (header_size < 0)
        return -1;
      if (header_size == 0)
        return 1;
    }
  else if (detect_zlib_wrapper (*data_ptr, *data_len_ptr))
    {
      header_size = 2;
      decoder->state.native.zlib_wrapped = 1;
    }

  *data_ptr += header_size;
  *data_len_ptr -= header_size;
  *consumed += header_size;
  decoder->state.native.header_parsed = 1;
  return 0;
}

/**
 * decode_native_handle_finished - Handle completed DEFLATE stream
 *
 * Processes trailers for gzip (with multi-member support) and zlib streams,
 * or finishes immediately for raw deflate.
 *
 * Returns: 1 if result_out was set (caller should return it),
 *          0 if no result (continue to inflate),
 *         -1 if multi-member reset happened (re-parse header then inflate)
 */
static int
decode_native_handle_finished (SocketHTTP1_Decoder_T decoder,
                               const uint8_t **data_ptr,
                               size_t *data_len_ptr,
                               size_t *consumed,
                               SocketHTTP1_Result *result_out)
{
  while (SocketDeflate_Inflater_finished (decoder->state.native.inflater))
    {
      if (decoder->state.native.is_gzip)
        {
          size_t collected
              = collect_trailer_bytes (decoder, *data_ptr, *data_len_ptr);
          *consumed += collected;
          *data_ptr += collected;
          *data_len_ptr -= collected;

          if (decoder->state.native.trailer_pos < GZIP_TRAILER_SIZE)
            {
              *result_out = HTTP1_INCOMPLETE;
              return 1;
            }

          if (!decoder->state.native.trailer_verified)
            {
              int verify = verify_gzip_trailer (decoder);
              if (verify < 0)
                {
                  *result_out = HTTP1_ERROR;
                  return 1;
                }
              decoder->state.native.trailer_verified = 1;
            }

          int next = check_next_gzip_member (*data_ptr, *data_len_ptr);
          if (next < 0)
            {
              *result_out = HTTP1_INCOMPLETE;
              return 1;
            }
          if (next == 0)
            {
              decoder->finished = 1;
              *result_out = HTTP1_OK;
              return 1;
            }

          reset_for_next_member (decoder);
          return -1; /* Re-parse header for next member */
        }
      else if (decoder->state.native.zlib_wrapped)
        {
          size_t collected
              = collect_trailer_bytes (decoder, *data_ptr, *data_len_ptr);
          *consumed += collected;
          (void)collected;
          if (decoder->state.native.trailer_pos < 4)
            {
              *result_out = HTTP1_INCOMPLETE;
              return 1;
            }
          decoder->finished = 1;
          *result_out = HTTP1_OK;
          return 1;
        }
      else
        {
          decoder->finished = 1;
          *result_out = HTTP1_OK;
          return 1;
        }
    }
  return 0;
}

static SocketHTTP1_Result
decode_native_deflate (SocketHTTP1_Decoder_T decoder,
                       const unsigned char *input,
                       size_t input_len,
                       size_t *consumed,
                       unsigned char *output,
                       size_t output_len,
                       size_t *written)
{
  SocketDeflate_Result res;
  const uint8_t *data = input;
  size_t data_len = input_len;
  int rc;
  SocketHTTP1_Result result;

  *consumed = 0;
  *written = 0;

  /* Parse header (first call or after multi-member reset) */
  rc = decode_native_parse_header (decoder, &data, &data_len, consumed);
  if (rc != 0)
    return rc < 0 ? HTTP1_ERROR : HTTP1_INCOMPLETE;

  /* Handle completed DEFLATE stream (trailers, multi-member gzip) */
  rc = decode_native_handle_finished (
      decoder, &data, &data_len, consumed, &result);
  if (rc == 1)
    return result;

  /* Multi-member reset: re-parse next member's header */
  if (rc == -1)
    {
      rc = decode_native_parse_header (decoder, &data, &data_len, consumed);
      if (rc != 0)
        return rc < 0 ? HTTP1_ERROR : HTTP1_INCOMPLETE;
    }

  /* Inflate DEFLATE data */
  if (data_len > 0 && output_len > 0)
    {
      size_t inf_consumed = 0;
      size_t inf_written = 0;

      res = SocketDeflate_Inflater_inflate (decoder->state.native.inflater,
                                            data,
                                            data_len,
                                            &inf_consumed,
                                            output,
                                            output_len,
                                            &inf_written);

      *consumed += inf_consumed;
      *written = inf_written;

      /* Update CRC for gzip */
      if (decoder->state.native.is_gzip && inf_written > 0)
        {
          decoder->state.native.crc = SocketDeflate_crc32 (
              decoder->state.native.crc, output, inf_written);
          decoder->state.native.total_out += inf_written;
        }

      if (res == DEFLATE_ERROR_BOMB)
        return HTTP1_ERROR_BODY_TOO_LARGE;

      if (res == DEFLATE_OK)
        {
          size_t actual = SocketDeflate_Inflater_actual_consumed (
              decoder->state.native.inflater);
          size_t remaining = data_len - actual;
          if (remaining > 0
              && (decoder->state.native.is_gzip
                  || decoder->state.native.zlib_wrapped))
            {
              size_t collected
                  = collect_trailer_bytes (decoder, data + actual, remaining);
              *consumed = *consumed - inf_consumed + actual + collected;
            }

          if (!decoder->state.native.is_gzip
              && !decoder->state.native.zlib_wrapped)
            {
              decoder->finished = 1;
              return HTTP1_OK;
            }
          return HTTP1_INCOMPLETE;
        }

      if (res == DEFLATE_INCOMPLETE || res == DEFLATE_OUTPUT_FULL)
        return HTTP1_INCOMPLETE;

      return HTTP1_ERROR;
    }

  return HTTP1_INCOMPLETE;
}

static SocketHTTP1_Result
finish_native_decode (SocketHTTP1_Decoder_T decoder,
                      unsigned char *output,
                      size_t output_len,
                      size_t *written)
{
  (void)output;
  (void)output_len;
  *written = 0;

  if (!SocketDeflate_Inflater_finished (decoder->state.native.inflater))
    return HTTP1_INCOMPLETE;

  /* Verify gzip trailer (skip if already verified in decode loop) */
  if (decoder->state.native.is_gzip && !decoder->state.native.trailer_verified)
    {
      int verify_result = verify_gzip_trailer (decoder);
      if (verify_result == 0)
        return HTTP1_INCOMPLETE; /* Need more trailer bytes */
      if (verify_result < 0)
        return HTTP1_ERROR; /* CRC or size mismatch */
    }

  /* For zlib-wrapped, we collected the Adler-32 but don't verify it
   * (would need to track running Adler-32 which we don't) */

  decoder->finished = 1;
  return HTTP1_OK;
}

static ssize_t
encode_native_deflate (SocketHTTP1_Encoder_T encoder,
                       const unsigned char *input,
                       size_t input_len,
                       unsigned char *output,
                       size_t output_len,
                       int flush)
{
  SocketDeflate_Result res;
  size_t header_size = 0;
  size_t def_consumed = 0;
  size_t def_written = 0;
  uint8_t *out_ptr = output;
  size_t out_remain = output_len;

  /* Write gzip header on first call */
  if (encoder->state.native.is_gzip && !encoder->state.native.header_written)
    {
      header_size = write_gzip_header (out_ptr, out_remain);
      if (header_size == 0)
        return -1;
      out_ptr += header_size;
      out_remain -= header_size;
      encoder->state.native.header_written = 1;
    }

  /* Update CRC for gzip */
  if (encoder->state.native.is_gzip && input_len > 0)
    {
      encoder->state.native.crc
          = SocketDeflate_crc32 (encoder->state.native.crc, input, input_len);
      encoder->state.native.total_in += input_len;
    }

  /* Compress data */
  res = SocketDeflate_Deflater_deflate (encoder->state.native.deflater,
                                        input,
                                        input_len,
                                        &def_consumed,
                                        out_ptr,
                                        out_remain,
                                        &def_written);

  (void)flush; /* Native DEFLATE handles flushing internally */

  if (res != DEFLATE_OK && res != DEFLATE_OUTPUT_FULL)
    return -1;

  return (ssize_t)(header_size + def_written);
}

static ssize_t
finish_native_encode (SocketHTTP1_Encoder_T encoder,
                      unsigned char *output,
                      size_t output_len)
{
  SocketDeflate_Result res;
  size_t def_written = 0;
  size_t trailer_size = 0;
  uint8_t *out_ptr = output;
  size_t out_remain = output_len;

  /* Finish the DEFLATE stream */
  res = SocketDeflate_Deflater_finish (
      encoder->state.native.deflater, out_ptr, out_remain, &def_written);

  if (res != DEFLATE_OK && res != DEFLATE_OUTPUT_FULL)
    return -1;

  out_ptr += def_written;
  out_remain -= def_written;

  /* Write gzip trailer */
  if (encoder->state.native.is_gzip
      && SocketDeflate_Deflater_finished (encoder->state.native.deflater))
    {
      trailer_size
          = write_gzip_trailer (out_ptr,
                                out_remain,
                                encoder->state.native.crc,
                                (uint32_t)encoder->state.native.total_in);
      if (trailer_size == 0 && out_remain < GZIP_TRAILER_SIZE)
        return (ssize_t)def_written; /* Need more space for trailer */
    }

  if (SocketDeflate_Deflater_finished (encoder->state.native.deflater))
    encoder->finished = 1;

  return (ssize_t)(def_written + trailer_size);
}

#endif /* SOCKETHTTP1_HAS_NATIVE_DEFLATE */

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

  if (deflateInit2 (&encoder->state.zlib,
                    zlib_level,
                    Z_DEFLATED,
                    window_bits,
                    ZLIB_MEM_LEVEL_DEFAULT,
                    Z_DEFAULT_STRATEGY)
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
decode_zlib (SocketHTTP1_Decoder_T decoder,
             const unsigned char *input,
             size_t input_len,
             size_t *consumed,
             unsigned char *output,
             size_t output_len,
             size_t *written)
{
  int ret;
  z_stream *s = &decoder->state.zlib;

  /* Runtime check - don't rely on assert which compiles out in release */
  if (input_len > ZLIB_MAX_BUFFER_SIZE || output_len > ZLIB_MAX_BUFFER_SIZE)
    return HTTP1_ERROR;

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
finish_zlib_decode (SocketHTTP1_Decoder_T decoder,
                    unsigned char *output,
                    size_t output_len,
                    size_t *written)
{
  int ret;
  z_stream *s = &decoder->state.zlib;

  /* Runtime check - don't rely on assert which compiles out in release */
  if (output_len > ZLIB_MAX_BUFFER_SIZE)
    return HTTP1_ERROR;

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
encode_zlib (SocketHTTP1_Encoder_T encoder,
             const unsigned char *input,
             size_t input_len,
             unsigned char *output,
             size_t output_len,
             int flush)
{
  int ret;
  int zlib_flush = flush ? Z_SYNC_FLUSH : Z_NO_FLUSH;
  z_stream *s = &encoder->state.zlib;

  /* Runtime check - don't rely on assert which compiles out in release */
  if (input_len > ZLIB_MAX_BUFFER_SIZE || output_len > ZLIB_MAX_BUFFER_SIZE)
    return -1;

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
finish_zlib_encode (SocketHTTP1_Encoder_T encoder,
                    unsigned char *output,
                    size_t output_len)
{
  int ret;
  size_t produced;
  z_stream *s = &encoder->state.zlib;

  /* Runtime check - don't rely on assert which compiles out in release */
  if (output_len > ZLIB_MAX_BUFFER_SIZE)
    return -1;

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

  BrotliEncoderSetParameter (
      encoder->state.brotli, BROTLI_PARAM_QUALITY, (uint32_t)quality);

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
decode_brotli (SocketHTTP1_Decoder_T decoder,
               const unsigned char *input,
               size_t input_len,
               size_t *consumed,
               unsigned char *output,
               size_t output_len,
               size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in = input_len;
  size_t avail_out = output_len;
  const uint8_t *next_in = input;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;

  ret = BrotliDecoderDecompressStream (
      decoder->state.brotli, &avail_in, &next_in, &avail_out, &next_out, NULL);

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
finish_brotli_decode (SocketHTTP1_Decoder_T decoder,
                      unsigned char *output,
                      size_t output_len,
                      size_t *written)
{
  BrotliDecoderResult ret;
  size_t avail_in = 0;
  size_t avail_out = output_len;
  const uint8_t *next_in = NULL;
  uint8_t *next_out = output_len > 0 ? output : NULL;

  ret = BrotliDecoderDecompressStream (
      decoder->state.brotli, &avail_in, &next_in, &avail_out, &next_out, NULL);
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
encode_brotli (SocketHTTP1_Encoder_T encoder,
               const unsigned char *input,
               size_t input_len,
               unsigned char *output,
               size_t output_len,
               int flush)
{
  size_t avail_in = input_len;
  size_t avail_out = output_len;
  const uint8_t *next_in = input;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;
  BrotliEncoderOperation op
      = flush ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;

  if (!BrotliEncoderCompressStream (encoder->state.brotli,
                                    op,
                                    &avail_in,
                                    &next_in,
                                    &avail_out,
                                    &next_out,
                                    NULL))
    return -1;

  return (ssize_t)(output_len - avail_out);
}

static ssize_t
finish_brotli_encode (SocketHTTP1_Encoder_T encoder,
                      unsigned char *output,
                      size_t output_len)
{
  size_t avail_in = 0;
  size_t avail_out = output_len;
  const uint8_t *next_in = NULL;
  uint8_t *next_out = output_len > 0 ? (uint8_t *)output : NULL;

  if (!BrotliEncoderCompressStream (encoder->state.brotli,
                                    BROTLI_OPERATION_FINISH,
                                    &avail_in,
                                    &next_in,
                                    &avail_out,
                                    &next_out,
                                    NULL))
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
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return init_native_deflate_decoder (decoder);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      cleanup_native_decoder (decoder);
      break;
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
dispatch_decode (SocketHTTP1_Decoder_T decoder,
                 const unsigned char *input,
                 size_t input_len,
                 size_t *consumed,
                 unsigned char *output,
                 size_t output_len,
                 size_t *written)
{
  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return decode_native_deflate (
          decoder, input, input_len, consumed, output, output_len, written);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return decode_zlib (
          decoder, input, input_len, consumed, output, output_len, written);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return decode_brotli (
          decoder, input, input_len, consumed, output, output_len, written);
#endif

    default:
      return HTTP1_ERROR;
    }
}

static SocketHTTP1_Result
dispatch_decode_finish (SocketHTTP1_Decoder_T decoder,
                        unsigned char *output,
                        size_t output_len,
                        size_t *written)
{
  switch (decoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return finish_native_decode (decoder, output, output_len, written);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return init_native_deflate_encoder (encoder);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      cleanup_native_encoder (encoder);
      break;
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
dispatch_encode (SocketHTTP1_Encoder_T encoder,
                 const unsigned char *input,
                 size_t input_len,
                 unsigned char *output,
                 size_t output_len,
                 int flush)
{
  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return encode_native_deflate (
          encoder, input, input_len, output, output_len, flush);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return encode_zlib (encoder, input, input_len, output, output_len, flush);
#endif

#ifdef SOCKETHTTP1_HAS_BROTLI
    case HTTP_CODING_BR:
      return encode_brotli (
          encoder, input, input_len, output, output_len, flush);
#endif

    default:
      return -1;
    }
}

static ssize_t
dispatch_encode_finish (SocketHTTP1_Encoder_T encoder,
                        unsigned char *output,
                        size_t output_len)
{
  switch (encoder->coding)
    {
#ifdef SOCKETHTTP1_HAS_NATIVE_DEFLATE
    case HTTP_CODING_GZIP:
    case HTTP_CODING_DEFLATE:
      return finish_native_encode (encoder, output, output_len);
#elif defined(SOCKETHTTP1_HAS_ZLIB)
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
                         const SocketHTTP1_Config *cfg,
                         Arena_T arena)
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
                            const unsigned char *input,
                            size_t input_len,
                            size_t *consumed,
                            unsigned char *output,
                            size_t output_len,
                            size_t *written)
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

  limit_res = check_decode_output_limits (
      decoder->total_decompressed, output_len, decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  if (!decoder->initialized)
    return HTTP1_ERROR;

  res = dispatch_decode (
      decoder, input, input_len, consumed, output, output_len, written);

  limit_res = update_decode_total (
      &decoder->total_decompressed, *written, decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  return res;
}

SocketHTTP1_Result
SocketHTTP1_Decoder_finish (SocketHTTP1_Decoder_T decoder,
                            unsigned char *output,
                            size_t output_len,
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

  if (output_len > ZLIB_MAX_BUFFER_SIZE)
    return HTTP1_ERROR;

  limit_res = check_decode_output_limits (
      decoder->total_decompressed, output_len, decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  if (!decoder->initialized)
    return HTTP1_ERROR;

  res = dispatch_decode_finish (decoder, output, output_len, written);

  limit_res = update_decode_total (
      &decoder->total_decompressed, *written, decoder->max_decompressed_size);
  if (limit_res != HTTP1_OK)
    return limit_res;

  return res;
}

SocketHTTP1_Encoder_T
SocketHTTP1_Encoder_new (SocketHTTP_Coding coding,
                         SocketHTTP1_CompressLevel level,
                         const SocketHTTP1_Config *cfg,
                         Arena_T arena)
{
  SocketHTTP1_Encoder_T encoder;

  (void)cfg; /* Currently unused, reserved for future configuration */
  assert (arena);

  if (!is_supported_coding (coding))
    return NULL;

  encoder = CALLOC (arena, 1, sizeof (*encoder));
  if (!encoder)
    return NULL;

  encoder->coding = coding;
  encoder->arena = arena;
  encoder->level = level;
  encoder->max_encoded_size = SIZE_MAX; /* No current limit on encoded size */

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
                            const unsigned char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_len,
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

  if (!check_encode_output_limits (
          encoder->total_encoded, output_len, encoder->max_encoded_size))
    return -1;

  if (!encoder->initialized)
    return -1;

  res = dispatch_encode (encoder, input, input_len, output, output_len, flush);

  if (res > 0)
    {
      if (!update_encode_total (
              &encoder->total_encoded, (size_t)res, encoder->max_encoded_size))
        return -1;
    }

  return res;
}

ssize_t
SocketHTTP1_Encoder_finish (SocketHTTP1_Encoder_T encoder,
                            unsigned char *output,
                            size_t output_len)
{
  ssize_t res;

  assert (encoder);
  assert (output || output_len == 0);

  if (encoder->finished)
    return 0;

  if (output_len > ZLIB_MAX_BUFFER_SIZE)
    return -1;

  if (!check_encode_output_limits (
          encoder->total_encoded, output_len, encoder->max_encoded_size))
    return -1;

  if (!encoder->initialized)
    return -1;

  res = dispatch_encode_finish (encoder, output, output_len);

  if (res > 0)
    {
      if (!update_encode_total (
              &encoder->total_encoded, (size_t)res, encoder->max_encoded_size))
        return -1;
    }

  return res;
}

#undef T_DECODER
#undef T_ENCODER

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

/* Empty file when compression not enabled */

#endif /* SOCKETHTTP1_HAS_COMPRESSION */
