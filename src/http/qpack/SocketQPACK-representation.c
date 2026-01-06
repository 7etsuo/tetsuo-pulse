/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-representation.c
 * @brief QPACK Indexed Field Line representation (RFC 9204 Section 4.5.2).
 *
 * Implements encoding and decoding of QPACK Indexed Field Line:
 * - Pattern: 1T followed by 6-bit indexed value
 * - T=1: Static table index (0-98)
 * - T=0: Dynamic table relative index (converted via Base)
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | T |      Index (6+)       |
 * +---+---+-----------------------+
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "http/SocketQPACK-private.h"

#include "core/SocketUtil.h"
#include "http/SocketHPACK.h" /* Reuse integer encoding from HPACK (RFC 7541) */

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *const qpack_result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC] = "Static index out of range (>98)",
  [QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC]
  = "Dynamic index out of range after Base conversion",
  [QPACK_ERROR_BASE_NOT_SET] = "Base not set for dynamic table access",
  [QPACK_ERROR_INTEGER_OVERFLOW] = "Integer overflow during decoding",
};

const char *
qpack_result_string (QPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_INTEGER_OVERFLOW)
    return "Unknown QPACK error";
  return qpack_result_strings[result];
}

/* ============================================================================
 * QPACK Static Table (RFC 9204 Appendix A)
 *
 * The QPACK static table has 99 entries (indices 0-98).
 * This differs from HPACK's 61 entries (indices 1-61).
 * ============================================================================
 */

/* clang-format off */
const QPACK_StaticEntry qpack_static_table[QPACK_STATIC_TABLE_SIZE] = {
  /* Index 0: :authority */
  { ":authority", "", 10, 0 },
  /* Index 1: :path / */
  { ":path", "/", 5, 1 },
  /* Index 2: age 0 */
  { "age", "0", 3, 1 },
  /* Index 3: content-disposition */
  { "content-disposition", "", 19, 0 },
  /* Index 4: content-length 0 */
  { "content-length", "0", 14, 1 },
  /* Index 5: cookie */
  { "cookie", "", 6, 0 },
  /* Index 6: date */
  { "date", "", 4, 0 },
  /* Index 7: etag */
  { "etag", "", 4, 0 },
  /* Index 8: if-modified-since */
  { "if-modified-since", "", 17, 0 },
  /* Index 9: if-none-match */
  { "if-none-match", "", 13, 0 },
  /* Index 10: last-modified */
  { "last-modified", "", 13, 0 },
  /* Index 11: link */
  { "link", "", 4, 0 },
  /* Index 12: location */
  { "location", "", 8, 0 },
  /* Index 13: referer */
  { "referer", "", 7, 0 },
  /* Index 14: set-cookie */
  { "set-cookie", "", 10, 0 },
  /* Index 15: :method CONNECT */
  { ":method", "CONNECT", 7, 7 },
  /* Index 16: :method DELETE */
  { ":method", "DELETE", 7, 6 },
  /* Index 17: :method GET */
  { ":method", "GET", 7, 3 },
  /* Index 18: :method HEAD */
  { ":method", "HEAD", 7, 4 },
  /* Index 19: :method OPTIONS */
  { ":method", "OPTIONS", 7, 7 },
  /* Index 20: :method POST */
  { ":method", "POST", 7, 4 },
  /* Index 21: :method PUT */
  { ":method", "PUT", 7, 3 },
  /* Index 22: :scheme http */
  { ":scheme", "http", 7, 4 },
  /* Index 23: :scheme https */
  { ":scheme", "https", 7, 5 },
  /* Index 24: :status 103 */
  { ":status", "103", 7, 3 },
  /* Index 25: :status 200 */
  { ":status", "200", 7, 3 },
  /* Index 26: :status 304 */
  { ":status", "304", 7, 3 },
  /* Index 27: :status 404 */
  { ":status", "404", 7, 3 },
  /* Index 28: :status 503 */
  { ":status", "503", 7, 3 },
  /* Index 29: accept * / * */
  { "accept", "*/*", 6, 3 },
  /* Index 30: accept application/dns-message */
  { "accept", "application/dns-message", 6, 23 },
  /* Index 31: accept-encoding gzip, deflate, br */
  { "accept-encoding", "gzip, deflate, br", 15, 17 },
  /* Index 32: accept-ranges bytes */
  { "accept-ranges", "bytes", 13, 5 },
  /* Index 33: access-control-allow-headers cache-control */
  { "access-control-allow-headers", "cache-control", 28, 13 },
  /* Index 34: access-control-allow-headers content-type */
  { "access-control-allow-headers", "content-type", 28, 12 },
  /* Index 35: access-control-allow-origin * */
  { "access-control-allow-origin", "*", 27, 1 },
  /* Index 36: cache-control max-age=0 */
  { "cache-control", "max-age=0", 13, 9 },
  /* Index 37: cache-control max-age=2592000 */
  { "cache-control", "max-age=2592000", 13, 15 },
  /* Index 38: cache-control max-age=604800 */
  { "cache-control", "max-age=604800", 13, 14 },
  /* Index 39: cache-control no-cache */
  { "cache-control", "no-cache", 13, 8 },
  /* Index 40: cache-control no-store */
  { "cache-control", "no-store", 13, 8 },
  /* Index 41: cache-control public, max-age=31536000 */
  { "cache-control", "public, max-age=31536000", 13, 24 },
  /* Index 42: content-encoding br */
  { "content-encoding", "br", 16, 2 },
  /* Index 43: content-encoding gzip */
  { "content-encoding", "gzip", 16, 4 },
  /* Index 44: content-type application/dns-message */
  { "content-type", "application/dns-message", 12, 23 },
  /* Index 45: content-type application/javascript */
  { "content-type", "application/javascript", 12, 22 },
  /* Index 46: content-type application/json */
  { "content-type", "application/json", 12, 16 },
  /* Index 47: content-type application/x-www-form-urlencoded */
  { "content-type", "application/x-www-form-urlencoded", 12, 33 },
  /* Index 48: content-type image/gif */
  { "content-type", "image/gif", 12, 9 },
  /* Index 49: content-type image/jpeg */
  { "content-type", "image/jpeg", 12, 10 },
  /* Index 50: content-type image/png */
  { "content-type", "image/png", 12, 9 },
  /* Index 51: content-type text/css */
  { "content-type", "text/css", 12, 8 },
  /* Index 52: content-type text/html; charset=utf-8 */
  { "content-type", "text/html; charset=utf-8", 12, 24 },
  /* Index 53: content-type text/plain */
  { "content-type", "text/plain", 12, 10 },
  /* Index 54: content-type text/plain;charset=utf-8 */
  { "content-type", "text/plain;charset=utf-8", 12, 24 },
  /* Index 55: range bytes=0- */
  { "range", "bytes=0-", 5, 8 },
  /* Index 56: strict-transport-security max-age=31536000 */
  { "strict-transport-security", "max-age=31536000", 25, 16 },
  /* Index 57: strict-transport-security max-age=31536000; includesubdomains */
  { "strict-transport-security", "max-age=31536000; includesubdomains", 25, 35 },
  /* Index 58: strict-transport-security max-age=31536000; includesubdomains; preload */
  { "strict-transport-security", "max-age=31536000; includesubdomains; preload", 25, 44 },
  /* Index 59: vary accept-encoding */
  { "vary", "accept-encoding", 4, 15 },
  /* Index 60: vary origin */
  { "vary", "origin", 4, 6 },
  /* Index 61: x-content-type-options nosniff */
  { "x-content-type-options", "nosniff", 22, 7 },
  /* Index 62: x-xss-protection 1; mode=block */
  { "x-xss-protection", "1; mode=block", 16, 13 },
  /* Index 63: :status 100 */
  { ":status", "100", 7, 3 },
  /* Index 64: :status 204 */
  { ":status", "204", 7, 3 },
  /* Index 65: :status 206 */
  { ":status", "206", 7, 3 },
  /* Index 66: :status 302 */
  { ":status", "302", 7, 3 },
  /* Index 67: :status 400 */
  { ":status", "400", 7, 3 },
  /* Index 68: :status 403 */
  { ":status", "403", 7, 3 },
  /* Index 69: :status 421 */
  { ":status", "421", 7, 3 },
  /* Index 70: :status 425 */
  { ":status", "425", 7, 3 },
  /* Index 71: :status 500 */
  { ":status", "500", 7, 3 },
  /* Index 72: accept-language */
  { "accept-language", "", 15, 0 },
  /* Index 73: access-control-allow-credentials FALSE */
  { "access-control-allow-credentials", "FALSE", 32, 5 },
  /* Index 74: access-control-allow-credentials TRUE */
  { "access-control-allow-credentials", "TRUE", 32, 4 },
  /* Index 75: access-control-allow-headers * */
  { "access-control-allow-headers", "*", 28, 1 },
  /* Index 76: access-control-allow-methods get */
  { "access-control-allow-methods", "get", 28, 3 },
  /* Index 77: access-control-allow-methods get, post, options */
  { "access-control-allow-methods", "get, post, options", 28, 18 },
  /* Index 78: access-control-allow-methods options */
  { "access-control-allow-methods", "options", 28, 7 },
  /* Index 79: access-control-expose-headers content-length */
  { "access-control-expose-headers", "content-length", 29, 14 },
  /* Index 80: access-control-request-headers content-type */
  { "access-control-request-headers", "content-type", 30, 12 },
  /* Index 81: access-control-request-method get */
  { "access-control-request-method", "get", 29, 3 },
  /* Index 82: access-control-request-method post */
  { "access-control-request-method", "post", 29, 4 },
  /* Index 83: alt-svc clear */
  { "alt-svc", "clear", 7, 5 },
  /* Index 84: authorization */
  { "authorization", "", 13, 0 },
  /* Index 85: content-security-policy script-src 'none'; object-src 'none'; base-uri 'none' */
  { "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'", 23, 52 },
  /* Index 86: early-data 1 */
  { "early-data", "1", 10, 1 },
  /* Index 87: expect-ct */
  { "expect-ct", "", 9, 0 },
  /* Index 88: forwarded */
  { "forwarded", "", 9, 0 },
  /* Index 89: if-range */
  { "if-range", "", 8, 0 },
  /* Index 90: origin */
  { "origin", "", 6, 0 },
  /* Index 91: purpose prefetch */
  { "purpose", "prefetch", 7, 8 },
  /* Index 92: server */
  { "server", "", 6, 0 },
  /* Index 93: timing-allow-origin * */
  { "timing-allow-origin", "*", 19, 1 },
  /* Index 94: upgrade-insecure-requests 1 */
  { "upgrade-insecure-requests", "1", 25, 1 },
  /* Index 95: user-agent */
  { "user-agent", "", 10, 0 },
  /* Index 96: x-forwarded-for */
  { "x-forwarded-for", "", 15, 0 },
  /* Index 97: x-frame-options deny */
  { "x-frame-options", "deny", 15, 4 },
  /* Index 98: x-frame-options sameorigin */
  { "x-frame-options", "sameorigin", 15, 10 },
};
/* clang-format on */

/* ============================================================================
 * Static Table Access
 * ============================================================================
 */

QPACK_Result
qpack_validate_static_index (uint32_t index)
{
  if (index > QPACK_STATIC_INDEX_MAX)
    return QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC;
  return QPACK_OK;
}

QPACK_Result
qpack_static_get (uint32_t index, const QPACK_StaticEntry **entry)
{
  if (entry == NULL)
    return QPACK_ERROR;

  QPACK_Result result = qpack_validate_static_index (index);
  if (result != QPACK_OK)
    return result;

  *entry = &qpack_static_table[index];
  return QPACK_OK;
}

/* ============================================================================
 * Base Offset Conversion (RFC 9204 Section 3.2.4)
 *
 * For dynamic table access, the wire format uses relative indices that
 * must be converted to absolute indices using the Base value from the
 * field section prefix.
 *
 * absolute_index = Base - 1 - relative_index
 * ============================================================================
 */

QPACK_Result
qpack_apply_base_offset (uint32_t relative_index,
                         const QPACK_DecoderContext *ctx,
                         uint32_t *absolute_out)
{
  if (ctx == NULL || absolute_out == NULL)
    return QPACK_ERROR;

  if (!ctx->base_is_set)
    return QPACK_ERROR_BASE_NOT_SET;

  /* Check for underflow: Base must be > relative_index */
  if (ctx->base == 0 || relative_index >= ctx->base)
    return QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC;

  *absolute_out = ctx->base - 1 - relative_index;

  /* Validate against max dynamic entries if set */
  if (ctx->max_dynamic > 0 && *absolute_out >= ctx->max_dynamic)
    return QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC;

  return QPACK_OK;
}

/* ============================================================================
 * Encoding Functions
 * ============================================================================
 */

ssize_t
qpack_encode_indexed_static (uint32_t index,
                             unsigned char *output,
                             size_t output_len)
{
  if (output == NULL || output_len == 0)
    return -1;

  /* Validate static index range */
  if (qpack_validate_static_index (index) != QPACK_OK)
    return -1;

  /* Use HPACK integer encoding with 6-bit prefix */
  unsigned char int_buf[16];
  size_t int_len
      = SocketHPACK_int_encode (index, QPACK_INDEXED_PREFIX_BITS, int_buf, 16);
  if (int_len == 0 || int_len > output_len)
    return -1;

  /* Set pattern bits: 1T where T=1 for static (0xC0) */
  output[0]
      = (QPACK_INDEXED_FIELD_MASK | QPACK_INDEXED_STATIC_BIT) | int_buf[0];

  /* Copy continuation bytes if any */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return (ssize_t)int_len;
}

ssize_t
qpack_encode_indexed_dynamic (uint32_t relative_index,
                              unsigned char *output,
                              size_t output_len)
{
  if (output == NULL || output_len == 0)
    return -1;

  /* Use HPACK integer encoding with 6-bit prefix */
  unsigned char int_buf[16];
  size_t int_len = SocketHPACK_int_encode (
      relative_index, QPACK_INDEXED_PREFIX_BITS, int_buf, 16);
  if (int_len == 0 || int_len > output_len)
    return -1;

  /* Set pattern bits: 1T where T=0 for dynamic (0x80) */
  output[0] = QPACK_INDEXED_FIELD_MASK | int_buf[0];

  /* Copy continuation bytes if any */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return (ssize_t)int_len;
}

/* ============================================================================
 * Decoding Functions
 * ============================================================================
 */

QPACK_Result
qpack_decode_indexed_field (const unsigned char *input,
                            size_t input_len,
                            const QPACK_DecoderContext *ctx,
                            struct QPACK_Representation_T *rep,
                            size_t *consumed)
{
  if (input == NULL || rep == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is an Indexed Field Line (high bit set) */
  if ((input[0] & QPACK_INDEXED_FIELD_MASK) == 0)
    return QPACK_ERROR_INVALID_INDEX;

  /* Extract type bit (T): 1 = static, 0 = dynamic */
  int is_static = (input[0] & QPACK_INDEXED_STATIC_BIT) != 0;

  /* Decode 6-bit prefixed integer */
  uint64_t index;
  size_t int_consumed;
  SocketHPACK_Result hpack_result = SocketHPACK_int_decode (
      input, input_len, QPACK_INDEXED_PREFIX_BITS, &index, &int_consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERROR_INTEGER_OVERFLOW;

  /* Check for 32-bit overflow */
  if (index > UINT32_MAX)
    return QPACK_ERROR_INTEGER_OVERFLOW;

  rep->type = QPACK_REP_INDEXED;
  rep->index = (uint32_t)index;
  rep->is_static = is_static;
  rep->absolute_idx = 0;

  if (is_static)
    {
      /* Validate static index */
      QPACK_Result result = qpack_validate_static_index (rep->index);
      if (result != QPACK_OK)
        return result;

      rep->absolute_idx = rep->index;
    }
  else
    {
      /* Dynamic table: convert relative to absolute via Base */
      if (ctx == NULL)
        return QPACK_ERROR_BASE_NOT_SET;

      QPACK_Result result
          = qpack_apply_base_offset (rep->index, ctx, &rep->absolute_idx);
      if (result != QPACK_OK)
        return result;
    }

  *consumed = int_consumed;
  return QPACK_OK;
}
