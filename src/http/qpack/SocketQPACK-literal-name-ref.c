/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-literal-name-ref.c
 * @brief QPACK Literal Field Line with Name Reference (RFC 9204 Section 4.5.4)
 *
 * Implements encoding and decoding for the Literal Field Line with Name
 * Reference representation used in QPACK encoded field sections. This
 * representation references a name from the static or dynamic table with
 * a literal value.
 *
 * Wire format (RFC 9204 Section 4.5.4):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | N | T |Name Index (4+)|
 * +---+---+---+---+---------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Bit pattern: 01NTxxxx
 * - Bits 7-6: Pattern = 01 (literal with name reference)
 * - Bit 5: N = Never-indexed bit (0=can cache, 1=must not cache)
 * - Bit 4: T = Table selection (0=dynamic, 1=static)
 * - Bits 3-0: First 4 bits of name index (continuation follows if >= 15)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.4
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/** Literal Field Line with Name Reference pattern mask: 01xxxxxx */
#define QPACK_LITERAL_NAMEREF_PATTERN 0x40

/** Pattern check mask (bits 7-6) */
#define QPACK_LITERAL_NAMEREF_PATTERN_MASK 0xC0

/** Never-indexed bit mask (bit 5) */
#define QPACK_LITERAL_NAMEREF_NEVER_INDEX 0x20

/** Static table bit mask (bit 4) */
#define QPACK_LITERAL_NAMEREF_STATIC 0x10

/** Name index prefix size in bits */
#define QPACK_LITERAL_NAMEREF_PREFIX 4

/** Huffman flag bit in value length byte (bit 7) */
#define QPACK_VALUE_HUFFMAN_FLAG 0x80

/** Huffman decoding expansion factor (worst case ~2x) */
#define QPACK_HUFFMAN_EXPANSION_FACTOR 2

/** Minimum Huffman decode buffer size in bytes */
#define QPACK_MIN_DECODE_BUFFER_SIZE 64

/** Value length prefix size in bits */
#define QPACK_VALUE_LENGTH_PREFIX 7

/** Maximum integer encoding buffer size */
#define QPACK_INT_ENCODE_BUF_SIZE 16

/**
 * @brief QPACK static table entry.
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
} QPACKStaticEntry;

/**
 * @brief QPACK static table (RFC 9204 Appendix A).
 *
 * 99 entries indexed from 0 to 98.
 */
static const QPACKStaticEntry qpack_static_table[] = {
  { ":authority", 10, "", 0 },
  { ":path", 5, "/", 1 },
  { "age", 3, "0", 1 },
  { "content-disposition", 19, "", 0 },
  { "content-length", 14, "0", 1 },
  { "cookie", 6, "", 0 },
  { "date", 4, "", 0 },
  { "etag", 4, "", 0 },
  { "if-modified-since", 17, "", 0 },
  { "if-none-match", 13, "", 0 },
  { "last-modified", 13, "", 0 },
  { "link", 4, "", 0 },
  { "location", 8, "", 0 },
  { "referer", 7, "", 0 },
  { "set-cookie", 10, "", 0 },
  { ":method", 7, "CONNECT", 7 },
  { ":method", 7, "DELETE", 6 },
  { ":method", 7, "GET", 3 },
  { ":method", 7, "HEAD", 4 },
  { ":method", 7, "OPTIONS", 7 },
  { ":method", 7, "POST", 4 },
  { ":method", 7, "PUT", 3 },
  { ":scheme", 7, "http", 4 },
  { ":scheme", 7, "https", 5 },
  { ":status", 7, "103", 3 },
  { ":status", 7, "200", 3 },
  { ":status", 7, "304", 3 },
  { ":status", 7, "404", 3 },
  { ":status", 7, "503", 3 },
  { "accept", 6, "*/*", 3 },
  { "accept", 6, "application/dns-message", 23 },
  { "accept-encoding", 15, "gzip, deflate, br", 17 },
  { "accept-ranges", 13, "bytes", 5 },
  { "access-control-allow-headers", 28, "cache-control", 13 },
  { "access-control-allow-headers", 28, "content-type", 12 },
  { "access-control-allow-origin", 27, "*", 1 },
  { "cache-control", 13, "max-age=0", 9 },
  { "cache-control", 13, "max-age=2592000", 15 },
  { "cache-control", 13, "max-age=604800", 14 },
  { "cache-control", 13, "no-cache", 8 },
  { "cache-control", 13, "no-store", 8 },
  { "cache-control", 13, "public, max-age=31536000", 24 },
  { "content-encoding", 16, "br", 2 },
  { "content-encoding", 16, "gzip", 4 },
  { "content-type", 12, "application/dns-message", 23 },
  { "content-type", 12, "application/javascript", 22 },
  { "content-type", 12, "application/json", 16 },
  { "content-type", 12, "application/x-www-form-urlencoded", 33 },
  { "content-type", 12, "image/gif", 9 },
  { "content-type", 12, "image/jpeg", 10 },
  { "content-type", 12, "image/png", 9 },
  { "content-type", 12, "text/css", 8 },
  { "content-type", 12, "text/html; charset=utf-8", 24 },
  { "content-type", 12, "text/plain", 10 },
  { "content-type", 12, "text/plain;charset=utf-8", 24 },
  { "range", 5, "bytes=0-", 8 },
  { "strict-transport-security", 25, "max-age=31536000", 16 },
  { "strict-transport-security",
    25,
    "max-age=31536000; includesubdomains",
    35 },
  { "strict-transport-security",
    25,
    "max-age=31536000; includesubdomains; preload",
    44 },
  { "vary", 4, "accept-encoding", 15 },
  { "vary", 4, "origin", 6 },
  { "x-content-type-options", 22, "nosniff", 7 },
  { "x-xss-protection", 16, "1; mode=block", 13 },
  { ":status", 7, "100", 3 },
  { ":status", 7, "204", 3 },
  { ":status", 7, "206", 3 },
  { ":status", 7, "302", 3 },
  { ":status", 7, "400", 3 },
  { ":status", 7, "403", 3 },
  { ":status", 7, "421", 3 },
  { ":status", 7, "425", 3 },
  { ":status", 7, "500", 3 },
  { "accept-language", 15, "", 0 },
  { "access-control-allow-credentials", 32, "FALSE", 5 },
  { "access-control-allow-credentials", 32, "TRUE", 4 },
  { "access-control-allow-headers", 28, "*", 1 },
  { "access-control-allow-methods", 28, "get", 3 },
  { "access-control-allow-methods", 28, "get, post, options", 18 },
  { "access-control-allow-methods", 28, "options", 7 },
  { "access-control-expose-headers", 29, "content-length", 14 },
  { "access-control-request-headers", 30, "content-type", 12 },
  { "access-control-request-method", 29, "get", 3 },
  { "access-control-request-method", 29, "post", 4 },
  { "alt-svc", 7, "clear", 5 },
  { "authorization", 13, "", 0 },
  { "content-security-policy",
    23,
    "script-src 'none'; object-src 'none'; base-uri 'none'",
    53 },
  { "early-data", 10, "1", 1 },
  { "expect-ct", 9, "", 0 },
  { "forwarded", 9, "", 0 },
  { "if-range", 8, "", 0 },
  { "origin", 6, "", 0 },
  { "purpose", 7, "prefetch", 8 },
  { "server", 6, "", 0 },
  { "timing-allow-origin", 19, "*", 1 },
  { "upgrade-insecure-requests", 25, "1", 1 },
  { "user-agent", 10, "", 0 },
  { "x-forwarded-for", 15, "", 0 },
  { "x-frame-options", 15, "deny", 4 },
  { "x-frame-options", 15, "sameorigin", 10 },
};

/**
 * @brief Get entry from QPACK static table (internal, name-only).
 */
static SocketQPACK_Result
qpack_static_get (uint64_t index, const char **name, size_t *name_len)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_ERR_INVALID_INDEX;

  *name = qpack_static_table[index].name;
  *name_len = qpack_static_table[index].name_len;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_static_table_get (uint64_t index,
                              const char **name,
                              size_t *name_len,
                              const char **value,
                              size_t *value_len)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_ERR_INVALID_INDEX;

  if (name != NULL)
    *name = qpack_static_table[index].name;
  if (name_len != NULL)
    *name_len = qpack_static_table[index].name_len;
  if (value != NULL)
    *value = qpack_static_table[index].value;
  if (value_len != NULL)
    *value_len = qpack_static_table[index].value_len;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_encode_literal_name_ref (unsigned char *output,
                                     size_t output_size,
                                     bool is_static,
                                     uint64_t name_index,
                                     bool never_indexed,
                                     const unsigned char *value,
                                     size_t value_len,
                                     bool use_huffman,
                                     size_t *bytes_written)
{
  unsigned char int_buf[QPACK_INT_ENCODE_BUF_SIZE];
  size_t pos = 0;
  size_t int_len;
  unsigned char first_byte;
  size_t huffman_len = 0;
  bool actually_use_huffman = false;

  /* Parameter validation */
  if (output == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (value == NULL && value_len > 0)
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * RFC 9204 Section 4.5.4: Build first byte
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 1 | N | T |Name Index (4+)|
   * +---+---+---+---+---------------+
   *
   * - Bits 7-6: Pattern = 01
   * - Bit 5: N = Never-indexed
   * - Bit 4: T = Static (1) or Dynamic (0)
   */
  first_byte = QPACK_LITERAL_NAMEREF_PATTERN; /* 01xxxxxx */
  if (never_indexed)
    first_byte |= QPACK_LITERAL_NAMEREF_NEVER_INDEX; /* bit 5 = N */
  if (is_static)
    first_byte |= QPACK_LITERAL_NAMEREF_STATIC; /* bit 4 = T */

  /* Encode name index with 4-bit prefix */
  int_len = SocketHPACK_int_encode (
      name_index, QPACK_LITERAL_NAMEREF_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_ERR_INTEGER;

  /* Merge first byte flags with integer encoding */
  int_buf[0] |= first_byte;

  /* Check if we have room for the index */
  if (pos + int_len > output_size)
    return QPACK_ERR_TABLE_SIZE;

  memcpy (output + pos, int_buf, int_len);
  pos += int_len;

  /* Determine if Huffman encoding is beneficial */
  if (use_huffman && value_len > 0)
    {
      huffman_len = SocketHPACK_huffman_encoded_size (value, value_len);
      if (huffman_len < value_len)
        actually_use_huffman = true;
    }

  /* Encode value length with 7-bit prefix */
  size_t encoded_value_len = actually_use_huffman ? huffman_len : value_len;
  int_len = SocketHPACK_int_encode (
      encoded_value_len, QPACK_VALUE_LENGTH_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set Huffman flag if using Huffman encoding */
  if (actually_use_huffman)
    int_buf[0] |= QPACK_VALUE_HUFFMAN_FLAG;

  /* Check if we have room for value length + value data */
  if (pos + int_len + encoded_value_len > output_size)
    return QPACK_ERR_TABLE_SIZE;

  memcpy (output + pos, int_buf, int_len);
  pos += int_len;

  /* Encode value string */
  if (value_len > 0)
    {
      if (actually_use_huffman)
        {
          ssize_t huff_result = SocketHPACK_huffman_encode (
              value, value_len, output + pos, output_size - pos);
          if (huff_result < 0)
            return QPACK_ERR_HUFFMAN;
          pos += (size_t)huff_result;
        }
      else
        {
          memcpy (output + pos, value, value_len);
          pos += value_len;
        }
    }

  *bytes_written = pos;
  return QPACK_OK;
}

/**
 * @brief Internal decode implementation with optional arena.
 */
static SocketQPACK_Result
decode_literal_name_ref_internal (const unsigned char *input,
                                  size_t input_len,
                                  Arena_T arena,
                                  SocketQPACK_LiteralNameRef *result,
                                  size_t *consumed)
{
  size_t pos = 0;
  uint64_t name_index;
  uint64_t value_len;
  size_t int_consumed;
  SocketHPACK_Result hpack_result;
  bool is_static;
  bool never_indexed;
  bool value_huffman;

  /* Parameter validation */
  if (result == NULL || consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *consumed = 0;
  memset (result, 0, sizeof (*result));

  /* Need at least one byte */
  if (input_len < 1)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.4: Verify pattern
   *
   * First byte must match: 01xxxxxx (bits 7-6 = 01)
   */
  if ((input[0] & QPACK_LITERAL_NAMEREF_PATTERN_MASK)
      != QPACK_LITERAL_NAMEREF_PATTERN)
    return QPACK_ERR_INTERNAL; /* Not a Literal Field Line with Name Ref */

  /* Extract N and T bits */
  never_indexed = (input[0] & QPACK_LITERAL_NAMEREF_NEVER_INDEX) != 0;
  is_static = (input[0] & QPACK_LITERAL_NAMEREF_STATIC) != 0;

  /* Decode name index (4-bit prefix integer) */
  hpack_result = SocketHPACK_int_decode (input,
                                         input_len,
                                         QPACK_LITERAL_NAMEREF_PREFIX,
                                         &name_index,
                                         &int_consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  pos += int_consumed;

  /* Decode value length (7-bit prefix integer) */
  if (pos >= input_len)
    return QPACK_INCOMPLETE;

  value_huffman = (input[pos] & QPACK_VALUE_HUFFMAN_FLAG) != 0;

  hpack_result = SocketHPACK_int_decode (input + pos,
                                         input_len - pos,
                                         QPACK_VALUE_LENGTH_PREFIX,
                                         &value_len,
                                         &int_consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  pos += int_consumed;

  /* Validate header value length against maximum (fixes #3474) */
  if (value_len > SOCKETQPACK_MAX_HEADER_VALUE_SIZE)
    return QPACK_ERR_HEADER_SIZE;

  /* Check if we have enough bytes for the value string */
  if (pos + value_len > input_len)
    return QPACK_INCOMPLETE;

  /* Populate result */
  result->name_index = name_index;
  result->is_static = is_static;
  result->never_indexed = never_indexed;
  result->value_huffman = value_huffman;

  if (value_len == 0)
    {
      result->value = NULL;
      result->value_len = 0;
    }
  else if (value_huffman)
    {
      /* Huffman-decode the value */
      if (arena == NULL)
        {
          /*
           * No arena provided - cannot decode Huffman.
           * Point to raw Huffman data; caller must copy/decode separately.
           * LIFETIME: result->value points into input buffer; caller must
           * keep input buffer valid for the lifetime of result.
           */
          result->value = (const char *)(input + pos);
          result->value_len = value_len;
        }
      else
        {
          /* Allocate decode buffer (worst case ~2x expansion) */
          /* Check for multiplication overflow before allocation (fixes #3457)
           */
          size_t decode_buf_size;
          if (!SocketSecurity_check_multiply (
                  value_len, QPACK_HUFFMAN_EXPANSION_FACTOR, &decode_buf_size))
            return QPACK_ERR_HEADER_SIZE;
          if (decode_buf_size < QPACK_MIN_DECODE_BUFFER_SIZE)
            decode_buf_size = QPACK_MIN_DECODE_BUFFER_SIZE;

          char *decode_buf = ALLOC (arena, decode_buf_size);
          if (decode_buf == NULL)
            return QPACK_ERR_INTERNAL;

          ssize_t decoded_len
              = SocketHPACK_huffman_decode (input + pos,
                                            value_len,
                                            (unsigned char *)decode_buf,
                                            decode_buf_size);
          if (decoded_len < 0)
            return QPACK_ERR_HUFFMAN;

          result->value = decode_buf;
          result->value_len = (size_t)decoded_len;
        }
    }
  else
    {
      /*
       * Literal value - point directly into input buffer.
       * LIFETIME: result->value points into input buffer; caller must
       * keep input buffer valid for the lifetime of result.
       */
      result->value = (const char *)(input + pos);
      result->value_len = value_len;
    }

  pos += value_len;
  *consumed = pos;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_decode_literal_name_ref (const unsigned char *input,
                                     size_t input_len,
                                     SocketQPACK_LiteralNameRef *result,
                                     size_t *consumed)
{
  return decode_literal_name_ref_internal (
      input, input_len, NULL, result, consumed);
}

SocketQPACK_Result
SocketQPACK_decode_literal_name_ref_arena (const unsigned char *input,
                                           size_t input_len,
                                           Arena_T arena,
                                           SocketQPACK_LiteralNameRef *result,
                                           size_t *consumed)
{
  if (arena == NULL)
    return QPACK_ERR_NULL_PARAM;

  return decode_literal_name_ref_internal (
      input, input_len, arena, result, consumed);
}

SocketQPACK_Result
SocketQPACK_validate_literal_name_ref_index (bool is_static,
                                             uint64_t name_index,
                                             uint64_t base,
                                             uint64_t dropped_count)
{
  /*
   * RFC 9204 Section 4.5.4: Validate name reference index
   *
   * For static table: index must be 0-98 (99 entries)
   * For dynamic table: index is field-relative, converted via Base
   */
  if (is_static)
    {
      /* Static table has 99 entries (indices 0-98) */
      if (name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
        return QPACK_ERR_INVALID_INDEX;
      return QPACK_OK;
    }

  /* Dynamic table: field-relative index validation */
  /* rel_index must be < base to reference a valid entry */
  if (name_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* Convert to absolute index: absolute = base - relative - 1 */
  uint64_t abs_index = base - name_index - 1;

  /* Check if entry has been evicted */
  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_resolve_literal_name_ref (bool is_static,
                                      uint64_t name_index,
                                      uint64_t base,
                                      SocketQPACK_Table_T table,
                                      const char **name,
                                      size_t *name_len)
{
  SocketQPACK_Result result;

  if (name == NULL || name_len == NULL)
    return QPACK_ERR_NULL_PARAM;

  *name = NULL;
  *name_len = 0;

  if (is_static)
    {
      /* Lookup in static table */
      result = qpack_static_get (name_index, name, name_len);
      return result;
    }

  /* Dynamic table lookup */
  if (table == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Convert field-relative to absolute index */
  if (name_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  uint64_t abs_index = base - name_index - 1;

  /* Validate absolute index against table bounds */
  if (abs_index < table->dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  if (abs_index >= table->insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* Convert absolute index to ring buffer position */
  /* Ring buffer position = head + (abs_index - dropped_count) */
  size_t ring_offset = (size_t)(abs_index - table->dropped_count);
  if (ring_offset >= table->count)
    return QPACK_ERR_INVALID_INDEX;

  size_t ring_pos = RINGBUF_WRAP (table->head + ring_offset, table->capacity);
  QPACK_DynamicEntry *entry = &table->entries[ring_pos];

  *name = entry->name;
  *name_len = entry->name_len;

  return QPACK_OK;
}
