/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Header Compression (RFC 9204)
 *
 * Implements QPACK encoder instructions, dynamic table management, and
 * integer encoding/decoding. QPACK is designed for HTTP/3 over QUIC.
 *
 * This file implements:
 * - Set Dynamic Table Capacity (Section 4.3.1)
 * - Integer encoding/decoding (RFC 7541 Section 5.1)
 * - Dynamic table management (Section 3.2)
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h> /* strncasecmp */

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketQPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_HUFFMAN] = "Huffman decoding error",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size update",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_NOT_FOUND] = "Entry not found",
  [QPACK_ENCODER_STREAM_ERROR] = "Encoder stream error",
  [QPACK_DECODER_STREAM_ERROR] = "Decoder stream error",
  [QPACK_DECOMPRESSION_FAILED] = "Decompression failed",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_DECOMPRESSION_FAILED)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Validation Helpers
 * ============================================================================
 */

static inline bool
valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

static int
qpack_validate_table (const SocketQPACK_Table_T table, const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK %s: NULL table pointer", func);
      return 0;
    }
  return 1;
}

/* ============================================================================
 * Integer Encoding (RFC 7541 Section 5.1)
 * ============================================================================
 */

static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= QPACK_INT_CONTINUATION_VALUE && pos < output_size)
    {
      output[pos++] = (unsigned char)(QPACK_INT_CONTINUATION_MASK
                                      | (value & QPACK_INT_PAYLOAD_MASK));
      value >>= 7;
    }

  if (pos >= output_size)
    return 0;

  output[pos++] = (unsigned char)value;
  return pos;
}

size_t
SocketQPACK_int_encode (uint64_t value,
                        int prefix_bits,
                        unsigned char *output,
                        size_t output_size)
{
  uint64_t max_prefix;

  if (output == NULL || output_size == 0 || !valid_prefix_bits (prefix_bits))
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[0] = (unsigned char)value;
      return 1;
    }

  output[0] = (unsigned char)max_prefix;
  return encode_int_continuation (value - max_prefix, output, 1, output_size);
}

/* ============================================================================
 * Integer Decoding (RFC 7541 Section 5.1)
 * ============================================================================
 */

static SocketQPACK_Result
decode_int_continuation (const unsigned char *input,
                         size_t input_len,
                         size_t *pos,
                         uint64_t *result,
                         unsigned int *shift)
{
  uint64_t byte_val;
  unsigned int continuation_count = 0;

  do
    {
      if (*pos >= input_len)
        return QPACK_INCOMPLETE;

      continuation_count++;
      if (continuation_count > QPACK_MAX_INT_CONTINUATION_BYTES)
        return QPACK_ERROR_INTEGER;

      byte_val = input[(*pos)++];

      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & QPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & QPACK_INT_CONTINUATION_MASK);

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_int_decode (const unsigned char *input,
                        size_t input_len,
                        int prefix_bits,
                        uint64_t *value,
                        size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  unsigned int shift = 0;

  if (input == NULL || value == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!valid_prefix_bits (prefix_bits))
    return QPACK_ERROR;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return QPACK_OK;
    }

  SocketQPACK_Result cont_result
      = decode_int_continuation (input, input_len, &pos, &result, &shift);
  if (cont_result != QPACK_OK)
    return cont_result;

  *value = result;
  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Dynamic Table - Internal Helpers
 * ============================================================================
 */

static size_t
qpack_dynamic_initial_capacity (size_t max_size)
{
  size_t est_entries;

  if (max_size == 0)
    return QPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  est_entries = max_size / QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
  if (est_entries < QPACK_MIN_DYNAMIC_TABLE_CAPACITY)
    est_entries = QPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  return socket_util_round_up_pow2 (est_entries);
}

static void
qpack_table_clear (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
}

/* ============================================================================
 * Dynamic Table - Eviction (RFC 9204 Section 3.2)
 * ============================================================================
 */

size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      QPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size = qpack_entry_size (entry->name_len, entry->value_len);

      if (entry_size > table->size)
        {
          SOCKET_LOG_ERROR_MSG (
              "SocketQPACK: table corruption detected (entry_size=%zu > "
              "table_size=%zu), resetting table",
              entry_size,
              table->size);
          table->size = 0;
          table->count = 0;
          return evicted;
        }

      table->size -= entry_size;
      table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
      table->count--;
      evicted++;
    }

  return evicted;
}

/* ============================================================================
 * Dynamic Table - Public API (RFC 9204 Section 3.2)
 * ============================================================================
 */

SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketQPACK_Table_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    SOCKET_RAISE_MSG (SocketQPACK,
                      SocketQPACK_Error,
                      "failed to allocate SocketQPACK_Table structure");

  initial_capacity = qpack_dynamic_initial_capacity (max_size);

  table->entries
      = CALLOC (arena, initial_capacity, sizeof (QPACK_DynamicEntry));
  if (table->entries == NULL)
    SOCKET_RAISE_MSG (
        SocketQPACK,
        SocketQPACK_Error,
        "failed to allocate SocketQPACK_Table entries array (capacity=%zu)",
        initial_capacity);

  table->capacity = initial_capacity;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_size = max_size;
  table->arena = arena;

  return table;
}

void
SocketQPACK_Table_free (SocketQPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;

  /* Arena handles deallocation */
  *table = NULL;
}

size_t
SocketQPACK_Table_size (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_size"))
    return 0;
  return table->size;
}

size_t
SocketQPACK_Table_count (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_count"))
    return 0;
  return table->count;
}

size_t
SocketQPACK_Table_max_size (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_max_size"))
    return 0;
  return table->max_size;
}

void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size)
{
  if (!qpack_validate_table (table, "Table_set_max_size"))
    return;

  if (max_size > SOCKETQPACK_MAX_TABLE_SIZE)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK Table_set_max_size: clamping max_size from %zu to %zu",
          max_size,
          (size_t)SOCKETQPACK_MAX_TABLE_SIZE);
      max_size = SOCKETQPACK_MAX_TABLE_SIZE;
    }

  table->max_size = max_size;

  if (max_size == 0)
    qpack_table_clear (table);
  else
    qpack_table_evict (table, 0);
}

/* ============================================================================
 * Set Dynamic Table Capacity (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

size_t
SocketQPACK_encode_set_capacity (size_t capacity,
                                 unsigned char *output,
                                 size_t output_size)
{
  unsigned char int_buf[16];
  size_t int_len;

  if (output == NULL || output_size == 0)
    return 0;

  /* Encode capacity as 5-bit prefix integer */
  int_len = SocketQPACK_int_encode (
      capacity, QPACK_SET_CAPACITY_PREFIX_BITS, int_buf, sizeof (int_buf));

  if (int_len == 0 || int_len > output_size)
    return 0;

  /* First byte: pattern 001xxxxx OR'd with lower 5 bits of integer */
  output[0] = QPACK_SET_CAPACITY_PATTERN | int_buf[0];

  /* Copy remaining bytes if multi-byte integer */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return int_len;
}

SocketQPACK_Result
SocketQPACK_decode_set_capacity (const unsigned char *input,
                                 size_t input_len,
                                 size_t *capacity,
                                 size_t *consumed)
{
  uint64_t value;
  size_t bytes_consumed;
  SocketQPACK_Result result;

  if (input == NULL || capacity == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Check pattern: must be 001xxxxx (0x20 when masked with 0xE0) */
  if ((input[0] & QPACK_SET_CAPACITY_MASK) != QPACK_SET_CAPACITY_PATTERN)
    return QPACK_ERROR;

  /* Decode 5-bit prefix integer */
  result = SocketQPACK_int_decode (input,
                                   input_len,
                                   QPACK_SET_CAPACITY_PREFIX_BITS,
                                   &value,
                                   &bytes_consumed);

  if (result != QPACK_OK)
    return result;

  /* Check for size_t overflow */
  if (value > SIZE_MAX)
    return QPACK_ERROR_INTEGER;

  *capacity = (size_t)value;
  *consumed = bytes_consumed;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_apply_set_capacity (SocketQPACK_Table_T table,
                                size_t capacity,
                                size_t max_capacity)
{
  if (table == NULL)
    return QPACK_ERROR;

  /* RFC 9204 Section 4.3.1: capacity exceeding maximum is an error */
  if (capacity > max_capacity)
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: Set Capacity value %zu exceeds maximum %zu",
          capacity,
          max_capacity);
      return QPACK_ENCODER_STREAM_ERROR;
    }

  /* Apply the capacity change */
  if (capacity < table->size)
    {
      /* Evict entries until size fits within new capacity */
      table->max_size = capacity;
      qpack_table_evict (table, 0);
    }
  else
    {
      /* No eviction needed, just update capacity */
      table->max_size = capacity;
    }

  /* Zero capacity clears the table completely */
  if (capacity == 0)
    qpack_table_clear (table);

  return QPACK_OK;
}

/* ============================================================================
 * Static Table (RFC 9204 Section 3.1, Appendix A)
 * ============================================================================
 */

/**
 * Static table entry structure for internal use.
 */
typedef struct
{
  const char *name;
  size_t name_len;
  const char *value;
  size_t value_len;
} QPACK_StaticEntry;

/* clang-format off */
static const QPACK_StaticEntry qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE] = {
  /*  0 */ { ":authority",                      10, "",                                                         0 },
  /*  1 */ { ":path",                            5, "/",                                                        1 },
  /*  2 */ { "age",                              3, "0",                                                        1 },
  /*  3 */ { "content-disposition",             19, "",                                                         0 },
  /*  4 */ { "content-length",                  14, "0",                                                        1 },
  /*  5 */ { "cookie",                           6, "",                                                         0 },
  /*  6 */ { "date",                             4, "",                                                         0 },
  /*  7 */ { "etag",                             4, "",                                                         0 },
  /*  8 */ { "if-modified-since",               17, "",                                                         0 },
  /*  9 */ { "if-none-match",                   13, "",                                                         0 },
  /* 10 */ { "last-modified",                   13, "",                                                         0 },
  /* 11 */ { "link",                             4, "",                                                         0 },
  /* 12 */ { "location",                         8, "",                                                         0 },
  /* 13 */ { "referer",                          7, "",                                                         0 },
  /* 14 */ { "set-cookie",                      10, "",                                                         0 },
  /* 15 */ { ":method",                          7, "CONNECT",                                                  7 },
  /* 16 */ { ":method",                          7, "DELETE",                                                   6 },
  /* 17 */ { ":method",                          7, "GET",                                                      3 },
  /* 18 */ { ":method",                          7, "HEAD",                                                     4 },
  /* 19 */ { ":method",                          7, "OPTIONS",                                                  7 },
  /* 20 */ { ":method",                          7, "POST",                                                     4 },
  /* 21 */ { ":method",                          7, "PUT",                                                      3 },
  /* 22 */ { ":scheme",                          7, "http",                                                     4 },
  /* 23 */ { ":scheme",                          7, "https",                                                    5 },
  /* 24 */ { ":status",                          7, "103",                                                      3 },
  /* 25 */ { ":status",                          7, "200",                                                      3 },
  /* 26 */ { ":status",                          7, "304",                                                      3 },
  /* 27 */ { ":status",                          7, "404",                                                      3 },
  /* 28 */ { ":status",                          7, "503",                                                      3 },
  /* 29 */ { "accept",                           6, "*/*",                                                      3 },
  /* 30 */ { "accept",                           6, "application/dns-message",                                 23 },
  /* 31 */ { "accept-encoding",                 15, "gzip, deflate, br",                                       17 },
  /* 32 */ { "accept-ranges",                   13, "bytes",                                                    5 },
  /* 33 */ { "access-control-allow-headers",    28, "cache-control",                                           13 },
  /* 34 */ { "access-control-allow-headers",    28, "content-type",                                            12 },
  /* 35 */ { "access-control-allow-origin",     27, "*",                                                        1 },
  /* 36 */ { "cache-control",                   13, "max-age=0",                                                9 },
  /* 37 */ { "cache-control",                   13, "max-age=2592000",                                         15 },
  /* 38 */ { "cache-control",                   13, "max-age=604800",                                          14 },
  /* 39 */ { "cache-control",                   13, "no-cache",                                                 8 },
  /* 40 */ { "cache-control",                   13, "no-store",                                                 8 },
  /* 41 */ { "cache-control",                   13, "public, max-age=31536000",                                24 },
  /* 42 */ { "content-encoding",                16, "br",                                                       2 },
  /* 43 */ { "content-encoding",                16, "gzip",                                                     4 },
  /* 44 */ { "content-type",                    12, "application/dns-message",                                 23 },
  /* 45 */ { "content-type",                    12, "application/javascript",                                  22 },
  /* 46 */ { "content-type",                    12, "application/json",                                        16 },
  /* 47 */ { "content-type",                    12, "application/x-www-form-urlencoded",                       33 },
  /* 48 */ { "content-type",                    12, "image/gif",                                                9 },
  /* 49 */ { "content-type",                    12, "image/jpeg",                                              10 },
  /* 50 */ { "content-type",                    12, "image/png",                                                9 },
  /* 51 */ { "content-type",                    12, "text/css",                                                 8 },
  /* 52 */ { "content-type",                    12, "text/html; charset=utf-8",                                24 },
  /* 53 */ { "content-type",                    12, "text/plain",                                              10 },
  /* 54 */ { "content-type",                    12, "text/plain;charset=utf-8",                                24 },
  /* 55 */ { "range",                            5, "bytes=0-",                                                 8 },
  /* 56 */ { "strict-transport-security",       25, "max-age=31536000",                                        16 },
  /* 57 */ { "strict-transport-security",       25, "max-age=31536000; includesubdomains",                     35 },
  /* 58 */ { "strict-transport-security",       25, "max-age=31536000; includesubdomains; preload",            44 },
  /* 59 */ { "vary",                             4, "accept-encoding",                                         15 },
  /* 60 */ { "vary",                             4, "origin",                                                   6 },
  /* 61 */ { "x-content-type-options",          22, "nosniff",                                                  7 },
  /* 62 */ { "x-xss-protection",                16, "1; mode=block",                                           13 },
  /* 63 */ { ":status",                          7, "100",                                                      3 },
  /* 64 */ { ":status",                          7, "204",                                                      3 },
  /* 65 */ { ":status",                          7, "206",                                                      3 },
  /* 66 */ { ":status",                          7, "302",                                                      3 },
  /* 67 */ { ":status",                          7, "400",                                                      3 },
  /* 68 */ { ":status",                          7, "403",                                                      3 },
  /* 69 */ { ":status",                          7, "421",                                                      3 },
  /* 70 */ { ":status",                          7, "425",                                                      3 },
  /* 71 */ { ":status",                          7, "500",                                                      3 },
  /* 72 */ { "accept-language",                 15, "",                                                         0 },
  /* 73 */ { "access-control-allow-credentials",32, "FALSE",                                                    5 },
  /* 74 */ { "access-control-allow-credentials",32, "TRUE",                                                     4 },
  /* 75 */ { "access-control-allow-headers",    28, "*",                                                        1 },
  /* 76 */ { "access-control-allow-methods",    28, "get",                                                      3 },
  /* 77 */ { "access-control-allow-methods",    28, "get, post, options",                                      18 },
  /* 78 */ { "access-control-allow-methods",    28, "options",                                                  7 },
  /* 79 */ { "access-control-expose-headers",   29, "content-length",                                          14 },
  /* 80 */ { "access-control-request-headers",  30, "content-type",                                            12 },
  /* 81 */ { "access-control-request-method",   29, "get",                                                      3 },
  /* 82 */ { "access-control-request-method",   29, "post",                                                     4 },
  /* 83 */ { "alt-svc",                          7, "clear",                                                    5 },
  /* 84 */ { "authorization",                   13, "",                                                         0 },
  /* 85 */ { "content-security-policy",         23, "script-src 'none'; object-src 'none'; base-uri 'none'",   52 },
  /* 86 */ { "early-data",                      10, "1",                                                        1 },
  /* 87 */ { "expect-ct",                        9, "",                                                         0 },
  /* 88 */ { "forwarded",                        9, "",                                                         0 },
  /* 89 */ { "if-range",                         8, "",                                                         0 },
  /* 90 */ { "origin",                           6, "",                                                         0 },
  /* 91 */ { "purpose",                          7, "prefetch",                                                 8 },
  /* 92 */ { "server",                           6, "",                                                         0 },
  /* 93 */ { "timing-allow-origin",             19, "*",                                                        1 },
  /* 94 */ { "upgrade-insecure-requests",       25, "1",                                                        1 },
  /* 95 */ { "user-agent",                      10, "",                                                         0 },
  /* 96 */ { "x-forwarded-for",                 15, "",                                                         0 },
  /* 97 */ { "x-frame-options",                 15, "deny",                                                     4 },
  /* 98 */ { "x-frame-options",                 15, "sameorigin",                                              10 },
};
/* clang-format on */

SocketQPACK_Result
SocketQPACK_static_get (size_t index,
                        const char **name,
                        size_t *name_len,
                        const char **value,
                        size_t *value_len)
{
  if (name == NULL || name_len == NULL || value == NULL || value_len == NULL)
    return QPACK_ERROR;

  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_ERROR_INVALID_INDEX;

  const QPACK_StaticEntry *entry = &qpack_static_table[index];
  *name = entry->name;
  *name_len = entry->name_len;
  *value = entry->value;
  *value_len = entry->value_len;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_static_find (const char *name,
                         size_t name_len,
                         const char *value,
                         size_t value_len,
                         size_t *index)
{
  if (name == NULL || index == NULL)
    return QPACK_ERROR;

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const QPACK_StaticEntry *entry = &qpack_static_table[i];

      /* Name comparison: case-insensitive per RFC 7230 Section 3.2 */
      if (entry->name_len != name_len)
        continue;

      if (strncasecmp (entry->name, name, name_len) != 0)
        continue;

      /* Value comparison: exact match (case-sensitive) */
      if (entry->value_len != value_len)
        continue;

      /* Handle empty value comparison */
      if (value_len == 0
          || (value != NULL && memcmp (entry->value, value, value_len) == 0))
        {
          *index = i;
          return QPACK_OK;
        }
    }

  return QPACK_ERROR_NOT_FOUND;
}

SocketQPACK_Result
SocketQPACK_static_find_name (const char *name, size_t name_len, size_t *index)
{
  if (name == NULL || index == NULL)
    return QPACK_ERROR;

  for (size_t i = 0; i < SOCKETQPACK_STATIC_TABLE_SIZE; i++)
    {
      const QPACK_StaticEntry *entry = &qpack_static_table[i];

      if (entry->name_len != name_len)
        continue;

      if (strncasecmp (entry->name, name, name_len) == 0)
        {
          *index = i;
          return QPACK_OK;
        }
    }

  return QPACK_ERROR_NOT_FOUND;
}

size_t
SocketQPACK_static_name_len (size_t index)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return 0;

  return qpack_static_table[index].name_len;
}

size_t
SocketQPACK_static_value_len (size_t index)
{
  if (index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return 0;

  return qpack_static_table[index].value_len;
}
