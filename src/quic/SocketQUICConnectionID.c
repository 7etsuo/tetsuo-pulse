/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICConnectionID.c - QUIC Connection ID Management (RFC 9000 §5.1)
 *
 * Implements Connection ID generation, comparison, encoding/decoding,
 * and utility functions.
 */

#include <stdio.h>
#include <string.h>

#include "quic/SocketQUICConnectionID.h"
#include "quic/SocketQUICConstants.h"
#include "core/SocketCrypto.h"

/* Use SocketCrypto_random_bytes() for platform-independent secure random */
#define SECURE_RANDOM(buf, len) (SocketCrypto_random_bytes ((buf), (len)) == 0)

/* FNV-1a 32-bit hash constants */
#define FNV1A_OFFSET_BASIS 2166136261u
#define FNV1A_PRIME        16777619u

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QUIC_CONNID_OK] = "OK",
  [QUIC_CONNID_ERROR_NULL] = "NULL pointer argument",
  [QUIC_CONNID_ERROR_LENGTH] = "Invalid Connection ID length",
  [QUIC_CONNID_ERROR_BUFFER] = "Output buffer too small",
  [QUIC_CONNID_ERROR_INCOMPLETE] = "Need more input data",
  [QUIC_CONNID_ERROR_RANDOM] = "Random generation failed",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICConnectionID, QUIC_CONNID_ERROR_RANDOM)

/* ============================================================================
 * Initialization Functions
 * ============================================================================
 */

void
SocketQUICConnectionID_init (SocketQUICConnectionID_T *cid)
{
  if (cid == NULL)
    return;

  memset (cid, 0, sizeof (*cid));
}

SocketQUICConnectionID_Result
SocketQUICConnectionID_set (SocketQUICConnectionID_T *cid, const uint8_t *data,
                            size_t len)
{
  if (cid == NULL)
    return QUIC_CONNID_ERROR_NULL;

  if (len > QUIC_CONNID_MAX_LEN)
    return QUIC_CONNID_ERROR_LENGTH;

  SocketQUICConnectionID_init (cid);

  if (len > 0 && data != NULL)
    memcpy (cid->data, data, len);

  cid->len = (uint8_t)len;
  return QUIC_CONNID_OK;
}

/* ============================================================================
 * Generation Functions
 * ============================================================================
 */

SocketQUICConnectionID_Result
SocketQUICConnectionID_generate (SocketQUICConnectionID_T *cid, size_t len)
{
  if (cid == NULL)
    return QUIC_CONNID_ERROR_NULL;

  if (len > QUIC_CONNID_MAX_LEN)
    return QUIC_CONNID_ERROR_LENGTH;

  SocketQUICConnectionID_init (cid);
  cid->len = (uint8_t)len;

  if (len > 0)
    {
      if (!SECURE_RANDOM (cid->data, len))
        return QUIC_CONNID_ERROR_RANDOM;
    }

  return QUIC_CONNID_OK;
}

SocketQUICConnectionID_Result
SocketQUICConnectionID_generate_reset_token (SocketQUICConnectionID_T *cid)
{
  if (cid == NULL)
    return QUIC_CONNID_ERROR_NULL;

  if (!SECURE_RANDOM (cid->stateless_reset_token, QUIC_STATELESS_RESET_TOKEN_LEN))
    return QUIC_CONNID_ERROR_RANDOM;

  cid->has_reset_token = 1;
  return QUIC_CONNID_OK;
}

/* ============================================================================
 * Comparison Functions
 * ============================================================================
 */

int
SocketQUICConnectionID_equal (const SocketQUICConnectionID_T *a,
                              const SocketQUICConnectionID_T *b)
{
  if (a == NULL || b == NULL)
    return 0;

  if (a->len != b->len)
    return 0;

  if (a->len == 0)
    return 1; /* Both zero-length CIDs are equal */

  return (memcmp (a->data, b->data, a->len) == 0);
}

int
SocketQUICConnectionID_equal_raw (const SocketQUICConnectionID_T *cid,
                                  const uint8_t *data, size_t len)
{
  if (cid == NULL)
    return 0;

  if (cid->len != len)
    return 0;

  if (len == 0)
    return 1;

  if (data == NULL)
    return 0;

  return (memcmp (cid->data, data, len) == 0);
}

SocketQUICConnectionID_Result
SocketQUICConnectionID_copy (SocketQUICConnectionID_T *dst,
                             const SocketQUICConnectionID_T *src)
{
  if (dst == NULL || src == NULL)
    return QUIC_CONNID_ERROR_NULL;

  memcpy (dst, src, sizeof (*dst));
  return QUIC_CONNID_OK;
}

/* ============================================================================
 * Wire Format Functions
 * ============================================================================
 */

size_t
SocketQUICConnectionID_encode_length (const SocketQUICConnectionID_T *cid,
                                      uint8_t *output, size_t output_size)
{
  if (cid == NULL || output == NULL)
    return 0;

  if (output_size < 1)
    return 0;

  output[0] = cid->len;
  return 1;
}

size_t
SocketQUICConnectionID_encode (const SocketQUICConnectionID_T *cid,
                               uint8_t *output, size_t output_size)
{
  if (cid == NULL)
    return 0;

  if (cid->len == 0)
    return 0; /* Nothing to write */

  if (output == NULL || output_size < cid->len)
    return 0;

  memcpy (output, cid->data, cid->len);
  return cid->len;
}

size_t
SocketQUICConnectionID_encode_with_length (const SocketQUICConnectionID_T *cid,
                                           uint8_t *output, size_t output_size)
{
  size_t total;

  if (cid == NULL || output == NULL)
    return 0;

  total = 1 + cid->len;

  if (output_size < total)
    return 0;

  output[0] = cid->len;

  if (cid->len > 0)
    memcpy (output + 1, cid->data, cid->len);

  return total;
}

SocketQUICConnectionID_Result
SocketQUICConnectionID_decode (const uint8_t *data, size_t len,
                               SocketQUICConnectionID_T *cid, size_t *consumed)
{
  uint8_t cid_len;

  if (data == NULL || cid == NULL || consumed == NULL)
    return QUIC_CONNID_ERROR_NULL;

  if (len < 1)
    return QUIC_CONNID_ERROR_INCOMPLETE;

  cid_len = data[0];

  if (cid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_CONNID_ERROR_LENGTH;

  if (len < 1 + (size_t)cid_len)
    return QUIC_CONNID_ERROR_INCOMPLETE;

  SocketQUICConnectionID_init (cid);
  cid->len = cid_len;

  if (cid_len > 0)
    memcpy (cid->data, data + 1, cid_len);

  *consumed = 1 + cid_len;
  return QUIC_CONNID_OK;
}

SocketQUICConnectionID_Result
SocketQUICConnectionID_decode_fixed (const uint8_t *data, size_t len,
                                     SocketQUICConnectionID_T *cid,
                                     size_t cid_len)
{
  if (data == NULL || cid == NULL)
    return QUIC_CONNID_ERROR_NULL;

  if (cid_len > QUIC_CONNID_MAX_LEN)
    return QUIC_CONNID_ERROR_LENGTH;

  if (len < cid_len)
    return QUIC_CONNID_ERROR_INCOMPLETE;

  SocketQUICConnectionID_init (cid);
  cid->len = (uint8_t)cid_len;

  if (cid_len > 0)
    memcpy (cid->data, data, cid_len);

  return QUIC_CONNID_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

uint32_t
SocketQUICConnectionID_hash (const SocketQUICConnectionID_T *cid)
{
  uint32_t hash;
  size_t i;

  if (cid == NULL || cid->len == 0)
    return 0;

  /* FNV-1a hash */
  hash = FNV1A_OFFSET_BASIS;

  for (i = 0; i < cid->len; i++)
    {
      hash ^= cid->data[i];
      hash *= FNV1A_PRIME;
    }

  return hash;
}

int
SocketQUICConnectionID_to_hex (const SocketQUICConnectionID_T *cid, char *buf,
                               size_t size)
{
  static const char hex[] = "0123456789abcdef";
  size_t pos;
  size_t i;

  if (buf == NULL || size == 0)
    return -1;

  if (cid == NULL || cid->len == 0)
    {
      if (size < 6)
        {
          buf[0] = '\0';
          return -1;
        }
      memcpy (buf, "empty", 6);
      return 5;
    }

  /* Format: "XX:XX:XX..." requires 3*len-1 chars + null */
  if (size < (size_t)(cid->len * 3))
    {
      buf[0] = '\0';
      return -1;
    }

  pos = 0;

  for (i = 0; i < cid->len; i++)
    {
      if (i > 0)
        buf[pos++] = ':';

      buf[pos++] = hex[(cid->data[i] >> 4) & 0x0f];
      buf[pos++] = hex[cid->data[i] & 0x0f];
    }

  buf[pos] = '\0';
  return (int)pos;
}
