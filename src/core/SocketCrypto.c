/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketCrypto.c - Cryptographic Utilities Implementation
 *
 * Part of the Socket Library
 *
 * Provides cryptographic primitives as thin wrappers around OpenSSL.
 * When SOCKET_HAS_TLS is not defined, provides fallbacks where possible
 * (random via /dev/urandom) or raises exceptions.
 *
 * Thread safety: All functions are thread-safe (no global state).
 */

#include "core/SocketCrypto.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#if SOCKET_HAS_TLS
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#endif

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/**
 * WebSocket key random bytes (16 bytes = 128 bits per RFC 6455)
 * Base64 encoded: 16 bytes -> 24 characters
 */
#define WEBSOCKET_KEY_RANDOM_BYTES 16

/**
 * WebSocket key base64 length (24 characters, no null terminator)
 * Derived from SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE - 1
 */
#define WEBSOCKET_KEY_BASE64_LEN (SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE - 1)

/**
 * WebSocket concat buffer size for key + GUID
 * 24 (key) + 36 (GUID) + 1 (null) = 61, round to 64 for alignment
 */
#define WEBSOCKET_CONCAT_BUFFER_SIZE 64

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketCrypto_Failed
    = { &SocketCrypto_Failed, "Cryptographic operation failed" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketCrypto);

/* Common macros to reduce code duplication in error checking */

/**
 * SOCKET_CRYPTO_CHECK_INPUT - Validate input pointer for non-zero length
 * @ptr: Pointer to validate
 * @len: Length associated with pointer
 * @name: Function-specific name for error message (e.g., "SHA-256")
 *
 * Raises SocketCrypto_Failed if ptr is NULL and len > 0.
 * Thread-safe: Yes
 */
#define SOCKET_CRYPTO_CHECK_INPUT(ptr, len, name)                             \
  do                                                                          \
    {                                                                         \
      if (!(ptr) && (len) > 0)                                                \
        SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,                  \
                          name ": NULL input with non-zero length");          \
    }                                                                         \
  while (0)

/**
 * SOCKET_CRYPTO_REQUIRE_TLS - Raise exception if TLS support not available
 *
 * Uses __func__ for specific function name in message.
 * Thread-safe: Yes
 */
#define SOCKET_CRYPTO_REQUIRE_TLS                                             \
  do                                                                          \
    {                                                                         \
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,                    \
                        "%s requires TLS support (SOCKET_HAS_TLS)",           \
                        __func__);                                            \
    }                                                                         \
  while (0)

/**
 * SOCKET_CRYPTO_RAISE_FAILED - Raise computation failure with algorithm name
 * @name: Algorithm name string (e.g., "SHA-1")
 *
 * Thread-safe: Yes
 */
#define SOCKET_CRYPTO_RAISE_FAILED(name)                                      \
  SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,                        \
                    "%s computation failed", name)

/* Use SOCKET_RAISE_MSG directly for clarity where macros not applicable */

/* ============================================================================
 * Static Constants
 * ============================================================================
 */

/* Base64 encoding alphabet (RFC 4648) */
static const char base64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 decoding table: maps ASCII to 6-bit value, 255 = invalid */
/* clang-format off */
static const unsigned char base64_decode_table[256] = {
  /* 0x00-0x0F */ 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  /* 0x10-0x1F */ 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  /* 0x20-0x2F */ 255,255,255,255,255,255,255,255,255,255,255, 62,255, 62,255, 63,
  /* 0x30-0x3F */  52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,
  /* 0x40-0x4F */ 255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  /* 0x50-0x5F */  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,
  /* 0x60-0x6F */ 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  /* 0x70-0x7F */  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  /* 0x80-0xFF - high ASCII all invalid */
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};
/* clang-format on */

/* Hex encoding alphabets */
static const char hex_lower[] = "0123456789abcdef";
static const char hex_upper[] = "0123456789ABCDEF";

/* ============================================================================
 * Hash Functions
 * ============================================================================
 */

void
SocketCrypto_sha1 (const void *input, size_t input_len,
                   unsigned char output[SOCKET_CRYPTO_SHA1_SIZE])
{
  assert (output);

  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "SHA-1");
  if (input_len > 0 && !SOCKET_SECURITY_VALID_SIZE (input_len))
    SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                      "SHA-1: input too large: %zu > %zu", (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  EVP_MD_CTX *ctx = NULL;
  TRY
  {
    ctx = EVP_MD_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "SHA-1: Failed to create context");

    if (EVP_DigestInit_ex (ctx, EVP_sha1 (), NULL) != 1
        || EVP_DigestUpdate (ctx, input, input_len) != 1
        || EVP_DigestFinal_ex (ctx, output, NULL) != 1)
      SOCKET_CRYPTO_RAISE_FAILED ("SHA-1");
  }
  FINALLY
  {
    if (ctx)
      EVP_MD_CTX_free (ctx);
  }
  END_TRY;
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

void
SocketCrypto_sha256 (const void *input, size_t input_len,
                     unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);

  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "SHA-256");
  if (input_len > 0 && !SOCKET_SECURITY_VALID_SIZE (input_len))
    SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                      "SHA-256: input too large: %zu > %zu", (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  EVP_MD_CTX *ctx = NULL;
  TRY
  {
    ctx = EVP_MD_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "SHA-256: Failed to create context");

    if (EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL) != 1
        || EVP_DigestUpdate (ctx, input, input_len) != 1
        || EVP_DigestFinal_ex (ctx, output, NULL) != 1)
      SOCKET_CRYPTO_RAISE_FAILED ("SHA-256");
  }
  FINALLY
  {
    if (ctx)
      EVP_MD_CTX_free (ctx);
  }
  END_TRY;
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

void
SocketCrypto_md5 (const void *input, size_t input_len,
                  unsigned char output[SOCKET_CRYPTO_MD5_SIZE])
{
  assert (output);

  SOCKET_CRYPTO_CHECK_INPUT (input, input_len, "MD5");
  if (input_len > 0 && !SOCKET_SECURITY_VALID_SIZE (input_len))
    SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                      "MD5: input too large: %zu > %zu", (size_t)input_len,
                      (size_t)SOCKET_SECURITY_MAX_ALLOCATION);

#if SOCKET_HAS_TLS
  EVP_MD_CTX *ctx = NULL;
  TRY
  {
    ctx = EVP_MD_CTX_new ();
    if (!ctx)
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "MD5: Failed to create context");

    if (EVP_DigestInit_ex (ctx, EVP_md5 (), NULL) != 1
        || EVP_DigestUpdate (ctx, input, input_len) != 1
        || EVP_DigestFinal_ex (ctx, output, NULL) != 1)
      SOCKET_CRYPTO_RAISE_FAILED ("MD5");
  }
  FINALLY
  {
    if (ctx)
      EVP_MD_CTX_free (ctx);
  }
  END_TRY;
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

/* ============================================================================
 * HMAC Functions
 * ============================================================================
 */

void
SocketCrypto_hmac_sha256 (const void *key, size_t key_len, const void *data,
                          size_t data_len,
                          unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);

  SOCKET_CRYPTO_CHECK_INPUT (key, key_len, "HMAC-SHA256 key");
  SOCKET_CRYPTO_CHECK_INPUT (data, data_len, "HMAC-SHA256 data");
  if (!SOCKET_SECURITY_VALID_SIZE (data_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "HMAC-SHA256: data too large: %zu > %zu",
                        (size_t)data_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }

#if SOCKET_HAS_TLS
  /*
   * Security: Validate key_len fits in int for OpenSSL HMAC API.
   * Keys exceeding INT_MAX would be truncated on cast, potentially
   * weakening the MAC. In practice, HMAC keys should be 32-64 bytes;
   * longer keys are internally hashed anyway.
   */
  if (!SOCKET_SECURITY_VALID_SIZE (key_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "HMAC-SHA256: key too large: %zu > %zu",
                        (size_t)key_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }
  if (key_len > (size_t)INT_MAX)
    SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                      "HMAC-SHA256: Key length %zu exceeds INT_MAX", key_len);

  unsigned int hmac_len = 0;
  unsigned char *result
      = HMAC (EVP_sha256 (), key, (int)key_len, (const unsigned char *)data,
              data_len, output, &hmac_len);

  if (!result || hmac_len != SOCKET_CRYPTO_SHA256_SIZE)
    SOCKET_CRYPTO_RAISE_FAILED ("HMAC-SHA256");
#else
  (void)output;
  SOCKET_CRYPTO_REQUIRE_TLS;
#endif
}

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================
 */

size_t
SocketCrypto_base64_encoded_size (size_t input_len)
{
  /*
   * Formula: ceil(input_len / 3) * 4 + 1 (for null terminator)
   *
   * Security: Check for overflow at each step to handle pathologically
   * large input_len values (near SIZE_MAX). Returns 0 on overflow.
   */

  /* Check for overflow in (input_len + 2) */
  if (input_len > SIZE_MAX - 2)
    return 0;

  size_t padded_groups = (input_len + 2) / 3;

  /* Check for overflow in padded_groups * 4 */
  if (padded_groups > SIZE_MAX / 4)
    return 0;

  size_t encoded_len = padded_groups * 4;

  /* Check for overflow in encoded_len + 1 (null terminator) */
  if (encoded_len > SIZE_MAX - 1)
    return 0;

  return encoded_len + 1;
}

size_t
SocketCrypto_base64_decoded_size (size_t input_len)
{
  /*
   * Maximum decoded size: ceil(input_len / 4) * 3
   *
   * Security: Check for overflow to handle large input_len values.
   * Returns 0 on overflow.
   */

  /* Check for overflow in (input_len + 3) */
  if (input_len > SIZE_MAX - 3)
    return 0;

  size_t groups = (input_len + 3) / 4;

  /* Check for overflow in groups * 3 */
  if (groups > SIZE_MAX / 3)
    return 0;

  return groups * 3;
}

/**
 * base64_encode_triplet - Encode 3 input bytes to 4 base64 characters (RFC
 * 4648)
 * @in: Input bytes (exactly 3 bytes)
 * @out: Output buffer (exactly 4 bytes, no null terminator)
 *
 * Encodes a complete triplet without padding.
 *
 * Thread-safe: Yes
 */
static void
base64_encode_triplet (const unsigned char *in, char *out)
{
  out[0] = base64_alphabet[in[0] >> 2];
  out[1] = base64_alphabet[((in[0] & 0x03) << 4) | (in[1] >> 4)];
  out[2] = base64_alphabet[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
  out[3] = base64_alphabet[in[2] & 0x3F];
}

/**
 * base64_encode_remainder - Handle final 1-2 bytes with padding (RFC 4648)
 * @in: Input bytes (1 or 2 bytes available)
 * @remaining: Number of remaining bytes (1 or 2)
 * @out: Output buffer (exactly 4 bytes, includes padding and no null)
 *
 * Adds '=' padding as required.
 *
 * Thread-safe: Yes
 */
static void
base64_encode_remainder (const unsigned char *in, size_t remaining, char *out)
{
  out[0] = base64_alphabet[in[0] >> 2];

  if (remaining == 2)
    {
      out[1] = base64_alphabet[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      out[2] = base64_alphabet[(in[1] & 0x0F) << 2];
    }
  else
    {
      out[1] = base64_alphabet[(in[0] & 0x03) << 4];
      out[2] = '=';
    }
  out[3] = '=';
}

ssize_t
SocketCrypto_base64_encode (const void *input, size_t input_len, char *output,
                            size_t output_size)
{
  const unsigned char *in = (const unsigned char *)input;
  size_t required_size;
  size_t out_pos = 0;
  size_t i;

  if (!output)
    return -1;

  if (!input && input_len > 0)
    return -1;

  /* Handle empty input */
  if (input_len == 0)
    {
      if (output_size < 1)
        return -1;
      output[0] = '\0';
      return 0;
    }

  if (!SOCKET_SECURITY_VALID_SIZE (input_len))
    {
      return -1; /* Buffer too large for security limits */
    }

  required_size = SocketCrypto_base64_encoded_size (input_len);
  if (required_size == 0 || output_size < required_size)
    return -1;

  /* Process 3 bytes at a time */
  for (i = 0; i + 2 < input_len; i += 3)
    {
      base64_encode_triplet (in + i, output + out_pos);
      out_pos += 4;
    }

  /* Handle remaining bytes */
  if (i < input_len)
    {
      base64_encode_remainder (in + i, input_len - i, output + out_pos);
      out_pos += 4;
    }

  output[out_pos] = '\0';
  return (ssize_t)out_pos;
}

/**
 * base64_is_whitespace - Check if character is ignorable whitespace per RFC
 * 4648 Section 3.3
 * @c: Character to check
 *
 * Returns: 1 if space, tab, newline, or carriage return (ignored in decoding),
 * 0 otherwise Thread-safe: Yes
 */
static int
base64_is_whitespace (unsigned char c)
{
  return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

/**
 * base64_decode_block - Decode complete 4-character Base64 block (RFC 4648)
 * @buffer: 4 decoded 6-bit values (0-63)
 * @padding_count: Number of '=' padding chars (0-2)
 * @output: Output buffer for decoded bytes
 * @out_pos: Current position in output (updated)
 * @output_size: Remaining space in output buffer
 *
 * Outputs 3-padding_count bytes.
 * Performs bounds check on output buffer.
 *
 * Returns: 0 on success, -1 if output buffer too small
 * Thread-safe: Yes
 */
static int
base64_decode_block (const unsigned char *buffer, int padding_count,
                     unsigned char *output, size_t *out_pos,
                     size_t output_size)
{
  int output_bytes = 3 - padding_count;

  if (*out_pos + (size_t)output_bytes > output_size)
    return -1;

  output[(*out_pos)++] = (buffer[0] << 2) | (buffer[1] >> 4);
  if (output_bytes >= 2)
    output[(*out_pos)++] = (buffer[1] << 4) | (buffer[2] >> 2);
  if (output_bytes >= 3)
    output[(*out_pos)++] = (buffer[2] << 6) | buffer[3];

  return 0;
}

/**
 * base64_decode_partial_block - Decode incomplete final block (no padding
 * expected)
 * @buffer: Partial block buffer (1-3 valid 6-bit values, will be zero-padded
 * to 4)
 * @buffer_pos: Number of valid 6-bit values in buffer (2 or 3)
 * @output: Output buffer
 * @out_pos: Current output position (updated)
 * @output_size: Remaining output capacity
 *
 * Handles cases where input ends without proper padding (non-conformant
 * input). Outputs 1 or 2 bytes depending on buffer_pos.
 *
 * Returns: 0 on success, -1 if insufficient data or buffer overflow
 * Thread-safe: Yes
 */
static int
base64_decode_partial_block (unsigned char *buffer, int buffer_pos,
                             unsigned char *output, size_t *out_pos,
                             size_t output_size)
{
  int real_chars = buffer_pos;

  /* Must have at least 2 characters */
  if (buffer_pos < 2)
    return -1;

  /* Pad with zeros */
  while (buffer_pos < 4)
    buffer[buffer_pos++] = 0;

  /* Output first byte */
  if (*out_pos >= output_size)
    return -1;
  output[(*out_pos)++] = (buffer[0] << 2) | (buffer[1] >> 4);

  /* Output second byte if we had 3+ characters */
  if (real_chars >= 3)
    {
      if (*out_pos >= output_size)
        return -1;
      output[(*out_pos)++] = (buffer[1] << 4) | (buffer[2] >> 2);
    }

  return 0;
}

/**
 * base64_decode_char - Process one input character during incremental decoding
 * (RFC 4648)
 * @c: Input character from Base64 string
 * @buffer: Temporary 4-value buffer for block assembly (updated)
 * @buffer_pos: Current fill level of buffer (0-3, updated)
 * @padding_count: Count of '=' padding encountered (updated)
 * @output: Decoded output buffer
 * @out_pos: Current position in output (updated on block completion)
 * @output_size: Remaining capacity in output buffer
 *
 * Handles whitespace skipping, padding, invalid chars, and block completion.
 * Accumulates 6-bit values until full block, then decodes to output.
 *
 * Returns: 0 continue (success), 1 skip char (whitespace), -1 error (invalid)
 * Thread-safe: Yes
 * Raises: None (caller checks return value)
 */
static int
base64_decode_char (unsigned char c, unsigned char *buffer, int *buffer_pos,
                    int *padding_count, unsigned char *output, size_t *out_pos,
                    size_t output_size)
{
  /* Skip whitespace (RFC 4648 Section 3.3) */
  if (base64_is_whitespace (c))
    return 1;

  /* Handle padding */
  if (c == '=')
    {
      (*padding_count)++;
      if (*padding_count > 2)
        return -1; /* Too much padding */
      buffer[(*buffer_pos)++] = 0;

      /* Process complete 4-character block with padding */
      if (*buffer_pos == 4)
        {
          if (base64_decode_block (buffer, *padding_count, output, out_pos,
                                   output_size)
              < 0)
            return -1;
          *buffer_pos = 0;
        }
      return 0;
    }

  /* No more data after padding */
  if (*padding_count > 0)
    return -1;

  /* Decode character */
  unsigned char val = base64_decode_table[c];
  if (val == 255)
    return -1; /* Invalid character */

  buffer[(*buffer_pos)++] = val;

  /* Process complete 4-character block (no padding) */
  if (*buffer_pos == 4)
    {
      if (base64_decode_block (buffer, 0, output, out_pos, output_size) < 0)
        return -1;
      *buffer_pos = 0;
      *padding_count = 0;
    }

  return 0;
}

ssize_t
SocketCrypto_base64_decode (const char *input, size_t input_len,
                            unsigned char *output, size_t output_size)
{
  size_t out_pos = 0;
  unsigned char buffer[4];
  int buffer_pos = 0;
  int padding_count = 0;
  size_t i;

  if (!output)
    return -1;

  if (!input)
    return (output_size >= 1) ? 0 : -1;

  /* Auto-detect length if not provided */
  if (input_len == 0)
    input_len = strlen (input);

  /* Empty input is valid - return 0 bytes decoded */
  if (input_len == 0)
    return 0;

  if (!SOCKET_SECURITY_VALID_SIZE (input_len))
    {
      return -1; /* Input string too large */
    }

  /* Process each character */
  for (i = 0; i < input_len; i++)
    {
      int result
          = base64_decode_char ((unsigned char)input[i], buffer, &buffer_pos,
                                &padding_count, output, &out_pos, output_size);
      if (result < 0)
        return -1;
    }

  /* Handle remaining partial block (no padding at end) */
  if (buffer_pos > 0)
    {
      if (base64_decode_partial_block (buffer, buffer_pos, output, &out_pos,
                                       output_size)
          < 0)
        return -1;
    }

  return (ssize_t)out_pos;
}

/* ============================================================================
 * Hexadecimal Encoding
 * ============================================================================
 */

void
SocketCrypto_hex_encode (const void *input, size_t input_len, char *output,
                         int lowercase)
{
  const unsigned char *in = (const unsigned char *)input;
  const char *alphabet = lowercase ? hex_lower : hex_upper;
  size_t i;

  assert (output);

  if (!input || input_len == 0)
    {
      output[0] = '\0';
      return;
    }

  if (!SOCKET_SECURITY_VALID_SIZE (input_len))
    {
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "hex_encode: input too large: %zu > %zu",
                        (size_t)input_len,
                        (size_t)SOCKET_SECURITY_MAX_ALLOCATION);
    }

  if (input_len > SIZE_MAX / 2)
    {
      SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                        "hex_encode: input_len %zu causes index overflow",
                        input_len);
    }

  for (i = 0; i < input_len; i++)
    {
      output[i * 2] = alphabet[(in[i] >> 4) & 0x0F];
      output[i * 2 + 1] = alphabet[in[i] & 0x0F];
    }
  output[input_len * 2] = '\0';
}

/**
 * hex_char_to_nibble - Convert single hex character to 4-bit nibble (0-F)
 * @c: Hex character ('0'-'9', 'a'-'f', 'A'-'F')
 *
 * Supports both uppercase and lowercase.
 *
 * Returns: 0-15 on valid hex digit, -1 on invalid
 * Thread-safe: Yes
 */
static int
hex_char_to_nibble (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

ssize_t
SocketCrypto_hex_decode (const char *input, size_t input_len,
                         unsigned char *output, size_t output_size)
{
  size_t i;

  if (!input || !output)
    return -1;

  /* No auto strlen; caller must provide accurate input_len */
  if (!SOCKET_SECURITY_VALID_SIZE (input_len))
    {
      return -1; /* Input string too large */
    }

  if (output_size < input_len / 2)
    return -1;

  /* Length must be even */
  if (input_len % 2 != 0)
    return -1;

  for (i = 0; i < input_len / 2; i++)
    {
      int hi = hex_char_to_nibble (input[i * 2]);
      int lo = hex_char_to_nibble (input[i * 2 + 1]);

      if (hi < 0 || lo < 0)
        return -1;

      output[i] = (unsigned char)((hi << 4) | lo);
    }

  return (ssize_t)(input_len / 2);
}

/* ============================================================================
 * Random Number Generation
 * ============================================================================
 */

#if !SOCKET_HAS_TLS
static pthread_mutex_t urand_mutex = PTHREAD_MUTEX_INITIALIZER;
static int urand_fd = -1;
#endif

int
SocketCrypto_random_bytes (void *output, size_t len)
{
  if (!output)
    return -1;

  if (len == 0)
    return 0;

  if (!SOCKET_SECURITY_VALID_SIZE (len))
    {
      return -1; /* Too large for security limits */
    }

#if SOCKET_HAS_TLS
  if (RAND_bytes ((unsigned char *)output, (int)len) != 1)
    return -1;
  return 0;
#else
  /* Fallback to /dev/urandom when TLS not available - cached fd for efficiency
   */
  pthread_mutex_lock (&urand_mutex);
  int fd = urand_fd;
  if (fd < 0)
    {
      fd = open ("/dev/urandom", O_RDONLY);
      if (fd < 0)
        {
          pthread_mutex_unlock (&urand_mutex);
          return -1;
        }
      urand_fd = fd;
    }

  ssize_t bytes_read = 0;
  unsigned char *buf = (unsigned char *)output;

  while ((size_t)bytes_read < len)
    {
      ssize_t n = read (fd, buf + bytes_read, len - (size_t)bytes_read);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          pthread_mutex_unlock (&urand_mutex);
          return -1;
        }
      if (n == 0)
        {
          pthread_mutex_unlock (&urand_mutex);
          return -1;
        }
      bytes_read += n;
    }

  pthread_mutex_unlock (&urand_mutex);
  return 0;
#endif
}

uint32_t
SocketCrypto_random_uint32 (void)
{
  uint32_t value;

  if (SocketCrypto_random_bytes (&value, sizeof (value)) != 0)
    SOCKET_RAISE_MSG (SocketCrypto, SocketCrypto_Failed,
                      "Random number generation failed");

  return value;
}

/* ============================================================================
 * WebSocket Handshake Helpers (RFC 6455)
 * ============================================================================
 */

int
SocketCrypto_websocket_accept (
    const char *client_key, char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE])
{
  unsigned char sha1_hash[SOCKET_CRYPTO_SHA1_SIZE];
  char concat_buffer[WEBSOCKET_CONCAT_BUFFER_SIZE];
  size_t key_len;
  size_t guid_len;
  size_t concat_len;

  if (!client_key || !output)
    return -1;

  key_len = strlen (client_key);
  guid_len = strlen (SOCKET_CRYPTO_WEBSOCKET_GUID);

  /* Validate key length (24 chars for 16 bytes base64 encoded) */
  if (key_len != WEBSOCKET_KEY_BASE64_LEN)
    return -1;

  /* Concatenate key + GUID */
  concat_len = key_len + guid_len;
  if (concat_len >= sizeof (concat_buffer))
    return -1;

  memcpy (concat_buffer, client_key, key_len);
  memcpy (concat_buffer + key_len, SOCKET_CRYPTO_WEBSOCKET_GUID, guid_len + 1);

#if SOCKET_HAS_TLS
  /* Compute SHA-1 hash */
  if (!SHA1 ((const unsigned char *)concat_buffer, concat_len, sha1_hash))
    return -1;

  /* Base64 encode the hash */
  if (SocketCrypto_base64_encode (sha1_hash, SOCKET_CRYPTO_SHA1_SIZE, output,
                                  SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE)
      < 0)
    return -1;

  /* Clear sensitive data */
  OPENSSL_cleanse (concat_buffer, sizeof (concat_buffer));
  OPENSSL_cleanse (sha1_hash, sizeof (sha1_hash));

  return 0;
#else
  (void)sha1_hash;
  return -1;
#endif
}

int
SocketCrypto_websocket_key (char output[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE])
{
  unsigned char random_bytes[WEBSOCKET_KEY_RANDOM_BYTES];

  if (!output)
    return -1;

  /* Generate 16 random bytes */
  if (SocketCrypto_random_bytes (random_bytes, sizeof (random_bytes)) != 0)
    return -1;

  /* Base64 encode to 24 characters */
  if (SocketCrypto_base64_encode (random_bytes, sizeof (random_bytes), output,
                                  SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE)
      < 0)
    {
      SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
      return -1;
    }

  SocketCrypto_secure_clear (random_bytes, sizeof (random_bytes));
  return 0;
}

/* ============================================================================
 * Security Utilities
 * ============================================================================
 */

int
SocketCrypto_secure_compare (const void *a, const void *b, size_t len)
{
  if (!a || !b)
    return 1; /* Not equal if either is NULL */

  if (len == 0)
    return 0; /* Equal for zero-length comparison */

#if SOCKET_HAS_TLS
  return CRYPTO_memcmp (a, b, len);
#else
  /* Manual constant-time comparison fallback */
  const unsigned char *ua = (const unsigned char *)a;
  const unsigned char *ub = (const unsigned char *)b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < len; i++)
    result |= ua[i] ^ ub[i];

  return result != 0;
#endif
}

void
SocketCrypto_secure_clear (void *ptr, size_t len)
{
  if (!ptr || len == 0)
    return;

#if SOCKET_HAS_TLS
  OPENSSL_cleanse (ptr, len);
#else
  /* Manual secure clear fallback - use volatile to prevent optimization */
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--)
    *p++ = 0;
#endif
}
