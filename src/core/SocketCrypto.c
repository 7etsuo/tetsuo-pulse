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
#include "core/SocketUtil.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#ifdef SOCKET_HAS_TLS
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketCrypto_Failed
    = { &SocketCrypto_Failed, "Cryptographic operation failed" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketCrypto);

#define RAISE_CRYPTO_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketCrypto, e)

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/* Base64 encoding alphabet (RFC 4648) */
static const char base64_alphabet[]
    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 decoding table: maps ASCII to 6-bit value, 255 = invalid */
static const unsigned char base64_decode_table[256] = {
  /* 0x00-0x0F */ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255,
  /* 0x10-0x1F */ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255,
  /* 0x20-0x2F */ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,
  255, 62, 255, 63,
  /* 0x30-0x3F '0'-'9' */ 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255,
  255, 255, 255,
  /* 0x40-0x4F '@','A'-'O' */ 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
  14,
  /* 0x50-0x5F 'P'-'Z','['-'_' */ 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
  255, 255, 255, 255, 63,
  /* 0x60-0x6F '`','a'-'o' */ 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
  37, 38, 39, 40,
  /* 0x70-0x7F 'p'-'z',... */ 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255,
  255, 255, 255, 255,
  /* 0x80-0xFF */ 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

/* Hex encoding alphabets */
static const char hex_lower[] = "0123456789abcdef";
static const char hex_upper[] = "0123456789ABCDEF";

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

void
SocketCrypto_sha1 (const void *input, size_t input_len,
                   unsigned char output[SOCKET_CRYPTO_SHA1_SIZE])
{
  assert (output);

  if (!input && input_len > 0)
    {
      SOCKET_ERROR_MSG ("SHA-1: NULL input with non-zero length");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

#ifdef SOCKET_HAS_TLS
  if (!SHA1 ((const unsigned char *)input, input_len, output))
    {
      SOCKET_ERROR_MSG ("SHA-1 computation failed");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }
#else
  SOCKET_ERROR_MSG ("SHA-1 requires TLS support (SOCKET_HAS_TLS)");
  RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
#endif
}

void
SocketCrypto_sha256 (const void *input, size_t input_len,
                     unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);

  if (!input && input_len > 0)
    {
      SOCKET_ERROR_MSG ("SHA-256: NULL input with non-zero length");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

#ifdef SOCKET_HAS_TLS
  if (!SHA256 ((const unsigned char *)input, input_len, output))
    {
      SOCKET_ERROR_MSG ("SHA-256 computation failed");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }
#else
  SOCKET_ERROR_MSG ("SHA-256 requires TLS support (SOCKET_HAS_TLS)");
  RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
#endif
}

void
SocketCrypto_md5 (const void *input, size_t input_len,
                  unsigned char output[SOCKET_CRYPTO_MD5_SIZE])
{
  assert (output);

  if (!input && input_len > 0)
    {
      SOCKET_ERROR_MSG ("MD5: NULL input with non-zero length");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

#ifdef SOCKET_HAS_TLS
  /* Use EVP interface for OpenSSL 3.0+ compatibility */
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  if (!ctx)
    {
      SOCKET_ERROR_MSG ("MD5: Failed to create context");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

  if (EVP_DigestInit_ex (ctx, EVP_md5 (), NULL) != 1
      || EVP_DigestUpdate (ctx, input, input_len) != 1
      || EVP_DigestFinal_ex (ctx, output, NULL) != 1)
    {
      EVP_MD_CTX_free (ctx);
      SOCKET_ERROR_MSG ("MD5 computation failed");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

  EVP_MD_CTX_free (ctx);
#else
  SOCKET_ERROR_MSG ("MD5 requires TLS support (SOCKET_HAS_TLS)");
  RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
#endif
}

/* ============================================================================
 * HMAC Functions
 * ============================================================================ */

void
SocketCrypto_hmac_sha256 (const void *key, size_t key_len, const void *data,
                          size_t data_len,
                          unsigned char output[SOCKET_CRYPTO_SHA256_SIZE])
{
  assert (output);

  if (!key && key_len > 0)
    {
      SOCKET_ERROR_MSG ("HMAC-SHA256: NULL key with non-zero length");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

  if (!data && data_len > 0)
    {
      SOCKET_ERROR_MSG ("HMAC-SHA256: NULL data with non-zero length");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

#ifdef SOCKET_HAS_TLS
  /*
   * Security: Validate key_len fits in int for OpenSSL HMAC API.
   * Keys exceeding INT_MAX would be truncated on cast, potentially
   * weakening the MAC. In practice, HMAC keys should be 32-64 bytes;
   * longer keys are internally hashed anyway.
   */
  if (key_len > (size_t)INT_MAX)
    {
      SOCKET_ERROR_MSG ("HMAC-SHA256: Key length %zu exceeds INT_MAX", key_len);
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

  unsigned int hmac_len = 0;
  unsigned char *result
      = HMAC (EVP_sha256 (), key, (int)key_len, (const unsigned char *)data,
              data_len, output, &hmac_len);

  if (!result || hmac_len != SOCKET_CRYPTO_SHA256_SIZE)
    {
      SOCKET_ERROR_MSG ("HMAC-SHA256 computation failed");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }
#else
  SOCKET_ERROR_MSG ("HMAC-SHA256 requires TLS support (SOCKET_HAS_TLS)");
  RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
#endif
}

/* ============================================================================
 * Base64 Encoding (RFC 4648)
 * ============================================================================ */

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

  required_size = SocketCrypto_base64_encoded_size (input_len);
  /* Check for overflow in size calculation */
  if (required_size == 0)
    return -1;

  if (output_size < required_size)
    return -1;

  /* Process 3 bytes at a time */
  for (i = 0; i + 2 < input_len; i += 3)
    {
      output[out_pos++] = base64_alphabet[in[i] >> 2];
      output[out_pos++] = base64_alphabet[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
      output[out_pos++] = base64_alphabet[((in[i + 1] & 0x0F) << 2) | (in[i + 2] >> 6)];
      output[out_pos++] = base64_alphabet[in[i + 2] & 0x3F];
    }

  /* Handle remaining bytes */
  if (i < input_len)
    {
      output[out_pos++] = base64_alphabet[in[i] >> 2];

      if (i + 1 < input_len)
        {
          output[out_pos++] = base64_alphabet[((in[i] & 0x03) << 4) | (in[i + 1] >> 4)];
          output[out_pos++] = base64_alphabet[(in[i + 1] & 0x0F) << 2];
        }
      else
        {
          output[out_pos++] = base64_alphabet[(in[i] & 0x03) << 4];
          output[out_pos++] = '=';
        }
      output[out_pos++] = '=';
    }

  output[out_pos] = '\0';
  return (ssize_t)out_pos;
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
    {
      if (output_size >= 1)
        return 0;
      return -1;
    }

  /* Auto-detect length if not provided */
  if (input_len == 0)
    input_len = strlen (input);

  /* Empty input */
  if (input_len == 0)
    return 0;

  for (i = 0; i < input_len; i++)
    {
      unsigned char c = (unsigned char)input[i];
      unsigned char val;

      /* Skip whitespace (RFC 4648 Section 3.3) */
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        continue;

      /* Handle padding */
      if (c == '=')
        {
          padding_count++;
          if (padding_count > 2)
            return -1; /* Too much padding */
          buffer[buffer_pos++] = 0;

          /* Process complete 4-character block with padding */
          if (buffer_pos == 4)
            {
              /* Output bytes based on padding count:
               * 2 padding chars = 1 output byte
               * 1 padding char  = 2 output bytes */
              int output_bytes = 3 - padding_count;

              if (out_pos + (size_t)output_bytes > output_size)
                return -1;

              output[out_pos++] = (buffer[0] << 2) | (buffer[1] >> 4);
              if (output_bytes >= 2)
                output[out_pos++] = (buffer[1] << 4) | (buffer[2] >> 2);
              if (output_bytes >= 3)
                output[out_pos++] = (buffer[2] << 6) | buffer[3];

              buffer_pos = 0;
            }
          continue;
        }

      /* No more data after padding */
      if (padding_count > 0)
        return -1;

      /* Decode character */
      val = base64_decode_table[c];
      if (val == 255)
        return -1; /* Invalid character */

      buffer[buffer_pos++] = val;

      /* Process complete 4-character block (no padding) */
      if (buffer_pos == 4)
        {
          if (out_pos + 3 > output_size)
            return -1; /* Buffer too small */

          output[out_pos++] = (buffer[0] << 2) | (buffer[1] >> 4);
          output[out_pos++] = (buffer[1] << 4) | (buffer[2] >> 2);
          output[out_pos++] = (buffer[2] << 6) | buffer[3];

          buffer_pos = 0;
          padding_count = 0;
        }
    }

  /* Handle remaining partial block (no padding at end) */
  if (buffer_pos > 0)
    {
      /* Must have at least 2 characters */
      if (buffer_pos < 2)
        return -1;

      /* Save original count before padding */
      int real_chars = buffer_pos;

      /* Pad with zeros */
      while (buffer_pos < 4)
        buffer[buffer_pos++] = 0;

      /* Output based on how many real chars we had:
       * 2 chars -> 1 output byte
       * 3 chars -> 2 output bytes */
      if (out_pos >= output_size)
        return -1;
      output[out_pos++] = (buffer[0] << 2) | (buffer[1] >> 4);

      if (real_chars >= 3)
        {
          if (out_pos >= output_size)
            return -1;
          output[out_pos++] = (buffer[1] << 4) | (buffer[2] >> 2);
        }
    }

  return (ssize_t)out_pos;
}

/* ============================================================================
 * Hexadecimal Encoding
 * ============================================================================ */

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

  for (i = 0; i < input_len; i++)
    {
      output[i * 2] = alphabet[(in[i] >> 4) & 0x0F];
      output[i * 2 + 1] = alphabet[in[i] & 0x0F];
    }
  output[input_len * 2] = '\0';
}

/**
 * hex_char_to_nibble - Convert hex character to nibble value
 * @c: Hex character ('0'-'9', 'a'-'f', 'A'-'F')
 *
 * Returns: 0-15 on success, -1 on invalid character
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
                         unsigned char *output)
{
  size_t i;

  if (!input || !output)
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
 * ============================================================================ */

int
SocketCrypto_random_bytes (void *output, size_t len)
{
  if (!output)
    return -1;

  if (len == 0)
    return 0;

#ifdef SOCKET_HAS_TLS
  if (RAND_bytes ((unsigned char *)output, (int)len) != 1)
    return -1;
  return 0;
#else
  /* Fallback to /dev/urandom when TLS not available */
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;

  ssize_t bytes_read = 0;
  unsigned char *buf = (unsigned char *)output;

  while ((size_t)bytes_read < len)
    {
      ssize_t n = read (fd, buf + bytes_read, len - (size_t)bytes_read);
      if (n < 0)
        {
          if (errno == EINTR)
            continue;
          close (fd);
          return -1;
        }
      if (n == 0)
        {
          close (fd);
          return -1;
        }
      bytes_read += n;
    }

  close (fd);
  return 0;
#endif
}

uint32_t
SocketCrypto_random_uint32 (void)
{
  uint32_t value;

  if (SocketCrypto_random_bytes (&value, sizeof (value)) != 0)
    {
      SOCKET_ERROR_MSG ("Random number generation failed");
      RAISE_CRYPTO_ERROR (SocketCrypto_Failed);
    }

  return value;
}

/* ============================================================================
 * WebSocket Handshake Helpers (RFC 6455)
 * ============================================================================ */

int
SocketCrypto_websocket_accept (const char *client_key,
                               char output[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE])
{
  unsigned char sha1_hash[SOCKET_CRYPTO_SHA1_SIZE];
  char concat_buffer[64]; /* 24 (key) + 36 (GUID) + padding */
  size_t key_len;
  size_t concat_len;

  if (!client_key || !output)
    return -1;

  key_len = strlen (client_key);

  /* Validate key length (should be 24 chars for 16 bytes base64 encoded) */
  if (key_len != 24)
    return -1;

  /* Concatenate key + GUID */
  concat_len = key_len + strlen (SOCKET_CRYPTO_WEBSOCKET_GUID);
  if (concat_len >= sizeof (concat_buffer))
    return -1;

  memcpy (concat_buffer, client_key, key_len);
  memcpy (concat_buffer + key_len, SOCKET_CRYPTO_WEBSOCKET_GUID,
          strlen (SOCKET_CRYPTO_WEBSOCKET_GUID) + 1);

#ifdef SOCKET_HAS_TLS
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
  unsigned char random_bytes[16];

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
 * ============================================================================ */

int
SocketCrypto_secure_compare (const void *a, const void *b, size_t len)
{
  if (!a || !b)
    return 1; /* Not equal if either is NULL */

  if (len == 0)
    return 0; /* Equal for zero-length comparison */

#ifdef SOCKET_HAS_TLS
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

#ifdef SOCKET_HAS_TLS
  OPENSSL_cleanse (ptr, len);
#else
  /* Manual secure clear fallback - use volatile to prevent optimization */
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--)
    *p++ = 0;
#endif
}

