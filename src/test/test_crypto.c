/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_crypto.c - Unit tests for SocketCrypto module
 *
 * Part of the Socket Library
 *
 * Tests cryptographic primitives against official test vectors from:
 * - SHA-1: RFC 3174
 * - SHA-256: NIST FIPS 180-4
 * - MD5: RFC 1321
 * - HMAC-SHA256: RFC 4231
 * - Base64: RFC 4648
 * - WebSocket: RFC 6455 Section 4.2.2
 */

#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/**
 * hex_to_bytes - Convert hex string to bytes for test vectors
 */
static int
hex_to_bytes (const char *hex, unsigned char *out, size_t max_len)
{
  size_t len = strlen (hex);
  if (len % 2 != 0 || len / 2 > max_len)
    return -1;

  for (size_t i = 0; i < len / 2; i++)
    {
      int hi, lo;
      char c;

      c = hex[i * 2];
      if (c >= '0' && c <= '9')
        hi = c - '0';
      else if (c >= 'a' && c <= 'f')
        hi = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        hi = c - 'A' + 10;
      else
        return -1;

      c = hex[i * 2 + 1];
      if (c >= '0' && c <= '9')
        lo = c - '0';
      else if (c >= 'a' && c <= 'f')
        lo = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        lo = c - 'A' + 10;
      else
        return -1;

      out[i] = (unsigned char)((hi << 4) | lo);
    }
  return (int)(len / 2);
}

#if SOCKET_HAS_TLS

TEST (sha1_empty)
{
  /* SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709 */
  unsigned char expected[20];
  unsigned char result[20];

  hex_to_bytes ("da39a3ee5e6b4b0d3255bfef95601890afd80709", expected, 20);

  SocketCrypto_sha1 ("", 0, result);
  ASSERT (memcmp (result, expected, 20) == 0);
}

TEST (sha1_abc)
{
  /* SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d */
  unsigned char expected[20];
  unsigned char result[20];

  hex_to_bytes ("a9993e364706816aba3e25717850c26c9cd0d89d", expected, 20);

  SocketCrypto_sha1 ("abc", 3, result);
  ASSERT (memcmp (result, expected, 20) == 0);
}

TEST (sha1_long)
{
  /* SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
   * = 84983e441c3bd26ebaae4aa1f95129e5e54670f1 */
  const char *input
      = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  unsigned char expected[20];
  unsigned char result[20];

  hex_to_bytes ("84983e441c3bd26ebaae4aa1f95129e5e54670f1", expected, 20);

  SocketCrypto_sha1 (input, strlen (input), result);
  ASSERT (memcmp (result, expected, 20) == 0);
}

TEST (sha256_empty)
{
  /* SHA-256("") */
  unsigned char expected[32];
  unsigned char result[32];

  hex_to_bytes (
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      expected,
      32);

  SocketCrypto_sha256 ("", 0, result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (sha256_abc)
{
  /* SHA-256("abc") */
  unsigned char expected[32];
  unsigned char result[32];

  hex_to_bytes (
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      expected,
      32);

  SocketCrypto_sha256 ("abc", 3, result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (sha256_long)
{
  /* SHA-256 of longer message */
  const char *input
      = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  unsigned char expected[32];
  unsigned char result[32];

  hex_to_bytes (
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      expected,
      32);

  SocketCrypto_sha256 (input, strlen (input), result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (md5_empty)
{
  /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
  unsigned char expected[16];
  unsigned char result[16];

  hex_to_bytes ("d41d8cd98f00b204e9800998ecf8427e", expected, 16);

  SocketCrypto_md5 ("", 0, result);
  ASSERT (memcmp (result, expected, 16) == 0);
}

TEST (md5_abc)
{
  /* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
  unsigned char expected[16];
  unsigned char result[16];

  hex_to_bytes ("900150983cd24fb0d6963f7d28e17f72", expected, 16);

  SocketCrypto_md5 ("abc", 3, result);
  ASSERT (memcmp (result, expected, 16) == 0);
}

TEST (md5_alphabet)
{
  /* MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b */
  const char *input = "abcdefghijklmnopqrstuvwxyz";
  unsigned char expected[16];
  unsigned char result[16];

  hex_to_bytes ("c3fcd3d76192e4007dfb496cca67e13b", expected, 16);

  SocketCrypto_md5 (input, strlen (input), result);
  ASSERT (memcmp (result, expected, 16) == 0);
}

TEST (hmac_sha256_test_case_1)
{
  /* RFC 4231 Test Case 1 */
  unsigned char key[20];
  unsigned char expected[32];
  unsigned char result[32];

  /* Key = 0x0b repeated 20 times */
  memset (key, 0x0b, 20);

  /* Data = "Hi There" */
  const char *data = "Hi There";

  hex_to_bytes (
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      expected,
      32);

  SocketCrypto_hmac_sha256 (key, 20, data, strlen (data), result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (hmac_sha256_test_case_2)
{
  /* RFC 4231 Test Case 2 */
  const char *key = "Jefe";
  const char *data = "what do ya want for nothing?";
  unsigned char expected[32];
  unsigned char result[32];

  hex_to_bytes (
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      expected,
      32);

  SocketCrypto_hmac_sha256 (key, strlen (key), data, strlen (data), result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (hmac_sha256_test_case_3)
{
  /* RFC 4231 Test Case 3 */
  unsigned char key[20];
  unsigned char data[50];
  unsigned char expected[32];
  unsigned char result[32];

  /* Key = 0xaa repeated 20 times */
  memset (key, 0xaa, 20);

  /* Data = 0xdd repeated 50 times */
  memset (data, 0xdd, 50);

  hex_to_bytes (
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      expected,
      32);

  SocketCrypto_hmac_sha256 (key, 20, data, 50, result);
  ASSERT (memcmp (result, expected, 32) == 0);
}

TEST (websocket_accept)
{
  /* RFC 6455 Section 4.2.2 example:
   * Client sends: Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
   * Server computes: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
   */
  char result[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
  int ret = SocketCrypto_websocket_accept ("dGhlIHNhbXBsZSBub25jZQ==", result);

  ASSERT (ret == 0);
  ASSERT (strcmp (result, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
}

TEST (websocket_key)
{
  char key[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];
  int ret = SocketCrypto_websocket_key (key);

  ASSERT (ret == 0);
  ASSERT (strlen (key) == 24); /* 16 bytes base64 = 24 chars */

  /* Generate another key and ensure different */
  char key2[SOCKET_CRYPTO_WEBSOCKET_KEY_SIZE];
  ret = SocketCrypto_websocket_key (key2);
  ASSERT (ret == 0);
  ASSERT (strcmp (key, key2) != 0);
}

TEST (websocket_accept_invalid)
{
  char result[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];

  /* Invalid key length */
  int ret = SocketCrypto_websocket_accept ("tooshort", result);
  ASSERT (ret == -1);

  /* NULL input */
  ret = SocketCrypto_websocket_accept (NULL, result);
  ASSERT (ret == -1);
}

TEST (random_uint32)
{
  uint32_t val1 = SocketCrypto_random_uint32 ();
  uint32_t val2 = SocketCrypto_random_uint32 ();

  /* Very unlikely to be equal */
  ASSERT (val1 != val2);
}

#endif /* SOCKET_HAS_TLS */

TEST (base64_encode_empty)
{
  char output[16];
  ssize_t len = SocketCrypto_base64_encode ("", 0, output, sizeof (output));
  ASSERT (len == 0);
  ASSERT (output[0] == '\0');
}

TEST (base64_encode_f)
{
  /* RFC 4648: "f" -> "Zg==" */
  char output[16];
  ssize_t len = SocketCrypto_base64_encode ("f", 1, output, sizeof (output));
  ASSERT (len == 4);
  ASSERT (strcmp (output, "Zg==") == 0);
}

TEST (base64_encode_fo)
{
  /* RFC 4648: "fo" -> "Zm8=" */
  char output[16];
  ssize_t len = SocketCrypto_base64_encode ("fo", 2, output, sizeof (output));
  ASSERT (len == 4);
  ASSERT (strcmp (output, "Zm8=") == 0);
}

TEST (base64_encode_foo)
{
  /* RFC 4648: "foo" -> "Zm9v" */
  char output[16];
  ssize_t len = SocketCrypto_base64_encode ("foo", 3, output, sizeof (output));
  ASSERT (len == 4);
  ASSERT (strcmp (output, "Zm9v") == 0);
}

TEST (base64_encode_foob)
{
  /* RFC 4648: "foob" -> "Zm9vYg==" */
  char output[16];
  ssize_t len = SocketCrypto_base64_encode ("foob", 4, output, sizeof (output));
  ASSERT (len == 8);
  ASSERT (strcmp (output, "Zm9vYg==") == 0);
}

TEST (base64_encode_fooba)
{
  /* RFC 4648: "fooba" -> "Zm9vYmE=" */
  char output[16];
  ssize_t len
      = SocketCrypto_base64_encode ("fooba", 5, output, sizeof (output));
  ASSERT (len == 8);
  ASSERT (strcmp (output, "Zm9vYmE=") == 0);
}

TEST (base64_encode_foobar)
{
  /* RFC 4648: "foobar" -> "Zm9vYmFy" */
  char output[16];
  ssize_t len
      = SocketCrypto_base64_encode ("foobar", 6, output, sizeof (output));
  ASSERT (len == 8);
  ASSERT (strcmp (output, "Zm9vYmFy") == 0);
}

TEST (base64_decode_empty)
{
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("", 0, output, sizeof (output));
  ASSERT (len == 0);
}

TEST (base64_decode_Zg)
{
  /* "Zg==" -> "f" */
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("Zg==", 4, output, sizeof (output));
  ASSERT (len == 1);
  ASSERT (output[0] == 'f');
}

TEST (base64_decode_Zm8)
{
  /* "Zm8=" -> "fo" */
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("Zm8=", 4, output, sizeof (output));
  ASSERT (len == 2);
  ASSERT (memcmp (output, "fo", 2) == 0);
}

TEST (base64_decode_Zm9v)
{
  /* "Zm9v" -> "foo" */
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("Zm9v", 4, output, sizeof (output));
  ASSERT (len == 3);
  ASSERT (memcmp (output, "foo", 3) == 0);
}

TEST (base64_decode_foobar)
{
  /* "Zm9vYmFy" -> "foobar" */
  unsigned char output[16];
  ssize_t len
      = SocketCrypto_base64_decode ("Zm9vYmFy", 8, output, sizeof (output));
  ASSERT (len == 6);
  ASSERT (memcmp (output, "foobar", 6) == 0);
}

TEST (base64_roundtrip)
{
  const char *original = "Hello, World! This is a test of Base64 encoding.";
  char encoded[128];
  unsigned char decoded[128];

  ssize_t enc_len = SocketCrypto_base64_encode (
      original, strlen (original), encoded, sizeof (encoded));
  ASSERT (enc_len > 0);

  ssize_t dec_len = SocketCrypto_base64_decode (
      encoded, (size_t)enc_len, decoded, sizeof (decoded));
  ASSERT (dec_len == (ssize_t)strlen (original));
  ASSERT (memcmp (decoded, original, (size_t)dec_len) == 0);
}

TEST (base64_unpadded_partial)
{
  /* Test unpadded partial blocks - regression test for bug where
   * 2-character input incorrectly produced 2 output bytes instead of 1 */
  unsigned char output[16];

  /* 2 base64 chars = 12 bits = 1 output byte (4 bits unused) */
  ssize_t len = SocketCrypto_base64_decode ("Zg", 2, output, sizeof (output));
  ASSERT (len == 1);
  ASSERT (output[0] == 'f');

  /* 3 base64 chars = 18 bits = 2 output bytes (2 bits unused) */
  len = SocketCrypto_base64_decode ("Zm8", 3, output, sizeof (output));
  ASSERT (len == 2);
  ASSERT (memcmp (output, "fo", 2) == 0);
}

TEST (base64_url_safe)
{
  /* URL-safe Base64 uses - and _ instead of + and / */
  unsigned char output[16];

  /* Standard: "+" decodes as 62, "/" decodes as 63 */
  /* URL-safe: "-" decodes as 62, "_" decodes as 63 */
  ssize_t len = SocketCrypto_base64_decode ("+/", 2, output, sizeof (output));
  ASSERT (len > 0);

  len = SocketCrypto_base64_decode ("-_", 2, output, sizeof (output));
  ASSERT (len > 0);
}

TEST (base64_whitespace)
{
  /* Base64 should ignore whitespace per RFC 4648 Section 3.3 */
  unsigned char output[16];
  const char *input = "Zm 9v\nYm\tFy";
  ssize_t len = SocketCrypto_base64_decode (
      input, strlen (input), output, sizeof (output));
  ASSERT (len == 6);
  ASSERT (memcmp (output, "foobar", 6) == 0);
}

TEST (base64_invalid)
{
  unsigned char output[16];

  /* Invalid character */
  ssize_t len
      = SocketCrypto_base64_decode ("Zm9v!", 5, output, sizeof (output));
  ASSERT (len == -1);
}

TEST (base64_buffer_size)
{
  ASSERT (SocketCrypto_base64_encoded_size (0) == 1);
  ASSERT (SocketCrypto_base64_encoded_size (1) == 5);
  ASSERT (SocketCrypto_base64_encoded_size (2) == 5);
  ASSERT (SocketCrypto_base64_encoded_size (3) == 5);
  ASSERT (SocketCrypto_base64_encoded_size (4) == 9);

  ASSERT (SocketCrypto_base64_decoded_size (0) == 0);
  ASSERT (SocketCrypto_base64_decoded_size (4) == 3);
  ASSERT (SocketCrypto_base64_decoded_size (8) == 6);
}

TEST (base64_decode_zero_length_rejected_for_non_empty_input)
{
  /* Non-empty input now requires explicit length to avoid unsafe scans. */
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("Zm9v", 0, output, sizeof (output));
  ASSERT (len == -1);
}

TEST (base64_decode_zero_length_allowed_for_empty_input)
{
  unsigned char output[16];
  ssize_t len = SocketCrypto_base64_decode ("", 0, output, sizeof (output));
  ASSERT (len == 0);
}

TEST (hex_encode_empty)
{
  char output[16];
  SocketCrypto_hex_encode ("", 0, output, 1);
  ASSERT (output[0] == '\0');
}

TEST (hex_encode_bytes)
{
  unsigned char input[] = { 0xde, 0xad, 0xbe, 0xef };
  char output[16];

  SocketCrypto_hex_encode (input, 4, output, 1);
  ASSERT (strcmp (output, "deadbeef") == 0);

  SocketCrypto_hex_encode (input, 4, output, 0);
  ASSERT (strcmp (output, "DEADBEEF") == 0);
}

TEST (hex_decode_valid)
{
  unsigned char output[16];
  unsigned char expected[] = { 0xde, 0xad, 0xbe, 0xef };

  ssize_t len
      = SocketCrypto_hex_decode ("deadbeef", 8, output, sizeof (output));
  ASSERT (len == 4);
  ASSERT (memcmp (output, expected, 4) == 0);

  len = SocketCrypto_hex_decode ("DEADBEEF", 8, output, sizeof (output));
  ASSERT (len == 4);
  ASSERT (memcmp (output, expected, 4) == 0);
}

TEST (hex_decode_invalid)
{
  unsigned char output[16];

  /* Odd length */
  ssize_t len = SocketCrypto_hex_decode ("abc", 3, output, sizeof (output));
  ASSERT (len == -1);

  /* Invalid character */
  len = SocketCrypto_hex_decode ("ghij", 4, output, sizeof (output));
  ASSERT (len == -1);
}

TEST (hex_roundtrip)
{
  unsigned char original[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  char encoded[64];
  unsigned char decoded[16];

  SocketCrypto_hex_encode (original, 16, encoded, 1);
  ssize_t len
      = SocketCrypto_hex_decode (encoded, 32, decoded, sizeof (decoded));
  ASSERT (len == 16);
  ASSERT (memcmp (decoded, original, 16) == 0);
}

TEST (random_bytes)
{
  unsigned char buf1[32];
  unsigned char buf2[32];

  /* Generate random bytes */
  int result = SocketCrypto_random_bytes (buf1, sizeof (buf1));
  ASSERT (result == 0);

  /* Generate again and ensure different */
  result = SocketCrypto_random_bytes (buf2, sizeof (buf2));
  ASSERT (result == 0);

  /* Very unlikely to be equal */
  ASSERT (memcmp (buf1, buf2, sizeof (buf1)) != 0);
}

TEST (random_bytes_empty)
{
  unsigned char buf[1] = { 0xAA };
  int result = SocketCrypto_random_bytes (buf, 0);
  ASSERT (result == 0);
  ASSERT (buf[0] == 0xAA); /* Unchanged */
}

TEST (secure_compare_equal)
{
  unsigned char a[] = { 0x01, 0x02, 0x03, 0x04 };
  unsigned char b[] = { 0x01, 0x02, 0x03, 0x04 };

  int result = SocketCrypto_secure_compare (a, b, 4);
  ASSERT (result == 0);
}

TEST (secure_compare_different)
{
  unsigned char a[] = { 0x01, 0x02, 0x03, 0x04 };
  unsigned char b[] = { 0x01, 0x02, 0x03, 0x05 };

  int result = SocketCrypto_secure_compare (a, b, 4);
  ASSERT (result != 0);
}

TEST (secure_compare_empty)
{
  unsigned char a[] = { 0x01 };
  unsigned char b[] = { 0x02 };

  int result = SocketCrypto_secure_compare (a, b, 0);
  ASSERT (result == 0); /* Empty comparison is equal */
}

TEST (secure_clear)
{
  unsigned char buf[16];
  memset (buf, 0xFF, sizeof (buf));

  SocketCrypto_secure_clear (buf, sizeof (buf));

  for (size_t i = 0; i < sizeof (buf); i++)
    {
      ASSERT (buf[i] == 0);
    }
}

#if SOCKET_HAS_TLS

TEST (hkdf_extract_quic_initial)
{
  /* RFC 9001 Appendix A.1: Initial secret derivation
   * salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
   * IKM = client DCID = 0x8394c8f03e515708
   * Expected PRK = 7db5df06e7a69e432496adedb0085192
   *                3595221596ae2ae9fb8115c1e9ed0a44
   */
  unsigned char salt[20], ikm[8], expected[32], prk[32];

  hex_to_bytes ("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", salt, 20);
  hex_to_bytes ("8394c8f03e515708", ikm, 8);
  hex_to_bytes ("7db5df06e7a69e432496adedb0085192"
                "3595221596ae2ae9fb8115c1e9ed0a44",
                expected,
                32);

  SocketCrypto_hkdf_extract (salt, 20, ikm, 8, prk);
  ASSERT (memcmp (prk, expected, 32) == 0);
}

TEST (hkdf_expand_label_client_in)
{
  /* RFC 9001 Appendix A.1: client_initial_secret
   * PRK = initial_secret from above
   * label = "client in" (without tls13 prefix)
   * context = ""
   * output_len = 32
   * Expected = c00cf151ca5be075ed0ebfb5c80323c4
   *            2d6b7db67881289af4008f1f6c357aea
   */
  unsigned char prk[32], expected[32], output[32];

  hex_to_bytes ("7db5df06e7a69e432496adedb0085192"
                "3595221596ae2ae9fb8115c1e9ed0a44",
                prk,
                32);
  hex_to_bytes ("c00cf151ca5be075ed0ebfb5c80323c4"
                "2d6b7db67881289af4008f1f6c357aea",
                expected,
                32);

  SocketCrypto_hkdf_expand_label (prk, 32, "client in", NULL, 0, output, 32);
  ASSERT (memcmp (output, expected, 32) == 0);
}

TEST (hkdf_expand_label_quic_key)
{
  /* RFC 9001 Appendix A.1: client key derivation
   * PRK = client_initial_secret
   * label = "quic key"
   * context = ""
   * output_len = 16
   * Expected = 1f369613dd76d5467730efcbe3b1a22d
   */
  unsigned char prk[32], expected[16], output[16];

  hex_to_bytes ("c00cf151ca5be075ed0ebfb5c80323c4"
                "2d6b7db67881289af4008f1f6c357aea",
                prk,
                32);
  hex_to_bytes ("1f369613dd76d5467730efcbe3b1a22d", expected, 16);

  SocketCrypto_hkdf_expand_label (prk, 32, "quic key", NULL, 0, output, 16);
  ASSERT (memcmp (output, expected, 16) == 0);
}

TEST (hkdf_expand_label_quic_iv)
{
  /* RFC 9001 Appendix A.1: client IV derivation
   * Expected = fa044b2f42a3fd3b46fb255c
   */
  unsigned char prk[32], expected[12], output[12];

  hex_to_bytes ("c00cf151ca5be075ed0ebfb5c80323c4"
                "2d6b7db67881289af4008f1f6c357aea",
                prk,
                32);
  hex_to_bytes ("fa044b2f42a3fd3b46fb255c", expected, 12);

  SocketCrypto_hkdf_expand_label (prk, 32, "quic iv", NULL, 0, output, 12);
  ASSERT (memcmp (output, expected, 12) == 0);
}

TEST (hkdf_expand_label_quic_hp)
{
  /* RFC 9001 Appendix A.1: client header protection key
   * Expected = 9f50449e04a0e810283a1e9933adedd2
   */
  unsigned char prk[32], expected[16], output[16];

  hex_to_bytes ("c00cf151ca5be075ed0ebfb5c80323c4"
                "2d6b7db67881289af4008f1f6c357aea",
                prk,
                32);
  hex_to_bytes ("9f50449e04a0e810283a1e9933adedd2", expected, 16);

  SocketCrypto_hkdf_expand_label (prk, 32, "quic hp", NULL, 0, output, 16);
  ASSERT (memcmp (output, expected, 16) == 0);
}

TEST (hkdf_expand_label_server_in)
{
  /* RFC 9001 Appendix A.1: server_initial_secret
   * Expected = 3c199828fd139efd216c155ad844cc81
   *            fb82fa8d7446fa7d78be803acdda951b
   */
  unsigned char prk[32], expected[32], output[32];

  hex_to_bytes ("7db5df06e7a69e432496adedb0085192"
                "3595221596ae2ae9fb8115c1e9ed0a44",
                prk,
                32);
  hex_to_bytes ("3c199828fd139efd216c155ad844cc81"
                "fb82fa8d7446fa7d78be803acdda951b",
                expected,
                32);

  SocketCrypto_hkdf_expand_label (prk, 32, "server in", NULL, 0, output, 32);
  ASSERT (memcmp (output, expected, 32) == 0);
}

TEST (hkdf_extract_null_salt)
{
  /* RFC 5869 §2.2: If salt not provided, use HashLen zero bytes */
  unsigned char ikm[16] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
  unsigned char prk1[32], prk2[32];
  unsigned char zero_salt[32] = { 0 };

  /* NULL salt should use zero bytes */
  SocketCrypto_hkdf_extract (NULL, 0, ikm, 16, prk1);
  SocketCrypto_hkdf_extract (zero_salt, 32, ikm, 16, prk2);

  ASSERT (memcmp (prk1, prk2, 32) == 0);
}

TEST (hkdf_expand_label_max_info_bounds_safe)
{
  unsigned char prk[32] = { 0 };
  unsigned char output[32] = { 0 };
  unsigned char context[255];
  char label[250];
  volatile int raised = 0;

  memset (context, 0xAB, sizeof (context));
  memset (label, 'L', sizeof (label) - 1);
  label[sizeof (label) - 1] = '\0'; /* label_len=249 */

  TRY
  {
    SocketCrypto_hkdf_expand_label (
        prk, sizeof (prk), label, context, sizeof (context), output, 32);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 0);
}

TEST (aead_aes128gcm_empty)
{
  /* NIST GCM Test Case 1: Empty plaintext, empty AAD
   * Key = 00000000000000000000000000000000
   * IV  = 000000000000000000000000
   * Expected Tag = 58e2fccefa7e3061367f1d57a4e7455a
   */
  unsigned char key[16], iv[12], expected_tag[16], tag[16];

  hex_to_bytes ("00000000000000000000000000000000", key, 16);
  hex_to_bytes ("000000000000000000000000", iv, 12);
  hex_to_bytes ("58e2fccefa7e3061367f1d57a4e7455a", expected_tag, 16);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             NULL,
                             0, /* empty plaintext */
                             NULL,
                             0, /* empty AAD */
                             NULL,
                             tag);

  ASSERT (memcmp (tag, expected_tag, 16) == 0);
}

TEST (aead_aes128gcm_roundtrip)
{
  /* Basic encrypt/decrypt round-trip test */
  unsigned char key[16], iv[12];
  const char *plaintext = "Hello, QUIC!";
  size_t pt_len = strlen (plaintext);
  unsigned char ct[32], pt_out[32], tag[16];

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                                          key,
                                          16,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, plaintext, pt_len) == 0);
}

TEST (aead_aes128gcm_with_aad)
{
  /* Encrypt with AAD and verify round-trip */
  unsigned char key[16], iv[12];
  const char *plaintext = "Payload";
  const char *aad = "Header";
  size_t pt_len = strlen (plaintext);
  size_t aad_len = strlen (aad);
  unsigned char ct[32], pt_out[32], tag[16];

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  hex_to_bytes ("0a0b0c0d0e0f01020304050a", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             (unsigned char *)aad,
                             aad_len,
                             ct,
                             tag);

  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                                          key,
                                          16,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          (unsigned char *)aad,
                                          aad_len,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, plaintext, pt_len) == 0);
}

TEST (aead_aes128gcm_tag_mismatch)
{
  /* Verify tag mismatch returns -1 (not exception) */
  unsigned char key[16], iv[12], tag[16], bad_tag[16];
  const char *plaintext = "Test";
  size_t pt_len = strlen (plaintext);
  unsigned char ct[16], pt_out[16];

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  /* Corrupt the tag */
  memcpy (bad_tag, tag, 16);
  bad_tag[0] ^= 0xFF;

  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                                          key,
                                          16,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          bad_tag,
                                          pt_out);

  ASSERT (result == -1); /* Auth failure */
}

TEST (aead_aes256gcm_roundtrip)
{
  /* AES-256-GCM round-trip */
  unsigned char key[32], iv[12];
  const char *plaintext = "AES-256 test";
  size_t pt_len = strlen (plaintext);
  unsigned char ct[32], pt_out[32], tag[16];

  hex_to_bytes (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      key,
      32);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_256_GCM,
                             key,
                             32,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_256_GCM,
                                          key,
                                          32,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, plaintext, pt_len) == 0);
}

TEST (aead_chacha20poly1305_roundtrip)
{
  /* ChaCha20-Poly1305 round-trip */
  unsigned char key[32], iv[12];
  const char *plaintext = "ChaCha20 test";
  size_t pt_len = strlen (plaintext);
  unsigned char ct[32], pt_out[32], tag[16];

  hex_to_bytes (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      key,
      32);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305,
                             key,
                             32,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305,
                                          key,
                                          32,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, plaintext, pt_len) == 0);
}

TEST (aead_quic_client_initial)
{
  /* RFC 9001 Appendix A.2: Client Initial packet protection
   * Uses derived keys from A.1:
   * key = 1f369613dd76d5467730efcbe3b1a22d
   * iv  = fa044b2f42a3fd3b46fb255c
   */
  unsigned char key[16], iv[12];
  const char *test_payload = "Test QUIC payload";
  size_t pt_len = strlen (test_payload);
  unsigned char ct[64], pt_out[64], tag[16];

  hex_to_bytes ("1f369613dd76d5467730efcbe3b1a22d", key, 16);
  hex_to_bytes ("fa044b2f42a3fd3b46fb255c", iv, 12);

  /* Encrypt */
  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             (unsigned char *)test_payload,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  /* Decrypt and verify */
  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                                          key,
                                          16,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, test_payload, pt_len) == 0);
}

TEST (aead_chacha20_rfc9001_keys)
{
  /* RFC 9001 Appendix A.5: ChaCha20-Poly1305 keys
   * key = c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
   * iv  = e0459b3474bdd0e44a41c144
   */
  unsigned char key[32], iv[12];
  const char *test_payload = "ChaCha20 QUIC test";
  size_t pt_len = strlen (test_payload);
  unsigned char ct[64], pt_out[64], tag[16];

  hex_to_bytes (
      "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
      key,
      32);
  hex_to_bytes ("e0459b3474bdd0e44a41c144", iv, 12);

  /* Encrypt */
  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305,
                             key,
                             32,
                             iv,
                             12,
                             (unsigned char *)test_payload,
                             pt_len,
                             NULL,
                             0,
                             ct,
                             tag);

  /* Decrypt and verify */
  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_CHACHA20_POLY1305,
                                          key,
                                          32,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          NULL,
                                          0,
                                          tag,
                                          pt_out);

  ASSERT (result == 0);
  ASSERT (memcmp (pt_out, test_payload, pt_len) == 0);
}

TEST (aead_aad_tamper_detection)
{
  /* Verify that modifying AAD causes auth failure */
  unsigned char key[16], iv[12];
  const char *plaintext = "Secret";
  const char *aad = "AuthenticatedHeader";
  const char *bad_aad = "ModifiedHeader12345";
  size_t pt_len = strlen (plaintext);
  size_t aad_len = strlen (aad);
  unsigned char ct[32], pt_out[32], tag[16];

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                             key,
                             16,
                             iv,
                             12,
                             (unsigned char *)plaintext,
                             pt_len,
                             (unsigned char *)aad,
                             aad_len,
                             ct,
                             tag);

  /* Decrypt with modified AAD should fail */
  int result = SocketCrypto_aead_decrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                                          key,
                                          16,
                                          iv,
                                          12,
                                          ct,
                                          pt_len,
                                          (unsigned char *)bad_aad,
                                          strlen (bad_aad),
                                          tag,
                                          pt_out);

  ASSERT (result == -1); /* Auth failure due to AAD mismatch */
}

TEST (aead_invalid_algorithm)
{
  /* Invalid algorithm enum should raise exception */
  unsigned char key[16], iv[12], ct[16], tag[16];
  volatile int raised = 0;

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  hex_to_bytes ("000000000000000000000000", iv, 12);

  TRY
  {
    SocketCrypto_aead_encrypt ((SocketCrypto_AeadAlg)99, /* invalid */
                               key,
                               16,
                               iv,
                               12,
                               NULL,
                               0,
                               NULL,
                               0,
                               ct,
                               tag);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 1);
}

TEST (aead_wrong_key_length)
{
  /* Wrong key length should raise exception */
  unsigned char key[15], iv[12], ct[16], tag[16]; /* 15 bytes, not 16 */
  volatile int raised = 0;

  memset (key, 0, sizeof (key));
  hex_to_bytes ("000000000000000000000000", iv, 12);

  TRY
  {
    SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                               key,
                               15, /* wrong: should be 16 */
                               iv,
                               12,
                               NULL,
                               0,
                               NULL,
                               0,
                               ct,
                               tag);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 1);
}

TEST (aead_null_key)
{
  /* NULL key should raise exception */
  unsigned char iv[12], ct[16], tag[16];
  volatile int raised = 0;

  hex_to_bytes ("000000000000000000000000", iv, 12);

  TRY
  {
    SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                               NULL, /* NULL key */
                               16,
                               iv,
                               12,
                               NULL,
                               0,
                               NULL,
                               0,
                               ct,
                               tag);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 1);
}

TEST (aead_null_nonce)
{
  /* NULL nonce should raise exception */
  unsigned char key[16], ct[16], tag[16];
  volatile int raised = 0;

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);

  TRY
  {
    SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                               key,
                               16,
                               NULL, /* NULL nonce */
                               12,
                               NULL,
                               0,
                               NULL,
                               0,
                               ct,
                               tag);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 1);
}

TEST (aead_wrong_nonce_length)
{
  /* Wrong nonce length should raise exception */
  unsigned char key[16], iv[11], ct[16], tag[16]; /* 11 bytes, not 12 */
  volatile int raised = 0;

  hex_to_bytes ("000102030405060708090a0b0c0d0e0f", key, 16);
  memset (iv, 0, sizeof (iv));

  TRY
  {
    SocketCrypto_aead_encrypt (SOCKET_CRYPTO_AEAD_AES_128_GCM,
                               key,
                               16,
                               iv,
                               11, /* wrong: should be 12 */
                               NULL,
                               0,
                               NULL,
                               0,
                               ct,
                               tag);
  }
  EXCEPT (SocketCrypto_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT (raised == 1);
}

#endif /* SOCKET_HAS_TLS */

TEST (cleanup_idempotent)
{
  /* Cleanup should be safe to call multiple times */
  SocketCrypto_cleanup ();
  SocketCrypto_cleanup ();
  SocketCrypto_cleanup ();
}

TEST (cleanup_after_use)
{
  unsigned char buf[16];

  /* Use crypto functions first */
  int ret = SocketCrypto_random_bytes (buf, sizeof (buf));
  ASSERT (ret == 0);

  /* Cleanup should succeed */
  SocketCrypto_cleanup ();
}

TEST (cleanup_without_prior_use)
{
  /* Cleanup should be safe when called without any prior SocketCrypto
   * operations */
  SocketCrypto_cleanup ();
}

#if !SOCKET_HAS_TLS
TEST (cleanup_reopens_urandom)
{
  unsigned char buf1[16];
  unsigned char buf2[16];

  /* Generate random bytes */
  int ret = SocketCrypto_random_bytes (buf1, sizeof (buf1));
  ASSERT (ret == 0);

  /* Cleanup closes /dev/urandom */
  SocketCrypto_cleanup ();

  /* Should still work - will reopen /dev/urandom */
  ret = SocketCrypto_random_bytes (buf2, sizeof (buf2));
  ASSERT (ret == 0);

  /* Should be different values (very unlikely to be equal) */
  ASSERT (memcmp (buf1, buf2, sizeof (buf1)) != 0);
}
#endif

int
main (void)
{
  printf ("SocketCrypto Module Tests\n");
  printf ("=========================\n");

#ifndef SOCKET_HAS_TLS
  printf ("Note: TLS-dependent tests skipped (SOCKET_HAS_TLS not defined)\n\n");
#endif

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
