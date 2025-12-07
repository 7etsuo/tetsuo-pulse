/**
 * test_hpack.c - Unit tests for HPACK Header Compression
 *
 * Part of the Socket Library
 *
 * Tests RFC 7541 HPACK implementation including:
 * - Integer encoding/decoding (Appendix C.1)
 * - Huffman encoding/decoding
 * - Static table lookup
 * - Dynamic table operations
 * - Header block decoding (Appendix C.2-C.6)
 * - Security checks (HPACK bomb, size limits)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple test assertion macro */
#define TEST_ASSERT(cond, msg)                                                 \
  do                                                                           \
    {                                                                          \
      if (!(cond))                                                             \
        {                                                                      \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);   \
          exit (1);                                                            \
        }                                                                      \
    }                                                                          \
  while (0)

/* ============================================================================
 * Test Helpers
 * ============================================================================ */

/**
 * Convert hex string to bytes
 */
static int
hex_to_bytes (const char *hex, unsigned char *out, size_t max_len)
{
  size_t len = strlen (hex);
  size_t out_len = 0;

  if (len % 2 != 0)
    return -1;

  for (size_t i = 0; i < len; i += 2)
    {
      if (out_len >= max_len)
        return -1;

      int hi, lo;
      char c;

      c = hex[i];
      if (c >= '0' && c <= '9')
        hi = c - '0';
      else if (c >= 'a' && c <= 'f')
        hi = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        hi = c - 'A' + 10;
      else
        return -1;

      c = hex[i + 1];
      if (c >= '0' && c <= '9')
        lo = c - '0';
      else if (c >= 'a' && c <= 'f')
        lo = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        lo = c - 'A' + 10;
      else
        return -1;

      out[out_len++] = (unsigned char)((hi << 4) | lo);
    }

  return (int)out_len;
}

/* ============================================================================
 * Integer Encoding Tests (RFC 7541 Section 5.1, Appendix C.1)
 * ============================================================================ */

/**
 * Test integer encoding with 5-bit prefix
 * RFC 7541 Section C.1.1: Encoding 10 using a 5-bit prefix
 */
static void
test_int_encode_5bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 10 with 5-bit prefix... ");

  len = SocketHPACK_int_encode (10, 5, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x0A, "Expected 0x0A (10)");

  printf ("PASS\n");
}

/**
 * Test integer encoding requiring multi-byte
 * RFC 7541 Section C.1.2: Encoding 1337 using a 5-bit prefix
 */
static void
test_int_encode_5bit_large (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 1337 with 5-bit prefix... ");

  len = SocketHPACK_int_encode (1337, 5, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Expected 3 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "First byte should be 31 (2^5 - 1)");
  TEST_ASSERT (buf[1] == 0x9A, "Second byte should be 0x9A");
  TEST_ASSERT (buf[2] == 0x0A, "Third byte should be 0x0A");

  printf ("PASS\n");
}

/**
 * Test integer encoding at prefix boundary
 * RFC 7541 Section C.1.3: Encoding 42 starting at an octet boundary
 */
static void
test_int_encode_8bit (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 42 with 8-bit prefix... ");

  len = SocketHPACK_int_encode (42, 8, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 42, "Expected 42");

  printf ("PASS\n");
}

/**
 * Test integer decoding
 */
static void
test_int_decode_small (void)
{
  unsigned char data[] = { 0x0A };
  uint64_t value;
  size_t consumed;
  SocketHPACK_Result result;

  printf ("  Integer decode 10... ");

  result = SocketHPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  TEST_ASSERT (result == HPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 10, "Value should be 10");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test multi-byte integer decoding
 */
static void
test_int_decode_large (void)
{
  unsigned char data[] = { 0x1F, 0x9A, 0x0A };
  uint64_t value;
  size_t consumed;
  SocketHPACK_Result result;

  printf ("  Integer decode 1337... ");

  result = SocketHPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  TEST_ASSERT (result == HPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 1337, "Value should be 1337");
  TEST_ASSERT (consumed == 3, "Should consume 3 bytes");

  printf ("PASS\n");
}

/**
 * Test integer decode with incomplete data
 */
static void
test_int_decode_incomplete (void)
{
  unsigned char data[] = { 0x1F, 0x9A }; /* Missing continuation */
  uint64_t value;
  size_t consumed;
  SocketHPACK_Result result;

  printf ("  Integer decode incomplete... ");

  result = SocketHPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  TEST_ASSERT (result == HPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/* ============================================================================
 * Static Table Tests
 * ============================================================================ */

/**
 * Test static table lookup by index
 */
static void
test_static_table_get (void)
{
  SocketHPACK_Header header;
  SocketHPACK_Result result;

  printf ("  Static table get index 1... ");

  result = SocketHPACK_static_get (1, &header);
  TEST_ASSERT (result == HPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (header.name, ":authority") == 0,
               "Name should be :authority");
  TEST_ASSERT (header.name_len == 10, "Name length should be 10");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

/**
 * Test static table lookup for :method GET
 */
static void
test_static_table_method_get (void)
{
  SocketHPACK_Header header;
  SocketHPACK_Result result;

  printf ("  Static table get :method GET... ");

  result = SocketHPACK_static_get (2, &header);
  TEST_ASSERT (result == HPACK_OK, "Should succeed");
  TEST_ASSERT (strcmp (header.name, ":method") == 0, "Name should be :method");
  TEST_ASSERT (strcmp (header.value, "GET") == 0, "Value should be GET");

  printf ("PASS\n");
}

/**
 * Test static table find
 */
static void
test_static_table_find (void)
{
  int idx;

  printf ("  Static table find :method GET... ");

  idx = SocketHPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (idx == 2, "Should find at index 2");

  printf ("PASS\n");
}

/**
 * Test static table find name only
 */
static void
test_static_table_find_name_only (void)
{
  int idx;

  printf ("  Static table find :method (name only)... ");

  idx = SocketHPACK_static_find (":method", 7, "PUT", 3);
  TEST_ASSERT (idx < 0, "Should return negative (name match only)");
  TEST_ASSERT (-idx == 2 || -idx == 3,
               "Should match :method index 2 or 3");

  printf ("PASS\n");
}

/**
 * Test static table invalid index
 */
static void
test_static_table_invalid_index (void)
{
  SocketHPACK_Header header;
  SocketHPACK_Result result;

  printf ("  Static table invalid index... ");

  result = SocketHPACK_static_get (0, &header);
  TEST_ASSERT (result == HPACK_ERROR_INVALID_INDEX, "Index 0 should fail");

  result = SocketHPACK_static_get (62, &header);
  TEST_ASSERT (result == HPACK_ERROR_INVALID_INDEX, "Index 62 should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * Dynamic Table Tests
 * ============================================================================ */

/**
 * Test dynamic table creation
 */
static void
test_dynamic_table_new (void)
{
  Arena_T arena;
  SocketHPACK_Table_T table;

  printf ("  Dynamic table new... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "Arena should be created");

  table = SocketHPACK_Table_new (4096, arena);
  TEST_ASSERT (table != NULL, "Table should be created");
  TEST_ASSERT (SocketHPACK_Table_size (table) == 0, "Initial size should be 0");
  TEST_ASSERT (SocketHPACK_Table_count (table) == 0,
               "Initial count should be 0");
  TEST_ASSERT (SocketHPACK_Table_max_size (table) == 4096,
               "Max size should be 4096");

  SocketHPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table add
 */
static void
test_dynamic_table_add (void)
{
  Arena_T arena;
  SocketHPACK_Table_T table;
  SocketHPACK_Header header;
  SocketHPACK_Result result;

  printf ("  Dynamic table add... ");

  arena = Arena_new ();
  table = SocketHPACK_Table_new (4096, arena);

  /* Add a header: custom-header: value */
  result = SocketHPACK_Table_add (table, "custom-header", 13, "value", 5);
  TEST_ASSERT (result == HPACK_OK, "Add should succeed");
  TEST_ASSERT (SocketHPACK_Table_count (table) == 1, "Count should be 1");

  /* Size = 13 + 5 + 32 = 50 */
  TEST_ASSERT (SocketHPACK_Table_size (table) == 50, "Size should be 50");

  /* Get the entry */
  result = SocketHPACK_Table_get (table, 1, &header);
  TEST_ASSERT (result == HPACK_OK, "Get should succeed");
  TEST_ASSERT (strcmp (header.name, "custom-header") == 0,
               "Name should match");
  TEST_ASSERT (strcmp (header.value, "value") == 0, "Value should match");

  SocketHPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table eviction
 */
static void
test_dynamic_table_eviction (void)
{
  Arena_T arena;
  SocketHPACK_Table_T table;
  SocketHPACK_Result result;

  printf ("  Dynamic table eviction... ");

  arena = Arena_new ();
  /* Small table: only 100 bytes */
  table = SocketHPACK_Table_new (100, arena);

  /* Add header1: 10 + 10 + 32 = 52 bytes */
  result = SocketHPACK_Table_add (table, "header1234", 10, "value12345", 10);
  TEST_ASSERT (result == HPACK_OK, "First add should succeed");
  TEST_ASSERT (SocketHPACK_Table_count (table) == 1, "Count should be 1");

  /* Add header2: same size, should evict header1 */
  result = SocketHPACK_Table_add (table, "header5678", 10, "value67890", 10);
  TEST_ASSERT (result == HPACK_OK, "Second add should succeed");
  TEST_ASSERT (SocketHPACK_Table_count (table) == 1,
               "Count should still be 1 (evicted)");

  /* Verify it's the new header */
  SocketHPACK_Header header;
  result = SocketHPACK_Table_get (table, 1, &header);
  TEST_ASSERT (result == HPACK_OK, "Get should succeed");
  TEST_ASSERT (strcmp (header.name, "header5678") == 0,
               "Should be new header");

  SocketHPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table size update to zero
 */
static void
test_dynamic_table_size_update_zero (void)
{
  Arena_T arena;
  SocketHPACK_Table_T table;
  SocketHPACK_Result result;

  printf ("  Dynamic table size update to 0... ");

  arena = Arena_new ();
  table = SocketHPACK_Table_new (4096, arena);

  /* Add a header */
  result = SocketHPACK_Table_add (table, "test", 4, "value", 5);
  TEST_ASSERT (result == HPACK_OK, "Add should succeed");
  TEST_ASSERT (SocketHPACK_Table_count (table) == 1, "Count should be 1");

  /* Update size to 0 - should clear table */
  SocketHPACK_Table_set_max_size (table, 0);
  TEST_ASSERT (SocketHPACK_Table_count (table) == 0, "Count should be 0");
  TEST_ASSERT (SocketHPACK_Table_size (table) == 0, "Size should be 0");

  SocketHPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Huffman Encoding/Decoding Tests
 * ============================================================================ */

/**
 * Test Huffman encoded size calculation
 */
static void
test_huffman_encoded_size (void)
{
  const unsigned char input[] = "www.example.com";
  size_t size;

  printf ("  Huffman encoded size... ");

  size = SocketHPACK_huffman_encoded_size (input, sizeof (input) - 1);
  /* www.example.com should compress well */
  TEST_ASSERT (size > 0, "Size should be > 0");
  TEST_ASSERT (size <= sizeof (input) - 1, "Should not expand");

  printf ("PASS\n");
}

/**
 * Test basic Huffman encoding
 */
static void
test_huffman_encode_basic (void)
{
  const unsigned char input[] = "test";
  unsigned char output[32];
  ssize_t len;

  printf ("  Huffman encode basic... ");

  len = SocketHPACK_huffman_encode (input, 4, output, sizeof (output));
  TEST_ASSERT (len > 0, "Should encode successfully");
  TEST_ASSERT ((size_t)len <= sizeof (output), "Should fit in buffer");

  printf ("PASS\n");
}

/**
 * Test Huffman round-trip
 */
static void
test_huffman_round_trip (void)
{
  const unsigned char input[] = "hello";
  unsigned char encoded[32];
  unsigned char decoded[32];
  ssize_t enc_len, dec_len;

  printf ("  Huffman round-trip... ");

  enc_len = SocketHPACK_huffman_encode (input, 5, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encode should succeed");

  dec_len
      = SocketHPACK_huffman_decode (encoded, (size_t)enc_len, decoded, sizeof (decoded));
  TEST_ASSERT (dec_len == 5, "Decoded length should be 5");
  TEST_ASSERT (memcmp (decoded, input, 5) == 0, "Decoded should match input");

  printf ("PASS\n");
}

/**
 * Test Huffman full round-trip for all bytes and edge cases (including long codes, empty, EOS validation)
 */
static void
test_huffman_full_roundtrip (void)
{
  unsigned char input[1];
  unsigned char encoded[64];  /* Ample for long code + EOS + pad */
  unsigned char decoded[64];
  ssize_t enc_len, dec_len;
  size_t i, est_size;

  printf ("  Huffman full round-trip (all bytes + edges)... ");

  /* Test empty string */
  enc_len = SocketHPACK_huffman_encode (input, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len == 4, "Empty encode: EOS (30 bits) + pad = 4 bytes");
  dec_len = SocketHPACK_huffman_decode (encoded, (size_t)enc_len, decoded, sizeof (decoded));
  TEST_ASSERT (dec_len == 0, "Empty decode: 0 bytes output");
  est_size = SocketHPACK_huffman_encoded_size (input, 0);
  TEST_ASSERT (est_size == 4, "Empty encoded_size: 4 bytes");

  /* Test basic invalid: truncated input (should fail decode) */
  unsigned char trunc[1] = {0xFF};  /* Short invalid bitstream */
  dec_len = SocketHPACK_huffman_decode (trunc, 1, decoded, sizeof (decoded));
  TEST_ASSERT (dec_len < 0, "Truncated input fails decode");

  /* Test all single bytes 0-255 (covers short/long codes, EOS handling) */
  for (i = 0; i < 256; i++)
    {
      input[0] = (unsigned char) i;
      enc_len = SocketHPACK_huffman_encode (input, 1, encoded, sizeof (encoded));
      TEST_ASSERT (enc_len > 0, "Encode byte succeeds");
      dec_len = SocketHPACK_huffman_decode (encoded, (size_t)enc_len, decoded, sizeof (decoded));
      TEST_ASSERT (dec_len == 1, "Decode byte: 1 byte");
      TEST_ASSERT (decoded[0] == input[0], "Round-trip byte matches");
      est_size = SocketHPACK_huffman_encoded_size (input, 1);
      TEST_ASSERT ((size_t)enc_len == est_size, "Size estimate matches for byte");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * Encoder Tests
 * ============================================================================ */

/**
 * Test encoder creation
 */
static void
test_encoder_new (void)
{
  Arena_T arena;
  SocketHPACK_Encoder_T encoder;

  printf ("  Encoder new... ");

  arena = Arena_new ();
  encoder = SocketHPACK_Encoder_new (NULL, arena);
  TEST_ASSERT (encoder != NULL, "Encoder should be created");

  SocketHPACK_Encoder_free (&encoder);
  TEST_ASSERT (encoder == NULL, "Encoder should be NULL after free");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test encoding a simple header
 */
static void
test_encoder_encode_indexed (void)
{
  Arena_T arena;
  SocketHPACK_Encoder_T encoder;
  SocketHPACK_Header headers[1];
  unsigned char output[256];
  ssize_t len;

  printf ("  Encoder encode indexed... ");

  arena = Arena_new ();
  encoder = SocketHPACK_Encoder_new (NULL, arena);

  /* :method GET is in static table at index 2 */
  headers[0].name = ":method";
  headers[0].name_len = 7;
  headers[0].value = "GET";
  headers[0].value_len = 3;
  headers[0].never_index = 0;

  len = SocketHPACK_Encoder_encode (encoder, headers, 1, output, sizeof (output));
  TEST_ASSERT (len > 0, "Encode should succeed");
  /* Indexed header field: 1xxxxxxx with index 2 = 0x82 */
  TEST_ASSERT (output[0] == 0x82, "Should encode as indexed header 0x82");
  TEST_ASSERT (len == 1, "Should be 1 byte for indexed");

  SocketHPACK_Encoder_free (&encoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Decoder Tests
 * ============================================================================ */

/**
 * Test decoder creation
 */
static void
test_decoder_new (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;

  printf ("  Decoder new... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  SocketHPACK_Decoder_free (&decoder);
  TEST_ASSERT (decoder == NULL, "Decoder should be NULL after free");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoding indexed header
 * RFC 7541 Section C.2.1: Literal Header Field with Indexing
 */
static void
test_decoder_decode_indexed (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* 0x82 = indexed header field, index 2 (:method: GET) */
  unsigned char input[] = { 0x82 };

  printf ("  Decoder decode indexed... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "Decode should succeed");
  TEST_ASSERT (header_count == 1, "Should decode 1 header");
  TEST_ASSERT (strcmp (headers[0].name, ":method") == 0,
               "Name should be :method");
  TEST_ASSERT (strcmp (headers[0].value, "GET") == 0, "Value should be GET");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoding literal header with indexing
 */
static void
test_decoder_decode_literal_indexed (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* Literal with indexing, new name "custom-key", value "custom-value" */
  /* 0x40 = literal with indexing, index 0 (new name) */
  /* Then length + "custom-key" + length + "custom-value" */
  unsigned char input[]
      = { 0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-',  'k',
          'e',  'y',  0x0c, 'c', 'u', 's', 't', 'o', 'm', '-',
          'v',  'a',  'l',  'u', 'e' };

  printf ("  Decoder decode literal indexed... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "Decode should succeed");
  TEST_ASSERT (header_count == 1, "Should decode 1 header");
  TEST_ASSERT (strcmp (headers[0].name, "custom-key") == 0,
               "Name should be custom-key");
  TEST_ASSERT (strcmp (headers[0].value, "custom-value") == 0,
               "Value should be custom-value");

  /* Verify it was added to dynamic table */
  SocketHPACK_Table_T table = SocketHPACK_Decoder_get_table (decoder);
  TEST_ASSERT (SocketHPACK_Table_count (table) == 1,
               "Should have 1 entry in dynamic table");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoding literal header never indexed
 */
static void
test_decoder_decode_literal_never (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* 0x10 = literal never indexed, index 0 (new name) */
  unsigned char input[] = { 0x10, 0x06, 's', 'e', 'c', 'r', 'e', 't',
                            0x05, 'v', 'a', 'l', 'u', 'e' };

  printf ("  Decoder decode literal never indexed... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "Decode should succeed");
  TEST_ASSERT (header_count == 1, "Should decode 1 header");
  TEST_ASSERT (strcmp (headers[0].name, "secret") == 0,
               "Name should be secret");
  TEST_ASSERT (headers[0].never_index == 1, "Should be never_index");

  /* Verify NOT added to dynamic table */
  SocketHPACK_Table_T table = SocketHPACK_Decoder_get_table (decoder);
  TEST_ASSERT (SocketHPACK_Table_count (table) == 0,
               "Should have 0 entries in dynamic table");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoding table size update
 */
static void
test_decoder_decode_table_size_update (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* 0x20 = table size update with value 0 */
  unsigned char input[] = { 0x20 };

  printf ("  Decoder decode table size update... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "Decode should succeed");
  TEST_ASSERT (header_count == 0, "Should decode 0 headers");

  /* Verify table size was updated */
  SocketHPACK_Table_T table = SocketHPACK_Decoder_get_table (decoder);
  TEST_ASSERT (SocketHPACK_Table_max_size (table) == 0,
               "Table max size should be 0");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test invalid table size update (after headers)
 */
static void
test_decoder_invalid_table_size_update (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* Header followed by table size update - should fail */
  unsigned char input[] = { 0x82, 0x20 }; /* :method GET, then size update */

  printf ("  Decoder invalid table size update... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_ERROR_TABLE_SIZE,
               "Should fail with TABLE_SIZE error");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * RFC 7541 Appendix C Test Vectors
 * ============================================================================ */

/**
 * Test C.2.1 - Literal Header Field with Indexing
 */
static void
test_rfc7541_c2_1 (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* custom-key: custom-header (from RFC 7541 C.2.1) */
  unsigned char input[]
      = { 0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-',  'k',  'e', 'y',
          0x0d, 'c',  'u', 's', 't', 'o', 'm', '-', 'h',  'e',  'a', 'd',
          'e',  'r' };

  printf ("  RFC 7541 C.2.1 - Literal with indexing... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "Decode should succeed");
  TEST_ASSERT (header_count == 1, "Should have 1 header");
  TEST_ASSERT (strcmp (headers[0].name, "custom-key") == 0, "Name matches");
  TEST_ASSERT (strcmp (headers[0].value, "custom-header") == 0,
               "Value matches");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test C.3 - Request Examples without Huffman Coding
 */
static void
test_rfc7541_c3 (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  printf ("  RFC 7541 C.3 - Request without Huffman... ");

  /* C.3.1 First Request: :method GET, :scheme http, :path /, :authority
   * www.example.com */
  unsigned char req1[] = {
    0x82, /* :method: GET (indexed 2) */
    0x86, /* :scheme: http (indexed 6) */
    0x84, /* :path: / (indexed 4) */
    0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c',
    'o', 'm' /* :authority: www.example.com (literal indexed, name idx 1) */
  };

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, req1, sizeof (req1), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_OK, "First request decode should succeed");
  TEST_ASSERT (header_count == 4, "Should have 4 headers");

  TEST_ASSERT (strcmp (headers[0].name, ":method") == 0, ":method name");
  TEST_ASSERT (strcmp (headers[0].value, "GET") == 0, ":method value");
  TEST_ASSERT (strcmp (headers[1].name, ":scheme") == 0, ":scheme name");
  TEST_ASSERT (strcmp (headers[1].value, "http") == 0, ":scheme value");
  TEST_ASSERT (strcmp (headers[2].name, ":path") == 0, ":path name");
  TEST_ASSERT (strcmp (headers[2].value, "/") == 0, ":path value");
  TEST_ASSERT (strcmp (headers[3].name, ":authority") == 0, ":authority name");
  TEST_ASSERT (strcmp (headers[3].value, "www.example.com") == 0,
               ":authority value");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Security Tests
 * ============================================================================ */

/**
 * Test header size limit
 */
static void
test_header_size_limit (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_DecoderConfig config;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  printf ("  Header size limit... ");

  /* Create header that exceeds default max size */
  unsigned char input[300];
  input[0] = 0x40; /* Literal with indexing, new name */
  input[1] = 0x64; /* Name length = 100 */
  memset (input + 2, 'x', 100);
  input[102] = 0x64; /* Value length = 100 */
  memset (input + 103, 'y', 100);

  arena = Arena_new ();

  /* Set small max header size */
  SocketHPACK_decoder_config_defaults (&config);
  config.max_header_size = 100; /* Less than 100 + 100 + 32 = 232 */

  decoder = SocketHPACK_Decoder_new (&config, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, 203, headers, 16,
                                       &header_count, arena);
  TEST_ASSERT (result == HPACK_ERROR_HEADER_SIZE,
               "Should fail with HEADER_SIZE error");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test invalid index
 */
static void
test_invalid_index (void)
{
  Arena_T arena;
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_Header headers[16];
  size_t header_count;
  SocketHPACK_Result result;

  /* 0xFF, 0x00 = indexed header 127 (beyond static table, empty dynamic) */
  unsigned char input[] = { 0xFF, 0x00 };

  printf ("  Invalid index... ");

  arena = Arena_new ();
  decoder = SocketHPACK_Decoder_new (NULL, arena);

  result = SocketHPACK_Decoder_decode (decoder, input, sizeof (input), headers,
                                       16, &header_count, arena);
  TEST_ASSERT (result == HPACK_ERROR_INVALID_INDEX,
               "Should fail with INVALID_INDEX");

  SocketHPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int
main (void)
{
  printf ("HPACK Unit Tests\n");
  printf ("================\n\n");

  printf ("Integer Coding Tests:\n");
  test_int_encode_5bit_small ();
  test_int_encode_5bit_large ();
  test_int_encode_8bit ();
  test_int_decode_small ();
  test_int_decode_large ();
  test_int_decode_incomplete ();

  printf ("\nStatic Table Tests:\n");
  test_static_table_get ();
  test_static_table_method_get ();
  test_static_table_find ();
  test_static_table_find_name_only ();
  test_static_table_invalid_index ();

  printf ("\nDynamic Table Tests:\n");
  test_dynamic_table_new ();
  test_dynamic_table_add ();
  test_dynamic_table_eviction ();
  test_dynamic_table_size_update_zero ();

  printf ("\nHuffman Tests:\n");
  test_huffman_encoded_size ();
  test_huffman_encode_basic ();
  test_huffman_round_trip ();
  test_huffman_full_roundtrip ();

  printf ("\nEncoder Tests:\n");
  test_encoder_new ();
  test_encoder_encode_indexed ();

  printf ("\nDecoder Tests:\n");
  test_decoder_new ();
  test_decoder_decode_indexed ();
  test_decoder_decode_literal_indexed ();
  test_decoder_decode_literal_never ();
  test_decoder_decode_table_size_update ();
  test_decoder_invalid_table_size_update ();

  printf ("\nRFC 7541 Test Vectors:\n");
  test_rfc7541_c2_1 ();
  test_rfc7541_c3 ();

  printf ("\nSecurity Tests:\n");
  test_header_size_limit ();
  test_invalid_index ();

  printf ("\n================\n");
  printf ("All HPACK tests passed!\n");

  return 0;
}

