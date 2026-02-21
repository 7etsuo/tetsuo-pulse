/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_gzip.c - gzip header/trailer parsing unit tests
 *
 * Tests for gzip format support including:
 * - Minimal header parsing (no flags)
 * - FEXTRA, FNAME, FCOMMENT, FHCRC flags
 * - All flags combined
 * - Trailer verification
 * - Error handling
 *
 * @see RFC 1952 - GZIP file format specification version 4.3
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Minimal Header (No Flags)
 *
 * 10-byte gzip header with no optional fields.
 */
TEST (gzip_header_minimal)
{
  uint8_t header[] = {
    0x1F, 0x8B,             /* Magic */
    0x08,                   /* Method: deflate */
    0x00,                   /* Flags: none */
    0x00, 0x00, 0x00, 0x00, /* Mtime: 0 */
    0x00,                   /* XFL */
    0xFF                    /* OS: unknown */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.method, 8);
  ASSERT_EQ (parsed.flags, 0);
  ASSERT_EQ (parsed.mtime, 0U);
  ASSERT_EQ (parsed.xfl, 0);
  ASSERT_EQ (parsed.os, 0xFF);
  ASSERT (parsed.filename == NULL);
  ASSERT (parsed.comment == NULL);
  ASSERT_EQ (parsed.header_size, 10);
}

/*
 * Header with FNAME Flag
 *
 * Tests null-terminated filename parsing.
 */
TEST (gzip_header_fname)
{
  uint8_t header[] = {
    0x1F, 0x8B,                                      /* Magic */
    0x08,                                            /* Method: deflate */
    0x08,                                            /* Flags: FNAME */
    0x00, 0x00, 0x00, 0x00,                          /* Mtime */
    0x00,                                            /* XFL */
    0x03,                                            /* OS: Unix */
    't',  'e',  's',  't',  '.', 't', 'x', 't', 0x00 /* Filename + null */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.flags, GZIP_FLAG_FNAME);
  ASSERT (parsed.filename != NULL);
  ASSERT (strcmp ((const char *)parsed.filename, "test.txt") == 0);
  ASSERT (parsed.comment == NULL);
  ASSERT_EQ (parsed.header_size, 19); /* 10 + 8 + 1 (null) */
}

/*
 * Header with FCOMMENT Flag
 */
TEST (gzip_header_fcomment)
{
  uint8_t header[] = {
    0x1F, 0x8B,                       /* Magic */
    0x08,                             /* Method: deflate */
    0x10,                             /* Flags: FCOMMENT */
    0x00, 0x00, 0x00, 0x00,           /* Mtime */
    0x00,                             /* XFL */
    0x00,                             /* OS: FAT */
    'H',  'e',  'l',  'l',  'o', 0x00 /* Comment + null */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.flags, GZIP_FLAG_FCOMMENT);
  ASSERT (parsed.filename == NULL);
  ASSERT (parsed.comment != NULL);
  ASSERT (strcmp ((const char *)parsed.comment, "Hello") == 0);
  ASSERT_EQ (parsed.header_size, 16); /* 10 + 5 + 1 (null) */
}

/*
 * Header with FEXTRA Flag
 *
 * Tests XLEN + extra field data parsing.
 */
TEST (gzip_header_fextra)
{
  uint8_t header[] = {
    0x1F, 0x8B,                 /* Magic */
    0x08,                       /* Method: deflate */
    0x04,                       /* Flags: FEXTRA */
    0x00, 0x00, 0x00, 0x00,     /* Mtime */
    0x00,                       /* XFL */
    0xFF,                       /* OS: unknown */
    0x05, 0x00,                 /* XLEN = 5 (little-endian) */
    'e',  'x',  't',  'r',  'a' /* Extra field data */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.flags, GZIP_FLAG_FEXTRA);
  ASSERT_EQ (parsed.header_size, 17); /* 10 + 2 (XLEN) + 5 (data) */
}

/*
 * Header with FHCRC Flag
 *
 * Tests header CRC16 validation.
 */
TEST (gzip_header_fhcrc)
{
  uint8_t header[] = {
    0x1F, 0x8B,             /* Magic */
    0x08,                   /* Method: deflate */
    0x02,                   /* Flags: FHCRC */
    0x00, 0x00, 0x00, 0x00, /* Mtime */
    0x00,                   /* XFL */
    0x00,                   /* OS */
    0x1D, 0x26              /* CRC16 = 0x261D (little-endian) */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.flags, GZIP_FLAG_FHCRC);
  ASSERT_EQ (parsed.header_size, 12); /* 10 + 2 (CRC16) */
}

/*
 * Header with All Flags
 *
 * FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT
 */
TEST (gzip_header_all_flags)
{
  uint8_t header[] = {
    0x1F, 0x8B,             /* Magic */
    0x08,                   /* Method: deflate */
    0x1F,                   /* Flags: all (0x01|0x02|0x04|0x08|0x10) */
    0x78, 0x56, 0x34, 0x12, /* Mtime: 0x12345678 */
    0x02,                   /* XFL: max compression */
    0x03,                   /* OS: Unix */
    0x03, 0x00,             /* XLEN = 3 */
    'A',  'B',  'C',        /* Extra field data */
    'f',  'i',  'l',  'e',  '.', 'g', 'z', 0x00,                 /* Filename */
    'M',  'y',  ' ',  'c',  'o', 'm', 'm', 'e',  'n', 't', 0x00, /* Comment */
    0xAD, 0x5A /* CRC16 = 0x5AAD (little-endian) */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (parsed.method, 8);
  ASSERT_EQ (parsed.flags, 0x1F);
  ASSERT_EQ (parsed.mtime, 0x12345678U);
  ASSERT_EQ (parsed.xfl, 2);
  ASSERT_EQ (parsed.os, 3);
  ASSERT (parsed.filename != NULL);
  ASSERT (strcmp ((const char *)parsed.filename, "file.gz") == 0);
  ASSERT (parsed.comment != NULL);
  ASSERT (strcmp ((const char *)parsed.comment, "My comment") == 0);
  /* 10 + 2 + 3 (extra) + 8 (fname) + 11 (comment) + 2 (crc16) = 36 */
  ASSERT_EQ (parsed.header_size, 36);
}

/*
 * Invalid Magic Bytes
 */
TEST (gzip_magic_mismatch)
{
  /* Wrong first magic byte */
  uint8_t header1[]
      = { 0x1E, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header1, sizeof (header1), &parsed);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_MAGIC);

  /* Wrong second magic byte */
  uint8_t header2[]
      = { 0x1F, 0x8A, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  result = SocketDeflate_gzip_parse_header (header2, sizeof (header2), &parsed);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_MAGIC);
}

/*
 * Invalid Compression Method
 */
TEST (gzip_method_invalid)
{
  /* Method = 0 (reserved) */
  uint8_t header[]
      = { 0x1F, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_METHOD);
}

/*
 * Truncated Header
 */
TEST (gzip_header_truncated)
{
  /* Only 5 bytes (need 10 minimum) */
  uint8_t header[] = { 0x1F, 0x8B, 0x08, 0x00, 0x00 };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

/*
 * Truncated FNAME
 */
TEST (gzip_header_truncated_fname)
{
  /* FNAME flag set but no null terminator */
  uint8_t header[]
      = { 0x1F, 0x8B, 0x08, 0x08, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 'f',  'i',  'l',  'e' /* No null terminator */ };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

/*
 * Truncated FEXTRA
 */
TEST (gzip_header_truncated_fextra)
{
  /* FEXTRA but XLEN says 10 bytes, only have 3 */
  uint8_t header[] = { 0x1F, 0x8B, 0x08, 0x04, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, /* XLEN = 10 */
                       'A',  'B',  'C' /* Only 3 bytes of extra */ };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

/*
 * Truncated FCOMMENT
 */
TEST (gzip_header_truncated_fcomment)
{
  /* FCOMMENT flag set but no null terminator */
  uint8_t header[]
      = { 0x1F, 0x8B, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 'H',  'e',  'l',  'l',  'o' /* No null terminator */ };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

/*
 * Truncated FHCRC
 */
TEST (gzip_header_truncated_fhcrc)
{
  /* FHCRC flag set but only 1 byte of CRC16 present */
  uint8_t header[]
      = { 0x1F, 0x8B, 0x08, 0x02, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x12 /* Only 1 byte, need 2 for CRC16 */ };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

/*
 * NULL Pointer Safety
 */
TEST (gzip_header_null_safety)
{
  uint8_t header[]
      = { 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  /* NULL data */
  result = SocketDeflate_gzip_parse_header (NULL, 10, &parsed);
  ASSERT_EQ (result, DEFLATE_ERROR);

  /* NULL header output */
  result = SocketDeflate_gzip_parse_header (header, sizeof (header), NULL);
  ASSERT_EQ (result, DEFLATE_ERROR);
}

/*
 * Trailer Verification - Valid
 */
TEST (gzip_trailer_valid)
{
  /* CRC = 0xCBF43926, Size = 9 (both little-endian) */
  uint8_t trailer[] = { 0x26, 0x39, 0xF4, 0xCB, 0x09, 0x00, 0x00, 0x00 };
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_verify_trailer (trailer, 0xCBF43926U, 9);
  ASSERT_EQ (result, DEFLATE_OK);
}

/*
 * Trailer Verification - CRC Mismatch
 */
TEST (gzip_trailer_bad_crc)
{
  /* Stored CRC = 0xCBF43926, computed CRC = 0x12345678 */
  uint8_t trailer[] = { 0x26, 0x39, 0xF4, 0xCB, 0x09, 0x00, 0x00, 0x00 };
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_verify_trailer (trailer, 0x12345678U, 9);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_CRC);
}

/*
 * Trailer Verification - Size Mismatch
 */
TEST (gzip_trailer_bad_size)
{
  /* Stored size = 9, computed size = 100 */
  uint8_t trailer[] = { 0x26, 0x39, 0xF4, 0xCB, 0x09, 0x00, 0x00, 0x00 };
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_verify_trailer (trailer, 0xCBF43926U, 100);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_SIZE);
}

/*
 * Trailer NULL Safety
 */
TEST (gzip_trailer_null_safety)
{
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_verify_trailer (NULL, 0, 0);
  ASSERT_EQ (result, DEFLATE_ERROR);
}

/*
 * Large Size (32-bit wrap)
 *
 * ISIZE is stored mod 2^32.
 */
TEST (gzip_trailer_large_size)
{
  /* Size = 0xFFFFFFFF (max 32-bit), stored little-endian */
  uint8_t trailer[] = { 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_verify_trailer (trailer, 0U, 0xFFFFFFFFU);
  ASSERT_EQ (result, DEFLATE_OK);
}

/*
 * Result String Test
 */
TEST (gzip_result_strings)
{
  /* Verify new error codes have proper strings */
  const char *s;

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_MAGIC);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_METHOD);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_CRC);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_SIZE);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_HCRC);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);

  s = SocketDeflate_result_string (DEFLATE_ERROR_GZIP_OS);
  ASSERT (s != NULL);
  ASSERT (strlen (s) > 0);
}

/*
 * FHCRC Mismatch Detection
 */
TEST (gzip_header_fhcrc_mismatch)
{
  /* Header with FHCRC flag but wrong CRC16 value */
  uint8_t header[] = {
    0x1F, 0x8B,             /* Magic */
    0x08,                   /* Method: deflate */
    0x02,                   /* Flags: FHCRC */
    0x00, 0x00, 0x00, 0x00, /* Mtime */
    0x00,                   /* XFL */
    0x00,                   /* OS */
    0xFF, 0xFF              /* Wrong CRC16 (correct would be 0x1D, 0x26) */
  };
  SocketDeflate_GzipHeader parsed;
  SocketDeflate_Result result;

  result = SocketDeflate_gzip_parse_header (header, sizeof (header), &parsed);
  ASSERT_EQ (result, DEFLATE_ERROR_GZIP_HCRC);
}

/*
 * OS Code Validation - Known Values
 */
TEST (gzip_os_valid_codes)
{
  /* All known OS codes should be valid */
  ASSERT (SocketDeflate_gzip_is_valid_os (GZIP_OS_FAT) == 1);
  ASSERT (SocketDeflate_gzip_is_valid_os (GZIP_OS_UNIX) == 1);
  ASSERT (SocketDeflate_gzip_is_valid_os (GZIP_OS_NTFS) == 1);
  ASSERT (SocketDeflate_gzip_is_valid_os (GZIP_OS_ACORN_RISCOS) == 1);
  ASSERT (SocketDeflate_gzip_is_valid_os (GZIP_OS_UNKNOWN) == 1);

  /* Reserved values should be invalid */
  ASSERT (SocketDeflate_gzip_is_valid_os (14) == 0); /* First reserved */
  ASSERT (SocketDeflate_gzip_is_valid_os (100) == 0);
  ASSERT (SocketDeflate_gzip_is_valid_os (254) == 0);
}

/*
 * OS Code String Names
 */
TEST (gzip_os_string_names)
{
  const char *s;

  s = SocketDeflate_gzip_os_string (GZIP_OS_FAT);
  ASSERT (strcmp (s, "FAT") == 0);

  s = SocketDeflate_gzip_os_string (GZIP_OS_UNIX);
  ASSERT (strcmp (s, "Unix") == 0);

  s = SocketDeflate_gzip_os_string (GZIP_OS_UNKNOWN);
  ASSERT (strcmp (s, "unknown") == 0);

  /* Reserved should return "reserved" */
  s = SocketDeflate_gzip_os_string (100);
  ASSERT (strcmp (s, "reserved") == 0);
}

/*
 * Integration Test: Full gzip stream parsing
 *
 * Parse a real gzip stream (header + deflate data + trailer) and verify
 * header fields and trailer CRC/size against known values.
 *
 * This gzip stream contains "Hello, gzip!" compressed with deflate.
 */
TEST (gzip_integration_full_stream)
{
  /* gzip compressed "Hello, gzip!" */
  /* Original: 12 bytes, Compressed: 32 bytes */
  static const uint8_t gzip_hello[] = {
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xF3,
    0x48, 0xCD, 0xC9, 0xC9, 0xD7, 0x51, 0x48, 0xAF, 0xCA, 0x2C, 0x50,
    0x04, 0x00, 0x3E, 0x3D, 0x0F, 0x10, 0x0C, 0x00, 0x00, 0x00,
  };

  SocketDeflate_GzipHeader header;
  SocketDeflate_Result result;

  /* Parse header */
  result = SocketDeflate_gzip_parse_header (
      gzip_hello, sizeof (gzip_hello), &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header.method, GZIP_METHOD_DEFLATE);
  ASSERT_EQ (header.flags, 0x00); /* No optional fields */
  ASSERT_EQ (header.mtime, 0U);
  ASSERT_EQ (header.xfl, 0x02); /* Maximum compression */
  ASSERT_EQ (header.os, 0xFF);  /* Unknown OS */
  ASSERT_EQ (header.header_size, 10);

  /* Verify trailer with known values */
  /* The trailer is the last 8 bytes */
  const uint8_t *trailer = gzip_hello + sizeof (gzip_hello) - GZIP_TRAILER_SIZE;

  /* Known values for "Hello, gzip!":
   * CRC32 = 0x100F3D3E
   * Size = 12 */
  result = SocketDeflate_gzip_verify_trailer (trailer, 0x100F3D3EU, 12);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Verify CRC of the original data matches */
  const char *original = "Hello, gzip!";
  uint32_t computed_crc
      = SocketDeflate_crc32 (0, (const uint8_t *)original, 12);
  ASSERT_EQ (computed_crc, 0x100F3D3EU);
}

/*
 * Integration Test: CRC32 Combine workflow
 *
 * Simulate parallel CRC computation on chunks, then combine.
 */
TEST (gzip_integration_parallel_crc)
{
  /* Large data split into 4 chunks for "parallel" processing */
  const char *data = "The quick brown fox jumps over the lazy dog. "
                     "Pack my box with five dozen liquor jugs. "
                     "How vexingly quick daft zebras jump!";
  size_t total_len = strlen (data);

  /* Split into 4 roughly equal chunks */
  size_t chunk_size = total_len / 4;
  size_t c1_len = chunk_size;
  size_t c2_len = chunk_size;
  size_t c3_len = chunk_size;
  size_t c4_len = total_len - (c1_len + c2_len + c3_len);

  /* Compute CRC of each chunk independently */
  uint32_t crc1 = SocketDeflate_crc32 (0, (const uint8_t *)data, c1_len);
  uint32_t crc2
      = SocketDeflate_crc32 (0, (const uint8_t *)data + c1_len, c2_len);
  uint32_t crc3 = SocketDeflate_crc32 (
      0, (const uint8_t *)data + c1_len + c2_len, c3_len);
  uint32_t crc4 = SocketDeflate_crc32 (
      0, (const uint8_t *)data + c1_len + c2_len + c3_len, c4_len);

  /* Combine all CRCs */
  uint32_t combined = crc1;
  combined = SocketDeflate_crc32_combine (combined, crc2, c2_len);
  combined = SocketDeflate_crc32_combine (combined, crc3, c3_len);
  combined = SocketDeflate_crc32_combine (combined, crc4, c4_len);

  /* Verify against single-pass CRC */
  uint32_t crc_full = SocketDeflate_crc32 (0, (const uint8_t *)data, total_len);
  ASSERT_EQ (combined, crc_full);
}

/*
 * Test Runner
 */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
