/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-gzip.c
 * @brief gzip header and trailer parsing (RFC 1952).
 *
 * Implements gzip format support including:
 * - Header parsing with all optional fields (FEXTRA, FNAME, FCOMMENT, FHCRC)
 * - Trailer verification (CRC-32 + original size)
 *
 * @see RFC 1952 - GZIP file format specification version 4.3
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate/SocketDeflate.h"

/**
 * Read a 16-bit little-endian value from buffer.
 */
static inline uint16_t
read_le16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * Read a 32-bit little-endian value from buffer.
 */
static inline uint32_t
read_le32 (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * Find null terminator in buffer.
 *
 * @param data  Buffer to search
 * @param len   Maximum length to search
 * @return Position of null terminator, or len if not found
 */
static size_t
find_null (const uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (data[i] == 0)
        return i;
    }
  return len;
}

/**
 * Parse FEXTRA field (RFC 1952 Section 2.3.1.1).
 *
 * @param data  Input buffer
 * @param len   Buffer length
 * @param pos   Current position (updated on success)
 * @return DEFLATE_OK or DEFLATE_INCOMPLETE
 */
static SocketDeflate_Result
parse_fextra (const uint8_t *data, size_t len, size_t *pos)
{
  if (len < *pos + 2)
    return DEFLATE_INCOMPLETE;

  uint16_t xlen = read_le16 (data + *pos);
  *pos += 2;

  if (len < *pos + xlen)
    return DEFLATE_INCOMPLETE;

  *pos += xlen;
  return DEFLATE_OK;
}

/**
 * Parse null-terminated string field (FNAME or FCOMMENT).
 *
 * @param data    Input buffer
 * @param len     Buffer length
 * @param pos     Current position (updated on success)
 * @param out_str Output: pointer to string start in buffer
 * @return DEFLATE_OK or DEFLATE_INCOMPLETE
 */
static SocketDeflate_Result
parse_null_string (const uint8_t *data, size_t len, size_t *pos,
                   const uint8_t **out_str)
{
  size_t null_pos = find_null (data + *pos, len - *pos);
  if (null_pos == len - *pos)
    return DEFLATE_INCOMPLETE;

  *out_str = data + *pos;
  *pos += null_pos + 1;
  return DEFLATE_OK;
}

/**
 * Verify FHCRC field (RFC 1952 Section 2.3.1.4).
 *
 * CRC16 is the low 16 bits of CRC32 of all header bytes before this field.
 *
 * @param data  Input buffer
 * @param len   Buffer length
 * @param pos   Current position (updated on success)
 * @return DEFLATE_OK, DEFLATE_INCOMPLETE, or DEFLATE_ERROR_GZIP_HCRC
 */
static SocketDeflate_Result
verify_fhcrc (const uint8_t *data, size_t len, size_t *pos)
{
  if (len < *pos + 2)
    return DEFLATE_INCOMPLETE;

  uint16_t stored = read_le16 (data + *pos);
  uint16_t computed = (uint16_t)(SocketDeflate_crc32 (0, data, *pos) & 0xFFFF);

  if (stored != computed)
    return DEFLATE_ERROR_GZIP_HCRC;

  *pos += 2;
  return DEFLATE_OK;
}

/**
 * Parse fixed gzip header fields.
 *
 * @param data   Input buffer (must have at least 10 bytes)
 * @param header Output header struct
 */
static void
parse_fixed_fields (const uint8_t *data, SocketDeflate_GzipHeader *header)
{
  header->method = data[2];
  header->flags = data[3];
  header->mtime = read_le32 (data + 4);
  header->xfl = data[8];
  header->os = data[9];
  header->filename = NULL;
  header->comment = NULL;
}

/**
 * Validate gzip magic bytes and compression method.
 *
 * @param data Input buffer
 * @param len  Buffer length
 * @return DEFLATE_OK, DEFLATE_INCOMPLETE, DEFLATE_ERROR_GZIP_MAGIC, or
 *         DEFLATE_ERROR_GZIP_METHOD
 */
static SocketDeflate_Result
validate_gzip_magic (const uint8_t *data, size_t len)
{
  if (len < GZIP_HEADER_MIN_SIZE)
    return DEFLATE_INCOMPLETE;

  if (data[0] != GZIP_MAGIC_0 || data[1] != GZIP_MAGIC_1)
    return DEFLATE_ERROR_GZIP_MAGIC;

  if (data[2] != GZIP_METHOD_DEFLATE)
    return DEFLATE_ERROR_GZIP_METHOD;

  return DEFLATE_OK;
}

/**
 * Parse optional gzip header fields based on flags.
 *
 * @param data   Input buffer
 * @param len    Buffer length
 * @param pos    Current position (updated)
 * @param header Header struct (filename/comment updated if present)
 * @return DEFLATE_OK or error code
 */
static SocketDeflate_Result
parse_optional_fields (const uint8_t *data, size_t len, size_t *pos,
                       SocketDeflate_GzipHeader *header)
{
  SocketDeflate_Result result;

  if (header->flags & GZIP_FLAG_FEXTRA)
    {
      result = parse_fextra (data, len, pos);
      if (result != DEFLATE_OK)
        return result;
    }

  if (header->flags & GZIP_FLAG_FNAME)
    {
      result = parse_null_string (data, len, pos, &header->filename);
      if (result != DEFLATE_OK)
        return result;
    }

  if (header->flags & GZIP_FLAG_FCOMMENT)
    {
      result = parse_null_string (data, len, pos, &header->comment);
      if (result != DEFLATE_OK)
        return result;
    }

  if (header->flags & GZIP_FLAG_FHCRC)
    {
      result = verify_fhcrc (data, len, pos);
      if (result != DEFLATE_OK)
        return result;
    }

  return DEFLATE_OK;
}

/**
 * Parse gzip header (RFC 1952 Section 2.3).
 */
SocketDeflate_Result
SocketDeflate_gzip_parse_header (const uint8_t *data, size_t len,
                                 SocketDeflate_GzipHeader *header)
{
  SocketDeflate_Result result;
  size_t pos;

  if (data == NULL || header == NULL)
    return DEFLATE_ERROR;

  result = validate_gzip_magic (data, len);
  if (result != DEFLATE_OK)
    return result;

  parse_fixed_fields (data, header);
  pos = GZIP_HEADER_MIN_SIZE;

  result = parse_optional_fields (data, len, &pos, header);
  if (result != DEFLATE_OK)
    return result;

  header->header_size = pos;
  return DEFLATE_OK;
}

/**
 * Verify gzip trailer (RFC 1952 Section 2.3.1).
 *
 * The gzip trailer is 8 bytes:
 *   Offset  Size  Description
 *   0       4     CRC32 of uncompressed data (little-endian)
 *   4       4     ISIZE: original size mod 2^32 (little-endian)
 */
SocketDeflate_Result
SocketDeflate_gzip_verify_trailer (const uint8_t *trailer,
                                   uint32_t computed_crc,
                                   uint32_t computed_size)
{
  uint32_t stored_crc;
  uint32_t stored_size;

  if (trailer == NULL)
    return DEFLATE_ERROR;

  /* Read stored values (little-endian) */
  stored_crc = read_le32 (trailer);
  stored_size = read_le32 (trailer + 4);

  /* Verify CRC */
  if (stored_crc != computed_crc)
    return DEFLATE_ERROR_GZIP_CRC;

  /* Verify size (mod 2^32) */
  if (stored_size != computed_size)
    return DEFLATE_ERROR_GZIP_SIZE;

  return DEFLATE_OK;
}

/**
 * OS code name table.
 */
static const char *os_names[] = {
  "FAT",           /* 0 */
  "Amiga",         /* 1 */
  "VMS",           /* 2 */
  "Unix",          /* 3 */
  "VM/CMS",        /* 4 */
  "Atari TOS",     /* 5 */
  "HPFS",          /* 6 */
  "Macintosh",     /* 7 */
  "Z-System",      /* 8 */
  "CP/M",          /* 9 */
  "TOPS-20",       /* 10 */
  "NTFS",          /* 11 */
  "QDOS",          /* 12 */
  "Acorn RISCOS",  /* 13 */
};

#define OS_NAMES_COUNT (sizeof (os_names) / sizeof (os_names[0]))

/**
 * Check if OS code is a known value (RFC 1952 Section 2.3).
 */
int
SocketDeflate_gzip_is_valid_os (uint8_t os)
{
  /* Known values: 0-13 and 255 (unknown) */
  return (os < OS_NAMES_COUNT) || (os == GZIP_OS_UNKNOWN);
}

/**
 * Get string name for OS code.
 */
const char *
SocketDeflate_gzip_os_string (uint8_t os)
{
  if (os < OS_NAMES_COUNT)
    return os_names[os];

  if (os == GZIP_OS_UNKNOWN)
    return "unknown";

  return "reserved";
}
