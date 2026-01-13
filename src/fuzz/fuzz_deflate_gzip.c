/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_gzip.c - libFuzzer harness for gzip header/trailer parsing
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_gzip_parse_header() with malformed headers
 * - SocketDeflate_gzip_verify_trailer() with fuzz-derived values
 * - Various flag combinations
 * - Truncated inputs
 * - Valid header mutation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_gzip
 * Run:   ./fuzz_deflate_gzip -max_len=1024 -runs=1000000
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate/SocketDeflate.h"

/* Maximum input size */
#define MAX_INPUT_SIZE 4096

/**
 * Fuzz operation modes
 */
enum FuzzOp
{
  OP_RAW_HEADER = 0,     /* Parse raw fuzz input as header */
  OP_VALID_PREFIX,       /* Valid magic/method + fuzz flags/content */
  OP_MUTATE_MAGIC,       /* Mutate magic bytes */
  OP_MUTATE_METHOD,      /* Mutate compression method */
  OP_ALL_FLAGS,          /* Exercise all flag combinations */
  OP_TRAILER,            /* Fuzz trailer verification */
  OP_MAX
};

/**
 * Build a gzip header with valid prefix and fuzz-derived content.
 */
static size_t
build_valid_header (const uint8_t *fuzz_data, size_t fuzz_size, uint8_t *out,
                    size_t out_cap)
{
  size_t pos = 0;

  if (out_cap < 10)
    return 0;

  /* Valid magic */
  out[pos++] = 0x1F;
  out[pos++] = 0x8B;

  /* Valid method */
  out[pos++] = 0x08;

  /* Flags from fuzz input (or 0 if no data) */
  out[pos++] = (fuzz_size > 0) ? fuzz_data[0] : 0x00;

  /* Mtime from fuzz input */
  for (size_t i = 0; i < 4 && pos < out_cap; i++)
    {
      out[pos++] = (fuzz_size > 1 + i) ? fuzz_data[1 + i] : 0x00;
    }

  /* XFL */
  out[pos++] = (fuzz_size > 5) ? fuzz_data[5] : 0x00;

  /* OS */
  out[pos++] = (fuzz_size > 6) ? fuzz_data[6] : 0xFF;

  /* Copy remaining fuzz data as optional fields */
  size_t remaining = (fuzz_size > 7) ? fuzz_size - 7 : 0;
  if (remaining > 0 && pos + remaining <= out_cap)
    {
      memcpy (out + pos, fuzz_data + 7, remaining);
      pos += remaining;
    }

  return pos;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  uint8_t op;
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result result;
  uint8_t buffer[MAX_INPUT_SIZE];

  /* Need at least 1 byte for operation code */
  if (size < 1)
    return 0;

  /* Limit input size */
  if (size > MAX_INPUT_SIZE)
    return 0;

  /* Parse operation */
  op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  switch (op)
    {
    case OP_RAW_HEADER:
      {
        /* Parse raw fuzz input as gzip header */
        result
            = SocketDeflate_gzip_parse_header (payload, payload_size, &header);
        (void)result;
      }
      break;

    case OP_VALID_PREFIX:
      {
        /* Build header with valid prefix + fuzz content */
        size_t header_len
            = build_valid_header (payload, payload_size, buffer, sizeof (buffer));
        if (header_len > 0)
          {
            result
                = SocketDeflate_gzip_parse_header (buffer, header_len, &header);
            (void)result;
          }
      }
      break;

    case OP_MUTATE_MAGIC:
      {
        /* Start with valid header, mutate magic bytes */
        if (payload_size < 2)
          return 0;

        memset (buffer, 0, 10);
        buffer[0] = payload[0]; /* Fuzz first magic */
        buffer[1] = payload[1]; /* Fuzz second magic */
        buffer[2] = 0x08;       /* Valid method */
        buffer[3] = 0x00;       /* No flags */

        result = SocketDeflate_gzip_parse_header (buffer, 10, &header);
        /* Should fail unless magic happens to be 0x1F 0x8B */
        (void)result;
      }
      break;

    case OP_MUTATE_METHOD:
      {
        /* Start with valid magic, mutate method byte */
        if (payload_size < 1)
          return 0;

        memset (buffer, 0, 10);
        buffer[0] = 0x1F;       /* Valid magic */
        buffer[1] = 0x8B;       /* Valid magic */
        buffer[2] = payload[0]; /* Fuzz method */
        buffer[3] = 0x00;       /* No flags */

        result = SocketDeflate_gzip_parse_header (buffer, 10, &header);
        /* Should fail unless method happens to be 0x08 */
        (void)result;
      }
      break;

    case OP_ALL_FLAGS:
      {
        /* Test all 32 flag combinations */
        if (payload_size < 1)
          return 0;

        uint8_t flags = payload[0] & 0x1F; /* Only valid flag bits */

        memset (buffer, 0, sizeof (buffer));
        buffer[0] = 0x1F; /* Magic */
        buffer[1] = 0x8B;
        buffer[2] = 0x08;  /* Method */
        buffer[3] = flags; /* Flags from fuzz */

        size_t pos = 10;

        /* Add optional fields based on flags */
        if (flags & GZIP_FLAG_FEXTRA)
          {
            /* XLEN = 0 (empty extra field) */
            buffer[pos++] = 0x00;
            buffer[pos++] = 0x00;
          }

        if (flags & GZIP_FLAG_FNAME)
          {
            /* Empty filename (just null) */
            buffer[pos++] = 0x00;
          }

        if (flags & GZIP_FLAG_FCOMMENT)
          {
            /* Empty comment (just null) */
            buffer[pos++] = 0x00;
          }

        if (flags & GZIP_FLAG_FHCRC)
          {
            /* CRC16 placeholder */
            buffer[pos++] = 0x00;
            buffer[pos++] = 0x00;
          }

        result = SocketDeflate_gzip_parse_header (buffer, pos, &header);
        /* Should succeed for all valid flag combinations */
        (void)result;
      }
      break;

    case OP_TRAILER:
      {
        /* Fuzz trailer verification */
        if (payload_size < 8)
          return 0;

        /* Use fuzz data as trailer bytes */
        uint32_t computed_crc = 0;
        uint32_t computed_size = 0;

        /* Derive computed values from more fuzz data if available */
        if (payload_size >= 16)
          {
            computed_crc = (uint32_t)payload[8] | ((uint32_t)payload[9] << 8)
                           | ((uint32_t)payload[10] << 16)
                           | ((uint32_t)payload[11] << 24);
            computed_size = (uint32_t)payload[12] | ((uint32_t)payload[13] << 8)
                            | ((uint32_t)payload[14] << 16)
                            | ((uint32_t)payload[15] << 24);
          }

        result
            = SocketDeflate_gzip_verify_trailer (payload, computed_crc, computed_size);
        (void)result;
      }
      break;
    }

  return 0;
}
