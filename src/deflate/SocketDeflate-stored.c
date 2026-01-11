/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-stored.c
 * @brief RFC 1951 stored block (BTYPE=00) decoder.
 *
 * Implements non-compressed block decoding per RFC 1951 Section 3.2.4.
 * Stored blocks contain literal bytes with a length/validation header:
 *
 * Format after BFINAL and BTYPE bits:
 *   [padding to byte boundary]
 *   [LEN: 16 bits, LSB-first]
 *   [NLEN: 16 bits, one's complement of LEN]
 *   [DATA: LEN bytes of literal data]
 *
 * NLEN provides a simple integrity check: (LEN ^ NLEN) must equal 0xFFFF.
 */

#include "deflate/SocketDeflate.h"

SocketDeflate_Result
SocketDeflate_decode_stored_block (SocketDeflate_BitReader_T reader,
                                   uint8_t *output, size_t output_len,
                                   size_t *written)
{
  uint32_t len_val;
  uint32_t nlen_val;
  uint16_t len;
  uint16_t nlen;
  SocketDeflate_Result result;

  *written = 0;

  /* Step 1: Align to byte boundary (RFC 1951 Section 3.2.4)
   * "Any bits of input up to the next byte boundary are ignored." */
  SocketDeflate_BitReader_align (reader);

  /* Step 2: Read LEN (16 bits, LSB-first) */
  result = SocketDeflate_BitReader_read (reader, 16, &len_val);
  if (result != DEFLATE_OK)
    return result;
  len = (uint16_t)len_val;

  /* Step 3: Read NLEN (16 bits, LSB-first) */
  result = SocketDeflate_BitReader_read (reader, 16, &nlen_val);
  if (result != DEFLATE_OK)
    return result;
  nlen = (uint16_t)nlen_val;

  /* Step 4: Validate NLEN = ~LEN
   * RFC 1951: "NLEN is the one's complement of LEN" */
  if ((len ^ nlen) != 0xFFFF)
    return DEFLATE_ERROR;

  /* Step 5: Verify output buffer can hold data */
  if (len > output_len)
    return DEFLATE_ERROR;

  /* Step 6: Read LEN bytes of literal data */
  if (len > 0)
    {
      result = SocketDeflate_BitReader_read_bytes (reader, output, len);
      if (result != DEFLATE_OK)
        return result;
    }

  *written = len;
  return DEFLATE_OK;
}
