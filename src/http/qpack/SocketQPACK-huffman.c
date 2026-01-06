/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-huffman.c - QPACK Huffman Encoding/Decoding
 *
 * QPACK uses the same Huffman codes as HPACK (RFC 7541 Appendix B).
 * This file provides wrapper functions that delegate to the HPACK
 * implementation to avoid code duplication.
 */

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include "http/SocketHPACK.h"

/* ============================================================================
 * Huffman Encoding
 * ============================================================================
 */

ssize_t
SocketQPACK_huffman_encode (const unsigned char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_size)
{
  /* QPACK uses identical Huffman codes to HPACK - delegate directly */
  return SocketHPACK_huffman_encode (input, input_len, output, output_size);
}

/* ============================================================================
 * Huffman Decoding
 * ============================================================================
 */

ssize_t
SocketQPACK_huffman_decode (const unsigned char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_size)
{
  /* QPACK uses identical Huffman codes to HPACK - delegate directly */
  return SocketHPACK_huffman_decode (input, input_len, output, output_size);
}

/* ============================================================================
 * Huffman Size Calculation
 * ============================================================================
 */

size_t
SocketQPACK_huffman_encoded_size (const unsigned char *input, size_t input_len)
{
  /* QPACK uses identical Huffman codes to HPACK - delegate directly */
  return SocketHPACK_huffman_encoded_size (input, input_len);
}
