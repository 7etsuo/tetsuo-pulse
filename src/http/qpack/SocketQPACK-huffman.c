/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-huffman.c - QPACK Huffman Encoding/Decoding
 *
 * QPACK (RFC 9204) uses the same Huffman code as HPACK (RFC 7541 Appendix B).
 * This file wraps the HPACK Huffman functions for QPACK use.
 */

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * Huffman Encoding - Wrapper for HPACK implementation
 * ============================================================================
 */

ssize_t
SocketQPACK_huffman_encode (const unsigned char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_size)
{
  return SocketHPACK_huffman_encode (input, input_len, output, output_size);
}

ssize_t
SocketQPACK_huffman_decode (const unsigned char *input,
                            size_t input_len,
                            unsigned char *output,
                            size_t output_size)
{
  return SocketHPACK_huffman_decode (input, input_len, output, output_size);
}

size_t
SocketQPACK_huffman_encoded_size (const unsigned char *input, size_t input_len)
{
  return SocketHPACK_huffman_encoded_size (input, input_len);
}
