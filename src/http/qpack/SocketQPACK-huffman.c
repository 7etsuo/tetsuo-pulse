/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-huffman.c - QPACK Huffman Encoding/Decoding (RFC 9204 Section
 * 4.1.2)
 *
 * QPACK uses the same Huffman table as HPACK (RFC 7541 Appendix B).
 * This file wraps the HPACK Huffman implementation for QPACK use.
 */

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "http/SocketHPACK.h"

/* ============================================================================
 * Huffman Encoding (wraps HPACK implementation)
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

/* ============================================================================
 * Export Huffman tables for QPACK internal use
 *
 * Note: These aliases point to the HPACK tables since QPACK uses identical
 * Huffman encoding (RFC 9204 Section 4.1.2 references RFC 7541 Appendix B).
 * ============================================================================
 */

/* The QPACK private header declares these as extern, but we don't need
 * separate copies since we delegate to HPACK. The tables are accessed
 * through the SocketHPACK_huffman_* functions above. */
