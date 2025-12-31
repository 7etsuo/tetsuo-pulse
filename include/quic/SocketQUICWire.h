/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQUICWire.h
 * @brief QUIC Packet Number Encoding/Decoding (RFC 9000 Appendix A).
 *
 * Implements packet number truncation, encoding, and reconstruction algorithms.
 * Packet numbers are 1-4 bytes, truncated based on the largest acknowledged
 * packet number to minimize overhead while allowing recovery.
 *
 * Key concepts:
 *   - Truncation: Only transmit minimum bytes needed based on unacked range
 *   - Encoding: Calculate optimal size (1, 2, 3, or 4 bytes)
 *   - Decoding: Reconstruct full 62-bit packet number from truncated value
 *   - Window: Receiver uses expected PN ± half_window for reconstruction
 *
 * Thread Safety: All functions are thread-safe (no shared state).
 *
 * @defgroup quic_wire QUIC Wire Format Module
 * @{
 * @see https://www.rfc-editor.org/rfc/rfc9000#appendix-A
 */

#ifndef SOCKETQUICWIRE_INCLUDED
#define SOCKETQUICWIRE_INCLUDED

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/**
 * @brief Maximum packet number value (2^62 - 1).
 *
 * Packet numbers are 62-bit unsigned integers. After reaching this value,
 * the connection must be closed to prevent overflow.
 */
#define QUIC_PN_MAX ((uint64_t)4611686018427387903ULL)

/**
 * @brief Minimum encoded packet number size (1 byte).
 */
#define QUIC_PN_MIN_SIZE 1

/**
 * @brief Maximum encoded packet number size (4 bytes).
 *
 * RFC 9000 specifies packet numbers are encoded in 1-4 bytes.
 */
#define QUIC_PN_MAX_SIZE 4

/**
 * @brief Sentinel value indicating no packet has been acknowledged.
 *
 * Use this as largest_acked when encoding the first packet in a space.
 */
#define QUIC_PN_NONE UINT64_MAX

/* ============================================================================
 * Result Codes
 * ============================================================================
 */

/**
 * @brief Result codes for packet number operations.
 */
typedef enum
{
  QUIC_PN_OK = 0,         /**< Operation succeeded */
  QUIC_PN_ERROR_NULL,     /**< NULL pointer argument */
  QUIC_PN_ERROR_BUFFER,   /**< Output buffer too small */
  QUIC_PN_ERROR_OVERFLOW, /**< Packet number exceeds maximum */
  QUIC_PN_ERROR_BITS      /**< Invalid bit count (must be 8, 16, 24, or 32) */
} SocketQUICWire_Result;

/* ============================================================================
 * Encoding Functions (RFC 9000 Appendix A.2)
 * ============================================================================
 */

/**
 * @brief Calculate minimum bytes needed to encode a packet number.
 *
 * Determines the optimal encoding size based on the number of unacknowledged
 * packets. The algorithm ensures the receiver can unambiguously reconstruct
 * the full packet number.
 *
 * @param full_pn      Full packet number to encode.
 * @param largest_acked Largest acknowledged packet number, or QUIC_PN_NONE
 *                      if no packets have been acknowledged yet.
 *
 * @return Number of bytes needed (1, 2, 3, or 4).
 *
 * @note Returns 4 if full_pn exceeds QUIC_PN_MAX (caller should handle).
 *
 * Example:
 * @code
 * uint64_t pn = 0xac5c02;
 * uint64_t acked = 0xabe8b3;
 * unsigned len = SocketQUICWire_pn_length(pn, acked);
 * // len = 2 (29,519 unacked packets, needs 16 bits)
 * @endcode
 */
extern unsigned
SocketQUICWire_pn_length (uint64_t full_pn, uint64_t largest_acked);

/**
 * @brief Encode a packet number with truncation.
 *
 * Encodes the packet number using the minimum bytes needed, based on
 * the largest acknowledged packet. The truncated value is written in
 * network byte order (big-endian).
 *
 * @param full_pn       Full packet number to encode.
 * @param largest_acked Largest acknowledged packet number, or QUIC_PN_NONE
 *                      if no packets have been acknowledged yet.
 * @param output        Output buffer for encoded bytes.
 * @param output_size   Size of output buffer in bytes.
 *
 * @return Number of bytes written (1-4), or 0 on error.
 *
 * @note Buffer must be at least SocketQUICWire_pn_length() bytes.
 *
 * Example:
 * @code
 * uint8_t buf[4];
 * size_t len = SocketQUICWire_pn_encode(0xac5c02, 0xabe8b3, buf, sizeof(buf));
 * // len = 2, buf = {0x5c, 0x02}
 * @endcode
 */
extern size_t SocketQUICWire_pn_encode (uint64_t full_pn,
                                        uint64_t largest_acked,
                                        uint8_t *output,
                                        size_t output_size);

/* ============================================================================
 * Decoding Functions (RFC 9000 Appendix A.3)
 * ============================================================================
 */

/**
 * @brief Decode a truncated packet number.
 *
 * Reconstructs the full 62-bit packet number from a truncated value.
 * Uses the largest successfully processed packet number to determine
 * the expected window for reconstruction.
 *
 * The algorithm handles wrap-around near the 2^62 boundary correctly.
 *
 * @param largest_pn   Largest packet number successfully processed in this
 *                     packet number space, or QUIC_PN_NONE if this is the
 * first.
 * @param truncated_pn Truncated packet number value from packet header.
 * @param pn_nbits     Number of bits in the truncated value (8, 16, 24, or 32).
 * @param full_pn      Output: reconstructed full packet number.
 *
 * @return QUIC_PN_OK on success, error code otherwise.
 *
 * Example:
 * @code
 * uint64_t full_pn;
 * SocketQUICWire_Result res = SocketQUICWire_pn_decode(
 *     0xa82f30ea,  // largest_pn
 *     0x9b32,      // truncated_pn
 *     16,          // 16-bit encoding
 *     &full_pn
 * );
 * // full_pn = 0xa82f9b32
 * @endcode
 */
extern SocketQUICWire_Result SocketQUICWire_pn_decode (uint64_t largest_pn,
                                                       uint64_t truncated_pn,
                                                       unsigned pn_nbits,
                                                       uint64_t *full_pn);

/**
 * @brief Read a truncated packet number from wire format.
 *
 * Reads 1-4 bytes from the input buffer and returns the truncated value.
 * Does not perform full packet number reconstruction.
 *
 * @param data   Input buffer containing encoded packet number.
 * @param len    Size of input buffer in bytes.
 * @param pn_len Number of bytes to read (1, 2, 3, or 4).
 * @param value  Output: truncated packet number value.
 *
 * @return QUIC_PN_OK on success, error code otherwise.
 */
extern SocketQUICWire_Result SocketQUICWire_pn_read (const uint8_t *data,
                                                     size_t len,
                                                     unsigned pn_len,
                                                     uint64_t *value);

/**
 * @brief Write a truncated packet number to wire format.
 *
 * Writes the least significant bytes of the packet number in
 * network byte order (big-endian).
 *
 * @param value       Truncated packet number value.
 * @param pn_len      Number of bytes to write (1, 2, 3, or 4).
 * @param output      Output buffer.
 * @param output_size Size of output buffer.
 *
 * @return Number of bytes written, or 0 on error.
 */
extern size_t SocketQUICWire_pn_write (uint64_t value,
                                       unsigned pn_len,
                                       uint8_t *output,
                                       size_t output_size);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * @brief Check if a packet number is valid.
 *
 * @param pn Packet number to check.
 *
 * @return 1 if valid (0 to QUIC_PN_MAX), 0 otherwise.
 */
static inline int
SocketQUICWire_pn_is_valid (uint64_t pn)
{
  return (pn <= QUIC_PN_MAX);
}

/**
 * @brief Get string representation of result code.
 *
 * @param result Result code to convert.
 *
 * @return Human-readable string describing the result.
 */
extern const char *SocketQUICWire_result_string (SocketQUICWire_Result result);

/** @} */

#endif /* SOCKETQUICWIRE_INCLUDED */
