/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQUICWire.c - QUIC Packet Number Encoding (RFC 9000 Appendix A)
 *
 * Implements packet number encoding and decoding algorithms for QUIC packets.
 * Based on the pseudocode in RFC 9000 Appendix A.2 and A.3.
 */

#include <assert.h>

#include "quic/SocketQUICWire.h"
#include "quic/SocketQUICConstants.h"

static const char *result_strings[] = {
  [QUIC_PN_OK] = "OK",
  [QUIC_PN_ERROR_NULL] = "NULL pointer argument",
  [QUIC_PN_ERROR_BUFFER] = "Output buffer too small",
  [QUIC_PN_ERROR_OVERFLOW] = "Packet number exceeds maximum",
  [QUIC_PN_ERROR_BITS] = "Invalid bit count (must be 8, 16, 24, or 32)",
};

DEFINE_RESULT_STRING_FUNC (SocketQUICWire, QUIC_PN_ERROR_BITS)

unsigned
SocketQUICWire_pn_length (uint64_t full_pn, uint64_t largest_acked)
{
  uint64_t num_unacked;
  unsigned min_bits;
  unsigned num_bytes;

  /* Enforce documented promise: return 4 if full_pn exceeds QUIC_PN_MAX */
  if (full_pn > QUIC_PN_MAX)
    return QUIC_PN_MAX_SIZE;

  /*
   * RFC 9000 Appendix A.2:
   * The number of bits must be at least one more than the base-2 logarithm
   * of the number of contiguous unacknowledged packet numbers.
   *
   * We need: pn_nbits > log2(num_unacked)
   * Which means: 2^(pn_nbits-1) >= num_unacked (half-window must cover range)
   */

  if (largest_acked == QUIC_PN_NONE)
    {
      /* No acknowledgments yet - use full range from 0 */
      num_unacked = full_pn + 1;
    }
  else
    {
      /* Calculate gap since last ack */
      num_unacked = full_pn - largest_acked;
    }

  /* Calculate floor(log2(num_unacked)) + 1 */
  if (num_unacked == 0)
    {
      min_bits = 1;
    }
  else
    {
      min_bits = 0;
      uint64_t tmp = num_unacked;
      while (tmp > 0)
        {
          min_bits++;
          tmp >>= 1;
        }
    }

  /*
   * Ensure half-window (2^(min_bits-1)) covers the unacked range.
   * If not, we need one more bit.
   */
  if (min_bits > 0 && ((uint64_t)1 << (min_bits - 1)) < num_unacked)
    min_bits++;

  /* Round up to next byte boundary */
  num_bytes = (min_bits + 7) / 8;

  /* Clamp to valid range 1-4 */
  if (num_bytes < QUIC_PN_MIN_SIZE)
    num_bytes = QUIC_PN_MIN_SIZE;
  if (num_bytes > QUIC_PN_MAX_SIZE)
    num_bytes = QUIC_PN_MAX_SIZE;

  return num_bytes;
}

size_t
SocketQUICWire_pn_encode (uint64_t full_pn,
                          uint64_t largest_acked,
                          uint8_t *output,
                          size_t output_size)
{
  unsigned pn_len;

  if (output == NULL)
    return 0;

  if (full_pn > QUIC_PN_MAX)
    return 0;

  pn_len = SocketQUICWire_pn_length (full_pn, largest_acked);

  if (output_size < pn_len)
    return 0;

  /* Write truncated packet number in network byte order */
  return SocketQUICWire_pn_write (full_pn, pn_len, output, output_size);
}

SocketQUICWire_Result
SocketQUICWire_pn_decode (uint64_t largest_pn,
                          uint64_t truncated_pn,
                          unsigned pn_nbits,
                          uint64_t *full_pn)
{
  uint64_t expected_pn;
  uint64_t pn_win;
  uint64_t pn_hwin;
  uint64_t pn_mask;
  uint64_t candidate_pn;

  if (full_pn == NULL)
    return QUIC_PN_ERROR_NULL;

  /* Validate bit count */
  if (pn_nbits != 8 && pn_nbits != 16 && pn_nbits != 24 && pn_nbits != 32)
    return QUIC_PN_ERROR_BITS;

  /*
   * RFC 9000 Appendix A.3 DecodePacketNumber algorithm:
   *
   * expected_pn = largest_pn + 1
   * pn_win = 1 << pn_nbits
   * pn_hwin = pn_win / 2
   * pn_mask = pn_win - 1
   */

  if (largest_pn == QUIC_PN_NONE)
    {
      /* First packet - no prior context */
      expected_pn = 0;
    }
  else
    {
      expected_pn = largest_pn + 1;
    }

  pn_win = (uint64_t)1 << pn_nbits;
  pn_hwin = pn_win >> 1;
  pn_mask = pn_win - 1;

  /*
   * The incoming packet number should be greater than
   * expected_pn - pn_hwin and less than or equal to
   * expected_pn + pn_hwin.
   *
   * candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
   */
  candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

  /*
   * Adjust candidate if it falls outside the expected window.
   * Note the extra checks to prevent overflow and underflow.
   */

  /* Check if candidate is too small (needs to wrap forward) */
  if (candidate_pn + pn_hwin <= expected_pn
      && candidate_pn < (QUIC_PN_MAX + 1) - pn_win)
    {
      *full_pn = candidate_pn + pn_win;
      return QUIC_PN_OK;
    }

  /* Check if candidate is too large (needs to wrap backward) */
  if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
    {
      *full_pn = candidate_pn - pn_win;
      return QUIC_PN_OK;
    }

  /* Candidate is within the expected window */
  *full_pn = candidate_pn;
  return QUIC_PN_OK;
}

SocketQUICWire_Result
SocketQUICWire_pn_read (const uint8_t *data,
                        size_t len,
                        unsigned pn_len,
                        uint64_t *value)
{
  if (data == NULL || value == NULL)
    return QUIC_PN_ERROR_NULL;

  if (pn_len < QUIC_PN_MIN_SIZE || pn_len > QUIC_PN_MAX_SIZE)
    return QUIC_PN_ERROR_BITS;

  if (len < pn_len)
    return QUIC_PN_ERROR_BUFFER;

  /* Read in network byte order (big-endian) */
  switch (pn_len)
    {
    case 1:
      *value = (uint64_t)data[0];
      break;

    case 2:
      *value = ((uint64_t)data[0] << 8) | (uint64_t)data[1];
      break;

    case 3:
      *value = ((uint64_t)data[0] << 16) | ((uint64_t)data[1] << 8)
               | (uint64_t)data[2];
      break;

    case 4:
      *value = ((uint64_t)data[0] << 24) | ((uint64_t)data[1] << 16)
               | ((uint64_t)data[2] << 8) | (uint64_t)data[3];
      break;

    default:
      /* Should never reach here due to validation above */
      assert (0 && "Invalid pn_len passed validation");
      return QUIC_PN_ERROR_BITS;
    }

  return QUIC_PN_OK;
}

size_t
SocketQUICWire_pn_write (uint64_t value,
                         unsigned pn_len,
                         uint8_t *output,
                         size_t output_size)
{
  if (output == NULL)
    return 0;

  if (pn_len < QUIC_PN_MIN_SIZE || pn_len > QUIC_PN_MAX_SIZE)
    return 0;

  if (output_size < pn_len)
    return 0;

  /* Write least significant bytes in network byte order (big-endian) */
  switch (pn_len)
    {
    case 1:
      output[0] = (uint8_t)(value & 0xFF);
      break;

    case 2:
      output[0] = (uint8_t)((value >> 8) & 0xFF);
      output[1] = (uint8_t)(value & 0xFF);
      break;

    case 3:
      output[0] = (uint8_t)((value >> 16) & 0xFF);
      output[1] = (uint8_t)((value >> 8) & 0xFF);
      output[2] = (uint8_t)(value & 0xFF);
      break;

    case 4:
      output[0] = (uint8_t)((value >> 24) & 0xFF);
      output[1] = (uint8_t)((value >> 16) & 0xFF);
      output[2] = (uint8_t)((value >> 8) & 0xFF);
      output[3] = (uint8_t)(value & 0xFF);
      break;

    default:
      /* Should never reach here due to validation above */
      assert (0 && "Invalid pn_len passed validation");
      return 0;
    }

  return pn_len;
}
