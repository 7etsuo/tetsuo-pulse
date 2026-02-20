/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-base.c
 * @brief QPACK Base Encoding (RFC 9204 Section 4.5.1.2)
 *
 * Implements Base calculation from Sign bit and Delta Base for QPACK
 * field section prefix. Base is used for relative indexing in field
 * sections.
 *
 * Wire format:
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | S |      Delta Base (7+)      |
 * +---+---------------------------+
 *
 * Base Calculation:
 *   - S=0: Base = Required Insert Count + Delta Base
 *   - S=1: Base = Required Insert Count - Delta Base - 1
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1.2
 */

#include "http/qpack/SocketQPACK.h"

#include <stdint.h>

SocketQPACK_Result
SocketQPACK_calculate_base (int sign,
                            uint64_t req_insert_count,
                            uint64_t delta_base,
                            uint64_t *base_out)
{
  if (base_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  *base_out = 0;

  if (sign == 0)
    {
      /*
       * RFC 9204 Section 4.5.1.2: Positive delta
       * Base = Required Insert Count + Delta Base
       *
       * Check for overflow.
       */
      if (delta_base > UINT64_MAX - req_insert_count)
        return QPACK_ERR_BASE_OVERFLOW;

      *base_out = req_insert_count + delta_base;
    }
  else
    {
      /*
       * RFC 9204 Section 4.5.1.2: Negative delta
       * Base = Required Insert Count - Delta Base - 1
       *
       * For this to yield a valid (non-negative) Base:
       *   Required Insert Count > Delta Base
       * which means: req_insert_count >= delta_base + 1
       */
      if (req_insert_count <= delta_base)
        return QPACK_ERR_INVALID_BASE;

      *base_out = req_insert_count - delta_base - 1;
    }

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_validate_base (int sign,
                           uint64_t req_insert_count,
                           uint64_t delta_base)
{
  if (sign == 0)
    {
      /*
       * Positive delta: Base = req_insert_count + delta_base
       * Check for overflow only.
       */
      if (delta_base > UINT64_MAX - req_insert_count)
        return QPACK_ERR_INVALID_BASE;
    }
  else
    {
      /*
       * Negative delta: Base = req_insert_count - delta_base - 1
       * req_insert_count MUST be > delta_base to ensure non-negative Base.
       */
      if (req_insert_count <= delta_base)
        return QPACK_ERR_INVALID_BASE;
    }

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_encode_base (uint64_t req_insert_count,
                         uint64_t base,
                         int *sign_out,
                         uint64_t *delta_out)
{
  if (sign_out == NULL || delta_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (base >= req_insert_count)
    {
      /*
       * RFC 9204 Section 4.5.1.2: Positive delta
       * Sign = 0, Delta Base = Base - Required Insert Count
       */
      *sign_out = 0;
      *delta_out = base - req_insert_count;
    }
  else
    {
      /*
       * RFC 9204 Section 4.5.1.2: Negative delta
       * Sign = 1, Delta Base = Required Insert Count - Base - 1
       */
      *sign_out = 1;
      *delta_out = req_insert_count - base - 1;
    }

  return QPACK_OK;
}
