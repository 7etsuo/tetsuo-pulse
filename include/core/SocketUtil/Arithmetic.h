/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_ARITHMETIC_H
#define SOCKETUTIL_ARITHMETIC_H

/**
 * @file SocketUtil/Arithmetic.h
 * @ingroup foundation
 * @brief Safe arithmetic utilities with overflow detection.
 *
 * Provides overflow-checked arithmetic operations for critical calculations
 * where overflow must be prevented. Similar to C11 Annex K safe functions
 * and Linux kernel's check_*_overflow() macros.
 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Safe addition with overflow detection for uint64_t.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 * @param result Output pointer for sum (only set if no overflow).
 * @return 1 if addition is safe, 0 if overflow would occur.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Used for:
 * - QUIC offset calculations (frame data, crypto streams)
 * - Buffer size validation
 * - Protocol length field additions
 */
static inline int
socket_util_safe_add_u64 (uint64_t a, uint64_t b, uint64_t *result)
{
  if (a > UINT64_MAX - b)
    return 0; /* Overflow would occur */
  *result = a + b;
  return 1;
}

/**
 * @brief Safe multiplication with overflow detection for size_t.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 * @param result Output pointer for product (only set if no overflow).
 * @return 1 if multiplication is safe, 0 if overflow would occur.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Similar to OpenBSD's reallocarray() overflow checking.
 * Uses division to detect overflow without requiring wider integer types.
 *
 * Used for:
 * - Array allocation size calculations
 * - Buffer capacity computations
 * - Memory region size validation
 */
static inline int
socket_util_safe_mul_size (size_t a, size_t b, size_t *result)
{
  if (a > 0 && b > SIZE_MAX / a)
    return 0; /* Overflow would occur */
  *result = a * b;
  return 1;
}

/**
 * @brief Safe multiplication with overflow detection for uint64_t.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 * @param result Output pointer for product (only set if no overflow).
 * @return 1 if multiplication is safe, 0 if overflow would occur.
 * @threadsafe Yes (pure function, no shared state)
 *
 * Used for:
 * - Protocol field arithmetic (port parsing, length calculations)
 * - Large buffer size computations
 */
static inline int
socket_util_safe_mul_u64 (uint64_t a, uint64_t b, uint64_t *result)
{
  if (a > 0 && b > UINT64_MAX / a)
    return 0; /* Overflow would occur */
  *result = a * b;
  return 1;
}

#endif /* SOCKETUTIL_ARITHMETIC_H */
