/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_safe_arithmetic.c - Safe arithmetic utility unit tests
 * Tests for socket_util_safe_add_u64() and socket_util_safe_mul_size()
 * overflow detection helpers in SocketUtil.h.
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "core/SocketUtil.h"
#include "test/Test.h"

/* ============================================================================
 * socket_util_safe_add_u64() Tests
 * ============================================================================
 */

/* Test basic addition without overflow */
TEST(safe_add_u64_no_overflow)
{
  uint64_t result;
  int ret;

  /* Small values */
  ret = socket_util_safe_add_u64(100, 200, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 300);

  /* Medium values */
  ret = socket_util_safe_add_u64(1000000, 2000000, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 3000000);

  /* Large values that don't overflow */
  ret = socket_util_safe_add_u64(UINT64_MAX / 2, UINT64_MAX / 4, &result);
  ASSERT_EQ(ret, 1);
}

/* Test addition with zero */
TEST(safe_add_u64_with_zero)
{
  uint64_t result;
  int ret;

  /* 0 + 0 */
  ret = socket_util_safe_add_u64(0, 0, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 0);

  /* value + 0 */
  ret = socket_util_safe_add_u64(12345, 0, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 12345);

  /* 0 + value */
  ret = socket_util_safe_add_u64(0, 54321, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 54321);

  /* UINT64_MAX + 0 (no overflow) */
  ret = socket_util_safe_add_u64(UINT64_MAX, 0, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, UINT64_MAX);
}

/* Test overflow detection */
TEST(safe_add_u64_overflow)
{
  uint64_t result = 0xDEADBEEF;  /* Sentinel value */
  int ret;

  /* UINT64_MAX + 1 */
  ret = socket_util_safe_add_u64(UINT64_MAX, 1, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xDEADBEEF);  /* Result should not be modified */

  /* UINT64_MAX + UINT64_MAX */
  result = 0xCAFEBABE;
  ret = socket_util_safe_add_u64(UINT64_MAX, UINT64_MAX, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xCAFEBABE);  /* Result should not be modified */

  /* Large value + large value */
  result = 0xABCDEF;
  ret = socket_util_safe_add_u64(UINT64_MAX - 10, 20, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xABCDEF);  /* Result should not be modified */
}

/* Test edge case: maximum safe addition */
TEST(safe_add_u64_edge_cases)
{
  uint64_t result;
  int ret;

  /* UINT64_MAX - 1 + 1 (should succeed) */
  ret = socket_util_safe_add_u64(UINT64_MAX - 1, 1, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, UINT64_MAX);

  /* UINT64_MAX - 100 + 100 (should succeed) */
  ret = socket_util_safe_add_u64(UINT64_MAX - 100, 100, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, UINT64_MAX);

  /* UINT64_MAX - 99 + 100 (should fail) */
  ret = socket_util_safe_add_u64(UINT64_MAX - 99, 100, &result);
  ASSERT_EQ(ret, 0);
}

/* Test QUIC use case: offset + length */
TEST(safe_add_u64_quic_offset)
{
  uint64_t result;
  int ret;

  /* Typical QUIC offset addition */
  uint64_t offset = 1000;
  uint64_t length = 500;
  ret = socket_util_safe_add_u64(offset, length, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 1500);

  /* Large QUIC stream offset */
  offset = 1ULL << 62;  /* 4 exabytes */
  length = 1024;
  ret = socket_util_safe_add_u64(offset, length, &result);
  ASSERT_EQ(ret, 1);

  /* Overflow in QUIC (malicious packet) */
  offset = UINT64_MAX - 100;
  length = 200;
  ret = socket_util_safe_add_u64(offset, length, &result);
  ASSERT_EQ(ret, 0);
}

/* ============================================================================
 * socket_util_safe_mul_size() Tests
 * ============================================================================
 */

/* Test basic multiplication without overflow */
TEST(safe_mul_size_no_overflow)
{
  size_t result;
  int ret;

  /* Small values */
  ret = socket_util_safe_mul_size(10, 20, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 200);

  /* Medium values */
  ret = socket_util_safe_mul_size(1000, 2000, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 2000000);
}

/* Test multiplication with zero */
TEST(safe_mul_size_with_zero)
{
  size_t result;
  int ret;

  /* 0 * 0 */
  ret = socket_util_safe_mul_size(0, 0, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 0);

  /* value * 0 */
  ret = socket_util_safe_mul_size(12345, 0, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 0);

  /* 0 * value */
  ret = socket_util_safe_mul_size(0, 54321, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 0);
}

/* Test multiplication with one */
TEST(safe_mul_size_with_one)
{
  size_t result;
  int ret;

  /* 1 * 1 */
  ret = socket_util_safe_mul_size(1, 1, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 1);

  /* value * 1 */
  ret = socket_util_safe_mul_size(9999, 1, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 9999);

  /* 1 * value */
  ret = socket_util_safe_mul_size(1, 8888, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 8888);

  /* SIZE_MAX * 1 (no overflow) */
  ret = socket_util_safe_mul_size(SIZE_MAX, 1, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, SIZE_MAX);
}

/* Test overflow detection */
TEST(safe_mul_size_overflow)
{
  size_t result = 0xDEADBEEF;  /* Sentinel value */
  int ret;

  /* SIZE_MAX * 2 */
  ret = socket_util_safe_mul_size(SIZE_MAX, 2, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xDEADBEEF);  /* Result should not be modified */

  /* SIZE_MAX * SIZE_MAX */
  result = 0xCAFEBABE;
  ret = socket_util_safe_mul_size(SIZE_MAX, SIZE_MAX, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xCAFEBABE);

  /* Large value * large value */
  result = 0xABCDEF;
  ret = socket_util_safe_mul_size(SIZE_MAX / 2 + 1, 2, &result);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(result, 0xABCDEF);
}

/* Test edge cases */
TEST(safe_mul_size_edge_cases)
{
  size_t result;
  int ret;

  /* Maximum safe multiplication on 64-bit: sqrt(SIZE_MAX) */
  /* SIZE_MAX / 2 * 2 (should succeed) */
  ret = socket_util_safe_mul_size(SIZE_MAX / 2, 2, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, SIZE_MAX - 1);  /* Or SIZE_MAX depending on rounding */

  /* Just over the edge */
  if (SIZE_MAX > 1000) {
    ret = socket_util_safe_mul_size(SIZE_MAX / 1000 + 1, 1001, &result);
    ASSERT_EQ(ret, 0);
  }
}

/* Test array allocation use case */
TEST(safe_mul_size_array_allocation)
{
  size_t result;
  int ret;

  /* Typical array: 1000 elements of 64 bytes */
  size_t count = 1000;
  size_t elem_size = 64;
  ret = socket_util_safe_mul_size(count, elem_size, &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 64000);

  /* Large array that fits */
  count = 1000000;
  elem_size = sizeof(int);  /* Usually 4 bytes */
  ret = socket_util_safe_mul_size(count, elem_size, &result);
  ASSERT_EQ(ret, 1);

  /* Overflow attempt (malicious allocation) */
  count = SIZE_MAX / 2 + 1;
  elem_size = 2;
  ret = socket_util_safe_mul_size(count, elem_size, &result);
  ASSERT_EQ(ret, 0);
}

/* Test typical struct allocation patterns */
TEST(safe_mul_size_struct_allocation)
{
  size_t result;
  int ret;

  /* Small struct */
  struct small { char data[16]; };
  ret = socket_util_safe_mul_size(100, sizeof(struct small), &result);
  ASSERT_EQ(ret, 1);
  ASSERT_EQ(result, 1600);

  /* Large struct array */
  struct large { char data[1024]; };
  ret = socket_util_safe_mul_size(10000, sizeof(struct large), &result);
  ASSERT_EQ(ret, 1);
}

int
main(void)
{
  Test_run_all();
  return Test_get_failures() > 0 ? 1 : 0;
}
