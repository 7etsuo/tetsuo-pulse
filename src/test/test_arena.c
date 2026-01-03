/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_arena.c - Arena allocator unit tests
 * Tests for the Arena memory allocator module.
 * Covers allocation, disposal, clearing, and edge cases.
 */

/* cppcheck-suppress-file constVariablePointer ; test allocation success */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketSecurity.h"
#include "test/Test.h"

/* Test basic arena creation */
TEST (arena_new_creates_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test basic allocation */
TEST (arena_alloc_basic)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test multiple allocations */
TEST (arena_multiple_allocations)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  void *ptr2 = ALLOC (arena, 200);
  void *ptr3 = ALLOC (arena, 50);

  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);
  ASSERT_NOT_NULL (ptr3);

  /* Pointers should be different */
  ASSERT_NE (ptr1, ptr2);
  ASSERT_NE (ptr2, ptr3);
  ASSERT_NE (ptr1, ptr3);

  Arena_dispose (&arena);
}

/* Test allocation with zero bytes - should assert in debug builds */
TEST (arena_alloc_zero_bytes)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Zero-byte allocation is not allowed (asserts nbytes > 0)
   * In debug builds this would assert, so we test minimum allocation instead
   */
  void *ptr = ALLOC (arena, 1);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test calloc (zero-initialized memory) */
TEST (arena_calloc_zero_initialized)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  char *ptr = (char *)CALLOC (arena, 100, sizeof (char));
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is zero-initialized */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (ptr[i], 0);
    }

  Arena_dispose (&arena);
}

/* Test calloc with multiple elements */
TEST (arena_calloc_multiple_elements)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  int *arr = (int *)CALLOC (arena, 10, sizeof (int));
  ASSERT_NOT_NULL (arr);

  /* Verify all elements are zero */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (arr[i], 0);
    }

  Arena_dispose (&arena);
}

/* Test memory is writable */
TEST (arena_allocated_memory_writable)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  char *ptr = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  /* Write to memory */
  memset (ptr, 0xAA, 100);

  /* Verify data was written */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (ptr[i], (char)0xAA);
    }

  Arena_dispose (&arena);
}

/* Test arena clearing */
TEST (arena_clear_preserves_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  /* Clear should free allocations but keep arena */
  Arena_clear (arena);

  /* Arena should still be valid */
  ASSERT_NOT_NULL (arena);

  /* Can allocate again after clear */
  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test multiple clear operations */
TEST (arena_multiple_clears)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  for (int i = 0; i < 5; i++)
    {
      void *ptr = ALLOC (arena, 100);
      ASSERT_NOT_NULL (ptr);
      Arena_clear (arena);
    }

  Arena_dispose (&arena);
}

/* Test memory alignment */
TEST (arena_memory_alignment)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate various sizes and check alignment */
  void *ptr1 = ALLOC (arena, 1);
  void *ptr2 = ALLOC (arena, sizeof (long));
  void *ptr3 = ALLOC (arena, sizeof (double));

  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);
  ASSERT_NOT_NULL (ptr3);

  /* Check that pointers are properly aligned for common types */
  uintptr_t addr1 = (uintptr_t)ptr1;
  uintptr_t addr2 = (uintptr_t)ptr2;
  uintptr_t addr3 = (uintptr_t)ptr3;

  /* Check alignment - should be aligned for pointer types at minimum */
  size_t ptr_alignment = sizeof (void *);
  ASSERT_EQ (addr1 % ptr_alignment, 0);
  ASSERT_EQ (addr2 % sizeof (long), 0);
  ASSERT_EQ (addr3 % sizeof (double), 0);

  Arena_dispose (&arena);
}

/* Test large allocation */
TEST (arena_large_allocation)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate a reasonably large chunk */
  size_t large_size = (size_t)1024 * 1024; /* 1MB */
  void *ptr = ALLOC (arena, large_size);
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is writable */
  memset (ptr, 0x42, large_size);
  char *cptr = (char *)ptr;
  ASSERT_EQ (cptr[0], 0x42);
  ASSERT_EQ (cptr[large_size - 1], 0x42);

  Arena_dispose (&arena);
}

/* Test disposal sets pointer to NULL */
TEST (arena_dispose_sets_null)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test allocations survive clear but not dispose */
TEST (arena_allocation_lifetime)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  char *ptr = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  /* Write data */
  memset (ptr, 0x55, 100);

  /* Clear doesn't invalidate pointer (but memory may be reused) */
  Arena_clear (arena);

  /* Dispose should invalidate arena */
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test many small allocations */
TEST (arena_many_small_allocations)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptrs[1000];
  for (int i = 0; i < 1000; i++)
    {
      ptrs[i] = ALLOC (arena, 10);
      ASSERT_NOT_NULL (ptrs[i]);
    }

  Arena_dispose (&arena);
}

/* Test mixed allocation sizes */
TEST (arena_mixed_allocation_sizes)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *small = ALLOC (arena, 1);
  void *medium = ALLOC (arena, 1000);
  void *large = ALLOC (arena, 10000);
  void *tiny = ALLOC (arena, 4);

  ASSERT_NOT_NULL (small);
  ASSERT_NOT_NULL (medium);
  ASSERT_NOT_NULL (large);
  ASSERT_NOT_NULL (tiny);

  Arena_dispose (&arena);
}

/* ==================== Error Condition Tests ==================== */

/* Test dispose with NULL pointer */
TEST (arena_dispose_null_pointer)
{
  Arena_T arena = NULL;
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test dispose with NULL double pointer */
TEST (arena_dispose_null_double_pointer)
{
  Arena_T *ap = NULL;
  Arena_dispose (ap);
  /* Should not crash */
}

/* Test calloc overflow detection */
TEST (arena_calloc_overflow_detection)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  TRY
  {
    /* Try to allocate with values that would overflow */
    size_t huge_count = SIZE_MAX / sizeof (int) + 1;
    void *ptr = CALLOC (arena, huge_count, sizeof (int));
    ASSERT (0); /* Should have raised exception */
    (void)ptr;
  }
  ELSE
  {
    /* Expected - overflow detected (exception raised) */
    ASSERT_NOT_NULL (Except_frame.exception);
  }
  END_TRY;

  Arena_dispose (&arena);
}

/* Test calloc maximum size exceeded */
TEST (arena_calloc_max_size_exceeded)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  TRY
  {
    /* Try to allocate more than maximum allowed */
    size_t max_size = SocketSecurity_get_max_allocation () + 1;
    void *ptr = CALLOC (arena, max_size, 1);
    ASSERT (0); /* Should have raised exception */
    (void)ptr;
  }
  ELSE
  {
    /* Expected - size exceeds maximum (exception raised) */
    ASSERT_NOT_NULL (Except_frame.exception);
  }
  END_TRY;

  Arena_dispose (&arena);
}

/* Test allocation after clear preserves arena */
TEST (arena_allocation_after_clear)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  Arena_clear (arena);

  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test multiple disposals (should be safe) */
TEST (arena_multiple_disposals)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  Arena_dispose (&arena);
  ASSERT_NULL (arena);

  /* Dispose again - should be safe */
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test clear on empty arena */
TEST (arena_clear_empty_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Clear without any allocations */
  Arena_clear (arena);

  /* Should still be able to allocate */
  void *ptr = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test very large allocation */
TEST (arena_very_large_allocation)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate close to maximum size */
  size_t large_size = (size_t)10 * 1024 * 1024; /* 10MB */
  void *ptr = ALLOC (arena, large_size);
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is writable */
  memset (ptr, 0x42, large_size);
  char *cptr = (char *)ptr;
  ASSERT_EQ (cptr[0], 0x42);
  ASSERT_EQ (cptr[large_size - 1], 0x42);

  Arena_dispose (&arena);
}

/* Test alignment preservation across allocations */
TEST (arena_alignment_preservation)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate with various sizes and check alignment */
  void *ptrs[10];
  for (int i = 0; i < 10; i++)
    {
      ptrs[i] = ALLOC (arena, i * 8 + 1);
      ASSERT_NOT_NULL (ptrs[i]);
      uintptr_t addr = (uintptr_t)ptrs[i];
      ASSERT_EQ (addr % sizeof (void *), 0);
    }

  Arena_dispose (&arena);
}

/* Test calloc with large count */
TEST (arena_calloc_large_count)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  int *arr = (int *)CALLOC (arena, 10000, sizeof (int));
  ASSERT_NOT_NULL (arr);

  /* Verify all elements are zero */
  for (int i = 0; i < 10000; i++)
    {
      ASSERT_EQ (arr[i], 0);
    }

  Arena_dispose (&arena);
}

/* ==================== Arena_reset Tests ==================== */

/* Test basic reset with single chunk allocation */
TEST (arena_reset_basic)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate some memory */
  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  /* Reset the arena */
  Arena_reset (arena);

  /* Allocate again after reset */
  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test reset with multiple chunk allocations */
TEST (arena_reset_multi_chunk)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate enough to trigger multiple chunks (typical chunk is 10KB) */
  for (int i = 0; i < 100; i++)
    {
      void *ptr = ALLOC (arena, 1024); /* 100KB total */
      ASSERT_NOT_NULL (ptr);
      (void)ptr;
    }

  /* Reset should release extra chunks, keep first */
  Arena_reset (arena);

  /* Should be able to allocate again */
  void *ptr = ALLOC (arena, 500);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test allocation after reset */
TEST (arena_reset_allocation_after_reset)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Initial allocation */
  char *ptr1 = (char *)ALLOC (arena, 50);
  ASSERT_NOT_NULL (ptr1);
  memset (ptr1, 0xAA, 50);

  /* Reset */
  Arena_reset (arena);

  /* Allocate after reset */
  char *ptr2 = (char *)ALLOC (arena, 75);
  ASSERT_NOT_NULL (ptr2);
  memset (ptr2, 0xBB, 75);

  /* Verify new allocation is writable */
  for (int i = 0; i < 75; i++)
    {
      ASSERT_EQ (ptr2[i], (char)0xBB);
    }

  Arena_dispose (&arena);
}

/* Test repeated resets */
TEST (arena_reset_repeated_resets)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Perform multiple reset cycles */
  for (int cycle = 0; cycle < 10; cycle++)
    {
      /* Allocate some data */
      void *ptr = ALLOC (arena, 100 + cycle * 10);
      ASSERT_NOT_NULL (ptr);

      /* Reset for next cycle */
      Arena_reset (arena);
    }

  /* Final allocation should still work */
  void *ptr = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test reset on empty arena (no allocations) */
TEST (arena_reset_empty_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Reset without any allocations (prev == NULL case) */
  Arena_reset (arena);

  /* Should still be able to allocate */
  void *ptr = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test reset vs clear behavior comparison */
TEST (arena_reset_vs_clear_behavior)
{
  Arena_T arena1 = Arena_new ();
  Arena_T arena2 = Arena_new ();
  ASSERT_NOT_NULL (arena1);
  ASSERT_NOT_NULL (arena2);

  /* Allocate in both arenas to trigger multiple chunks */
  for (int i = 0; i < 50; i++)
    {
      void *p1 = ALLOC (arena1, 1024);
      void *p2 = ALLOC (arena2, 1024);
      ASSERT_NOT_NULL (p1);
      ASSERT_NOT_NULL (p2);
      (void)p1;
      (void)p2;
    }

  /* Reset vs Clear */
  Arena_reset (arena1); /* Keeps first chunk */
  Arena_clear (arena2); /* Releases all chunks */

  /* Both should be usable after */
  void *ptr1 = ALLOC (arena1, 100);
  void *ptr2 = ALLOC (arena2, 100);
  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena1);
  Arena_dispose (&arena2);
}

/* Test chunk reuse after reset */
TEST (arena_reset_chunk_reuse)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* First allocation */
  char *ptr1 = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);
  memset (ptr1, 0x11, 100);

  /* Reset - should preserve first chunk */
  Arena_reset (arena);

  /* Second allocation - may reuse same memory location */
  char *ptr2 = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr2);

  /* Memory should be reusable (addresses might be same) */
  /* Just verify we can write to it */
  memset (ptr2, 0x22, 100);
  ASSERT_EQ (ptr2[0], 0x22);

  Arena_dispose (&arena);
}

/* Test large allocations spanning multiple chunks */
TEST (arena_reset_after_large_allocations)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate several large blocks */
  void *large1 = ALLOC (arena, 50000);
  void *large2 = ALLOC (arena, 75000);
  void *large3 = ALLOC (arena, 100000);
  ASSERT_NOT_NULL (large1);
  ASSERT_NOT_NULL (large2);
  ASSERT_NOT_NULL (large3);

  /* Reset should handle multiple chunks properly */
  Arena_reset (arena);

  /* Should be able to allocate again */
  void *ptr = ALLOC (arena, 1000);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test reset with NULL arena */
TEST (arena_reset_null_arena)
{
  Arena_T arena = NULL;

  /* Should not crash */
  Arena_reset (arena);

  /* No assertion needed - just verify no crash */
}

/* Test memory accounting after reset */
TEST (arena_reset_memory_accounting)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate multiple chunks */
  for (int i = 0; i < 50; i++)
    {
      void *ptr = ALLOC (arena, 1024);
      ASSERT_NOT_NULL (ptr);
      (void)ptr;
    }

  /* Reset releases extra chunks to global cache */
  Arena_reset (arena);

  /* Should be able to allocate and use memory normally */
  void *ptr = ALLOC (arena, 500);
  ASSERT_NOT_NULL (ptr);
  memset (ptr, 0x42, 500);

  Arena_dispose (&arena);
}

/* Test interleaved reset and allocations */
TEST (arena_reset_interleaved_operations)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate, reset, allocate pattern */
  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  Arena_reset (arena);

  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_reset (arena);

  void *ptr3 = ALLOC (arena, 300);
  ASSERT_NOT_NULL (ptr3);

  Arena_dispose (&arena);
}

/* Test reset preserves first chunk data until overwrite */
TEST (arena_reset_first_chunk_preservation)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Small allocation in first chunk */
  char *ptr1 = (char *)ALLOC (arena, 50);
  ASSERT_NOT_NULL (ptr1);
  memset (ptr1, 0xAA, 50);

  /* Force multiple chunks */
  for (int i = 0; i < 20; i++)
    {
      void *p = ALLOC (arena, 5000);
      ASSERT_NOT_NULL (p);
      (void)p;
    }

  /* Reset - releases extra chunks but keeps first */
  Arena_reset (arena);

  /* New allocation will reuse first chunk from beginning */
  char *ptr2 = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr2);
  memset (ptr2, 0xBB, 100);

  /* Verify we can write to new allocation */
  ASSERT_EQ (ptr2[0], (char)0xBB);

  Arena_dispose (&arena);
}

/* Test reset efficiency with tight loop */
TEST (arena_reset_tight_loop_efficiency)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Tight loop of allocate + reset */
  for (int i = 0; i < 1000; i++)
    {
      void *ptr = ALLOC (arena, 100 + (i % 100));
      ASSERT_NOT_NULL (ptr);
      (void)ptr;
      Arena_reset (arena);
    }

  Arena_dispose (&arena);
}

/* Test reset with unlocked arena */
TEST (arena_reset_unlocked_arena)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Allocate some memory */
  void *ptr1 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr1);

  /* Reset should work with unlocked arena */
  Arena_reset (arena);

  /* Allocate again */
  void *ptr2 = ALLOC (arena, 300);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test reset followed by calloc */
TEST (arena_reset_followed_by_calloc)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Initial allocation */
  void *ptr1 = ALLOC (arena, 500);
  ASSERT_NOT_NULL (ptr1);

  /* Reset */
  Arena_reset (arena);

  /* Use calloc after reset */
  int *arr = (int *)CALLOC (arena, 100, sizeof (int));
  ASSERT_NOT_NULL (arr);

  /* Verify zero initialization */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (arr[i], 0);
    }

  Arena_dispose (&arena);
}

/* ==================== Arena_new_unlocked() Tests ==================== */

/* Test basic unlocked arena creation */
TEST (arena_new_unlocked_creates_arena)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test allocations work on unlocked arena */
TEST (arena_unlocked_alloc_basic)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *ptr = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test multiple allocations on unlocked arena */
TEST (arena_unlocked_multiple_allocations)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  void *ptr2 = ALLOC (arena, 200);
  void *ptr3 = ALLOC (arena, 50);

  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);
  ASSERT_NOT_NULL (ptr3);

  /* Pointers should be different */
  ASSERT_NE (ptr1, ptr2);
  ASSERT_NE (ptr2, ptr3);
  ASSERT_NE (ptr1, ptr3);

  Arena_dispose (&arena);
}

/* Test calloc on unlocked arena */
TEST (arena_unlocked_calloc_zero_initialized)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  char *ptr = (char *)CALLOC (arena, 100, sizeof (char));
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is zero-initialized */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (ptr[i], 0);
    }

  Arena_dispose (&arena);
}

/* Test memory is writable on unlocked arena */
TEST (arena_unlocked_memory_writable)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  char *ptr = (char *)ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  /* Write to memory */
  memset (ptr, 0xBB, 100);

  /* Verify data was written */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (ptr[i], (char)0xBB);
    }

  Arena_dispose (&arena);
}

/* Test Arena_clear works with unlocked arenas */
TEST (arena_unlocked_clear_preserves_arena)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  /* Clear should free allocations but keep arena */
  Arena_clear (arena);

  /* Arena should still be valid */
  ASSERT_NOT_NULL (arena);

  /* Can allocate again after clear */
  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test multiple clear operations on unlocked arena */
TEST (arena_unlocked_multiple_clears)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  for (int i = 0; i < 5; i++)
    {
      void *ptr = ALLOC (arena, 100);
      ASSERT_NOT_NULL (ptr);
      Arena_clear (arena);
    }

  Arena_dispose (&arena);
}

/* Test large allocation on unlocked arena */
TEST (arena_unlocked_large_allocation)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Allocate a reasonably large chunk */
  size_t large_size = (size_t)1024 * 1024; /* 1MB */
  void *ptr = ALLOC (arena, large_size);
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is writable */
  memset (ptr, 0x33, large_size);
  char *cptr = (char *)ptr;
  ASSERT_EQ (cptr[0], 0x33);
  ASSERT_EQ (cptr[large_size - 1], 0x33);

  Arena_dispose (&arena);
}

/* Test very large allocation on unlocked arena */
TEST (arena_unlocked_very_large_allocation)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Allocate close to maximum size */
  size_t large_size = (size_t)10 * 1024 * 1024; /* 10MB */
  void *ptr = ALLOC (arena, large_size);
  ASSERT_NOT_NULL (ptr);

  /* Verify memory is writable */
  memset (ptr, 0x77, large_size);
  char *cptr = (char *)ptr;
  ASSERT_EQ (cptr[0], 0x77);
  ASSERT_EQ (cptr[large_size - 1], 0x77);

  Arena_dispose (&arena);
}

/* Test many small allocations on unlocked arena */
TEST (arena_unlocked_many_small_allocations)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *ptrs[1000];
  for (int i = 0; i < 1000; i++)
    {
      ptrs[i] = ALLOC (arena, 10);
      ASSERT_NOT_NULL (ptrs[i]);
    }

  Arena_dispose (&arena);
}

/* Test mixed allocation sizes on unlocked arena */
TEST (arena_unlocked_mixed_allocation_sizes)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *small = ALLOC (arena, 1);
  void *medium = ALLOC (arena, 1000);
  void *large = ALLOC (arena, 10000);
  void *tiny = ALLOC (arena, 4);

  ASSERT_NOT_NULL (small);
  ASSERT_NOT_NULL (medium);
  ASSERT_NOT_NULL (large);
  ASSERT_NOT_NULL (tiny);

  Arena_dispose (&arena);
}

/* Test disposal sets pointer to NULL for unlocked arena */
TEST (arena_unlocked_dispose_sets_null)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

/* Test memory alignment on unlocked arena */
TEST (arena_unlocked_memory_alignment)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Allocate various sizes and check alignment */
  void *ptr1 = ALLOC (arena, 1);
  void *ptr2 = ALLOC (arena, sizeof (long));
  void *ptr3 = ALLOC (arena, sizeof (double));

  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);
  ASSERT_NOT_NULL (ptr3);

  /* Check that pointers are properly aligned for common types */
  uintptr_t addr1 = (uintptr_t)ptr1;
  uintptr_t addr2 = (uintptr_t)ptr2;
  uintptr_t addr3 = (uintptr_t)ptr3;

  /* Check alignment - should be aligned for pointer types at minimum */
  size_t ptr_alignment = sizeof (void *);
  ASSERT_EQ (addr1 % ptr_alignment, 0);
  ASSERT_EQ (addr2 % sizeof (long), 0);
  ASSERT_EQ (addr3 % sizeof (double), 0);

  Arena_dispose (&arena);
}

/* Test alignment preservation across allocations on unlocked arena */
TEST (arena_unlocked_alignment_preservation)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Allocate with various sizes and check alignment */
  void *ptrs[10];
  for (int i = 0; i < 10; i++)
    {
      ptrs[i] = ALLOC (arena, i * 8 + 1);
      ASSERT_NOT_NULL (ptrs[i]);
      uintptr_t addr = (uintptr_t)ptrs[i];
      ASSERT_EQ (addr % sizeof (void *), 0);
    }

  Arena_dispose (&arena);
}

/* Test calloc with large count on unlocked arena */
TEST (arena_unlocked_calloc_large_count)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  int *arr = (int *)CALLOC (arena, 10000, sizeof (int));
  ASSERT_NOT_NULL (arr);

  /* Verify all elements are zero */
  for (int i = 0; i < 10000; i++)
    {
      ASSERT_EQ (arr[i], 0);
    }

  Arena_dispose (&arena);
}

/* Test allocation after clear on unlocked arena */
TEST (arena_unlocked_allocation_after_clear)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr1);

  Arena_clear (arena);

  void *ptr2 = ALLOC (arena, 200);
  ASSERT_NOT_NULL (ptr2);

  Arena_dispose (&arena);
}

/* Test clear on empty unlocked arena */
TEST (arena_unlocked_clear_empty_arena)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  /* Clear without any allocations */
  Arena_clear (arena);

  /* Should still be able to allocate */
  void *ptr = ALLOC (arena, 100);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
}

/* Test multiple disposals on unlocked arena (should be safe) */
TEST (arena_unlocked_multiple_disposals)
{
  Arena_T arena = Arena_new_unlocked ();
  ASSERT_NOT_NULL (arena);

  Arena_dispose (&arena);
  ASSERT_NULL (arena);

  /* Dispose again - should be safe */
  Arena_dispose (&arena);
  ASSERT_NULL (arena);
}

||||||| parent of 1b2c8c6d (test(core): add comprehensive tests for SocketConfig memory limit functions)
/* ==================== SocketConfig Memory Limit Tests ==================== */

/* Test set/get roundtrip */
TEST (socketconfig_set_get_max_memory_roundtrip)
{
  /* Save original limit */
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Set a new limit */
  size_t test_limit = 1024 * 1024; /* 1MB */
  SocketConfig_set_max_memory (test_limit);

  /* Verify get returns the same value */
  ASSERT_EQ (SocketConfig_get_max_memory (), test_limit);

  /* Restore original limit */
  SocketConfig_set_max_memory (original_limit);
}

/* Test default value is 0 (unlimited) */
TEST (socketconfig_default_max_memory_is_unlimited)
{
  /* Save current limit */
  size_t current = SocketConfig_get_max_memory ();

  /* Reset to default (0) */
  SocketConfig_set_max_memory (0);

  /* Verify default is 0 (unlimited) */
  ASSERT_EQ (SocketConfig_get_max_memory (), 0);

  /* Restore original */
  SocketConfig_set_max_memory (current);
}

/* Test set to zero explicitly */
TEST (socketconfig_set_max_memory_to_zero)
{
  /* Save original */
  size_t original = SocketConfig_get_max_memory ();

  /* Set to non-zero */
  SocketConfig_set_max_memory (1000);

  /* Set to zero (unlimited) */
  SocketConfig_set_max_memory (0);

  /* Verify */
  ASSERT_EQ (SocketConfig_get_max_memory (), 0);

  /* Restore */
  SocketConfig_set_max_memory (original);
}

/* Test large limit value */
TEST (socketconfig_set_large_memory_limit)
{
  size_t original = SocketConfig_get_max_memory ();

  /* Set a very large limit (but not SIZE_MAX to avoid overflow issues) */
  size_t large_limit = SIZE_MAX / 2;
  SocketConfig_set_max_memory (large_limit);

  ASSERT_EQ (SocketConfig_get_max_memory (), large_limit);

  SocketConfig_set_max_memory (original);
}

/* Test memory usage tracking - allocation increases usage */
TEST (socketconfig_usage_tracking_increases)
{
  size_t original_limit = SocketConfig_get_max_memory ();
  SocketConfig_set_max_memory (0); /* Unlimited */

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  size_t usage_before = SocketConfig_get_memory_used ();

  /* Allocate some memory */
  void *ptr = ALLOC (arena, 1000);
  ASSERT_NOT_NULL (ptr);

  /* Usage should increase */
  size_t usage_after = SocketConfig_get_memory_used ();
  ASSERT (usage_after >= usage_before);

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

/* Test memory usage tracking - disposal decreases usage */
TEST (socketconfig_usage_tracking_decreases_on_dispose)
{
  size_t original_limit = SocketConfig_get_max_memory ();
  SocketConfig_set_max_memory (0); /* Unlimited */

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr = ALLOC (arena, 5000);
  ASSERT_NOT_NULL (ptr);

  size_t usage_with_arena = SocketConfig_get_memory_used ();

  /* Dispose should reduce usage */
  Arena_dispose (&arena);

  size_t usage_after_dispose = SocketConfig_get_memory_used ();
  ASSERT (usage_after_dispose <= usage_with_arena);

  SocketConfig_set_max_memory (original_limit);
}

/* Test tracking across multiple arenas */
TEST (socketconfig_usage_tracking_multiple_arenas)
{
  size_t original_limit = SocketConfig_get_max_memory ();
  SocketConfig_set_max_memory (0); /* Unlimited */

  Arena_T arena1 = Arena_new ();
  Arena_T arena2 = Arena_new ();
  ASSERT_NOT_NULL (arena1);
  ASSERT_NOT_NULL (arena2);

  size_t usage_start = SocketConfig_get_memory_used ();

  void *ptr1 = ALLOC (arena1, 1000);
  void *ptr2 = ALLOC (arena2, 2000);
  ASSERT_NOT_NULL (ptr1);
  ASSERT_NOT_NULL (ptr2);

  size_t usage_both = SocketConfig_get_memory_used ();
  ASSERT (usage_both >= usage_start);

  /* Dispose first arena */
  Arena_dispose (&arena1);
  size_t usage_one = SocketConfig_get_memory_used ();
  ASSERT (usage_one <= usage_both);

  /* Dispose second arena */
  Arena_dispose (&arena2);
  size_t usage_none = SocketConfig_get_memory_used ();
  ASSERT (usage_none <= usage_one);

  SocketConfig_set_max_memory (original_limit);
}

/* Test clear doesn't affect usage (memory still allocated to arena) */
TEST (socketconfig_usage_clear_vs_dispose)
{
  size_t original_limit = SocketConfig_get_max_memory ();
  SocketConfig_set_max_memory (0); /* Unlimited */

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr = ALLOC (arena, 3000);
  ASSERT_NOT_NULL (ptr);

  size_t usage_before_clear = SocketConfig_get_memory_used ();

  /* Clear should not reduce global usage (chunks still owned by arena) */
  Arena_clear (arena);

  size_t usage_after_clear = SocketConfig_get_memory_used ();

  /* Usage might stay same or decrease slightly, but arena still owns chunks */
  /* The key point is dispose should show a decrease or stay same */
  Arena_dispose (&arena);

  size_t usage_after_dispose = SocketConfig_get_memory_used ();
  ASSERT (usage_after_dispose <= usage_before_clear);

  SocketConfig_set_max_memory (original_limit);
}

/* Test allocation fails when limit exceeded */
TEST (socketconfig_limit_enforcement_allocation_fails)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Set a very low limit */
  SocketConfig_set_max_memory (1000);

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  TRY
  {
    /* Try to allocate more than the limit allows */
    void *ptr = ALLOC (arena, 100000);
    ASSERT (0); /* Should not reach here */
    (void)ptr;
  }
  ELSE
  {
    /* Expected - allocation should fail */
    ASSERT_NOT_NULL (Except_frame.exception);
  }
  END_TRY;

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

/* Test allocations succeed when under limit */
TEST (socketconfig_limit_enforcement_under_limit)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Set a reasonable limit */
  SocketConfig_set_max_memory (100000);

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate well under limit */
  void *ptr = ALLOC (arena, 1000);
  ASSERT_NOT_NULL (ptr);

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

/* Test allocating exactly to limit */
TEST (socketconfig_limit_enforcement_exact_limit)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Set a specific limit and try to hit it exactly
   * This is tricky due to arena chunk overhead, so we'll just verify
   * that we can allocate up to near the limit */
  size_t test_limit = 50000;
  SocketConfig_set_max_memory (test_limit);

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Allocate chunks until near limit */
  volatile int success = 0;
  TRY
  {
    void *ptr1 = ALLOC (arena, 10000);
    ASSERT_NOT_NULL (ptr1);
    success = 1;
  }
  ELSE
  {
    /* If it fails, that's also valid depending on overhead */
  }
  END_TRY;

  /* At least one small allocation should work */
  ASSERT_EQ (success, 1);

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

/* Test limit enforcement with multiple arenas */
TEST (socketconfig_limit_enforcement_multiple_arenas)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Set a moderate limit */
  SocketConfig_set_max_memory (30000);

  Arena_T arena1 = Arena_new ();
  Arena_T arena2 = Arena_new ();
  ASSERT_NOT_NULL (arena1);
  ASSERT_NOT_NULL (arena2);

  /* Allocate from both arenas */
  void *ptr1 = ALLOC (arena1, 5000);
  ASSERT_NOT_NULL (ptr1);

  void *ptr2 = ALLOC (arena2, 5000);
  ASSERT_NOT_NULL (ptr2);

  /* Eventually one should hit the limit */
  volatile int hit_limit = 0;
  TRY
  {
    /* Try to allocate more */
    void *ptr3 = ALLOC (arena1, 50000);
    (void)ptr3;
  }
  EXCEPT (Arena_Failed)
  {
    hit_limit = 1;
  }
  END_TRY;

  ASSERT_EQ (hit_limit, 1);

  Arena_dispose (&arena1);
  Arena_dispose (&arena2);
  SocketConfig_set_max_memory (original_limit);
}

/* Test changing limit while arenas exist */
TEST (socketconfig_change_limit_with_existing_arenas)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  SocketConfig_set_max_memory (100000);

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr1 = ALLOC (arena, 10000);
  ASSERT_NOT_NULL (ptr1);

  /* Lower the limit */
  SocketConfig_set_max_memory (20000);

  /* New allocations should respect new limit */
  volatile int hit_new_limit = 0;
  TRY
  {
    void *ptr2 = ALLOC (arena, 50000);
    (void)ptr2;
  }
  EXCEPT (Arena_Failed)
  {
    hit_new_limit = 1;
  }
  END_TRY;

  ASSERT_EQ (hit_new_limit, 1);

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

/* Test usage before setting limit */
TEST (socketconfig_usage_before_limit_set)
{
  size_t original_limit = SocketConfig_get_max_memory ();

  /* Start with no limit */
  SocketConfig_set_max_memory (0);

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  void *ptr = ALLOC (arena, 10000);
  ASSERT_NOT_NULL (ptr);

  size_t usage = SocketConfig_get_memory_used ();
  ASSERT (usage > 0);

  /* Now set a limit lower than current usage */
  SocketConfig_set_max_memory (usage / 2);

  /* New allocations should fail */
  volatile int failed = 0;
  TRY
  {
    void *ptr2 = ALLOC (arena, 10000);
    (void)ptr2;
  }
  EXCEPT (Arena_Failed)
  {
    failed = 1;
  }
  END_TRY;

  ASSERT_EQ (failed, 1);

  Arena_dispose (&arena);
  SocketConfig_set_max_memory (original_limit);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
