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

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
