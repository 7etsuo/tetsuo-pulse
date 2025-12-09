/**
 * fuzz_arena.c - libFuzzer harness for Arena memory allocator
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Integer overflow in size calculations
 * - Chunk management edge cases
 * - Alignment handling
 * - Memory corruption from malicious allocation patterns
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_arena
 * Run:   ./fuzz_arena corpus/arena/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"

/* Maximum allocation size to avoid OOM in fuzzer */
#define FUZZ_MAX_ALLOC (1024 * 1024)      /* 1MB per allocation */
#define FUZZ_MAX_TOTAL (16 * 1024 * 1024) /* 16MB total per test */

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_ALLOC = 0,
  OP_CALLOC,
  OP_MANY_SMALL,
  OP_FEW_LARGE,
  OP_CLEAR_REUSE,
  OP_OVERFLOW_SIZE,
  OP_MAX
};

/**
 * parse_size - Parse allocation size from fuzz input
 * @data: Input bytes
 * @len: Number of bytes available
 *
 * Returns: Size capped at FUZZ_MAX_ALLOC
 */
static size_t
parse_size (const uint8_t *data, size_t len)
{
  size_t size = 0;

  if (len >= 4)
    {
      size = ((size_t)data[0]) | ((size_t)data[1] << 8)
             | ((size_t)data[2] << 16) | ((size_t)data[3] << 24);
    }
  else if (len >= 2)
    {
      size = ((size_t)data[0]) | ((size_t)data[1] << 8);
    }
  else if (len >= 1)
    {
      size = data[0];
    }

  /* Cap at max to avoid OOM */
  return size % FUZZ_MAX_ALLOC;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  if (size < 1)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    switch (op)
      {
      case OP_ALLOC:
        {
          /* Single allocation with fuzz-controlled size */
          size_t alloc_size = parse_size (payload, payload_size);
          if (alloc_size > 0)
            {
              void *ptr = Arena_alloc (arena, alloc_size, __FILE__, __LINE__);
              if (ptr)
                {
                  /* Touch first and last bytes to detect corruption
                   * Use volatile to prevent compiler optimizing away */
                  volatile char *vptr = (volatile char *)ptr;
                  vptr[0] = 0xAA;
                  if (alloc_size > 1)
                    vptr[alloc_size - 1] = 0xBB;
                }
            }
        }
        break;

      case OP_CALLOC:
        {
          /* calloc with fuzz-controlled count and size */
          if (payload_size >= 4)
            {
              size_t count = ((size_t)payload[0] << 8) | payload[1];
              size_t elem_size = ((size_t)payload[2] << 8) | payload[3];

              /* Cap to avoid huge allocations */
              count = count % 1000;
              elem_size = elem_size % 1000;

              if (count > 0 && elem_size > 0)
                {
                  void *ptr = Arena_calloc (arena, count, elem_size, __FILE__,
                                            __LINE__);
                  if (ptr)
                    {
                      /* Verify memory is zeroed */
                      size_t total = count * elem_size;
                      const char *p = ptr;
                      for (size_t i = 0; i < total && i < 100; i++)
                        {
                          assert (p[i] == 0);
                        }
                    }
                }
            }
        }
        break;

      case OP_MANY_SMALL:
        {
          /* Many small allocations to stress chunk management */
          size_t total_allocated = 0;
          size_t i = 0;

          while (i < payload_size && total_allocated < FUZZ_MAX_TOTAL)
            {
              size_t alloc_size = (payload[i] % 256) + 1; /* 1-256 bytes */
              void *ptr = Arena_alloc (arena, alloc_size, __FILE__, __LINE__);
              if (ptr)
                {
                  memset (ptr, (int)(i & 0xFF), alloc_size);
                  total_allocated += alloc_size;
                }
              i++;
            }
        }
        break;

      case OP_FEW_LARGE:
        {
          /* Few large allocations */
          size_t total_allocated = 0;
          size_t i = 0;

          while (i + 2 <= payload_size && total_allocated < FUZZ_MAX_TOTAL)
            {
              size_t alloc_size = ((size_t)payload[i] << 8) | payload[i + 1];
              alloc_size = (alloc_size % (256 * 1024)) + 1; /* 1-256KB */

              if (total_allocated + alloc_size > FUZZ_MAX_TOTAL)
                break;

              void *ptr = Arena_alloc (arena, alloc_size, __FILE__, __LINE__);
              if (ptr)
                {
                  /* Touch boundaries to detect corruption
                   * Use volatile to prevent compiler optimizing away */
                  volatile char *vptr = (volatile char *)ptr;
                  vptr[0] = 0xCC;
                  vptr[alloc_size - 1] = 0xDD;
                  total_allocated += alloc_size;
                }
              i += 2;
            }
        }
        break;

      case OP_CLEAR_REUSE:
        {
          /* Allocate, clear, allocate again to test chunk reuse */
          for (int round = 0; round < 3; round++)
            {
              size_t total = 0;
              for (size_t i = 0;
                   i < payload_size && total < FUZZ_MAX_TOTAL / 4; i++)
                {
                  size_t alloc_size = (payload[i] % 512) + 1;
                  void *ptr
                      = Arena_alloc (arena, alloc_size, __FILE__, __LINE__);
                  if (ptr)
                    {
                      memset (ptr, round, alloc_size);
                      total += alloc_size;
                    }
                }
              /* Clear arena for reuse */
              Arena_clear (arena);
            }
        }
        break;

      case OP_OVERFLOW_SIZE:
        {
          /* Test overflow protection with large sizes */
          /* These should fail gracefully, not crash */
          size_t dangerous_sizes[] = {
            SIZE_MAX,
            SIZE_MAX - 1,
            SIZE_MAX / 2,
            SIZE_MAX / 2 + 1,
            (size_t)1 << 62,
            (size_t)1 << 61,
            0, /* Zero size */
          };

          for (size_t i = 0;
               i < sizeof (dangerous_sizes) / sizeof (dangerous_sizes[0]); i++)
            {
              TRY
              {
                void *ptr = Arena_alloc (arena, dangerous_sizes[i], __FILE__,
                                         __LINE__);
                (void)ptr; /* May succeed for 0, should fail for large */
              }
              EXCEPT (Arena_Failed)
              {
                /* Expected - overflow protection working */
              }
              END_TRY;
            }
        }
        break;
      }
  }
  EXCEPT (Arena_Failed) { /* Expected for overflow/large allocations */ }
  FINALLY
  {
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
