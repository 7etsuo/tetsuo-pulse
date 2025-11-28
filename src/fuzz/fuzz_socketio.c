/**
 * fuzz_socketio.c - Fuzzer for iovec scatter/gather operations
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketCommon_calculate_total_iov_len() overflow protection
 * - SocketCommon_advance_iov() bounds checking
 * - SocketCommon_find_active_iov() edge cases
 * - SocketCommon_alloc_iov_copy() allocation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketio
 * Run:   ./fuzz_socketio corpus/socketio/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketCommon.h"

/* Maximum iovec count to test */
#define MAX_IOV_COUNT 16

/* Operation codes */
enum IovOp
{
  IOV_CALCULATE_TOTAL = 0,
  IOV_ADVANCE,
  IOV_FIND_ACTIVE,
  IOV_ALLOC_COPY,
  IOV_SYNC_PROGRESS,
  IOV_OP_COUNT
};

/* Static buffers for iovec bases */
static char iov_buffers[MAX_IOV_COUNT][256];

/**
 * read_u16 - Read a 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * build_iov_from_fuzz - Build iovec array from fuzz data
 * @data: Fuzz input
 * @size: Size of fuzz input
 * @iov: Output iovec array
 * @max_count: Maximum iovec count
 *
 * Input format: pairs of (len_lo, len_hi) for each iovec
 * Returns: Number of iovecs created
 */
static int
build_iov_from_fuzz (const uint8_t *data, size_t size, struct iovec *iov,
                     int max_count)
{
  int count = 0;
  size_t offset = 0;

  while (offset + 2 <= size && count < max_count)
    {
      uint16_t len = read_u16 (data + offset);
      offset += 2;

      /* Limit individual iov_len to buffer size */
      if (len > sizeof (iov_buffers[0]))
        len = sizeof (iov_buffers[0]);

      iov[count].iov_base = iov_buffers[count];
      iov[count].iov_len = len;
      count++;
    }

  return count;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Byte 1: iovcnt (limited to MAX_IOV_COUNT)
 * - Bytes 2-3: advance_bytes (for IOV_ADVANCE)
 * - Remaining: iovec lengths
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct iovec iov[MAX_IOV_COUNT];
  struct iovec iov_copy[MAX_IOV_COUNT];
  int iovcnt;

  if (size < 4)
    return 0;

  uint8_t op = data[0];
  int requested_count = data[1] % MAX_IOV_COUNT;
  uint16_t advance_bytes = read_u16 (data + 2);

  /* Build iovec array from remaining data */
  iovcnt = build_iov_from_fuzz (data + 4, size - 4, iov,
                                requested_count > 0 ? requested_count : 1);

  if (iovcnt == 0)
    return 0;

  /* Make a copy for operations that modify iovec */
  memcpy (iov_copy, iov, sizeof (iov));

  TRY
  {
    switch (op % IOV_OP_COUNT)
      {
      case IOV_CALCULATE_TOTAL:
        {
          /* Test total length calculation with overflow protection */
          size_t total = SocketCommon_calculate_total_iov_len (iov, iovcnt);
          (void)total;
        }
        break;

      case IOV_ADVANCE:
        {
          /* Calculate total first to validate advance amount */
          size_t total = SocketCommon_calculate_total_iov_len (iov_copy,
                                                               iovcnt);
          /* Limit advance to total length */
          size_t advance = advance_bytes % (total + 1);
          if (advance > 0)
            {
              SocketCommon_advance_iov (iov_copy, iovcnt, advance);
            }
        }
        break;

      case IOV_FIND_ACTIVE:
        {
          /* Find first non-empty iovec */
          int active_count = 0;
          struct iovec *active = SocketCommon_find_active_iov (iov, iovcnt,
                                                               &active_count);
          (void)active;
          (void)active_count;
        }
        break;

      case IOV_ALLOC_COPY:
        {
          /* Test iovec copy allocation */
          struct iovec *copy = SocketCommon_alloc_iov_copy (iov, iovcnt,
                                                            SocketCommon_Failed);
          if (copy)
            {
              /* Verify copy */
              for (int i = 0; i < iovcnt; i++)
                {
                  assert (copy[i].iov_len == iov[i].iov_len);
                }
              free (copy);
            }
        }
        break;

      case IOV_SYNC_PROGRESS:
        {
          /* Test sync after advance */
          size_t total = SocketCommon_calculate_total_iov_len (iov_copy,
                                                               iovcnt);
          size_t advance = advance_bytes % (total + 1);
          if (advance > 0)
            {
              /* Advance copy, then sync back to original */
              SocketCommon_advance_iov (iov_copy, iovcnt, advance);
              SocketCommon_sync_iov_progress (iov, iov_copy, iovcnt);
            }
        }
        break;
      }
  }
  EXCEPT (SocketCommon_Failed)
  {
    /* Expected for overflow or invalid params */
  }
  END_TRY;

  return 0;
}

