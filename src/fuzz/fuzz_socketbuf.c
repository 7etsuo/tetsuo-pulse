/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_socketbuf.c - Fuzzer for circular buffer operations
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Buffer creation with various capacities
 * - Circular buffer write/read/peek operations
 * - Wraparound edge cases
 * - Dynamic buffer resizing (reserve)
 * - Zero-copy pointer access
 * - Secure memory clearing
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_socketbuf
 * Run:   ./fuzz_socketbuf corpus/socketbuf/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"
#include "socket/SocketBuf.h"

/* Operation codes */
enum BufOp
{
  OP_CREATE_BUF = 0,
  OP_WRITE_READ,
  OP_PEEK_CONSUME,
  OP_RESERVE_GROW,
  OP_ZERO_COPY,
  OP_WRAPAROUND,
  OP_SECURE_CLEAR,
  OP_MIXED_OPS,
  OP_COUNT
};

/* Limits for fuzzing */
#define MAX_FUZZ_CAPACITY 4096
#define MIN_FUZZ_CAPACITY 64

/**
 * read_u16 - Read 16-bit value from byte stream
 */
static uint16_t
read_u16 (const uint8_t *p)
{
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * Input format:
 * - Byte 0: Operation selector
 * - Bytes 1-2: Capacity parameter
 * - Bytes 3-4: Length parameter
 * - Remaining: Data to write
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketBuf_T buf = NULL;
  /* cppcheck-suppress variableScope ; used across multiple switch cases */
  char read_buffer[MAX_FUZZ_CAPACITY];

  if (size < 5)
    return 0;

  uint8_t op = data[0];
  uint16_t capacity_raw = read_u16 (data + 1);
  size_t capacity = (capacity_raw % (MAX_FUZZ_CAPACITY - MIN_FUZZ_CAPACITY))
                    + MIN_FUZZ_CAPACITY;
  uint16_t len_param = read_u16 (data + 3);
  size_t data_offset = 5;
  size_t data_len = size > data_offset ? size - data_offset : 0;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    switch (op % OP_COUNT)
      {
      case OP_CREATE_BUF:
        {
          /* Test buffer creation with various capacities */
          buf = SocketBuf_new (arena, capacity);

          /* Verify initial state */
          assert (SocketBuf_available (buf) == 0);
          assert (SocketBuf_space (buf) == capacity);
          assert (SocketBuf_empty (buf));
          assert (!SocketBuf_full (buf));

          /* Try edge case capacities */
          SocketBuf_T small_buf = NULL;
          TRY
          {
            small_buf = SocketBuf_new (arena, MIN_FUZZ_CAPACITY);
            assert (SocketBuf_space (small_buf) == MIN_FUZZ_CAPACITY);
            (void)small_buf; /* Suppress unused-but-set warning */
          }
          EXCEPT (SocketBuf_Failed) { /* Expected for invalid capacities */ }
          END_TRY;
        }
        break;

      case OP_WRITE_READ:
        {
          /* Test basic write then read */
          buf = SocketBuf_new (arena, capacity);

          /* Write data */
          size_t to_write = data_len > capacity ? capacity : data_len;
          size_t written = 0;
          if (to_write > 0)
            written = SocketBuf_write (buf, data + data_offset, to_write);

          assert (SocketBuf_available (buf) == written);
          assert (SocketBuf_space (buf) == capacity - written);

          /* Read it back */
          size_t bytes_read = SocketBuf_read (buf, read_buffer, written);
          assert (bytes_read == written);
          assert (SocketBuf_empty (buf));

          /* Verify data integrity */
          if (written > 0)
            assert (memcmp (read_buffer, data + data_offset, written) == 0);
        }
        break;

      case OP_PEEK_CONSUME:
        {
          /* Test peek (non-destructive read) and consume */
          buf = SocketBuf_new (arena, capacity);

          /* Write some data */
          size_t to_write = data_len > capacity ? capacity : data_len;
          size_t written = 0;
          if (to_write > 0)
            written = SocketBuf_write (buf, data + data_offset, to_write);

          /* Peek at data */
          size_t peeked = SocketBuf_peek (buf, read_buffer, written);
          assert (peeked == written);
          assert (SocketBuf_available (buf) == written); /* Still there */

          /* Consume partial */
          size_t consume_amt = len_param % (written + 1);
          if (consume_amt > 0 && consume_amt <= written)
            {
              SocketBuf_consume (buf, consume_amt);
              assert (SocketBuf_available (buf) == written - consume_amt);
            }

          /* Clear the rest */
          SocketBuf_clear (buf);
          assert (SocketBuf_empty (buf));
        }
        break;

      case OP_RESERVE_GROW:
        {
          /* Test dynamic resizing */
          buf = SocketBuf_new (arena, capacity);

          /* Write initial data */
          size_t initial_write
              = data_len > capacity / 2 ? capacity / 2 : data_len;
          if (initial_write > 0)
            SocketBuf_write (buf, data + data_offset, initial_write);

          /* Reserve more space - trigger resize */
          size_t reserve_amt = len_param % MAX_FUZZ_CAPACITY;
          if (reserve_amt > 0)
            {
              TRY
              {
                SocketBuf_reserve (buf, reserve_amt);
                /* After reserve, space should be >= reserve_amt */
                assert (SocketBuf_space (buf) >= reserve_amt);
              }
              EXCEPT (SocketBuf_Failed)
              {
                /* Overflow or allocation failure - expected for large values
                 */
              }
              END_TRY;
            }

          /* Verify data integrity after resize */
          if (initial_write > 0)
            {
              size_t available = SocketBuf_available (buf);
              assert (available >= initial_write || available == 0);
            }
        }
        break;

      case OP_ZERO_COPY:
        {
          /* Test zero-copy pointer access */
          buf = SocketBuf_new (arena, capacity);

          /* Get write pointer and write directly */
          size_t write_space = 0;
          void *write_ptr = SocketBuf_writeptr (buf, &write_space);

          if (write_ptr && write_space > 0)
            {
              size_t direct_write
                  = data_len > write_space ? write_space : data_len;
              if (direct_write > 0)
                {
                  memcpy (write_ptr, data + data_offset, direct_write);
                  SocketBuf_written (buf, direct_write);

                  assert (SocketBuf_available (buf) == direct_write);
                }
            }

          /* Get read pointer and verify */
          size_t read_avail = 0;
          const void *read_ptr = SocketBuf_readptr (buf, &read_avail);

          if (read_ptr && read_avail > 0)
            {
              /* Verify data matches */
              size_t check_len = read_avail < data_len ? read_avail : data_len;
              if (check_len > 0)
                assert (memcmp (read_ptr, data + data_offset, check_len) == 0);
            }
        }
        break;

      case OP_WRAPAROUND:
        {
          /* Test circular buffer wraparound */
          buf = SocketBuf_new (arena, capacity);

          /* Fill buffer partially */
          size_t first_write = capacity / 2;
          if (first_write > data_len)
            first_write = data_len;

          if (first_write > 0)
            {
              SocketBuf_write (buf, data + data_offset, first_write);

              /* Read some to advance head */
              size_t to_read = first_write / 2;
              SocketBuf_read (buf, read_buffer, to_read);

              /* Now write more - should wrap around */
              size_t remaining_data
                  = data_len > first_write ? data_len - first_write : 0;
              size_t space = SocketBuf_space (buf);
              size_t second_write
                  = remaining_data > space ? space : remaining_data;

              if (second_write > 0)
                {
                  size_t offset = data_offset + first_write;
                  if (offset < size)
                    SocketBuf_write (buf, data + offset, second_write);
                }

              /* Verify we can read all data back */
              size_t total_available = SocketBuf_available (buf);
              size_t total_read
                  = SocketBuf_read (buf, read_buffer, total_available);
              assert (total_read == total_available);
            }
        }
        break;

      case OP_SECURE_CLEAR:
        {
          /* Test secure memory clearing */
          buf = SocketBuf_new (arena, capacity);

          /* Write sensitive data */
          size_t to_write = data_len > capacity ? capacity : data_len;
          if (to_write > 0)
            SocketBuf_write (buf, data + data_offset, to_write);

          /* Securely clear */
          SocketBuf_secureclear (buf);

          /* Verify buffer is empty */
          assert (SocketBuf_empty (buf));
          assert (SocketBuf_available (buf) == 0);

          /* Buffer should be usable again */
          if (to_write > 0)
            {
              size_t written
                  = SocketBuf_write (buf, data + data_offset, to_write);
              assert (written == to_write);
            }
        }
        break;

      case OP_MIXED_OPS:
        {
          /* Mixed operations stress test */
          buf = SocketBuf_new (arena, capacity);

          /* Series of operations based on fuzz data */
          for (size_t i = data_offset; i < size && i < data_offset + 20; i++)
            {
              uint8_t sub_op = data[i] % 6;

              switch (sub_op)
                {
                case 0: /* Write */
                  {
                    size_t space = SocketBuf_space (buf);
                    size_t amt = (data[i] % 64) + 1;
                    if (amt > space)
                      amt = space;
                    if (amt > 0 && i + amt < size)
                      SocketBuf_write (buf, data + i, amt);
                  }
                  break;

                case 1: /* Read */
                  {
                    size_t avail = SocketBuf_available (buf);
                    size_t amt = (data[i] % 64) + 1;
                    if (amt > avail)
                      amt = avail;
                    if (amt > 0)
                      SocketBuf_read (buf, read_buffer, amt);
                  }
                  break;

                case 2: /* Peek */
                  {
                    size_t avail = SocketBuf_available (buf);
                    if (avail > 0)
                      SocketBuf_peek (buf, read_buffer, avail);
                  }
                  break;

                case 3: /* Consume */
                  {
                    size_t avail = SocketBuf_available (buf);
                    size_t amt = data[i] % (avail + 1);
                    if (amt > 0)
                      SocketBuf_consume (buf, amt);
                  }
                  break;

                case 4: /* Clear */
                  SocketBuf_clear (buf);
                  break;

                case 5: /* Check state */
                  {
                    size_t avail = SocketBuf_available (buf);
                    size_t space = SocketBuf_space (buf);
                    int empty = SocketBuf_empty (buf);
                    int full = SocketBuf_full (buf);
                    (void)avail;
                    (void)space;
                    (void)empty;
                    (void)full;
                  }
                  break;
                }
            }
        }
        break;
      }
  }
  EXCEPT (SocketBuf_Failed) { /* Expected for some operations */ }
  EXCEPT (Arena_Failed) { /* Memory allocation can fail */ }
  FINALLY
  {
    /* Release buffer (arena owns memory) */
    if (buf)
      SocketBuf_release (&buf);

    /* Dispose of the arena */
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
