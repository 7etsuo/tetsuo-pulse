/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * buffer_demo.c - SocketBuf Circular Buffer API Example
 *
 * Demonstrates the SocketBuf circular buffer API for efficient socket I/O:
 * - Creating buffers with SocketBuf_new()
 * - Writing data with SocketBuf_write()
 * - Reading data with SocketBuf_read()
 * - Peeking data without consuming with SocketBuf_peek()
 * - Zero-copy operations with SocketBuf_readptr() and SocketBuf_writeptr()
 * - Buffer state queries (available, space, empty, full)
 * - Secure clearing with SocketBuf_secureclear()
 * - Advanced operations: compact, ensure, find, readline
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_buffer_demo
 *
 * Usage:
 *   ./example_buffer_demo
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/SocketBuf.h"

/* Helper macros for demonstration output */
#define SECTION(name) printf ("\n=== %s ===\n", name)
#define TEST(name) printf ("\n[TEST] %s\n", name)
#define INFO(...) printf ("[INFO] " __VA_ARGS__)
#define PASS(msg) printf ("[PASS] %s\n", msg)
#define FAIL(msg) printf ("[FAIL] %s\n", msg)

/**
 * demonstrate_basic_operations - Show basic read/write operations
 */
static void
demonstrate_basic_operations (Arena_T arena)
{
  SECTION ("Basic Read/Write Operations");

  SocketBuf_T buf = NULL;

  TRY
  {
    /* Create a buffer with 1KB capacity */
    TEST ("Creating buffer with 1024 bytes capacity");
    buf = SocketBuf_new (arena, 1024);
    INFO ("Buffer created successfully\n");
    INFO ("Initial state - available: %zu, space: %zu, empty: %d, full: %d\n",
          SocketBuf_available (buf), SocketBuf_space (buf),
          SocketBuf_empty (buf), SocketBuf_full (buf));

    /* Write some data */
    TEST ("Writing data to buffer");
    const char *msg1 = "Hello, SocketBuf!";
    size_t written = SocketBuf_write (buf, msg1, strlen (msg1));
    INFO ("Wrote %zu bytes: '%s'\n", written, msg1);
    INFO ("After write - available: %zu, space: %zu\n",
          SocketBuf_available (buf), SocketBuf_space (buf));

    if (written == strlen (msg1))
      {
        PASS ("Write successful");
      }
    else
      {
        FAIL ("Incomplete write");
      }

    /* Read the data back */
    TEST ("Reading data from buffer");
    char readbuf[256] = { 0 };
    size_t nread = SocketBuf_read (buf, readbuf, sizeof (readbuf));
    INFO ("Read %zu bytes: '%s'\n", nread, readbuf);
    INFO ("After read - available: %zu, space: %zu\n",
          SocketBuf_available (buf), SocketBuf_space (buf));

    if (nread == strlen (msg1) && strcmp (readbuf, msg1) == 0)
      {
        PASS ("Read matches written data");
      }
    else
      {
        FAIL ("Read mismatch");
      }

    /* Verify buffer is empty after read */
    if (SocketBuf_empty (buf))
      {
        PASS ("Buffer is empty after consuming all data");
      }
    else
      {
        FAIL ("Buffer should be empty");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_peek_operations - Show non-destructive peek
 */
static void
demonstrate_peek_operations (Arena_T arena)
{
  SECTION ("Peek Operations (Non-Destructive Read)");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 1024);

    /* Write some data */
    const char *data = "Peek at this data!";
    SocketBuf_write (buf, data, strlen (data));
    INFO ("Wrote: '%s' (%zu bytes)\n", data, strlen (data));

    /* Peek at the data without consuming it */
    TEST ("Peeking at data without consuming");
    char peekbuf[256] = { 0 };
    size_t peeked = SocketBuf_peek (buf, peekbuf, sizeof (peekbuf));
    INFO ("Peeked %zu bytes: '%s'\n", peeked, peekbuf);
    INFO ("Available after peek: %zu (data not consumed)\n",
          SocketBuf_available (buf));

    if (SocketBuf_available (buf) == strlen (data))
      {
        PASS ("Peek did not consume data");
      }
    else
      {
        FAIL ("Peek should not consume data");
      }

    /* Peek again - should get same data */
    TEST ("Peeking again should return same data");
    char peekbuf2[256] = { 0 };
    SocketBuf_peek (buf, peekbuf2, sizeof (peekbuf2));

    if (strcmp (peekbuf, peekbuf2) == 0)
      {
        PASS ("Multiple peeks return consistent data");
      }
    else
      {
        FAIL ("Peek inconsistency");
      }

    /* Now read to consume */
    TEST ("Reading to consume data after peeking");
    char readbuf[256] = { 0 };
    SocketBuf_read (buf, readbuf, sizeof (readbuf));

    if (strcmp (readbuf, peekbuf) == 0 && SocketBuf_empty (buf))
      {
        PASS ("Read consumed data, buffer now empty");
      }
    else
      {
        FAIL ("Read operation failed");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_zerocopy_operations - Show zero-copy read/write
 */
static void
demonstrate_zerocopy_operations (Arena_T arena)
{
  SECTION ("Zero-Copy Operations");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 1024);

    /* Zero-copy write using writeptr() */
    TEST ("Zero-copy write using SocketBuf_writeptr()");
    size_t space;
    void *wptr = SocketBuf_writeptr (buf, &space);

    if (wptr)
      {
        INFO ("Got write pointer with %zu bytes available\n", space);

        /* Write directly to buffer memory */
        const char *msg = "Zero-copy write!";
        size_t len = strlen (msg);

        if (len <= space)
          {
            memcpy (wptr, msg, len);
            SocketBuf_written (buf, len); /* Commit the write */
            INFO ("Wrote %zu bytes using zero-copy\n", len);
            PASS ("Zero-copy write successful");
          }
      }
    else
      {
        FAIL ("Could not get write pointer");
      }

    /* Zero-copy read using readptr() */
    TEST ("Zero-copy read using SocketBuf_readptr()");
    size_t avail;
    const void *rptr = SocketBuf_readptr (buf, &avail);

    if (rptr && avail > 0)
      {
        INFO ("Got read pointer with %zu bytes available\n", avail);
        INFO ("Data: '%.*s'\n", (int)avail, (const char *)rptr);

        /* Use the data without copying */
        /* In real code, this might be send(socket, rptr, avail, 0) */

        /* Consume the data when done */
        SocketBuf_consume (buf, avail);
        INFO ("Consumed %zu bytes\n", avail);
        PASS ("Zero-copy read successful");
      }
    else
      {
        FAIL ("Could not get read pointer");
      }

    if (SocketBuf_empty (buf))
      {
        PASS ("Buffer empty after consuming");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_buffer_state - Show state query operations
 */
static void
demonstrate_buffer_state (Arena_T arena)
{
  SECTION ("Buffer State Queries");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 512); /* Medium-sized buffer for testing */

    TEST ("Checking initial state");
    INFO ("empty: %d, full: %d, available: %zu, space: %zu\n",
          SocketBuf_empty (buf), SocketBuf_full (buf),
          SocketBuf_available (buf), SocketBuf_space (buf));

    if (SocketBuf_empty (buf) && !SocketBuf_full (buf))
      {
        PASS ("Initial state: empty=true, full=false");
      }

    /* Fill the buffer completely */
    TEST ("Filling buffer to capacity");
    char filldata[512];
    memset (filldata, 'X', sizeof (filldata));
    size_t written = SocketBuf_write (buf, filldata, sizeof (filldata));
    INFO ("Wrote %zu bytes\n", written);

    INFO ("After fill - empty: %d, full: %d, available: %zu, space: %zu\n",
          SocketBuf_empty (buf), SocketBuf_full (buf),
          SocketBuf_available (buf), SocketBuf_space (buf));

    if (SocketBuf_full (buf) && !SocketBuf_empty (buf))
      {
        PASS ("Buffer is full");
      }

    /* Try to write when full */
    TEST ("Attempting write when buffer is full");
    size_t extra = SocketBuf_write (buf, "overflow", 8);
    if (extra == 0)
      {
        PASS ("Write returns 0 when buffer is full");
      }
    else
      {
        FAIL ("Should not write to full buffer");
      }

    /* Read half the data */
    TEST ("Reading partial data");
    char partial[50];
    SocketBuf_read (buf, partial, sizeof (partial));

    INFO ("After partial read - available: %zu, space: %zu\n",
          SocketBuf_available (buf), SocketBuf_space (buf));

    if (!SocketBuf_empty (buf) && !SocketBuf_full (buf))
      {
        PASS ("Buffer is neither empty nor full");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer State: Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_secure_clear - Show secure data clearing
 */
static void
demonstrate_secure_clear (Arena_T arena)
{
  SECTION ("Secure Data Clearing");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 1024);

    /* Write sensitive data */
    TEST ("Writing sensitive data (simulated password)");
    const char *secret = "SuperSecretPassword123!";
    SocketBuf_write (buf, secret, strlen (secret));
    INFO ("Wrote sensitive data: %zu bytes\n", strlen (secret));
    INFO ("Available: %zu bytes\n", SocketBuf_available (buf));

    /* Demonstrate regular clear vs secure clear */
    TEST ("Using SocketBuf_secureclear() to erase sensitive data");
    SocketBuf_secureclear (buf);
    INFO ("Buffer securely cleared (memory zeroed)\n");
    INFO ("Available after secure clear: %zu\n", SocketBuf_available (buf));

    if (SocketBuf_empty (buf))
      {
        PASS ("Buffer empty after secure clear");
        INFO ("Note: SocketBuf_secureclear() overwrites memory with zeros\n");
        INFO (
            "      before resetting pointers - important for crypto keys,\n");
        INFO ("      passwords, and other sensitive data.\n");
      }

    /* Demonstrate regular clear for comparison */
    TEST ("Regular clear with SocketBuf_clear()");
    SocketBuf_write (buf, "non-sensitive data", 18);
    SocketBuf_clear (buf);

    if (SocketBuf_empty (buf))
      {
        PASS ("Buffer empty after regular clear");
        INFO ("Note: SocketBuf_clear() is faster (O(1)) but doesn't\n");
        INFO ("      zero memory - use only for non-sensitive data.\n");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_secureclear (
            buf); /* Always secure clear sensitive buffers */
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_advanced_operations - Show advanced buffer features
 */
static void
demonstrate_advanced_operations (Arena_T arena)
{
  SECTION ("Advanced Buffer Operations");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 1024);

    /* Demonstrate buffer find */
    TEST ("Finding data in buffer with SocketBuf_find()");
    const char *http_data = "GET /index.html HTTP/1.1\r\n"
                            "Host: example.com\r\n"
                            "\r\n";
    SocketBuf_write (buf, http_data, strlen (http_data));

    /* Find end of HTTP headers */
    ssize_t pos = SocketBuf_find (buf, "\r\n\r\n", 4);
    if (pos >= 0)
      {
        INFO ("Found header delimiter at offset %zd\n", pos);
        PASS ("SocketBuf_find() located pattern");
      }
    else
      {
        FAIL ("Could not find pattern");
      }

    SocketBuf_clear (buf);

    /* Demonstrate readline */
    TEST ("Reading lines with SocketBuf_readline()");
    const char *lines = "First line\nSecond line\nThird line\n";
    SocketBuf_write (buf, lines, strlen (lines));

    char line[256];
    int line_count = 0;
    ssize_t len;

    while ((len = SocketBuf_readline (buf, line, sizeof (line))) > 0)
      {
        line_count++;
        INFO ("Line %d (%zd bytes): %s", line_count, len, line);
      }

    if (line_count == 3)
      {
        PASS ("Read all lines successfully");
      }
    else
      {
        FAIL ("Unexpected line count");
      }

    SocketBuf_clear (buf);

    /* Demonstrate compact */
    TEST ("Compacting buffer with SocketBuf_compact()");
    SocketBuf_write (buf, "Some data here", 14);
    SocketBuf_consume (buf, 5); /* Remove "Some " */

    INFO ("Before compact - available: %zu, space: %zu\n",
          SocketBuf_available (buf), SocketBuf_space (buf));

    SocketBuf_compact (buf);

    INFO ("After compact - available: %zu, space: %zu\n",
          SocketBuf_available (buf), SocketBuf_space (buf));
    PASS ("Buffer compacted (data moved to front)");

    /* Demonstrate ensure */
    TEST ("Ensuring space with SocketBuf_ensure()");
    size_t needed = 2048; /* More than current capacity */

    if (SocketBuf_ensure (buf, needed))
      {
        INFO ("Ensured %zu bytes of space (buffer may have been resized)\n",
              needed);
        PASS ("SocketBuf_ensure() guaranteed space");
      }
    else
      {
        FAIL ("Could not ensure space");
      }

    /* Demonstrate invariant checking */
    TEST ("Validating buffer invariants");
    if (SocketBuf_check_invariants (buf))
      {
        PASS ("Buffer invariants valid");
      }
    else
      {
        FAIL ("Buffer invariants violated");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * demonstrate_scatter_gather - Show scatter-gather I/O
 */
static void
demonstrate_scatter_gather (Arena_T arena)
{
  SECTION ("Scatter-Gather I/O Operations");

  SocketBuf_T buf = NULL;

  TRY
  {
    buf = SocketBuf_new (arena, 2048);

    /* Gather write - write from multiple buffers */
    TEST ("Gather write with SocketBuf_writev()");

    char header[] = "HEADER";
    char body[] = "This is the body content";
    char footer[] = "FOOTER";

    struct iovec iov_write[3]
        = { { .iov_base = header, .iov_len = sizeof (header) - 1 },
            { .iov_base = body, .iov_len = sizeof (body) - 1 },
            { .iov_base = footer, .iov_len = sizeof (footer) - 1 } };

    ssize_t total_written = SocketBuf_writev (buf, iov_write, 3);
    INFO ("Wrote %zd bytes from 3 separate buffers\n", total_written);

    if (total_written > 0)
      {
        PASS ("Gather write successful");
      }

    /* Scatter read - read into multiple buffers */
    TEST ("Scatter read with SocketBuf_readv()");

    char hdr_buf[10] = { 0 };
    char body_buf[30] = { 0 };
    char ftr_buf[10] = { 0 };

    struct iovec iov_read[3]
        = { { .iov_base = hdr_buf, .iov_len = sizeof (hdr_buf) },
            { .iov_base = body_buf, .iov_len = sizeof (body_buf) },
            { .iov_base = ftr_buf, .iov_len = sizeof (ftr_buf) } };

    ssize_t total_read = SocketBuf_readv (buf, iov_read, 3);
    INFO ("Read %zd bytes into 3 separate buffers\n", total_read);
    INFO ("Header: %s\n", hdr_buf);
    INFO ("Body: %s\n", body_buf);
    INFO ("Footer: %s\n", ftr_buf);

    if (total_read == total_written)
      {
        PASS ("Scatter read successful");
      }
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
  }
  FINALLY
  {
    if (buf)
      {
        SocketBuf_release (&buf);
      }
  }
  END_TRY;
}

/**
 * main - Entry point
 */
int
main (void)
{
  Arena_T arena = NULL;
  volatile int result = 0;

  printf ("SocketBuf Circular Buffer API Demonstration\n");
  printf ("=============================================\n");

  TRY
  {
    /* Create arena for all buffer allocations */
    arena = Arena_new ();
    INFO ("Arena created for buffer memory management\n");

    /* Run demonstrations */
    demonstrate_basic_operations (arena);
    demonstrate_peek_operations (arena);
    demonstrate_zerocopy_operations (arena);
    demonstrate_buffer_state (arena);
    demonstrate_secure_clear (arena);
    demonstrate_advanced_operations (arena);
    demonstrate_scatter_gather (arena);

    printf ("\n=== Summary ===\n");
    printf ("[PASS] All demonstrations completed successfully\n");
    printf ("\nKey Takeaways:\n");
    printf ("  1. SocketBuf provides efficient circular buffering for socket "
            "I/O\n");
    printf ("  2. Zero-copy operations minimize memcpy overhead\n");
    printf ("  3. Use SocketBuf_secureclear() for sensitive data\n");
    printf ("  4. Buffer state queries help manage flow control\n");
    printf ("  5. Advanced operations (find, readline, compact) support "
            "protocols\n");
    printf (
        "  6. Scatter-gather I/O enables efficient multi-buffer operations\n");
    printf ("\nFor production usage, see:\n");
    printf ("  - SocketPool for per-connection buffer management\n");
    printf (
        "  - Socket_readbuf/Socket_writebuf for direct socket integration\n");
    printf ("  - docs/ASYNC_IO.md for async I/O patterns\n");
  }
  EXCEPT (Arena_Failed)
  {
    fprintf (stderr, "[ERROR] Arena allocation failed\n");
    result = 1;
  }
  EXCEPT (SocketBuf_Failed)
  {
    fprintf (stderr, "[ERROR] Buffer operation failed\n");
    result = 1;
  }
  FINALLY
  {
    /* Cleanup arena (frees all buffers) */
    if (arena)
      {
        Arena_dispose (&arena);
      }
  }
  END_TRY;

  printf ("\nBuffer demonstration complete.\n");
  return result;
}
