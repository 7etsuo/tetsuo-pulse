/**
 * test_socketbuf.c - SocketBuf circular buffer unit tests
 * Tests for the SocketBuf circular buffer module.
 * Covers write, read, peek, wraparound, capacity limits, and edge cases.
 */

#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "socket/SocketBuf.h"
#include "test/Test.h"

/* Test buffer creation */
TEST (socketbuf_new_creates_buffer)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketBuf_T buf = SocketBuf_new (arena, 1024);
  ASSERT_NOT_NULL (buf);

  Arena_dispose (&arena);
}

/* Test basic write operation */
TEST (socketbuf_write_basic)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  const char *data = "Hello, World!";
  size_t written = SocketBuf_write (buf, data, strlen (data));

  ASSERT_EQ (written, strlen (data));
  ASSERT_EQ (SocketBuf_available (buf), strlen (data));

  Arena_dispose (&arena);
}

/* Test basic read operation */
TEST (socketbuf_read_basic)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  const char *data = "Hello, World!";
  SocketBuf_write (buf, data, strlen (data));

  char read_buf[1024] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf));

  ASSERT_EQ (read, strlen (data));
  ASSERT_EQ (strcmp (read_buf, data), 0);
  ASSERT_EQ (SocketBuf_available (buf), 0);
  ASSERT_NE (SocketBuf_empty (buf), 0);

  Arena_dispose (&arena);
}

/* Test peek operation doesn't remove data */
TEST (socketbuf_peek_doesnt_remove)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  const char *data = "Test data";
  SocketBuf_write (buf, data, strlen (data));

  char peek_buf[1024] = { 0 };
  size_t peeked = SocketBuf_peek (buf, peek_buf, sizeof (peek_buf));

  ASSERT_EQ (peeked, strlen (data));
  ASSERT_EQ (strcmp (peek_buf, data), 0);
  ASSERT_EQ (SocketBuf_available (buf), strlen (data)); /* Still available */

  /* Read should still work */
  char read_buf[1024] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf));
  ASSERT_EQ (read, strlen (data));

  Arena_dispose (&arena);
}

/* Test multiple writes */
TEST (socketbuf_multiple_writes)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  SocketBuf_write (buf, "Hello", 5);
  SocketBuf_write (buf, ", ", 2);
  SocketBuf_write (buf, "World!", 6);

  ASSERT_EQ (SocketBuf_available (buf), 13);

  char read_buf[1024] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf));
  ASSERT_EQ (read, 13);
  ASSERT_EQ (strcmp (read_buf, "Hello, World!"), 0);

  Arena_dispose (&arena);
}

/* Test partial read */
TEST (socketbuf_partial_read)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  const char *data = "Hello, World!";
  SocketBuf_write (buf, data, strlen (data));

  char read_buf[5] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf) - 1);

  ASSERT_EQ (read, 4); /* Reading 4 bytes, not 5 */
  read_buf[4] = '\0';  /* Null terminate */
  ASSERT_EQ (strcmp (read_buf, "Hell"), 0);
  ASSERT_EQ (SocketBuf_available (buf), strlen (data) - 4);

  Arena_dispose (&arena);
}

/* Test write beyond capacity */
TEST (socketbuf_write_beyond_capacity)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 512); /* Min buffer is 512 */

  /* Create a string longer than 512 bytes */
  char data[600];
  memset (data, 'X', sizeof (data) - 1);
  data[sizeof (data) - 1] = '\0';

  size_t written = SocketBuf_write (buf, data, strlen (data));

  /* Should write up to capacity */
  ASSERT_EQ (written, 512);
  ASSERT_EQ (SocketBuf_available (buf), 512);
  ASSERT_NE (SocketBuf_full (buf), 0);

  Arena_dispose (&arena);
}

/* Test empty buffer */
TEST (socketbuf_empty_buffer)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  ASSERT_NE (SocketBuf_empty (buf), 0);
  ASSERT_EQ (SocketBuf_available (buf), 0);
  ASSERT_EQ (SocketBuf_space (buf), 1024);

  Arena_dispose (&arena);
}

/* Test full buffer */
TEST (socketbuf_full_buffer)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 512); /* Min buffer is 512 */

  /* Fill 512 bytes */
  char fill_data[512];
  memset (fill_data, 'A', 512);
  SocketBuf_write (buf, fill_data, 512);

  ASSERT_NE (SocketBuf_full (buf), 0);
  ASSERT_EQ (SocketBuf_space (buf), 0);
  ASSERT_EQ (SocketBuf_available (buf), 512);

  Arena_dispose (&arena);
}

/* Test available and space */
TEST (socketbuf_available_and_space)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 512); /* Min buffer is 512 */

  ASSERT_EQ (SocketBuf_available (buf), 0);
  ASSERT_EQ (SocketBuf_space (buf), 512);

  SocketBuf_write (buf, "Test", 4);

  ASSERT_EQ (SocketBuf_available (buf), 4);
  ASSERT_EQ (SocketBuf_space (buf), 508);

  Arena_dispose (&arena);
}

/* Test clear operation */
TEST (socketbuf_clear)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  SocketBuf_write (buf, "Test data", 9);
  ASSERT_EQ (SocketBuf_available (buf), 9);

  SocketBuf_clear (buf);

  ASSERT_EQ (SocketBuf_available (buf), 0);
  ASSERT_NE (SocketBuf_empty (buf), 0);
  ASSERT_EQ (SocketBuf_space (buf), 1024);

  /* Can write again after clear */
  SocketBuf_write (buf, "New data", 8);
  ASSERT_EQ (SocketBuf_available (buf), 8);

  Arena_dispose (&arena);
}

/* Test consume operation */
TEST (socketbuf_consume)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  SocketBuf_write (buf, "Hello, World!", 13);
  ASSERT_EQ (SocketBuf_available (buf), 13);

  SocketBuf_consume (buf, 7);
  ASSERT_EQ (SocketBuf_available (buf), 6);

  char read_buf[1024] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf));
  ASSERT_EQ (read, 6);
  ASSERT_EQ (strcmp (read_buf, "World!"), 0);

  Arena_dispose (&arena);
}

/* Test wraparound scenario */
TEST (socketbuf_wraparound)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 512); /* Min buffer is 512 */

  /* Fill buffer with 512 bytes */
  char fill_data[512];
  for (int i = 0; i < 512; i++)
    fill_data[i] = 'A' + (i % 26);
  SocketBuf_write (buf, fill_data, 512);
  ASSERT_EQ (SocketBuf_available (buf), 512);

  /* Read some data to create space */
  char read_buf[256];
  SocketBuf_read (buf, read_buf, 256);
  ASSERT_EQ (SocketBuf_available (buf), 256);
  ASSERT_EQ (SocketBuf_space (buf), 256);

  /* Write more data - should wraparound */
  char new_data[256];
  memset (new_data, 'X', 256);
  SocketBuf_write (buf, new_data, 256);
  ASSERT_EQ (SocketBuf_available (buf), 512);

  /* Read all data and verify structure */
  char full_buf[513] = { 0 };
  size_t read = SocketBuf_read (buf, full_buf, 512);
  ASSERT_EQ (read, 512);
  /* First 256 bytes should be the remaining original data (A-Z pattern
   * starting at 256) */
  /* Next 256 bytes should be 'X' characters */
  for (int i = 256; i < 512; i++)
    ASSERT (full_buf[i] == 'X');

  Arena_dispose (&arena);
}

/* Test readptr for zero-copy read */
TEST (socketbuf_readptr)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  SocketBuf_write (buf, "Test data", 9);

  size_t len = 0;
  const void *ptr = SocketBuf_readptr (buf, &len);

  ASSERT_NOT_NULL (ptr);
  ASSERT_EQ (len, 9);
  ASSERT_EQ (memcmp (ptr, "Test data", 9), 0);

  /* Data should still be available */
  ASSERT_EQ (SocketBuf_available (buf), 9);

  Arena_dispose (&arena);
}

/* Test writeptr for zero-copy write */
TEST (socketbuf_writeptr)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  size_t len = 0;
  void *ptr = SocketBuf_writeptr (buf, &len);

  ASSERT_NOT_NULL (ptr);
  ASSERT_NE (len, 0); /* Should have at least some space */

  /* Write data directly */
  memcpy (ptr, "Direct write", 12);
  SocketBuf_written (buf, 12);

  ASSERT_EQ (SocketBuf_available (buf), 12);

  char read_buf[1024] = { 0 };
  size_t read = SocketBuf_read (buf, read_buf, sizeof (read_buf));
  ASSERT_EQ (read, 12);
  ASSERT_EQ (strcmp (read_buf, "Direct write"), 0);

  Arena_dispose (&arena);
}

/* Test release operation */
TEST (socketbuf_release)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  ASSERT_NOT_NULL (buf);

  SocketBuf_release (&buf);
  ASSERT_NULL (buf);

  Arena_dispose (&arena);
}

/* Test write-read-write cycle */
TEST (socketbuf_write_read_cycle)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024); /* Min buffer is 512 */

  for (int i = 0; i < 10; i++)
    {
      char write_data[16];
      snprintf (write_data, sizeof (write_data), "Data%d", i);
      SocketBuf_write (buf, write_data, strlen (write_data));

      char read_data[16] = { 0 };
      size_t read = SocketBuf_read (buf, read_data, sizeof (read_data));
      ASSERT_EQ (read, strlen (write_data));
      ASSERT_EQ (strcmp (read_data, write_data), 0);
    }

  Arena_dispose (&arena);
}

/* Test secure clear operation */
TEST (socketbuf_secureclear)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf = SocketBuf_new (arena, 1024);

  /* Write sensitive data */
  const char *sensitive = "password123";
  SocketBuf_write (buf, sensitive, strlen (sensitive));
  ASSERT_EQ (SocketBuf_available (buf), strlen (sensitive));

  /* Secure clear should zero memory and reset buffer */
  SocketBuf_secureclear (buf);

  ASSERT_EQ (SocketBuf_available (buf), 0);
  ASSERT_NE (SocketBuf_empty (buf), 0);
  ASSERT_EQ (SocketBuf_space (buf), 1024);

  /* Can write again after secure clear */
  SocketBuf_write (buf, "New data", 8);
  ASSERT_EQ (SocketBuf_available (buf), 8);

  Arena_dispose (&arena);
}

/* Test clear vs secureclear difference */
TEST (socketbuf_clear_vs_secureclear)
{
  Arena_T arena = Arena_new ();
  SocketBuf_T buf1 = SocketBuf_new (arena, 1024);
  SocketBuf_T buf2 = SocketBuf_new (arena, 1024);

  const char *data = "Sensitive information";

  /* Test regular clear */
  SocketBuf_write (buf1, data, strlen (data));
  SocketBuf_clear (buf1);
  ASSERT_EQ (SocketBuf_available (buf1), 0);

  /* Test secure clear */
  SocketBuf_write (buf2, data, strlen (data));
  SocketBuf_secureclear (buf2);
  ASSERT_EQ (SocketBuf_available (buf2), 0);

  /* Both should be empty after clear */
  ASSERT_NE (SocketBuf_empty (buf1), 0);
  ASSERT_NE (SocketBuf_empty (buf2), 0);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
