/**
 * SocketBuf.c - Circular buffer for socket I/O
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "socket/SocketBuf.h"

#define T SocketBuf_T

/* Minimum buffer capacity for practical network I/O
 * Matches SOCKET_MIN_BUFFER_SIZE from SocketConfig.h for consistency */

/* Validation macro for buffer invariants */
#define SOCKETBUF_INVARIANTS(buf)                                             \
  do                                                                          \
    {                                                                         \
      assert ((buf) != NULL);                                                 \
      assert ((buf)->data != NULL);                                           \
      assert ((buf)->capacity > 0);                                           \
      assert ((buf)->size <= (buf)->capacity);                                \
      assert ((buf)->tail < (buf)->capacity);                                 \
      assert ((buf)->head < (buf)->capacity);                                 \
    }                                                                         \
  while (0)

struct T
{
  char *data;
  size_t capacity;
  size_t head;
  size_t tail;
  size_t size;
  Arena_T arena;
};

T
SocketBuf_new (Arena_T arena, size_t capacity)
{
  T buf;

  assert (arena);
  assert (capacity > 0);

  /* Limit capacity to SIZE_MAX/2 to prevent overflow in pointer arithmetic */
  if (capacity > SIZE_MAX / 2)
    return NULL;

  /* Note: No minimum capacity enforced - allows small buffers for testing.
   * Production code should use SOCKET_MIN_BUFFER_SIZE (512) for efficiency. */

  buf = ALLOC (arena, sizeof (*buf));
  if (!buf)
    return NULL;

  /* Use CALLOC to zero buffer */
  buf->data = CALLOC (arena, capacity, 1);
  if (!buf->data)
    return NULL;

  buf->capacity = capacity;
  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
  buf->arena = arena;

  return buf;
}

void
SocketBuf_release (T *buf)
{
  assert (buf && *buf);
  *buf = NULL;
}

size_t
SocketBuf_write (T buf, const void *data, size_t len)
{
  size_t space;
  size_t written = 0;
  const char *src = data;

  assert (buf);
  assert (buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  space = buf->capacity - buf->size;
  if (len > space)
    len = space;

  while (written < len)
    {
      size_t chunk = buf->capacity - buf->tail;

      if (chunk > len - written)
        chunk = len - written;

      if (chunk == 0)
        break;

      /* This should only be zero if len == written (loop condition false) */
      assert (chunk > 0 || len == written);
      assert (buf->tail + chunk <= buf->capacity);
      memcpy (buf->data + buf->tail, src + written, chunk);
      buf->tail = (buf->tail + chunk) % buf->capacity;
      written += chunk;
    }

  buf->size += written;
  SOCKETBUF_INVARIANTS (buf);
  return written;
}

size_t
SocketBuf_read (T buf, void *data, size_t len)
{
  size_t read = 0;
  char *dst = data;

  assert (buf);
  assert (buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  if (len > buf->size)
    len = buf->size;

  while (read < len)
    {
      size_t chunk = buf->capacity - buf->head;

      if (chunk > len - read)
        chunk = len - read;

      if (chunk == 0)
        break;

      /* This should only be zero if len == read (loop condition false) */
      assert (chunk > 0 || len == read);
      assert (buf->head + chunk <= buf->capacity);
      memcpy (dst + read, buf->data + buf->head, chunk);
      buf->head = (buf->head + chunk) % buf->capacity;
      read += chunk;
    }

  buf->size -= read;
  SOCKETBUF_INVARIANTS (buf);
  return read;
}

size_t
SocketBuf_peek (T buf, void *data, size_t len)
{
  size_t read = 0;
  char *dst = data;
  size_t head;

  assert (buf);
  assert (buf->data);
  assert (data || len == 0);
  SOCKETBUF_INVARIANTS (buf);

  if (len > buf->size)
    len = buf->size;

  head = buf->head;
  while (read < len)
    {
      size_t chunk = buf->capacity - head;

      if (chunk > len - read)
        chunk = len - read;

      if (chunk == 0)
        break;

      /* This should only be zero if len == read (loop condition false) */
      assert (chunk > 0 || len == read);
      assert (head < buf->capacity);
      assert (head + chunk <= buf->capacity);
      memcpy (dst + read, buf->data + head, chunk);
      head = (head + chunk) % buf->capacity;
      read += chunk;
    }

  return read;
}

void
SocketBuf_consume (T buf, size_t len)
{
  assert (buf);
  SOCKETBUF_INVARIANTS (buf);
  assert (len <= buf->size);

  /* Prevent overflow in modulo operation */
  assert (len <= buf->capacity);
  assert (buf->head <= buf->capacity - 1);

  buf->head = (buf->head + len) % buf->capacity;
  buf->size -= len;

  SOCKETBUF_INVARIANTS (buf);
}

size_t
SocketBuf_available (const T buf)
{
  assert (buf);
  return buf->size;
}

size_t
SocketBuf_space (const T buf)
{
  assert (buf);
  return buf->capacity - buf->size;
}

int
SocketBuf_empty (const T buf)
{
  assert (buf);
  return buf->size == 0;
}

int
SocketBuf_full (const T buf)
{
  assert (buf);
  return buf->size == buf->capacity;
}

void
SocketBuf_clear (T buf)
{
  assert (buf);

  /* Fast clear - just reset pointers without zeroing memory */
  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}

void
SocketBuf_secureclear (T buf)
{
  assert (buf);
  assert (buf->data);

  /* Secure clear - zero memory contents before resetting pointers
   * SECURITY PATTERN: Defense-in-depth with assertion + runtime check
   * - Debug builds: assertion catches programming errors early
   * - Release builds (NDEBUG): runtime check prevents security vulnerabilities
   * This pattern ensures security-critical operations work correctly even when
   * assertions are disabled in production builds. Recommended for all
   * operations involving sensitive data (passwords, keys, tokens, etc.). */
  if (buf->data && buf->capacity > 0)
    memset (buf->data, 0, buf->capacity);

  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}

const void *
SocketBuf_readptr (T buf, size_t *len)
{
  size_t contiguous;

  assert (buf);
  assert (len);
  assert (buf->data);
  SOCKETBUF_INVARIANTS (buf);

  if (buf->size == 0)
    {
      *len = 0;
      return NULL;
    }

  contiguous = buf->capacity - buf->head;
  if (contiguous > buf->size)
    contiguous = buf->size;

  assert (contiguous > 0);
  assert (contiguous <= buf->capacity);
  assert (buf->head + contiguous <= buf->capacity);

  *len = contiguous;
  return buf->data + buf->head;
}

void *
SocketBuf_writeptr (T buf, size_t *len)
{
  size_t space;
  size_t contiguous;

  assert (buf);
  assert (len);
  assert (buf->data);
  SOCKETBUF_INVARIANTS (buf);

  space = buf->capacity - buf->size;
  if (space == 0)
    {
      *len = 0;
      return NULL;
    }

  contiguous = buf->capacity - buf->tail;
  if (contiguous > space)
    contiguous = space;

  assert (contiguous > 0);
  assert (contiguous <= buf->capacity);
  assert (buf->tail + contiguous <= buf->capacity);

  *len = contiguous;
  return buf->data + buf->tail;
}

void
SocketBuf_written (T buf, size_t len)
{
  assert (buf);
  SOCKETBUF_INVARIANTS (buf);

  /* Validate len fits in available space */
  assert (len <= buf->capacity - buf->size);

  /* Prevent overflow in modulo operation */
  assert (len <= buf->capacity);

  buf->tail = (buf->tail + len) % buf->capacity;
  buf->size += len;

  SOCKETBUF_INVARIANTS (buf);
}

#undef T
