/**
 * SocketBuf.c - Circular buffer for socket I/O
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/SocketBuf.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketBuf"

const Except_T SocketBuf_Failed
    = { &SocketBuf_Failed, "SocketBuf operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketBuf);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketBuf, e)

#define T SocketBuf_T

/* Minimum buffer capacity for practical network I/O
 * Matches SOCKET_MIN_BUFFER_SIZE from SocketConfig.h for consistency */

#define SOCKETBUF_INVARIANTS(buf)                                             \
  do                                                                          \
    {                                                                         \
      if (!SocketBuf_check_invariants (buf))                                  \
        {                                                                     \
          SOCKET_ERROR_MSG ("SocketBuf invariants violated");                 \
          RAISE_MODULE_ERROR (SocketBuf_Failed);                              \
        }                                                                     \
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

/* Runtime invariant check (rules: prefer over asserts for prod security) */
bool
SocketBuf_check_invariants (T buf)
{
  if (!buf || !buf->data || buf->capacity == 0 || buf->size > buf->capacity
      || buf->tail >= buf->capacity || buf->head >= buf->capacity)
    {
      return false;
    }
  return true;
}

/**
 * SocketBuf_reserve - Dynamically resize buffer to ensure min_space available
 * Raises on realloc fail or overflow
 * Doubles capacity or min_space, rebase circular data to start if head >0
 * Called automatically in write if needed
 */
void
SocketBuf_reserve (T buf, size_t min_space)
{
  size_t needed = buf->size + min_space;
  if (needed <= buf->capacity)
    return;

  /* Calculate new capacity with overflow check */
  size_t new_cap = buf->capacity ? buf->capacity * 2 : 1024;
  if (new_cap < min_space || new_cap > SIZE_MAX - 64) /* Overhead */
    {
      SOCKET_ERROR_MSG ("SocketBuf reserve overflow: needed %zu current %zu",
                        needed, buf->capacity);
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }
  new_cap = new_cap > min_space ? new_cap : min_space;

  char *old_data = buf->data;
  size_t old_cap = buf->capacity;
  char *new_data = Arena_calloc (buf->arena, 1, new_cap, __FILE__, __LINE__);
  if (!new_data)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Failed to calloc SocketBuf to %zu",
                        new_cap);
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

  /* Copy existing data to start of new buffer */
  if (buf->size > 0)
    {
      memcpy (new_data, old_data + buf->head, buf->size);
    }

  /* Zero old data for security (abandoned until arena dispose) */
  if (old_data && old_cap > 0)
    {
      memset (old_data, 0, old_cap);
    }

  buf->data = new_data;
  buf->capacity = new_cap;
  buf->head = 0;
  buf->tail = buf->size;

  SOCKETBUF_INVARIANTS (buf); /* Validate after resize */
}

T
SocketBuf_new (Arena_T arena, size_t capacity)
{
  T buf;

  assert (arena);
  assert (capacity > 0);

  /* Limit capacity to SIZE_MAX/2 to prevent overflow in pointer arithmetic */
  if (capacity > SIZE_MAX / 2)
    {
      SOCKET_ERROR_MSG (
          "SocketBuf_new: capacity %zu too large (> SIZE_MAX/2 = %zu)",
          capacity, SIZE_MAX / 2);
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

  /* Note: No minimum capacity enforced - allows small buffers for testing.
   * Production code should use SOCKET_MIN_BUFFER_SIZE (512) for efficiency. */

  buf = ALLOC (arena, sizeof (*buf));
  if (!buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Failed to ALLOC SocketBuf struct (size %zu)",
                        sizeof (*buf));
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

  /* Use CALLOC to zero buffer */
  buf->data = CALLOC (arena, capacity, 1);
  if (!buf->data)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Failed to CALLOC SocketBuf data (capacity %zu)",
                        capacity);
      RAISE_MODULE_ERROR (SocketBuf_Failed);
    }

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
    {
      /* Secure clear with volatile to prevent compiler optimization removal */
      volatile char *vdata = (volatile char *)buf->data;
      for (size_t i = 0; i < buf->capacity; i++)
        vdata[i] = 0;
    }

  buf->head = 0;
  buf->tail = 0;
  buf->size = 0;
}


#undef T
